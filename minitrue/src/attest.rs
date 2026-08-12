//! Attestations e corroboração (SPEC-0009 §6/§8) — o Ministério do Amor com lei
//! escrita. Um builder ASSINA {pacote, versão, recipe_fingerprint, artifact_hash}
//! com sua chave ed25519; ≥2 builders CONFIÁVEIS distintos concordando no
//! artifact_hash ⇒ CORROBORADO (ortodoxo). Um confiável discordando ⇒ DESVIO.
//!
//! A raiz é o `reprocorr` (o hash reprodutível pinado na receita, SPEC-0009 §6):
//! como a rede só consegue entregar o artefato canônico, ela vira só um espelho,
//! e a confiança vem da convergência dos pares — não do publicador.

use crate::install::{attestable_meta, confined_regular_files};
use crate::{fail, iso_now, Ctx};
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const ATTEST_FORMAT: &str = "1";

/// O corpo canônico assinado (ordem fixa). BUILT_AT/SIG ficam FORA — informativo
/// e assinatura. Reconstruído idêntico na verificação, então ordem/espaços do
/// arquivo não importa; os valores, porém, precisam estar na forma canônica.
fn body(
    pkg: &str,
    version: &str,
    recipe_fp: &str,
    artifact: &str,
    builder: &str,
    builder_key: &str,
) -> String {
    format!(
        "ATTEST_FORMAT={ATTEST_FORMAT}\nPACKAGE={pkg}\nVERSION={version}\nRECIPE_FINGERPRINT={recipe_fp}\nARTIFACT_HASH={artifact}\nBUILDER={builder}\nBUILDER_KEY={builder_key}\n"
    )
}

fn validate_text_field(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value != value.trim() || value.chars().any(char::is_control) {
        return fail(
            2,
            format!("{field} vazio, não canônico ou com caractere de controle"),
        );
    }
    Ok(())
}

fn validate_lower_hex(field: &str, value: &str, bytes: usize) -> Result<()> {
    let canonical = value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if value.len() != bytes * 2 || !canonical {
        return fail(
            2,
            format!(
                "{field} inválido (esperado hex minúsculo de {} bytes)",
                bytes
            ),
        );
    }
    Ok(())
}

fn decode_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    validate_lower_hex(field, value, N)?;
    let bytes = hex::decode(value).map_err(|_| crate::Fail {
        code: 2,
        msg: format!("{field} inválido"),
    })?;
    bytes.try_into().map_err(|_| {
        crate::Fail {
            code: 2,
            msg: format!("{field} não tem {N} bytes"),
        }
        .into()
    })
}

fn parse_verifying_key(value: &str) -> Result<VerifyingKey> {
    let bytes = decode_hex::<32>("BUILDER_KEY", value)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| {
        crate::Fail {
            code: 2,
            msg: "BUILDER_KEY não é chave ed25519 válida".into(),
        }
        .into()
    })
}

#[derive(Clone)]
struct ArtifactIdentity {
    version: String,
    recipe_fingerprint: String,
    artifact_hash: String,
}

fn local_identity(ctx: &Ctx, pkg: &str) -> Result<ArtifactIdentity> {
    crate::recipe::validate_name(pkg)?;
    let meta = attestable_meta(ctx, pkg)?;
    let required = |field: &str| {
        meta.get(field)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| crate::Fail {
                code: 2,
                msg: format!("{pkg}: registro sem {field}"),
            })
    };
    let version = required("VERSION")?;
    let recipe_fingerprint = required("FINGERPRINT")?;
    let artifact_hash = required("ARTIFACT_HASH")?;
    validate_text_field("VERSION", &version)?;
    validate_lower_hex("FINGERPRINT", &recipe_fingerprint, 32)?;
    validate_lower_hex("ARTIFACT_HASH", &artifact_hash, 32)?;
    Ok(ArtifactIdentity {
        version,
        recipe_fingerprint,
        artifact_hash,
    })
}

/// Gera o par ed25519 do builder: grava a secreta (hex, 0600) e imprime a
/// pública (hex) — a identidade que o admin PINA em
/// `/etc/minitrue/builders/<nome>`
/// (o ato explícito de confiança, SPEC-0009 §7).
pub fn keygen(name: &str, secret_path: &Path) -> Result<()> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| crate::Fail {
        code: 1,
        msg: format!("sem entropia: {e}"),
    })?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    if let Some(dir) = secret_path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    // `create_new` transforma o teste de existência e a criação numa só
    // operação: não há janela de corrida e nem symlink final é seguido.
    let mut secret = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(secret_path)
        .map_err(|e| {
            let msg = if e.kind() == ErrorKind::AlreadyExists {
                format!(
                    "{} já existe — não sobrescrevo chave secreta",
                    secret_path.display()
                )
            } else {
                format!("não foi possível criar {}: {e}", secret_path.display())
            };
            crate::Fail { code: 1, msg }
        })?;
    // O descritor já nasceu no máximo 0600; fchmod garante exatamente 0600
    // mesmo sob uma umask mais restritiva, sem reabrir o caminho.
    secret.set_permissions(fs::Permissions::from_mode(0o600))?;
    writeln!(secret, "{}", hex::encode(sk.to_bytes()))?;
    secret.sync_all()?;
    println!(
        "builder '{name}': chave secreta em {} (0600)",
        secret_path.display()
    );
    println!("chave pública (pine em /etc/minitrue/builders/{name}):");
    println!("{}", hex::encode(pk.to_bytes()));
    Ok(())
}

fn load_secret(path: &Path) -> Result<SigningKey> {
    let hexed = fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(&hexed).map_err(|_| crate::Fail {
        code: 2,
        msg: format!("{}: chave secreta não é hex", path.display()),
    })?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| crate::Fail {
        code: 2,
        msg: "chave secreta não tem 32 bytes".into(),
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Emite uma attestation ASSINADA para `<pkg>` a partir do registro instalado.
/// Imprime o texto (o mantenedor publica/entrega). Op de mantenedor (miniplenty).
pub fn attest(ctx: &Ctx, pkg: &str, builder: &str, secret_path: &Path) -> Result<()> {
    validate_text_field("PACKAGE", pkg)?;
    validate_text_field("BUILDER", builder)?;
    let identity = local_identity(ctx, pkg)?;
    let sk = load_secret(secret_path)?;
    let builder_key = hex::encode(sk.verifying_key().to_bytes());
    let b = body(
        pkg,
        &identity.version,
        &identity.recipe_fingerprint,
        &identity.artifact_hash,
        builder,
        &builder_key,
    );
    let sig = sk.sign(b.as_bytes());
    print!("{b}");
    println!("BUILT_AT={}", iso_now());
    println!("SIG={}", hex::encode(sig.to_bytes()));
    Ok(())
}

/// Attestation parseada e com a AUTO-assinatura verificada (SIG bate com a
/// BUILDER_KEY declarada). NÃO decide confiança — isso é a corroboração.
#[derive(Debug)]
pub struct Attestation {
    pub package: String,
    pub version: String,
    pub recipe_fingerprint: String,
    pub artifact_hash: String,
    pub builder_key: String,
}

pub fn parse_and_verify(text: &str) -> Result<Attestation> {
    let mut f: HashMap<&str, &str> = HashMap::new();
    for (line_no, line) in text.lines().enumerate() {
        let Some((field, value)) = line.split_once('=') else {
            return fail(2, format!("attestation: linha {} malformada", line_no + 1));
        };
        if !matches!(
            field,
            "ATTEST_FORMAT"
                | "PACKAGE"
                | "VERSION"
                | "RECIPE_FINGERPRINT"
                | "ARTIFACT_HASH"
                | "BUILDER"
                | "BUILDER_KEY"
                | "BUILT_AT"
                | "SIG"
        ) {
            return fail(2, format!("attestation: campo desconhecido {field}"));
        }
        if value != value.trim() {
            return fail(
                2,
                format!("attestation: {field} contém espaço externo não canônico"),
            );
        }
        if f.insert(field, value).is_some() {
            return fail(2, format!("attestation: campo duplicado {field}"));
        }
    }
    let need = |k: &str| {
        f.get(k).copied().ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("attestation sem {k}"),
        })
    };
    let format = need("ATTEST_FORMAT")?;
    if format != ATTEST_FORMAT {
        return fail(
            2,
            format!("ATTEST_FORMAT incompatível: {format} (esperado {ATTEST_FORMAT})"),
        );
    }
    let package = need("PACKAGE")?.to_string();
    let version = need("VERSION")?.to_string();
    let recipe_fp = need("RECIPE_FINGERPRINT")?.to_string();
    let artifact_hash = need("ARTIFACT_HASH")?.to_string();
    let builder = need("BUILDER")?.to_string();
    let builder_key = need("BUILDER_KEY")?.to_string();
    let sig_hex = need("SIG")?;
    validate_text_field("PACKAGE", &package)?;
    validate_text_field("VERSION", &version)?;
    validate_text_field("BUILDER", &builder)?;
    validate_lower_hex("RECIPE_FINGERPRINT", &recipe_fp, 32)?;
    validate_lower_hex("ARTIFACT_HASH", &artifact_hash, 32)?;
    if let Some(built_at) = f.get("BUILT_AT") {
        validate_text_field("BUILT_AT", built_at)?;
    }
    let b = body(
        &package,
        &version,
        &recipe_fp,
        &artifact_hash,
        &builder,
        &builder_key,
    );
    let pk = parse_verifying_key(&builder_key)?;
    let sig_bytes = decode_hex::<64>("SIG", sig_hex)?;
    let sig = Signature::from_bytes(&sig_bytes);
    pk.verify_strict(b.as_bytes(), &sig)
        .map_err(|_| crate::Fail {
            code: 7,
            msg: format!("crimestop (attestation): assinatura de '{builder}' não confere"),
        })?;
    Ok(Attestation {
        package,
        version,
        recipe_fingerprint: recipe_fp,
        artifact_hash,
        builder_key,
    })
}

/// Builders CONFIÁVEIS: pubkeys pinadas pelo admin em
/// `/etc/minitrue/builders/<nome>`
/// (o ato explícito de confiança). Mapa pubkey_hex(minúsculo) → nome.
fn trusted_builders(ctx: &Ctx) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let directory = "/etc/minitrue/builders";
    let files = match confined_regular_files(&ctx.root, directory) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("minitrue: não foi possível ler builders confiáveis em {directory}: {e}");
            return m;
        }
    };
    for (name, bytes) in files {
        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) => {
                eprintln!("minitrue: builder pin {name} ignorado: não é UTF-8");
                continue;
            }
        };
        let key = content.trim().to_lowercase();
        if let Err(e) = parse_verifying_key(&key) {
            eprintln!("minitrue: builder pin {name} ignorado: {e}");
            continue;
        }
        m.insert(key, name);
    }
    m
}

/// Veredito da corroboração.
pub enum Verdict {
    /// ≥2 builders confiáveis distintos concordam com o artifact_hash local.
    Corroborated(Vec<String>),
    /// Um builder confiável atesta um hash DIFERENTE — desvio (SPEC-0009 §9).
    Divergence(Vec<(String, String)>),
    /// menos de 2 corroboradores confiáveis (n de attestations válidas).
    Insufficient(usize),
    /// registro sem identidade completa — nada reprodutível a corroborar.
    NoArtifact,
}

fn corroboration_for(
    ctx: &Ctx,
    pkg: &str,
    local: &ArtifactIdentity,
    trusted: &HashMap<String, String>,
) -> Verdict {
    let directory = format!("/var/lib/minitrue/attestations/{pkg}");
    let mut agree: Vec<String> = Vec::new();
    let mut diverge: Vec<(String, String)> = Vec::new();
    let files = match confined_regular_files(&ctx.root, &directory) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("minitrue: não foi possível ler attestations em {directory}: {e}");
            return Verdict::Insufficient(0);
        }
    };
    for (name, bytes) in files {
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                eprintln!("minitrue: attestation {name} ignorada: não é UTF-8");
                continue;
            }
        };
        let att = match parse_and_verify(&text) {
            Ok(att) => att,
            Err(e) => {
                eprintln!("minitrue: attestation {name} ignorada: {e}");
                continue;
            }
        };
        // Uma attestation válida de outra versão/fingerprint é histórica
        // (stale): não conta e, sobretudo, nunca vira divergência.
        if att.package != pkg
            || att.version != local.version
            || att.recipe_fingerprint != local.recipe_fingerprint
        {
            continue;
        }
        // Só uma identidade local exata emitida por builder PINADO decide.
        let Some(name) = trusted.get(&att.builder_key) else {
            continue;
        };
        if att.artifact_hash == local.artifact_hash {
            if !agree.contains(name) {
                agree.push(name.clone());
            }
        } else if !diverge.iter().any(|(n, _)| n == name) {
            diverge.push((name.clone(), att.artifact_hash.clone()));
        }
    }
    if !diverge.is_empty() {
        Verdict::Divergence(diverge)
    } else if agree.len() >= 2 {
        agree.sort();
        Verdict::Corroborated(agree)
    } else {
        Verdict::Insufficient(agree.len())
    }
}

/// Corrobora `<pkg>`: compara a identidade completa do registro (versão,
/// fingerprint e hash) com as attestations coletadas em
/// `var/lib/minitrue/attestations/<pkg>/`, contando builders CONFIÁVEIS distintos.
/// ≥2 concordando ⇒ corroborado; um discordando nessa mesma identidade ⇒ desvio.
pub fn corroboration(ctx: &Ctx, pkg: &str) -> Verdict {
    let local = match local_identity(ctx, pkg) {
        Ok(local) => local,
        Err(e) => {
            eprintln!("minitrue: corroboração de {pkg} indisponível: {e}");
            return Verdict::NoArtifact;
        }
    };
    let trusted = trusted_builders(ctx);
    corroboration_for(ctx, pkg, &local, &trusted)
}

fn short(s: &str) -> &str {
    &s[..s.len().min(16)]
}

/// Uma linha para o `explain` (None quando não há o que dizer).
pub fn corroboration_line(ctx: &Ctx, pkg: &str) -> Option<String> {
    match corroboration(ctx, pkg) {
        Verdict::Corroborated(b) => Some(format!(
            "corroborado por {} builders ({}) — ortodoxo",
            b.len(),
            b.join(", ")
        )),
        Verdict::Divergence(d) => {
            let who: Vec<String> = d.iter().map(|(n, h)| format!("{n}→{}", short(h))).collect();
            Some(format!("DIVERGÊNCIA — desvio! {}", who.join(", ")))
        }
        Verdict::Insufficient(0) | Verdict::NoArtifact => None,
        Verdict::Insufficient(n) => Some(format!("{n} attestation confiável (precisa de ≥2)")),
    }
}

/// `corroborate <pkg>` — imprime o veredito detalhado (SPEC-0009 §6/§8).
pub fn corroborate(ctx: &Ctx, pkg: &str) -> Result<()> {
    let local = local_identity(ctx, pkg)?;
    let trusted = trusted_builders(ctx);
    println!("corroboração de {pkg}:");
    println!("  versão local: {}", local.version);
    println!(
        "  recipe_fingerprint local: {}",
        short(&local.recipe_fingerprint)
    );
    println!("  artifact_hash local: {}", short(&local.artifact_hash));
    println!("  builders confiáveis pinados: {}", trusted.len());
    match corroboration_for(ctx, pkg, &local, &trusted) {
        Verdict::Corroborated(b) => {
            println!(
                "  VEREDITO: corroborado por {} builders ({}) — ortodoxo",
                b.len(),
                b.join(", ")
            );
            Ok(())
        }
        Verdict::Divergence(d) => {
            println!("  VEREDITO: DIVERGÊNCIA — desvio (SPEC-0009 §9):");
            for (n, h) in &d {
                println!("    builder '{n}' atesta {} (≠ local)", short(h));
            }
            fail(
                8,
                "crimestop: builders confiáveis discordam do artefato local",
            )
        }
        Verdict::Insufficient(n) => {
            println!(
                "  VEREDITO: não corroborado ({n} attestation(s) confiável(is); precisa de ≥2)"
            );
            Ok(())
        }
        Verdict::NoArtifact => {
            println!("  VEREDITO: sem artifact_hash");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);
    const HASH: &str = "de4710b70e7acc1267cf106b285f80e4a384ce6923fb4ed2b3bf4181bb29946e";
    const OTHER_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_V1: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn temp_root(label: &str) -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("mt-att-{label}-{}-{n}", std::process::id()))
    }

    fn context(root: &Path) -> Ctx {
        Ctx {
            root: root.to_path_buf(),
            offline: false,
            tofu: false,
            jobs: 1,
        }
    }

    fn directory_integrity(mode: u32, tree_sha256: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(b"minitrue-directory-integrity-v1\0");
        hash.update((mode & 0o7777).to_be_bytes());
        hash.update(tree_sha256.as_bytes());
        hex::encode(hash.finalize())
    }

    fn write_runner_record(ctx: &Ctx, recipe: &crate::recipe::Recipe, fingerprint: &str) -> bool {
        let rec = ctx.records_dir().join(crate::recipe::BUILD_RUNNER_PACKAGE);
        if crate::install::read_meta_strict(&rec)
            .unwrap()
            .is_some_and(|meta| meta.get("RECORD_FORMAT").map(String::as_str) == Some("4"))
        {
            return false;
        }
        let payload = ctx
            .opt(crate::recipe::BUILD_RUNNER_PACKAGE)
            .join(&recipe.version);
        fs::create_dir_all(&payload).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();
        let tree_sha256 = crate::pack::pack_deterministic(&payload, 0, std::io::sink()).unwrap();
        let manifest = format!(
            "d:{}  /opt/{}/{}\n",
            directory_integrity(0o755, &tree_sha256),
            recipe.name,
            recipe.version
        );
        let baseline_hash = hex::encode(Sha256::digest(manifest.as_bytes()));
        fs::create_dir_all(&rec).unwrap();
        fs::write(
            rec.join("meta"),
            format!(
                "RECORD_FORMAT=3\nNAME={}\nVERSION={}\nKIND=binary\nWORLD=A\nORIGIN=vendor\nSHA256={}\nDEPS=\nSHARED_DIRS=\nFINGERPRINT={fingerprint}\nINSTALLED_AT=2026-08-11T00:00:00Z\nLICENSE={}\nSUPERSEDES=\nMANIFEST_BASELINE_SHA256={baseline_hash}\n",
                recipe.name,
                recipe.version,
                recipe.sha256.join(" "),
                recipe.license.as_deref().unwrap()
            ),
        )
        .unwrap();
        fs::write(rec.join("manifest"), &manifest).unwrap();
        fs::write(rec.join(format!("manifest@{}", recipe.version)), &manifest).unwrap();
        fs::write(rec.join("recipe"), &recipe.recipe_bytes).unwrap();
        fs::write(
            rec.join(format!("recipe@{}", recipe.version)),
            &recipe.recipe_bytes,
        )
        .unwrap();
        let current = ctx.opt(crate::recipe::BUILD_RUNNER_PACKAGE).join("current");
        let _ = fs::remove_file(&current);
        symlink(&recipe.version, current).unwrap();
        true
    }

    fn write_record(ctx: &Ctx, version: &str, hash: &str) -> String {
        let rec = ctx.records_dir().join("m4");
        let tree = ctx.root.join("var/lib/minitrue/newspeak");
        let recipe_dir = tree.join("m4");
        let runner_dir = tree.join(crate::recipe::BUILD_RUNNER_PACKAGE);
        let installed = ctx.root.join("usr/bin/m4");
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&runner_dir).unwrap();
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        let recipe_bytes = format!(
            "NAME=m4\nVERSION={version}\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nbuild() {{ :; }}\n"
        );
        fs::write(recipe_dir.join("recipe"), &recipe_bytes).unwrap();
        let runner_payload = b"runner de fixture\n";
        let runner_sha = hex::encode(Sha256::digest(runner_payload));
        fs::write(
            runner_dir.join("recipe"),
            format!(
                "NAME={}\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://example.invalid/runner\nSHA256={runner_sha}\ninstall_pkg() {{ :; }}\n",
                crate::recipe::BUILD_RUNNER_PACKAGE
            ),
        )
        .unwrap();
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(ctx.cache_dir().join(&runner_sha), runner_payload).unwrap();
        let recipes = [
            crate::recipe::load(ctx, "m4").unwrap(),
            crate::recipe::load(ctx, crate::recipe::BUILD_RUNNER_PACKAGE).unwrap(),
        ];
        let fingerprints = crate::recipe::build_fingerprints(&recipes).unwrap();
        let fingerprint = fingerprints.get("m4").unwrap().clone();
        let runner_written = write_runner_record(
            ctx,
            &recipes[1],
            fingerprints
                .get(crate::recipe::BUILD_RUNNER_PACKAGE)
                .unwrap(),
        );
        fs::write(&installed, b"payload atestado\n").unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o644)).unwrap();
        let file_hash = hex::encode(Sha256::digest(b"payload atestado\n"));
        let integrity = crate::install::regular_integrity(0o644, &file_hash);
        let manifest = format!("f:{integrity}  /usr/bin/m4\n");
        let baseline_hash = hex::encode(Sha256::digest(manifest.as_bytes()));
        fs::write(
            rec.join("meta"),
            format!(
                "RECORD_FORMAT=3\nNAME=m4\nVERSION={version}\nKIND=source\nWORLD=B\nORIGIN=fonte\nSHA256=\nDEPS=\nSHARED_DIRS=\nFINGERPRINT={fingerprint}\nINSTALLED_AT=2026-08-11T00:00:00Z\nARTIFACT_HASH={hash}\nLICENSE=MIT\nSUPERSEDES=\nMANIFEST_BASELINE_SHA256={baseline_hash}\nTRANSACTION_ID=test\n"
            ),
        )
        .unwrap();
        fs::write(rec.join("manifest"), &manifest).unwrap();
        fs::write(rec.join(format!("manifest@{version}")), &manifest).unwrap();
        fs::write(rec.join("recipe"), &recipe_bytes).unwrap();
        fs::write(rec.join(format!("recipe@{version}")), &recipe_bytes).unwrap();
        let installed_recipe = crate::recipe::load(ctx, "m4").unwrap();
        assert!(
            !crate::install::source_needs_install_for_plan(
                ctx,
                &installed_recipe,
                &fingerprint,
                crate::install::BinaryPolicy::PreferBinary,
                true,
            )
            .unwrap(),
            "a fixture v3 precisa ser factual antes da promoção v4"
        );
        let mut written_records = std::collections::BTreeSet::from(["m4".to_string()]);
        if runner_written {
            written_records.insert(crate::recipe::BUILD_RUNNER_PACKAGE.to_string());
        }
        crate::plan::finalize_applied(
            ctx,
            &["m4".to_string()],
            crate::plan::PlanPurpose::ChannelEmit,
            crate::install::BinaryPolicy::PreferBinary,
            crate::plan::AbiPolicy::Strict,
            &written_records,
        )
        .unwrap();
        fingerprint
    }

    /// Assina uma attestation com chave derivada de `seed` (determinística).
    /// Devolve (texto, pubkey_hex).
    fn sign(
        seed: u8,
        builder: &str,
        version: &str,
        fingerprint: &str,
        hash: &str,
    ) -> (String, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let b = body("m4", version, fingerprint, hash, builder, &pk);
        let sig = sk.sign(b.as_bytes());
        (
            format!(
                "{b}BUILT_AT=2026-07-21T00:00:00Z\nSIG={}\n",
                hex::encode(sig.to_bytes())
            ),
            pk,
        )
    }

    #[test]
    fn assinatura_e_corroboracao() {
        let root = temp_root("corroboration");
        let ctx = context(&root);
        let fingerprint = write_record(&ctx, "1.4.21", HASH);
        let bdir = root.join("etc/minitrue/builders");
        let adir = root.join("var/lib/minitrue/attestations/m4");
        fs::create_dir_all(&bdir).unwrap();
        fs::create_dir_all(&adir).unwrap();

        // 1) parse_and_verify aceita uma att válida e RECUSA uma adulterada
        let (alice, alice_pk) = sign(1, "alice", "1.4.21", &fingerprint, HASH);
        assert!(parse_and_verify(&alice).is_ok());
        let tampered = alice.replace("de4710", "de4711");
        let signature_error = parse_and_verify(&tampered).unwrap_err();
        assert_eq!(
            signature_error
                .downcast_ref::<crate::Fail>()
                .map(|e| e.code),
            Some(7),
            "assinatura inválida usa o código contratual"
        );

        // 2) sem builders pinados → nada corrobora (attestations existem, mas não confiáveis)
        let (bob, bob_pk) = sign(2, "bob", "1.4.21", &fingerprint, HASH);
        fs::write(adir.join("alice.att"), &alice).unwrap();
        fs::write(adir.join("bob.att"), &bob).unwrap();
        assert!(matches!(
            corroboration(&ctx, "m4"),
            Verdict::Insufficient(0)
        ));

        // 3) pina alice+bob → corroborado por 2
        fs::write(bdir.join("alice"), &alice_pk).unwrap();
        fs::write(bdir.join("bob"), &bob_pk).unwrap();
        match corroboration(&ctx, "m4") {
            Verdict::Corroborated(v) => assert_eq!(v.len(), 2),
            _ => panic!("esperava corroborado por 2"),
        }

        // 4) mallory (pinada) atesta hash DIFERENTE → divergência (desvio)
        let (mal, mal_pk) = sign(3, "mallory", "1.4.21", &fingerprint, OTHER_HASH);
        fs::write(bdir.join("mallory"), &mal_pk).unwrap();
        fs::write(adir.join("mallory.att"), &mal).unwrap();
        assert!(matches!(corroboration(&ctx, "m4"), Verdict::Divergence(_)));
        let divergence = corroborate(&ctx, "m4").unwrap_err();
        assert_eq!(
            divergence.downcast_ref::<crate::Fail>().map(|e| e.code),
            Some(8)
        );

        // 5) builder NÃO pinado não conta (a forjada adulterada tb é ignorada)
        fs::remove_file(adir.join("mallory.att")).unwrap();
        fs::remove_file(bdir.join("mallory")).unwrap();
        let (carol, _) = sign(4, "carol", "1.4.21", &fingerprint, HASH); // carol NÃO pinada
        fs::write(adir.join("carol.att"), &carol).unwrap();
        fs::write(adir.join("alice.att"), &tampered).unwrap(); // alice agora adulterada
                                                               // sobra só bob válido+confiável → 1 (precisa ≥2)
        assert!(matches!(
            corroboration(&ctx, "m4"),
            Verdict::Insufficient(1)
        ));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn replay_de_versao_ou_fingerprint_antigo_e_stale() {
        let root = temp_root("replay");
        let ctx = context(&root);
        let bdir = root.join("etc/minitrue/builders");
        let adir = root.join("var/lib/minitrue/attestations/m4");
        fs::create_dir_all(&bdir).unwrap();
        fs::create_dir_all(&adir).unwrap();

        // Attestations válidas para a identidade anterior ficam armazenadas.
        let old_fp = write_record(&ctx, "1.4.21", OTHER_HASH);
        let (old_version, alice_pk) = sign(11, "alice", "1.4.21", &old_fp, OTHER_HASH);
        let (old_fingerprint, bob_pk) = sign(12, "bob", "2.0.0", &old_fp, OTHER_HASH);
        fs::write(bdir.join("alice"), &alice_pk).unwrap();
        fs::write(bdir.join("bob"), &bob_pk).unwrap();
        fs::write(adir.join("alice-old.att"), old_version).unwrap();
        fs::write(adir.join("bob-old-fingerprint.att"), old_fingerprint).unwrap();

        // Após o upgrade, ambas são stale. O hash antigo não pode virar desvio.
        let current_fp = write_record(&ctx, "2.0.0", HASH);
        assert!(matches!(
            corroboration(&ctx, "m4"),
            Verdict::Insufficient(0)
        ));

        // Só attestations da identidade exata atual passam a contar.
        let (alice_current, _) = sign(11, "alice", "2.0.0", &current_fp, HASH);
        let (bob_current, _) = sign(12, "bob", "2.0.0", &current_fp, HASH);
        fs::write(adir.join("alice-current.att"), alice_current).unwrap();
        fs::write(adir.join("bob-current.att"), bob_current).unwrap();
        assert!(matches!(
            corroboration(&ctx, "m4"),
            Verdict::Corroborated(_)
        ));

        // Hash diferente só é divergência quando versão e fingerprint casam.
        let (mallory_current, mallory_pk) = sign(13, "mallory", "2.0.0", &current_fp, OTHER_HASH);
        fs::write(bdir.join("mallory"), mallory_pk).unwrap();
        fs::write(adir.join("mallory-current.att"), mallory_current).unwrap();
        assert!(matches!(corroboration(&ctx, "m4"), Verdict::Divergence(_)));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn identidade_local_exige_payload_baseline_e_snapshots_integros() {
        let root = temp_root("local-integrity");
        let ctx = context(&root);
        write_record(&ctx, "1.4.21", HASH);
        assert!(local_identity(&ctx, "m4").is_ok());

        let installed = root.join("usr/bin/m4");
        fs::write(&installed, b"payload adulterado\n").unwrap();
        assert!(local_identity(&ctx, "m4").is_err());
        fs::write(&installed, b"payload atestado\n").unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(local_identity(&ctx, "m4").is_err());
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o644)).unwrap();

        let baseline = ctx.records_dir().join("m4/manifest@1.4.21");
        fs::write(
            &baseline,
            "f:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /usr/bin/m4\n",
        )
        .unwrap();
        assert!(local_identity(&ctx, "m4").is_err());

        write_record(&ctx, "1.4.21", HASH);
        let outside = root.with_extension("record-outside");
        fs::create_dir_all(&outside).unwrap();
        let rec = ctx.records_dir().join("m4");
        for leaf in ["meta", "manifest", "manifest@1.4.21"] {
            let path = rec.join(leaf);
            let original = fs::read(&path).unwrap();
            let external = outside.join(leaf.replace('@', "-"));
            fs::write(&external, &original).unwrap();
            fs::remove_file(&path).unwrap();
            symlink(&external, &path).unwrap();
            assert!(
                local_identity(&ctx, "m4").is_err(),
                "{leaf} externo não pode participar da assinatura"
            );
            fs::remove_file(&path).unwrap();
            fs::write(&path, original).unwrap();
        }
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn pins_e_attestations_nao_seguem_symlinks_externos() {
        let root = temp_root("confined-trust");
        let outside = root.with_extension("outside");
        let ctx = context(&root);
        let fingerprint = write_record(&ctx, "1.4.21", HASH);
        let bdir = root.join("etc/minitrue/builders");
        let adir = root.join("var/lib/minitrue/attestations/m4");
        fs::create_dir_all(&bdir).unwrap();
        fs::create_dir_all(&adir).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let (alice, alice_pk) = sign(41, "alice", "1.4.21", &fingerprint, HASH);
        fs::write(outside.join("alice.pin"), &alice_pk).unwrap();
        fs::write(outside.join("alice.att"), &alice).unwrap();
        symlink(outside.join("alice.pin"), bdir.join("alice")).unwrap();
        symlink(outside.join("alice.att"), adir.join("alice.att")).unwrap();

        assert!(trusted_builders(&ctx).is_empty());
        fs::remove_file(bdir.join("alice")).unwrap();
        fs::write(bdir.join("alice"), &alice_pk).unwrap();
        assert!(matches!(
            corroboration(&ctx, "m4"),
            Verdict::Insufficient(0)
        ));

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn parser_exige_formato_campos_e_digests_canonicos() {
        let (valid, _) = sign(21, "alice", "1.4.21", FP_V1, HASH);
        let parsed = parse_and_verify(&valid).unwrap();
        assert_eq!(parsed.version, "1.4.21");
        assert_eq!(parsed.recipe_fingerprint, FP_V1);

        let missing_format = valid.replacen("ATTEST_FORMAT=1\n", "", 1);
        assert!(parse_and_verify(&missing_format).is_err());

        let future_format = valid.replacen("ATTEST_FORMAT=1", "ATTEST_FORMAT=2", 1);
        assert!(parse_and_verify(&future_format).is_err());

        let unknown = valid.replacen("SIG=", "EXTRA=surpresa\nSIG=", 1);
        assert!(parse_and_verify(&unknown).is_err());

        let malformed = format!("linha-sem-igual\n{valid}");
        assert!(parse_and_verify(&malformed).is_err());

        // Mesmo corretamente assinados, digest curto ou não-canônico é recusado.
        let (short_fingerprint, _) = sign(22, "alice", "1.4.21", "abcd", HASH);
        assert!(parse_and_verify(&short_fingerprint).is_err());
        let uppercase_hash = HASH.to_uppercase();
        let (noncanonical_hash, _) = sign(23, "alice", "1.4.21", FP_V1, &uppercase_hash);
        assert!(parse_and_verify(&noncanonical_hash).is_err());

        let (spaced_version, _) = sign(24, "alice", "1.4.21 ", FP_V1, HASH);
        assert!(parse_and_verify(&spaced_version).is_err());
        let (spaced_builder, _) = sign(25, " alice", "1.4.21", FP_V1, HASH);
        assert!(parse_and_verify(&spaced_builder).is_err());
        assert!(validate_text_field("BUILDER", "alice ").is_err());
    }

    #[test]
    fn parser_recusa_campos_duplicados() {
        let (valid, _) = sign(31, "alice", "1.4.21", FP_V1, HASH);
        let duplicate_package = valid.replacen("PACKAGE=m4\n", "PACKAGE=m4\nPACKAGE=m4\n", 1);
        assert!(parse_and_verify(&duplicate_package).is_err());

        let signature = valid.lines().find(|line| line.starts_with("SIG=")).unwrap();
        let duplicate_signature = format!("{valid}{signature}\n");
        assert!(parse_and_verify(&duplicate_signature).is_err());
    }

    #[test]
    fn keygen_cria_0600_sem_sobrescrever_ou_seguir_symlink() {
        let root = temp_root("keygen");
        fs::create_dir_all(&root).unwrap();
        let secret = root.join("builder.key");

        keygen("alice", &secret).unwrap();
        let metadata = fs::metadata(&secret).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let original = fs::read_to_string(&secret).unwrap();
        let encoded = original.trim();
        assert_eq!(encoded.len(), 64);
        assert!(encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));

        let error = keygen("alice", &secret).unwrap_err();
        assert!(error.to_string().contains("não sobrescrevo"));
        assert_eq!(fs::read_to_string(&secret).unwrap(), original);

        // Um symlink pendente burlava `Path::exists()` e podia criar o alvo.
        let victim = root.join("nao-deve-ser-criada");
        let link = root.join("link.key");
        symlink(&victim, &link).unwrap();
        let error = keygen("bob", &link).unwrap_err();
        assert!(error.to_string().contains("não sobrescrevo"));
        assert!(!victim.exists());

        let _ = fs::remove_dir_all(&root);
    }
}
