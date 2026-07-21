//! Attestations e corroboração (SPEC-0009 §6/§8) — o Ministério do Amor com lei
//! escrita. Um builder ASSINA {pacote, versão, recipe_fingerprint, artifact_hash}
//! com sua chave ed25519; ≥2 builders CONFIÁVEIS distintos concordando no
//! artifact_hash ⇒ CORROBORADO (ortodoxo). Um confiável discordando ⇒ DESVIO.
//!
//! A raiz é o `reprocorr` (o hash reprodutível pinado na receita, SPEC-0009 §6):
//! como a rede só consegue entregar o artefato canônico, ela vira só um espelho,
//! e a confiança vem da convergência dos pares — não do publicador.

use crate::install::read_meta;
use crate::{fail, iso_now, Ctx};
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// O corpo canônico assinado (ordem fixa). BUILT_AT/SIG ficam FORA — informativo
/// e assinatura. Reconstruído idêntico na verificação, então ordem/espaços do
/// arquivo não importam.
fn body(
    pkg: &str,
    version: &str,
    recipe_fp: &str,
    artifact: &str,
    builder: &str,
    builder_key: &str,
) -> String {
    format!(
        "ATTEST_FORMAT=1\nPACKAGE={pkg}\nVERSION={version}\nRECIPE_FINGERPRINT={recipe_fp}\nARTIFACT_HASH={artifact}\nBUILDER={builder}\nBUILDER_KEY={builder_key}\n"
    )
}

/// Gera o par ed25519 do builder: grava a secreta (hex, 0600) e imprime a
/// pública (hex) — a identidade que o admin PINA em /etc/minitrue/builders/<nome>
/// (o ato explícito de confiança, SPEC-0009 §7).
pub fn keygen(name: &str, secret_path: &Path) -> Result<()> {
    if secret_path.exists() {
        return fail(
            1,
            format!(
                "{} já existe — não sobrescrevo chave secreta",
                secret_path.display()
            ),
        );
    }
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
    fs::write(secret_path, format!("{}\n", hex::encode(sk.to_bytes())))?;
    fs::set_permissions(secret_path, fs::Permissions::from_mode(0o600))?;
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

/// Emite uma attestation ASSINADA para <pkg> a partir do registro instalado.
/// Imprime o texto (o mantenedor publica/entrega). Op de mantenedor (miniplenty).
pub fn attest(ctx: &Ctx, pkg: &str, builder: &str, secret_path: &Path) -> Result<()> {
    let rec = ctx.records_dir().join(pkg);
    let meta = read_meta(&rec).ok_or_else(|| crate::Fail {
        code: 1,
        msg: format!("{pkg} não está instalado (sem registro)"),
    })?;
    let get = |k: &str| meta.get(k).cloned().unwrap_or_default();
    let artifact = get("ARTIFACT_HASH");
    if artifact.is_empty() {
        return fail(
            1,
            format!("{pkg}: registro sem ARTIFACT_HASH — nada reprodutível a atestar"),
        );
    }
    let sk = load_secret(secret_path)?;
    let builder_key = hex::encode(sk.verifying_key().to_bytes());
    let b = body(
        pkg,
        &get("VERSION"),
        &get("FINGERPRINT"),
        &artifact,
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
pub struct Attestation {
    pub package: String,
    pub artifact_hash: String,
    pub builder_key: String,
}

pub fn parse_and_verify(text: &str) -> Result<Attestation> {
    let mut f: HashMap<&str, &str> = HashMap::new();
    let mut sig_hex = "";
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k == "SIG" {
                sig_hex = v.trim();
            } else {
                f.insert(k, v.trim());
            }
        }
    }
    let need = |k: &str| {
        f.get(k).copied().ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("attestation sem {k}"),
        })
    };
    let package = need("PACKAGE")?.to_string();
    let version = need("VERSION")?.to_string();
    let recipe_fp = need("RECIPE_FINGERPRINT")?.to_string();
    let artifact_hash = need("ARTIFACT_HASH")?.to_string();
    let builder = need("BUILDER")?.to_string();
    let builder_key = need("BUILDER_KEY")?.to_string();
    let b = body(
        &package,
        &version,
        &recipe_fp,
        &artifact_hash,
        &builder,
        &builder_key,
    );
    let pk_bytes: [u8; 32] = hex::decode(&builder_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| crate::Fail {
            code: 2,
            msg: "BUILDER_KEY inválida (hex de 32 bytes)".into(),
        })?;
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| crate::Fail {
        code: 2,
        msg: "BUILDER_KEY não é chave ed25519 válida".into(),
    })?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| crate::Fail {
            code: 2,
            msg: "SIG inválida (hex de 64 bytes)".into(),
        })?;
    let sig = Signature::from_bytes(&sig_bytes);
    pk.verify_strict(b.as_bytes(), &sig)
        .map_err(|_| crate::Fail {
            code: 4,
            msg: format!("crimestop (attestation): assinatura de '{builder}' não confere"),
        })?;
    Ok(Attestation {
        package,
        artifact_hash,
        builder_key,
    })
}

/// Builders CONFIÁVEIS: pubkeys pinadas pelo admin em /etc/minitrue/builders/<nome>
/// (o ato explícito de confiança). Mapa pubkey_hex(minúsculo) → nome.
fn trusted_builders(ctx: &Ctx) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(rd) = fs::read_dir(ctx.root.join("etc/minitrue/builders")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Ok(content) = fs::read_to_string(e.path()) {
                let key = content.trim().to_lowercase();
                if !key.is_empty() {
                    m.insert(key, name);
                }
            }
        }
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
    /// registro sem ARTIFACT_HASH — nada reprodutível a corroborar.
    NoArtifact,
}

/// Corrobora <pkg>: compara o ARTIFACT_HASH do registro com as attestations
/// coletadas em var/lib/minitrue/attestations/<pkg>/, contando builders
/// CONFIÁVEIS distintos. ≥2 concordando ⇒ corroborado; um discordando ⇒ desvio.
pub fn corroboration(ctx: &Ctx, pkg: &str) -> Verdict {
    let rec = ctx.records_dir().join(pkg);
    let local = match read_meta(&rec).and_then(|m| m.get("ARTIFACT_HASH").cloned()) {
        Some(h) if !h.is_empty() => h,
        _ => return Verdict::NoArtifact,
    };
    let trusted = trusted_builders(ctx);
    let dir = ctx.root.join("var/lib/minitrue/attestations").join(pkg);
    let mut agree: Vec<String> = Vec::new();
    let mut diverge: Vec<(String, String)> = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let Ok(text) = fs::read_to_string(e.path()) else {
                continue;
            };
            // assinatura ruim ⇒ ignora silenciosamente (não é do builder que diz)
            let Ok(att) = parse_and_verify(&text) else {
                continue;
            };
            // só conta builder PINADO (confiável) e do mesmo pacote
            let Some(name) = trusted.get(&att.builder_key.to_lowercase()) else {
                continue;
            };
            if att.package != pkg {
                continue;
            }
            if att.artifact_hash == local {
                if !agree.contains(name) {
                    agree.push(name.clone());
                }
            } else if !diverge.iter().any(|(n, _)| n == name) {
                diverge.push((name.clone(), att.artifact_hash.clone()));
            }
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
    let rec = ctx.records_dir().join(pkg);
    let local = read_meta(&rec)
        .and_then(|m| m.get("ARTIFACT_HASH").cloned())
        .filter(|h| !h.is_empty());
    let Some(local) = local else {
        return fail(
            1,
            format!("{pkg}: registro sem ARTIFACT_HASH (nada a corroborar)"),
        );
    };
    let trusted = trusted_builders(ctx);
    println!("corroboração de {pkg}:");
    println!("  artifact_hash local: {}", short(&local));
    println!("  builders confiáveis pinados: {}", trusted.len());
    match corroboration(ctx, pkg) {
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
                4,
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
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);
    const HASH: &str = "de4710b70e7acc1267cf106b285f80e4a384ce6923fb4ed2b3bf4181bb29946e";

    /// Assina uma attestation para (m4, ah) com uma chave derivada de `seed`
    /// (determinístico p/ teste). Devolve (texto, pubkey_hex).
    fn sign(seed: u8, builder: &str, ah: &str) -> (String, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let b = body("m4", "1.4.21", "fp", ah, builder, &pk);
        let sig = sk.sign(b.as_bytes());
        (format!("{b}SIG={}\n", hex::encode(sig.to_bytes())), pk)
    }

    #[test]
    fn assinatura_e_corroboracao() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-att-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let rec = ctx.records_dir().join("m4");
        fs::create_dir_all(&rec).unwrap();
        fs::write(rec.join("meta"), format!("NAME=m4\nARTIFACT_HASH={HASH}\n")).unwrap();
        let bdir = root.join("etc/minitrue/builders");
        let adir = root.join("var/lib/minitrue/attestations/m4");
        fs::create_dir_all(&bdir).unwrap();
        fs::create_dir_all(&adir).unwrap();

        // 1) parse_and_verify aceita uma att válida e RECUSA uma adulterada
        let (alice, alice_pk) = sign(1, "alice", HASH);
        assert!(parse_and_verify(&alice).is_ok());
        let tampered = alice.replace("de4710", "de4711");
        assert!(
            parse_and_verify(&tampered).is_err(),
            "att adulterada: assinatura não confere"
        );

        // 2) sem builders pinados → nada corrobora (attestations existem, mas não confiáveis)
        let (bob, bob_pk) = sign(2, "bob", HASH);
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
        let (mal, mal_pk) = sign(3, "mallory", &"a".repeat(64));
        fs::write(bdir.join("mallory"), &mal_pk).unwrap();
        fs::write(adir.join("mallory.att"), &mal).unwrap();
        assert!(matches!(corroboration(&ctx, "m4"), Verdict::Divergence(_)));

        // 5) builder NÃO pinado não conta (a forjada adulterada tb é ignorada)
        fs::remove_file(adir.join("mallory.att")).unwrap();
        fs::remove_file(bdir.join("mallory")).unwrap();
        let (carol, _) = sign(4, "carol", HASH); // carol NÃO pinada
        fs::write(adir.join("carol.att"), &carol).unwrap();
        fs::write(adir.join("alice.att"), &tampered).unwrap(); // alice agora adulterada
                                                               // sobra só bob válido+confiável → 1 (precisa ≥2)
        assert!(matches!(
            corroboration(&ctx, "m4"),
            Verdict::Insufficient(1)
        ));

        let _ = fs::remove_dir_all(&root);
    }
}
