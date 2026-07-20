use crate::{fail, Ctx};
use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Binary,
    Source,
}

/// Toolchain de build por estágio (SPEC-0005). O executor injeta `CC`/`AR`/…
/// conforme o perfil; é o que permite a cadeia pass-1 → glibc → pass-2 existir
/// como fluxo, em vez de tudo cair no zig/musl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Toolchain {
    /// `zig cc -target x86_64-linux-musl` — a semente. Default (pré-E2).
    #[default]
    Seed,
    /// `x86_64-distropica-linux-gnu-*` — gcc passada 1 + binutils-cross.
    Cross,
    /// `gcc`/`g++` nativo, hospedado na glibc nova (pós-E2).
    Native,
}

#[derive(Debug, Clone)]
pub struct Recipe {
    pub name: String,
    pub version: String,
    pub kind: Kind,
    pub srcs: Vec<String>,
    pub sha256: Vec<String>,
    pub deps: Vec<String>,
    pub build_deps: Vec<String>,
    pub links: Vec<(String, String)>,
    pub sig: Vec<String>,
    pub sigsums: Option<String>,
    pub sigkey: Option<String>,
    pub requires_glibc: bool,
    pub provisional: bool,
    pub epoch: Option<String>,
    pub toolchain: Toolchain,
    pub retries: u32,
    /// Pacotes PROVISIONAL cujos caminhos esta receita tem licença de tomar
    /// (SPEC-0003 §7): a supersessão vira declarativa — colisão com um
    /// provisional NÃO listado aqui é *doublethink*, não cessão.
    pub supersedes: Vec<String>,
    pub path: PathBuf,
    pub has_install: bool,
}

impl Recipe {
    /// Fingerprint **próprio** (só desta receita): o arquivo `recipe` — que já
    /// carrega VERSION, SRC, SHA256, TOOLCHAIN, DEPS, BUILD_DEPS e o corpo de
    /// `build()` — mais o diretório `files/` (patches, chaves). Muda quando
    /// qualquer um deles muda, **mesmo sem bump de VERSION**. É o átomo do
    /// fingerprint de build transitivo ([`build_fingerprint`], SPEC-0011 §4),
    /// que é o que a idempotência do `rectify` e o `--sync` de fato usam.
    pub fn own_fingerprint(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"minitrue-fp-v2\0recipe\0");
        h.update(std::fs::read(&self.path)?);
        if let Some(files) = self.path.parent().map(|p| p.join("files")) {
            if files.is_dir() {
                // Reusa o empacotador determinístico (SPEC-0010): o hash do tar
                // normalizado de files/ é estável entre máquinas.
                let fh = crate::pack::pack_deterministic(&files, 0, std::io::sink())?;
                h.update(b"\0files\0");
                h.update(fh.as_bytes());
            }
        }
        Ok(hex::encode(h.finalize()))
    }
}

const DUMP: &str = r#". "$1"
printf 'NAME=%s\n' "${NAME:-}"
printf 'VERSION=%s\n' "${VERSION:-}"
printf 'KIND=%s\n' "${KIND:-}"
printf 'SRC=%s\n' "${SRC:-}"
printf 'SHA256=%s\n' "${SHA256:-}"
printf 'DEPS=%s\n' "${DEPS:-}"
printf 'BUILD_DEPS=%s\n' "${BUILD_DEPS:-}"
printf 'LINKS=%s\n' "${LINKS:-}"
printf 'SIG=%s\n' "${SIG:-}"
printf 'SIGSUMS=%s\n' "${SIGSUMS:-}"
printf 'SIGKEY=%s\n' "${SIGKEY:-}"
printf 'REQUIRES_GLIBC=%s\n' "${REQUIRES_GLIBC:-}"
printf 'PROVISIONAL=%s\n' "${PROVISIONAL:-}"
printf 'SUPERSEDES=%s\n' "${SUPERSEDES:-}"
printf 'EPOCH=%s\n' "${EPOCH:-}"
printf 'TOOLCHAIN=%s\n' "${TOOLCHAIN:-}"
printf 'RETRIES=%s\n' "${RETRIES:-}"
type install_pkg >/dev/null 2>&1 && printf 'HAS_INSTALL=1\n' || :
"#;

pub fn find(ctx: &Ctx, name: &str) -> Result<PathBuf> {
    for tree in ctx.newspeak_paths() {
        let p = tree.join(name).join("recipe");
        if p.is_file() {
            return Ok(p);
        }
    }
    fail(
        2,
        format!("não há receita para '{name}' em nenhuma árvore newspeak"),
    )
}

pub fn load(ctx: &Ctx, name: &str) -> Result<Recipe> {
    let path = find(ctx, name)?;
    let out = Command::new("sh")
        .arg("-ec")
        .arg(DUMP)
        .arg("sh")
        .arg(&path)
        .output()
        .map_err(|e| crate::Fail {
            code: 2,
            msg: format!("não consegui avaliar a receita: {e}"),
        })?;
    if !out.status.success() {
        return fail(
            2,
            format!(
                "receita inválida em {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        );
    }

    let mut get = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((k, v)) = line.split_once('=') {
            get.insert(k.to_string(), v.to_string());
        }
    }
    let field = |k: &str| get.get(k).cloned().unwrap_or_default();
    let list =
        |k: &str| -> Vec<String> { field(k).split_whitespace().map(str::to_string).collect() };

    let rname = field("NAME");
    if rname != name {
        return fail(2, format!("NAME='{rname}' difere do diretório '{name}'"));
    }
    let version = field("VERSION");
    if version.is_empty() {
        return fail(2, format!("{name}: VERSION ausente"));
    }
    let kind = match field("KIND").as_str() {
        "binary" => Kind::Binary,
        "source" => Kind::Source,
        other => {
            return fail(
                2,
                format!("{name}: KIND '{other}' inválido (binary|source)"),
            )
        }
    };
    let srcs = list("SRC");
    if srcs.is_empty() {
        return fail(2, format!("{name}: SRC ausente"));
    }
    let sha256: Vec<String> = list("SHA256").iter().map(|s| s.to_lowercase()).collect();
    if !sha256.is_empty() && sha256.len() != srcs.len() {
        return fail(2, format!("{name}: SHA256 e SRC com contagens diferentes"));
    }
    if sha256
        .iter()
        .any(|h| h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return fail(
            2,
            format!("{name}: SHA256 mal-formado (64 hex por artefato)"),
        );
    }
    if sha256.is_empty() && !ctx.tofu {
        return fail(
            2,
            format!("{name}: receita sem SHA256 (só com --tofu, e com aviso)"),
        );
    }
    let sig = list("SIG");
    if !sig.is_empty() && sig.len() != srcs.len() {
        return fail(2, format!("{name}: SIG e SRC com contagens diferentes"));
    }
    let mut links = Vec::new();
    for item in list("LINKS") {
        match item.split_once('=') {
            Some((cmd, rel)) if !cmd.is_empty() && !rel.is_empty() && !rel.starts_with('/') => {
                links.push((cmd.to_string(), rel.to_string()))
            }
            _ => {
                return fail(
                    2,
                    format!("{name}: LINKS '{item}' inválido (nome=caminho/relativo)"),
                )
            }
        }
    }
    let sigsums = Some(field("SIGSUMS")).filter(|s| !s.is_empty());
    let sigkey = Some(field("SIGKEY")).filter(|s| !s.is_empty());
    let toolchain = match field("TOOLCHAIN").as_str() {
        "" | "seed" => Toolchain::Seed,
        "cross" => Toolchain::Cross,
        "native" => Toolchain::Native,
        other => {
            return fail(
                2,
                format!("{name}: TOOLCHAIN '{other}' inválido (seed|cross|native)"),
            )
        }
    };
    let retries: u32 = match field("RETRIES").as_str() {
        "" => 0,
        s => s.parse().map_err(|_| crate::Fail {
            code: 2,
            msg: format!("{name}: RETRIES '{s}' não é número"),
        })?,
    };

    let r = Recipe {
        name: rname,
        version,
        kind,
        srcs,
        sha256,
        deps: list("DEPS"),
        build_deps: list("BUILD_DEPS"),
        links,
        sig,
        sigsums,
        sigkey,
        requires_glibc: field("REQUIRES_GLIBC") == "1",
        provisional: field("PROVISIONAL") == "1",
        epoch: Some(field("EPOCH")).filter(|s| !s.is_empty()),
        toolchain,
        retries,
        supersedes: list("SUPERSEDES"),
        path,
        has_install: get.contains_key("HAS_INSTALL"),
    };
    if r.kind == Kind::Binary && !r.has_install {
        return fail(2, format!("{name}: KIND=binary exige install_pkg()"));
    }
    Ok(r)
}

/// Fingerprint de build **transitivo** (SPEC-0011 §4): o `own_fingerprint` da
/// receita **combinado com os fingerprints das suas `DEPS`+`BUILD_DEPS`**,
/// recursivamente. Assim, se o `binutils` muda, o fingerprint do `gcc` também
/// muda — e o `rectify`/`--sync` re-builda o dependente, não só o pacote
/// alterado. Consertando o limite não-transitivo do v1.
///
/// Memoiza (diamantes) e é robusto a ciclo (a árvore num commit é acíclica —
/// `collect` detecta; aqui um ciclo apenas encerra a recursão sem travar).
pub fn build_fingerprint(ctx: &Ctx, name: &str) -> Result<String> {
    let mut cache = std::collections::HashMap::new();
    build_fp_rec(ctx, name, &mut cache, &mut Vec::new())
}

fn build_fp_rec(
    ctx: &Ctx,
    name: &str,
    cache: &mut std::collections::HashMap<String, String>,
    stack: &mut Vec<String>,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    if let Some(fp) = cache.get(name) {
        return Ok(fp.clone());
    }
    if stack.iter().any(|s| s == name) {
        return Ok(String::new()); // ciclo: encerra sem recorrer
    }
    let r = load(ctx, name)?;
    let mut h = Sha256::new();
    h.update(b"minitrue-bfp-v1\0self\0");
    h.update(r.own_fingerprint()?.as_bytes());
    stack.push(name.to_string());
    // Ordem canônica dos deps para o hash ser estável.
    let mut deps: Vec<&String> = r.deps.iter().chain(r.build_deps.iter()).collect();
    deps.sort();
    deps.dedup();
    for d in deps {
        h.update(b"\0dep\0");
        h.update(d.as_bytes());
        h.update(b"=");
        h.update(build_fp_rec(ctx, d, cache, stack)?.as_bytes());
    }
    stack.pop();
    let fp = hex::encode(h.finalize());
    cache.insert(name.to_string(), fp.clone());
    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Grava um recipe num tree temporário e o carrega via `load`.
    fn load_body(extra: &str) -> Result<Recipe> {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-recipe-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/foo");
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "a".repeat(64);
        let body = format!(
            "NAME=foo\nVERSION=1.0\nKIND=source\nSRC=https://e/foo.tar.xz\nSHA256={hash}\n{extra}\nbuild(){{ :; }}\n"
        );
        std::fs::write(dir.join("recipe"), body).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let r = load(&ctx, "foo");
        let _ = std::fs::remove_dir_all(&root);
        r
    }

    /// Carrega uma receita (opcionalmente com arquivos em `files/`), computa o
    /// fingerprint ANTES de limpar (o fingerprint lê o arquivo do disco).
    fn fp_of(extra: &str, files: &[(&str, &str)]) -> String {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-fp-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/foo");
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "a".repeat(64);
        std::fs::write(
            dir.join("recipe"),
            format!("NAME=foo\nVERSION=1.0\nKIND=source\nSRC=https://e/f.tar.xz\nSHA256={hash}\n{extra}\nbuild(){{ :; }}\n"),
        )
        .unwrap();
        if !files.is_empty() {
            std::fs::create_dir_all(dir.join("files")).unwrap();
            for (name, content) in files {
                std::fs::write(dir.join("files").join(name), content).unwrap();
            }
        }
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let f = load(&ctx, "foo").unwrap().own_fingerprint().unwrap();
        let _ = std::fs::remove_dir_all(&root);
        f
    }

    #[test]
    fn fingerprint_estavel_e_sensivel() {
        let base = fp_of("", &[]);
        // determinístico: mesma receita → mesmo fingerprint
        assert_eq!(base, fp_of("", &[]));
        // MESMA versão (1.0), receita diferente → fingerprint diferente.
        // É o bug do review consertado: mudar a receita sem bump de VERSION
        // agora dispara rebuild.
        assert_ne!(base, fp_of("TOOLCHAIN=cross", &[]), "toolchain muda o fp");
        assert_ne!(base, fp_of("DEPS=glibc", &[]), "deps mudam o fp");
        // files/ entra no fingerprint (patches, chaves)
        let com_patch = fp_of("", &[("fix.patch", "--- a\n+++ b\n")]);
        assert_ne!(base, com_patch, "files/ muda o fp");
        assert_eq!(com_patch, fp_of("", &[("fix.patch", "--- a\n+++ b\n")]));
        assert_ne!(
            com_patch,
            fp_of("", &[("fix.patch", "outro conteúdo\n")]),
            "conteúdo de files/ conta"
        );
    }

    #[test]
    fn build_fingerprint_transitivo() {
        // Árvore A → B: A depende de B. Mudar B muda o fingerprint de A.
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-bfp-{}-{n}", std::process::id()));
        let tree = root.join("var/lib/minitrue/newspeak");
        let hash = "a".repeat(64);
        let write = |name: &str, extra: &str| {
            let d = tree.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("recipe"),
                format!("NAME={name}\nVERSION=1\nKIND=source\nSRC=https://e/{name}.tar.xz\nSHA256={hash}\n{extra}\nbuild(){{ :; }}\n"),
            )
            .unwrap();
        };
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        write("b", "");
        write("a", "DEPS=b");
        let fp_a1 = build_fingerprint(&ctx, "a").unwrap();
        // determinístico
        assert_eq!(fp_a1, build_fingerprint(&ctx, "a").unwrap());
        // muda B (mesma versão) → o fingerprint de A muda também (transitivo)
        write("b", "# toque em b");
        let fp_a2 = build_fingerprint(&ctx, "a").unwrap();
        assert_ne!(fp_a1, fp_a2, "mudar um dep deve mudar o fp do dependente");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn toolchain_default_e_seed_sem_retries() {
        let r = load_body("").unwrap();
        assert_eq!(r.toolchain, Toolchain::Seed);
        assert_eq!(r.retries, 0);
    }

    #[test]
    fn toolchain_cross_com_retries() {
        let r = load_body("TOOLCHAIN=cross\nRETRIES=50").unwrap();
        assert_eq!(r.toolchain, Toolchain::Cross);
        assert_eq!(r.retries, 50);
    }

    #[test]
    fn toolchain_native() {
        assert_eq!(
            load_body("TOOLCHAIN=native").unwrap().toolchain,
            Toolchain::Native
        );
    }

    #[test]
    fn toolchain_invalido_recusado() {
        assert!(load_body("TOOLCHAIN=quantum").is_err());
    }

    #[test]
    fn retries_nao_numero_recusado() {
        assert!(load_body("RETRIES=muitas").is_err());
    }
}
