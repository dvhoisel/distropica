use crate::{fail, Ctx};
use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Binary,
    Source,
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
    pub path: PathBuf,
    pub has_install: bool,
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
printf 'EPOCH=%s\n' "${EPOCH:-}"
type install_pkg >/dev/null 2>&1 && printf 'HAS_INSTALL=1\n' || :
"#;

pub fn find(ctx: &Ctx, name: &str) -> Result<PathBuf> {
    for tree in ctx.newspeak_paths() {
        let p = tree.join(name).join("recipe");
        if p.is_file() {
            return Ok(p);
        }
    }
    fail(2, format!("não há receita para '{name}' em nenhuma árvore newspeak"))
}

pub fn load(ctx: &Ctx, name: &str) -> Result<Recipe> {
    let path = find(ctx, name)?;
    let out = Command::new("sh")
        .arg("-ec")
        .arg(DUMP)
        .arg("sh")
        .arg(&path)
        .output()
        .map_err(|e| crate::Fail { code: 2, msg: format!("não consegui avaliar a receita: {e}") })?;
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
    let list = |k: &str| -> Vec<String> {
        field(k).split_whitespace().map(str::to_string).collect()
    };

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
        other => return fail(2, format!("{name}: KIND '{other}' inválido (binary|source)")),
    };
    let srcs = list("SRC");
    if srcs.is_empty() {
        return fail(2, format!("{name}: SRC ausente"));
    }
    let sha256: Vec<String> = list("SHA256").iter().map(|s| s.to_lowercase()).collect();
    if !sha256.is_empty() && sha256.len() != srcs.len() {
        return fail(2, format!("{name}: SHA256 e SRC com contagens diferentes"));
    }
    if sha256.iter().any(|h| h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit())) {
        return fail(2, format!("{name}: SHA256 mal-formado (64 hex por artefato)"));
    }
    if sha256.is_empty() && !ctx.tofu {
        return fail(2, format!("{name}: receita sem SHA256 (só com --tofu, e com aviso)"));
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
            _ => return fail(2, format!("{name}: LINKS '{item}' inválido (nome=caminho/relativo)")),
        }
    }
    let sigsums = Some(field("SIGSUMS")).filter(|s| !s.is_empty());
    let sigkey = Some(field("SIGKEY")).filter(|s| !s.is_empty());

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
        path,
        has_install: get.contains_key("HAS_INSTALL"),
    };
    if r.kind == Kind::Binary && !r.has_install {
        return fail(2, format!("{name}: KIND=binary exige install_pkg()"));
    }
    Ok(r)
}
