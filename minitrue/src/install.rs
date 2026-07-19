use crate::recipe::{self, Kind, Recipe};
use crate::{fail, fetch, iso_now, Ctx};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------- rectify ----------

pub fn rectify(ctx: &Ctx, names: &[String]) -> Result<()> {
    let explicit: HashSet<&str> = names.iter().map(String::as_str).collect();
    let mut order: Vec<Recipe> = Vec::new();
    let mut seen = HashSet::new();
    for n in names {
        collect(ctx, n, &mut seen, &mut Vec::new(), &mut order)?;
    }
    for r in &order {
        install_one(ctx, r, explicit.contains(r.name.as_str()))?;
    }
    Ok(())
}

fn collect(
    ctx: &Ctx,
    name: &str,
    seen: &mut HashSet<String>,
    stack: &mut Vec<String>,
    out: &mut Vec<Recipe>,
) -> Result<()> {
    if stack.iter().any(|s| s == name) {
        return fail(2, format!("ciclo de dependências: {} -> {name}", stack.join(" -> ")));
    }
    if !seen.insert(name.to_string()) {
        return Ok(());
    }
    let r = recipe::load(ctx, name)?;
    stack.push(name.to_string());
    for d in &r.deps {
        collect(ctx, d, seen, stack, out)?;
    }
    stack.pop();
    out.push(r);
    Ok(())
}

fn install_one(ctx: &Ctx, r: &Recipe, explicit: bool) -> Result<()> {
    if r.kind == Kind::Source {
        return fail(1, format!("{}: mundo B (fonte) chega no Marco 0.2", r.name));
    }
    if r.requires_glibc && !ctx.root.join("usr/lib/ld-linux-x86-64.so.2").exists() {
        return fail(
            5,
            format!("{}: exige a ABI glibc, que só existe após o Estágio 2 (SPEC-0005 §4)", r.name),
        );
    }

    // Idempotência: registro na versão da receita e current coerente = nada a fazer.
    let rec_dir = ctx.records_dir().join(&r.name);
    let opt = ctx.opt(&r.name);
    if let Some(meta) = read_meta(&rec_dir) {
        if meta.get("VERSION") == Some(&r.version)
            && fs::read_link(opt.join("current")).ok() == Some(PathBuf::from(&r.version))
            && opt.join(&r.version).is_dir()
        {
            println!("os registros já estão corretos: {} {}", r.name, r.version);
            return Ok(());
        }
    }

    println!("retificando os registros: {} {}", r.name, r.version);
    let artifacts = fetch::ensure_artifacts(ctx, r)?;

    // install_pkg() em staging dentro de /opt/<nome>, rename atômico ao final.
    fs::create_dir_all(&opt)?;
    let staging = opt.join(format!(".{}.tmp", r.version));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    let work = ctx.root.join("tmp").join(format!("minitrue-work-{}", r.name));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work)?;

    let mut cmd = Command::new("sh");
    cmd.arg("-ec")
        .arg(". \"$RECIPE\"\ninstall_pkg")
        .current_dir(&work)
        .env("RECIPE", &r.path)
        .env("PREFIX", &staging)
        .env("WORK", &work)
        .env("ROOT", &ctx.root)
        .env("JOBS", ctx.jobs.to_string());
    for (i, (p, _)) in artifacts.iter().enumerate() {
        let abs = p.canonicalize()?;
        if i == 0 {
            cmd.env("DL", &abs);
        }
        cmd.env(format!("DL_{}", i + 1), &abs);
    }
    let out = cmd.output().map_err(|e| crate::Fail { code: 1, msg: format!("sh indisponível: {e}") })?;
    if !out.status.success() {
        fs::create_dir_all(ctx.room101())?;
        let log = ctx.room101().join(format!("{}-{}.log", r.name, r.version));
        let mut body = out.stdout.clone();
        body.extend_from_slice(&out.stderr);
        fs::write(&log, body)?;
        let _ = fs::remove_dir_all(&staging);
        let _ = fs::remove_dir_all(&work);
        return fail(
            1,
            format!("{}: install_pkg falhou — o interrogatório completo está em {}", r.name, log.display()),
        );
    }
    let _ = fs::remove_dir_all(&work);

    let verdir = opt.join(&r.version);
    let previous = read_meta(&rec_dir).and_then(|m| m.get("VERSION").cloned()).filter(|v| *v != r.version);
    if verdir.exists() {
        fs::remove_dir_all(&verdir)?;
    }
    fs::rename(&staging, &verdir)?;

    // Flip atômico do current.
    let tmp_cur = opt.join(".current.tmp");
    let _ = fs::remove_file(&tmp_cur);
    symlink(&r.version, &tmp_cur)?;
    fs::rename(&tmp_cur, opt.join("current"))?;

    // Farm de links: LINKS da receita, ou tudo de bin/ do prefixo.
    let pairs: Vec<(String, String)> = if r.links.is_empty() {
        let bin = verdir.join("bin");
        let mut v = Vec::new();
        if bin.is_dir() {
            for e in fs::read_dir(&bin)? {
                let name = e?.file_name().to_string_lossy().into_owned();
                v.push((name.clone(), format!("bin/{name}")));
            }
        }
        v.sort();
        v
    } else {
        r.links.clone()
    };

    let old_links: HashSet<String> = read_manifest(&rec_dir)
        .into_iter()
        .filter(|l| l.starts_with("/usr/"))
        .collect();
    let claims = all_manifests(ctx);
    fs::create_dir_all(ctx.usr_bin())?;
    let mut manifest: Vec<String> = vec![
        format!("/opt/{}/{}", r.name, r.version),
        format!("/opt/{}/current", r.name),
    ];
    for (cmdname, rel) in &pairs {
        let linkpath = ctx.usr_bin().join(cmdname);
        let target = format!("../../opt/{}/current/{}", r.name, rel);
        let virt = format!("/usr/bin/{cmdname}");
        match fs::symlink_metadata(&linkpath) {
            Ok(md) if md.file_type().is_symlink() => {
                let cur = fs::read_link(&linkpath)?;
                if cur != Path::new(&target) {
                    let owner = claims
                        .iter()
                        .find(|(n, _, set)| *n != r.name && set.contains(&virt))
                        .map(|(n, v, _)| format!("{n} {v}"))
                        .unwrap_or_else(|| "algo fora dos registros".into());
                    return fail(4, format!("doublethink detectado: {virt} já pertence a {owner}"));
                }
            }
            Ok(_) => return fail(4, format!("doublethink detectado: {virt} existe e não é link gerido")),
            Err(_) => {}
        }
        let _ = fs::remove_file(&linkpath);
        symlink(&target, &linkpath)?;
        manifest.push(virt);
    }

    // Upgrade: links antigos que saíram do conjunto são recolhidos.
    for l in &old_links {
        if !manifest.contains(l) {
            let p = ctx.root.join(l.trim_start_matches('/'));
            if let Ok(t) = fs::read_link(&p) {
                if t.to_string_lossy().contains(&format!("/opt/{}/", r.name)) {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

    // Retenção corrente+1 (SPEC-0003 §5).
    let keep: HashSet<String> = [Some(r.version.clone()), previous.clone()].into_iter().flatten().collect();
    if let Ok(entries) = fs::read_dir(&opt) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == "current" || name.starts_with('.') || keep.contains(&name) {
                continue;
            }
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let _ = fs::remove_dir_all(e.path());
                let _ = fs::remove_file(rec_dir.join(format!("manifest@{name}")));
                let _ = fs::remove_file(rec_dir.join(format!("recipe@{name}")));
            }
        }
    }

    // O registro: meta, manifest, recipe — texto puro, um fato por linha.
    fs::create_dir_all(&rec_dir)?;
    manifest.sort();
    let meta = format!(
        "NAME={}\nVERSION={}\nKIND=binary\nWORLD=A\nSHA256={}\nDEPS={}\nINSTALLED_AT={}\n",
        r.name,
        r.version,
        r.sha256.join(" "),
        r.deps.join(" "),
        iso_now()
    );
    fs::write(rec_dir.join("meta"), meta)?;
    fs::write(rec_dir.join("manifest"), manifest.join("\n") + "\n")?;
    fs::copy(&r.path, rec_dir.join("recipe"))?;
    fs::copy(&r.path, rec_dir.join(format!("recipe@{}", r.version)))?;
    fs::write(rec_dir.join(format!("manifest@{}", r.version)), manifest.join("\n") + "\n")?;

    if explicit {
        world_add(ctx, &r.name)?;
    }
    println!("{} {} — retificado. doubleplusgood.", r.name, r.version);
    Ok(())
}

// ---------- memoryhole ----------

pub fn memoryhole(ctx: &Ctx, names: &[String]) -> Result<()> {
    let removing: HashSet<&str> = names.iter().map(String::as_str).collect();
    for name in names {
        let rec_dir = ctx.records_dir().join(name);
        if !rec_dir.is_dir() {
            return fail(2, format!("{name}: não há registro — talvez nunca tenha existido"));
        }
        for (other, _, _) in all_manifests(ctx) {
            if removing.contains(other.as_str()) {
                continue;
            }
            let deps = read_meta(&ctx.records_dir().join(&other))
                .and_then(|m| m.get("DEPS").cloned())
                .unwrap_or_default();
            if deps.split_whitespace().any(|d| d == name) {
                return fail(1, format!("{name} ainda sustenta {other} — memoryhole recusado"));
            }
        }
        for line in read_manifest(&rec_dir) {
            if let Some(rest) = line.strip_prefix("/usr/") {
                let p = ctx.root.join("usr").join(rest);
                if let Ok(t) = fs::read_link(&p) {
                    if t.to_string_lossy().contains(&format!("/opt/{name}/")) {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(ctx.opt(name));
        fs::remove_dir_all(&rec_dir)?;
        world_remove(ctx, name)?;
        println!("{name} nunca existiu.");
    }
    Ok(())
}

// ---------- archives / verify / newspeak ----------

pub fn archives(ctx: &Ctx) -> Result<()> {
    let dir = ctx.records_dir();
    let mut rows: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let meta = read_meta(&e.path()).unwrap_or_default();
            let n_paths = read_manifest(&e.path()).len();
            rows.push(format!(
                "{name} {} [mundo {}] {} caminhos",
                meta.get("VERSION").map(String::as_str).unwrap_or("?"),
                meta.get("WORLD").map(String::as_str).unwrap_or("?"),
                n_paths
            ));
        }
    }
    rows.sort();
    if rows.is_empty() {
        println!("os arquivos estão vazios: nada foi registrado ainda.");
    } else {
        for r in rows {
            println!("{r}");
        }
    }
    Ok(())
}

pub fn verify(ctx: &Ctx) -> Result<()> {
    let mut problems = 0usize;
    let claims = all_manifests(ctx);
    let mut claimed: HashSet<String> = HashSet::new();
    for (name, _, set) in &claims {
        for line in set {
            claimed.insert(line.clone());
            let p = ctx.root.join(line.trim_start_matches('/'));
            if fs::symlink_metadata(&p).is_err() {
                println!("wrongthink: {line} (de {name}) sumiu do filesystem");
                problems += 1;
            }
        }
    }
    // Direção inversa: links em /usr/bin apontando para /opt sem dono.
    if let Ok(entries) = fs::read_dir(ctx.usr_bin()) {
        for e in entries.flatten() {
            let p = e.path();
            let Ok(t) = fs::read_link(&p) else { continue };
            if !t.to_string_lossy().contains("/opt/") {
                continue;
            }
            let virt = format!("/usr/bin/{}", e.file_name().to_string_lossy());
            if !claimed.contains(&virt) {
                println!("wrongthink: {virt} é órfão (aponta {} sem dono em manifesto)", t.display());
                problems += 1;
            }
        }
    }
    if problems == 0 {
        println!("thinkpol: nenhum wrongthink.");
        Ok(())
    } else {
        fail(1, format!("{problems} problema(s) — nada foi apagado sem ordem"))
    }
}

pub fn newspeak_show(ctx: &Ctx, name: &str) -> Result<()> {
    let path = recipe::find(ctx, name)?;
    println!("# origem: {}", path.display());
    print!("{}", fs::read_to_string(&path)?);
    Ok(())
}

// ---------- registros e world ----------

fn read_meta(rec_dir: &Path) -> Option<HashMap<String, String>> {
    let txt = fs::read_to_string(rec_dir.join("meta")).ok()?;
    Some(
        txt.lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect(),
    )
}

fn read_manifest(rec_dir: &Path) -> Vec<String> {
    fs::read_to_string(rec_dir.join("manifest"))
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn all_manifests(ctx: &Ctx) -> Vec<(String, String, HashSet<String>)> {
    let mut v = Vec::new();
    if let Ok(entries) = fs::read_dir(ctx.records_dir()) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let ver = read_meta(&e.path())
                .and_then(|m| m.get("VERSION").cloned())
                .unwrap_or_else(|| "?".into());
            let set: HashSet<String> = read_manifest(&e.path()).into_iter().collect();
            v.push((name, ver, set));
        }
    }
    v
}

fn world_add(ctx: &Ctx, name: &str) -> Result<()> {
    let p = ctx.world_path();
    fs::create_dir_all(p.parent().unwrap())?;
    let mut lines: Vec<String> = fs::read_to_string(&p)
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default();
    if !lines.iter().any(|l| l.trim() == name) {
        lines.push(name.to_string());
        fs::write(&p, lines.join("\n") + "\n")?;
    }
    Ok(())
}

fn world_remove(ctx: &Ctx, name: &str) -> Result<()> {
    let p = ctx.world_path();
    if let Ok(txt) = fs::read_to_string(&p) {
        let lines: Vec<&str> = txt.lines().filter(|l| l.trim() != name).collect();
        fs::write(&p, lines.join("\n") + "\n")?;
    }
    Ok(())
}
