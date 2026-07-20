use crate::recipe::{self, Kind, Recipe};
use crate::{fail, fetch, iso_now, Ctx};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
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
    // DEPS (runtime) e BUILD_DEPS (só compilação) precisam existir antes deste
    // pacote compilar; só as DEPS entram no meta como dependências de runtime.
    for d in r.deps.iter().chain(r.build_deps.iter()) {
        collect(ctx, d, seen, stack, out)?;
    }
    stack.pop();
    out.push(r);
    Ok(())
}

fn install_one(ctx: &Ctx, r: &Recipe, explicit: bool) -> Result<()> {
    if r.requires_glibc && !ctx.root.join("usr/lib/ld-linux-x86-64.so.2").exists() {
        return fail(
            5,
            format!("{}: exige a ABI glibc, que só existe após o Estágio 2 (SPEC-0005 §4)", r.name),
        );
    }
    match r.kind {
        Kind::Binary => install_binary(ctx, r, explicit),
        Kind::Source => install_source(ctx, r, explicit),
    }
}

// ---------- mundo A: binário do mantenedor ----------

fn install_binary(ctx: &Ctx, r: &Recipe, explicit: bool) -> Result<()> {
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
        room101(ctx, r, &out.stdout, &out.stderr)?;
        let _ = fs::remove_dir_all(&staging);
        let _ = fs::remove_dir_all(&work);
        return fail(
            1,
            format!(
                "{}: install_pkg falhou — o interrogatório completo está em {}",
                r.name,
                ctx.room101().join(format!("{}-{}.log", r.name, r.version)).display()
            ),
        );
    }
    let _ = fs::remove_dir_all(&work);

    let verdir = opt.join(&r.version);
    let previous = read_meta(&rec_dir).and_then(|m| m.get("VERSION").cloned()).filter(|v| *v != r.version);
    if verdir.exists() {
        fs::remove_dir_all(&verdir)?;
    }
    fs::rename(&staging, &verdir)?;

    let tmp_cur = opt.join(".current.tmp");
    let _ = fs::remove_file(&tmp_cur);
    symlink(&r.version, &tmp_cur)?;
    fs::rename(&tmp_cur, opt.join("current"))?;

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

    let old_links: HashSet<String> =
        read_manifest(&rec_dir).into_iter().filter(|l| l.starts_with("/usr/")).collect();
    let claims = all_manifests(ctx);
    fs::create_dir_all(ctx.usr_bin())?;
    let mut manifest: Vec<String> =
        vec![format!("/opt/{}/{}", r.name, r.version), format!("/opt/{}/current", r.name)];
    for (cmdname, rel) in &pairs {
        let linkpath = ctx.usr_bin().join(cmdname);
        let target = format!("../../opt/{}/current/{}", r.name, rel);
        let virt = format!("/usr/bin/{cmdname}");
        match fs::symlink_metadata(&linkpath) {
            Ok(md) if md.file_type().is_symlink() => {
                let cur = fs::read_link(&linkpath)?;
                if cur != Path::new(&target) {
                    if let Some(prov) = adopt_provisional_path(ctx, &virt, &r.name) {
                        eprintln!("  {virt}: assume o controle de {prov} (provisório)");
                    } else {
                        let owner = claims
                            .iter()
                            .find(|(n, _, set)| *n != r.name && set.contains(&virt))
                            .map(|(n, v, _)| format!("{n} {v}"))
                            .unwrap_or_else(|| "algo fora dos registros".into());
                        return fail(4, format!("doublethink detectado: {virt} já pertence a {owner}"));
                    }
                }
            }
            Ok(_) => return fail(4, format!("doublethink detectado: {virt} existe e não é link gerido")),
            Err(_) => {}
        }
        let _ = fs::remove_file(&linkpath);
        symlink(&target, &linkpath)?;
        manifest.push(virt);
    }

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

    let keep: HashSet<String> =
        [Some(r.version.clone()), previous.clone()].into_iter().flatten().collect();
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

    write_record(&rec_dir, r, "A", &mut manifest)?;
    if explicit {
        world_add(ctx, &r.name)?;
    }
    println!("{} {} — retificado. doubleplusgood.", r.name, r.version);
    Ok(())
}

// ---------- mundo B: compilado da fonte ----------

/// Monta um diretório de shims cc/ld/ar/ranlib que fazem `zig` se passar pela
/// toolchain de C corrente (SPEC-0005: pré-E2 é zig+musl). É o que o contrato
/// da receita chama de $CC — a receita não sabe se por baixo é zig ou gcc.
fn setup_toolchain(ctx: &Ctx, work: &Path) -> Result<PathBuf> {
    let zig = ctx.root.join("opt/zig/current/zig");
    if !zig.exists() {
        return fail(5, "mundo B pré-E2 exige a toolchain zig — `minitrue rectify zig` antes");
    }
    let zig_abs = zig.canonicalize()?;
    let z = zig_abs.display();
    // -ffile-prefix-map=$WORK=. torna a reprodutibilidade independente do
    // caminho de build (SPEC-0010): reescreve o comp_dir/__FILE__ para relativo.
    let w = work.display();
    let map = format!("-ffile-prefix-map={w}=.");
    let tc = work.join(".tc");
    fs::create_dir_all(&tc)?;
    let shims = [
        ("cc", format!("#!/bin/sh\nexec \"{z}\" cc -target x86_64-linux-musl {map} \"$@\"\n")),
        ("gcc", format!("#!/bin/sh\nexec \"{z}\" cc -target x86_64-linux-musl {map} \"$@\"\n")),
        ("c++", format!("#!/bin/sh\nexec \"{z}\" c++ -target x86_64-linux-musl {map} \"$@\"\n")),
        ("g++", format!("#!/bin/sh\nexec \"{z}\" c++ -target x86_64-linux-musl {map} \"$@\"\n")),
        // configure só sonda a existência de `ld` no PATH; o link real é interno ao zig cc.
        ("ld", format!("#!/bin/sh\nexec \"{z}\" ld.lld \"$@\"\n")),
        ("ar", format!("#!/bin/sh\nexec \"{z}\" ar \"$@\"\n")),
        ("ranlib", format!("#!/bin/sh\nexec \"{z}\" ranlib \"$@\"\n")),
    ];
    for (name, body) in shims {
        let p = tc.join(name);
        fs::write(&p, body)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755))?;
    }
    Ok(tc)
}

fn install_source(ctx: &Ctx, r: &Recipe, explicit: bool) -> Result<()> {
    let rec_dir = ctx.records_dir().join(&r.name);
    if let Some(meta) = read_meta(&rec_dir) {
        if meta.get("VERSION") == Some(&r.version) {
            println!("os registros já estão corretos: {} {}", r.name, r.version);
            return Ok(());
        }
    }

    println!("retificando os registros (fonte): {} {}", r.name, r.version);
    let artifacts = fetch::ensure_artifacts(ctx, r)?;

    let work = ctx.root.join("tmp").join(format!("minitrue-build-{}", r.name));
    let _ = fs::remove_dir_all(&work);
    let src_dir = work.join("src");
    let stage = work.join("stage");
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&stage)?;
    let tc = setup_toolchain(ctx, &work)?;
    let zcache = ctx.cache_dir().join("zig");
    fs::create_dir_all(&zcache)?;

    let path = format!("{}:{}", tc.display(), std::env::var("PATH").unwrap_or_default());
    // Ambiente determinístico (SPEC-0010): mesmo insumo → mesmo artefato, para
    // que o binário do canal seja verificável por reprodução (SPEC-0009 §6).
    // EPOCH default fixo (2024-01-01) sobreponível pela receita; LC/TZ fixos;
    // umask fixo. O caminho de build é canônico dentro do chroot.
    let epoch = r.epoch.clone().unwrap_or_else(|| "1704067200".into());
    let mut cmd = Command::new("sh");
    cmd.arg("-ec")
        .arg("umask 022\n. \"$RECIPE\"\nbuild")
        .current_dir(&src_dir)
        .env("RECIPE", &r.path)
        .env("STAGE", &stage)
        .env("WORK", &work)
        .env("ROOT", &ctx.root)
        .env("JOBS", ctx.jobs.to_string())
        .env("PATH", &path)
        .env("CC", "cc")
        .env("CXX", "c++")
        .env("LD", "ld")
        .env("AR", "ar")
        .env("RANLIB", "ranlib")
        .env("HOME", &work)
        .env("ZIG_GLOBAL_CACHE_DIR", &zcache)
        .env("SOURCE_DATE_EPOCH", &epoch)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("LANGUAGE", "")
        .env("TZ", "UTC");
    for (i, (p, _)) in artifacts.iter().enumerate() {
        let abs = p.canonicalize()?;
        if i == 0 {
            cmd.env("DL", &abs);
        }
        cmd.env(format!("DL_{}", i + 1), &abs);
    }
    let out = cmd.output().map_err(|e| crate::Fail { code: 1, msg: format!("sh indisponível: {e}") })?;
    if !out.status.success() {
        room101(ctx, r, &out.stdout, &out.stderr)?;
        let _ = fs::remove_dir_all(&work);
        return fail(
            1,
            format!(
                "{}: build() falhou — o interrogatório completo está em {}",
                r.name,
                ctx.room101().join(format!("{}-{}.log", r.name, r.version)).display()
            ),
        );
    }

    // Coleta o que foi para o staging (pré-ordem: pais antes dos filhos).
    let mut entries = Vec::new();
    walk(&stage, &stage, &mut entries)?;

    // Colisão (doublethink): confere alvos contra os manifestos dos outros.
    // Pacote provisório (busybox) não gera doublethink — cede o caminho na cópia.
    let claims = all_manifests(ctx);
    for (_, rel, ft) in &entries {
        if ft.is_dir() {
            continue;
        }
        let virt = virt_path(rel);
        if let Some((n, v, _)) = claims
            .iter()
            .find(|(n, _, set)| *n != r.name && set.contains(&virt) && !is_provisional(ctx, n))
        {
            let _ = fs::remove_dir_all(&work);
            return fail(4, format!("doublethink detectado: {virt} já pertence a {n} {v}"));
        }
    }

    // Sincroniza staging → root, com desvio de /etc para /usr/share/factory.
    let mut manifest: Vec<String> = Vec::new();
    for (src, rel, ft) in &entries {
        if let Some(sub) = rel.strip_prefix("etc/") {
            // Nenhum pacote é dono de /etc: o default vai para a fábrica…
            let factory = ctx.root.join("usr/share/factory/etc").join(sub);
            mkparent(&factory)?;
            let _ = fs::remove_file(&factory);
            if ft.is_symlink() {
                symlink(fs::read_link(src)?, &factory)?;
            } else if !ft.is_dir() {
                fs::copy(src, &factory)?;
            } else {
                fs::create_dir_all(&factory)?;
            }
            if !ft.is_dir() {
                manifest.push(format!("/usr/share/factory/etc/{sub}"));
                // …e é materializado em /etc só se o administrador ainda não decidiu.
                materialize_etc(ctx, &factory, sub)?;
            }
        } else {
            let dst = ctx.root.join(rel);
            if ft.is_dir() {
                fs::create_dir_all(&dst)?;
            } else {
                let virt = virt_path(rel);
                if let Some(prov) = adopt_provisional_path(ctx, &virt, &r.name) {
                    eprintln!("  {virt}: assume o controle de {prov} (provisório)");
                }
                mkparent(&dst)?;
                let _ = fs::remove_file(&dst);
                if ft.is_symlink() {
                    symlink(fs::read_link(src)?, &dst)?;
                } else {
                    fs::copy(src, &dst)?;
                }
                manifest.push(virt);
            }
        }
    }

    // Upgrade: recolhe caminhos do manifesto antigo que sumiram do novo.
    let new_set: HashSet<&String> = manifest.iter().collect();
    for old in read_manifest(&rec_dir) {
        if !new_set.contains(&old) {
            let p = ctx.root.join(old.trim_start_matches('/'));
            let _ = fs::remove_file(&p);
            if let Some(par) = p.parent() {
                prune_empty(&ctx.root, par);
            }
        }
    }
    let _ = fs::remove_dir_all(&work);

    write_record(&rec_dir, r, "B", &mut manifest)?;
    if explicit {
        world_add(ctx, &r.name)?;
    }
    println!("{} {} — compilado e retificado. doubleplusgood.", r.name, r.version);
    Ok(())
}

/// Materializa um default de fábrica em /etc conforme a política do admin
/// (Clear Linux + `.new` do Slackware): copia se ausente; se o admin já mexeu,
/// grava `<arquivo>.new` ao lado e avisa. O /etc vivo não entra no manifesto.
fn materialize_etc(ctx: &Ctx, factory: &Path, sub: &str) -> Result<()> {
    let live = ctx.root.join("etc").join(sub);
    if !live.exists() {
        mkparent(&live)?;
        fs::copy(factory, &live)?;
        return Ok(());
    }
    let same = fs::read(&live).ok() == fs::read(factory).ok();
    if !same {
        let new = live.with_file_name(format!(
            "{}.new",
            live.file_name().unwrap().to_string_lossy()
        ));
        fs::copy(factory, &new)?;
        eprintln!(
            "  aviso: /etc/{sub} foi modificado pelo administrador; novo default em {}",
            new.display()
        );
    }
    Ok(())
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, String, fs::FileType)>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let rel = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
        let ft = fs::symlink_metadata(&path)?.file_type();
        out.push((path.clone(), rel, ft));
        if ft.is_dir() {
            walk(base, &path, out)?;
        }
    }
    Ok(())
}

fn virt_path(rel: &str) -> String {
    format!("/{rel}")
}

fn mkparent(p: &Path) -> Result<()> {
    if let Some(par) = p.parent() {
        fs::create_dir_all(par)?;
    }
    Ok(())
}

fn prune_empty(root: &Path, start: &Path) {
    let mut p = start.to_path_buf();
    while p.starts_with(root) && p != *root {
        let empty = fs::read_dir(&p).map(|mut d| d.next().is_none()).unwrap_or(false);
        if !empty || fs::remove_dir(&p).is_err() {
            break;
        }
        match p.parent() {
            Some(par) => p = par.to_path_buf(),
            None => break,
        }
    }
}

fn room101(ctx: &Ctx, r: &Recipe, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    fs::create_dir_all(ctx.room101())?;
    let log = ctx.room101().join(format!("{}-{}.log", r.name, r.version));
    let mut body = stdout.to_vec();
    body.extend_from_slice(stderr);
    fs::write(&log, body)?;
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

        let world = read_meta(&rec_dir).and_then(|m| m.get("WORLD").cloned()).unwrap_or_else(|| "A".into());
        if world == "A" {
            for line in read_manifest(&rec_dir) {
                if line.starts_with("/usr/") {
                    let p = ctx.root.join(line.trim_start_matches('/'));
                    if let Ok(t) = fs::read_link(&p) {
                        if t.to_string_lossy().contains(&format!("/opt/{name}/")) {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
            let _ = fs::remove_dir_all(ctx.opt(name));
        } else {
            let mut paths = read_manifest(&rec_dir);
            paths.sort();
            for line in paths.iter().rev() {
                let p = ctx.root.join(line.trim_start_matches('/'));
                let _ = fs::remove_file(&p);
                if let Some(par) = p.parent() {
                    prune_empty(&ctx.root, par);
                }
            }
        }

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

fn write_record(rec_dir: &Path, r: &Recipe, world: &str, manifest: &mut Vec<String>) -> Result<()> {
    fs::create_dir_all(rec_dir)?;
    manifest.sort();
    manifest.dedup();
    let meta = format!(
        "NAME={}\nVERSION={}\nKIND={}\nWORLD={}\nSHA256={}\nDEPS={}\nINSTALLED_AT={}\n{}",
        r.name,
        r.version,
        if r.kind == Kind::Binary { "binary" } else { "source" },
        world,
        r.sha256.join(" "),
        r.deps.join(" "),
        iso_now(),
        if r.provisional { "PROVISIONAL=1\n" } else { "" }
    );
    fs::write(rec_dir.join("meta"), meta)?;
    fs::write(rec_dir.join("manifest"), manifest.join("\n") + "\n")?;
    fs::copy(&r.path, rec_dir.join("recipe"))?;
    fs::copy(&r.path, rec_dir.join(format!("recipe@{}", r.version)))?;
    fs::write(rec_dir.join(format!("manifest@{}", r.version)), manifest.join("\n") + "\n")?;
    Ok(())
}

fn is_provisional(ctx: &Ctx, name: &str) -> bool {
    read_meta(&ctx.records_dir().join(name))
        .and_then(|m| m.get("PROVISIONAL").cloned())
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Cede um caminho reivindicado por um pacote PROVISIONAL (busybox): remove-o
/// do manifesto do cedente e devolve o nome dele. Assim as ferramentas reais
/// (binutils, coreutils…) tomam o lugar dos applets provisórios sem doublethink.
fn adopt_provisional_path(ctx: &Ctx, virt: &str, myself: &str) -> Option<String> {
    for e in fs::read_dir(ctx.records_dir()).ok()?.flatten() {
        let owner = e.file_name().to_string_lossy().into_owned();
        if owner == myself || !is_provisional(ctx, &owner) {
            continue;
        }
        let mut m = read_manifest(&e.path());
        if let Some(pos) = m.iter().position(|l| l == virt) {
            m.remove(pos);
            let _ = fs::write(e.path().join("manifest"), m.join("\n") + "\n");
            return Some(owner);
        }
    }
    None
}

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
