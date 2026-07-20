use crate::recipe::{self, Kind, Recipe, Toolchain};
use crate::{fail, fetch, iso_now, Ctx};
use anyhow::Result;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Versão do esquema de registro (gravada em `RECORD_FORMAT=`). Muda quando o
/// formato de `meta`/`manifest` muda — permite migração e leitura consciente.
const RECORD_FORMAT: &str = "1";

/// Escreve `bytes` em `path` **atomicamente**: grava num temporário irmão e
/// `rename` por cima (atômico no mesmo filesystem). Um leitor nunca vê um
/// arquivo meio-escrito, e um crash não deixa `path` corrompido (SPEC-0003 §6).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("x");
    let tmp = path.with_file_name(format!("{name}.tmp-{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Trava exclusiva **por rootfs** — impede dois `minitrue` mutando o mesmo
/// sistema ao mesmo tempo. É advisory (`flock`) e **auto-liberada quando o
/// processo sai**, então um crash não deixa o lock preso. O `File` devolvido é
/// o guarda: segure-o pela operação inteira; soltá-lo libera a trava.
fn acquire_lock(ctx: &Ctx) -> Result<fs::File> {
    let dir = ctx.root.join("var/lib/minitrue");
    fs::create_dir_all(&dir)?;
    let f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join("lock"))?;
    f.try_lock_exclusive().map_err(|_| crate::Fail {
        code: 1,
        msg: "outro minitrue já opera este sistema (lock em var/lib/minitrue/lock)".into(),
    })?;
    Ok(f)
}

// ---------- rectify ----------

pub fn rectify(ctx: &Ctx, names: &[String]) -> Result<()> {
    let _lock = acquire_lock(ctx)?; // segurado até o fim da operação
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
        return fail(
            2,
            format!("ciclo de dependências: {} -> {name}", stack.join(" -> ")),
        );
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
            format!(
                "{}: exige a ABI glibc, que só existe após o Estágio 2 (SPEC-0005 §4)",
                r.name
            ),
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
    let fp = r.fingerprint()?;
    if let Some(meta) = read_meta(&rec_dir) {
        if meta.get("VERSION") == Some(&r.version)
            && meta.get("FINGERPRINT") == Some(&fp)
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
    let work = ctx
        .root
        .join("tmp")
        .join(format!("minitrue-work-{}", r.name));
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
    let out = cmd.output().map_err(|e| crate::Fail {
        code: 1,
        msg: format!("sh indisponível: {e}"),
    })?;
    if !out.status.success() {
        room101(ctx, r, &out.stdout, &out.stderr)?;
        let _ = fs::remove_dir_all(&staging);
        let _ = fs::remove_dir_all(&work);
        return fail(
            1,
            format!(
                "{}: install_pkg falhou — o interrogatório completo está em {}",
                r.name,
                ctx.room101()
                    .join(format!("{}-{}.log", r.name, r.version))
                    .display()
            ),
        );
    }
    let _ = fs::remove_dir_all(&work);

    let verdir = opt.join(&r.version);
    let previous = read_meta(&rec_dir)
        .and_then(|m| m.get("VERSION").cloned())
        .filter(|v| *v != r.version);
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

    let old_links: HashSet<String> = read_manifest(&rec_dir)
        .iter()
        .map(|l| manifest_path(l).to_string())
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
                    if let Some(prov) = adopt_provisional_path(ctx, &virt, &r.name, &r.supersedes) {
                        eprintln!("  {virt}: assume o controle de {prov} (provisório)");
                    } else {
                        let owner = claims
                            .iter()
                            .find(|(n, _, set)| *n != r.name && set.contains(&virt))
                            .map(|(n, v, _)| format!("{n} {v}"))
                            .unwrap_or_else(|| "algo fora dos registros".into());
                        return fail(
                            4,
                            format!("doublethink detectado: {virt} já pertence a {owner}"),
                        );
                    }
                }
            }
            Ok(_) => {
                return fail(
                    4,
                    format!("doublethink detectado: {virt} existe e não é link gerido"),
                )
            }
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

    let keep: HashSet<String> = [Some(r.version.clone()), previous.clone()]
        .into_iter()
        .flatten()
        .collect();
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

    write_record(ctx, &rec_dir, r, "A", &mut manifest)?;
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
/// Ferramentas e prefixos de PATH que o build recebe, conforme o perfil de
/// toolchain da receita (SPEC-0005). É o que faz a cadeia pass-1 → glibc →
/// pass-2 existir como fluxo, em vez de tudo cair no zig/musl.
struct BuildEnv {
    cc: String,
    cxx: String,
    ar: String,
    ranlib: String,
    ld: String,
    nm: String,
    path_prefix: Vec<PathBuf>,
}

/// Alvo do gcc/binutils cross que produz glibc (SPEC-0005).
const CROSS_TRIPLE: &str = "x86_64-distropica-linux-gnu";

/// Cria os shims da semente (zig cc/c++/ld/ar…) num diretório e o devolve.
/// `-ffile-prefix-map=$WORK=.` torna a reprodutibilidade independente do
/// caminho de build (SPEC-0010): reescreve o comp_dir/__FILE__ para relativo.
fn seed_shims(ctx: &Ctx, work: &Path) -> Result<PathBuf> {
    let zig_host = ctx.root.join("opt/zig/current/zig");
    if !zig_host.exists() {
        return fail(
            5,
            "toolchain seed exige o zig — `minitrue rectify zig` antes",
        );
    }
    // Os shims rodam DENTRO do chroot (bwrap): o caminho do zig e o
    // prefix-map são os de dentro do rootfs, não os do host.
    let zc = in_chroot(&ctx.root, &zig_host);
    let z = zc.display();
    let map = format!(
        "-ffile-prefix-map={}=.",
        in_chroot(&ctx.root, work).display()
    );
    let tc = work.join(".tc");
    fs::create_dir_all(&tc)?;
    let shims = [
        (
            "cc",
            format!("#!/bin/sh\nexec \"{z}\" cc -target x86_64-linux-musl {map} \"$@\"\n"),
        ),
        (
            "gcc",
            format!("#!/bin/sh\nexec \"{z}\" cc -target x86_64-linux-musl {map} \"$@\"\n"),
        ),
        (
            "c++",
            format!("#!/bin/sh\nexec \"{z}\" c++ -target x86_64-linux-musl {map} \"$@\"\n"),
        ),
        (
            "g++",
            format!("#!/bin/sh\nexec \"{z}\" c++ -target x86_64-linux-musl {map} \"$@\"\n"),
        ),
        // configure só sonda a existência de `ld` no PATH; o link é interno ao zig cc.
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

fn setup_toolchain(ctx: &Ctx, work: &Path, r: &Recipe) -> Result<BuildEnv> {
    match r.toolchain {
        Toolchain::Seed => {
            let tc = seed_shims(ctx, work)?;
            Ok(BuildEnv {
                cc: "cc".into(),
                cxx: "c++".into(),
                ar: "ar".into(),
                ranlib: "ranlib".into(),
                ld: "ld".into(),
                nm: "nm".into(),
                path_prefix: vec![tc],
            })
        }
        Toolchain::Cross => {
            // gcc da passada 1 (real, não zig), em /usr/bin. Exige os build-deps
            // `gcc` e `binutils-cross` (que trazem as/ld/ar/nm do alvo). Os shims
            // da semente também ficam no PATH: um build cross usa o cross-gcc p/ o
            // alvo (CC) e a semente p/ ferramentas do build-host (ex.: BUILD_CC=cc
            // da glibc).
            let cc = ctx.root.join("usr/bin").join(format!("{CROSS_TRIPLE}-gcc"));
            if !cc.exists() {
                return fail(
                    5,
                    format!("toolchain cross exige {CROSS_TRIPLE}-gcc (passada 1) — build-deps gcc + binutils-cross"),
                );
            }
            let tc = seed_shims(ctx, work)?;
            Ok(BuildEnv {
                cc: format!("{CROSS_TRIPLE}-gcc"),
                cxx: format!("{CROSS_TRIPLE}-g++"),
                ar: format!("{CROSS_TRIPLE}-ar"),
                ranlib: format!("{CROSS_TRIPLE}-ranlib"),
                ld: format!("{CROSS_TRIPLE}-ld"),
                nm: format!("{CROSS_TRIPLE}-nm"),
                path_prefix: vec![tc, ctx.root.join("usr/bin"), ctx.root.join("bin")],
            })
        }
        Toolchain::Native => {
            // gcc nativo hospedado na glibc (passada 2). Pós-E2.
            let gcc = ctx.root.join("usr/bin/gcc");
            if !gcc.exists() {
                return fail(5, "toolchain native exige o gcc da passada 2 (pós-E2)");
            }
            Ok(BuildEnv {
                cc: "gcc".into(),
                cxx: "g++".into(),
                ar: "ar".into(),
                ranlib: "ranlib".into(),
                ld: "ld".into(),
                nm: "nm".into(),
                path_prefix: vec![ctx.root.join("usr/bin"), ctx.root.join("bin")],
            })
        }
    }
}

/// Traduz um caminho do host (sob `root`) para o equivalente dentro do chroot
/// (`root` montado em `/`). Fora de `root`, devolve como está.
fn in_chroot(root: &Path, p: &Path) -> PathBuf {
    match p.strip_prefix(root) {
        Ok(rel) => Path::new("/").join(rel),
        Err(_) => p.to_path_buf(),
    }
}

/// Preâmbulo do build: `umask`, a função `retry` (SPEC-0005 — reexecuta um
/// comando até `RETRIES` vezes, remédio do ICE flaky do gcc-passada-1, que é
/// só crash: o `.o` é determinístico, SPEC-0010 §6), então `. $RECIPE; build`.
const BUILD_PREAMBLE: &str = "umask 022\n\
    retry(){ i=0; until \"$@\"; do i=$((i+1)); \
    [ \"$i\" -gt \"${RETRIES:-0}\" ] && return 1; \
    echo \"minitrue: retry $i (ICE?): $*\" >&2; done; }\n\
    . \"$RECIPE\"\nbuild";

/// Monta o comando de build. Num rootfs (`--root` != `/`) roda dentro dele via
/// `bwrap`, o que (a) é necessário para o perfil `native` — o gcc da passada 2
/// é **dinâmico** e usa o loader/libs glibc do rootfs (`/lib64`, `/usr/lib`
/// absolutos), que só são os do rootfs sob chroot — e (b) torna **todo** build
/// hermético: `--clearenv` (só as variáveis do contrato) e `--unshare-net`
/// (nenhum insumo pela rede — SPEC-0004 §3.2; o fetch já ocorreu no host). O
/// gcc é relocável, então o perfil `cross` (estático) rodaria fora do chroot
/// também, mas o runner o roda igual, hermético. No próprio sistema
/// (`--root /`) roda direto — o alvo já é `/`.
fn build_command(
    ctx: &Ctx,
    be: &BuildEnv,
    retries: u32,
    work: &Path,
    epoch: &str,
    artifacts: &[(PathBuf, String)],
) -> Command {
    let root = ctx.root.clone();
    let src_dir = work.join("src");
    let stage = work.join("stage");
    let c = |p: &Path| in_chroot(&root, p).display().to_string();

    // PATH hermético: prefixos do perfil (em forma de chroot) + /usr/bin:/bin.
    let mut path = String::new();
    for p in &be.path_prefix {
        path.push_str(&c(p));
        path.push(':');
    }
    path.push_str("/usr/bin:/bin");

    let mut envs: Vec<(String, String)> = vec![
        ("RECIPE".into(), c(&work.join("recipe"))),
        ("STAGE".into(), c(&stage)),
        ("WORK".into(), c(work)),
        ("ROOT".into(), "/".into()),
        ("JOBS".into(), ctx.jobs.to_string()),
        ("PATH".into(), path),
        ("CC".into(), be.cc.clone()),
        ("CXX".into(), be.cxx.clone()),
        ("LD".into(), be.ld.clone()),
        ("AR".into(), be.ar.clone()),
        ("RANLIB".into(), be.ranlib.clone()),
        ("NM".into(), be.nm.clone()),
        ("RETRIES".into(), retries.to_string()),
        ("HOME".into(), c(work)),
        (
            "ZIG_GLOBAL_CACHE_DIR".into(),
            c(&ctx.cache_dir().join("zig")),
        ),
        ("SOURCE_DATE_EPOCH".into(), epoch.to_string()),
        ("LC_ALL".into(), "C".into()),
        ("LANG".into(), "C".into()),
        ("LANGUAGE".into(), String::new()),
        ("TZ".into(), "UTC".into()),
    ];
    for (i, (p, _)) in artifacts.iter().enumerate() {
        let cp = c(p);
        if i == 0 {
            envs.push(("DL".into(), cp.clone()));
        }
        envs.push((format!("DL_{}", i + 1), cp));
    }

    if root == Path::new("/") {
        let mut cmd = Command::new("sh");
        cmd.arg("-ec").arg(BUILD_PREAMBLE).current_dir(&src_dir);
        for (k, v) in &envs {
            cmd.env(k, v);
        }
        cmd
    } else {
        let mut cmd = Command::new("bwrap");
        cmd.arg("--bind")
            .arg(&root)
            .arg("/")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--unshare-pid")
            .arg("--unshare-net")
            .arg("--die-with-parent")
            .arg("--clearenv")
            .arg("--chdir")
            .arg(in_chroot(&root, &src_dir));
        for (k, v) in &envs {
            cmd.arg("--setenv").arg(k).arg(v);
        }
        cmd.arg("/bin/sh").arg("-ec").arg(BUILD_PREAMBLE);
        cmd
    }
}

fn install_source(ctx: &Ctx, r: &Recipe, explicit: bool) -> Result<()> {
    let rec_dir = ctx.records_dir().join(&r.name);
    let fp = r.fingerprint()?;
    if let Some(meta) = read_meta(&rec_dir) {
        // Idempotência por FINGERPRINT, não só VERSION (SPEC-0011 §4): uma
        // receita corrigida com a MESMA versão muda o fingerprint e re-builda.
        if meta.get("VERSION") == Some(&r.version) && meta.get("FINGERPRINT") == Some(&fp) {
            println!("os registros já estão corretos: {} {}", r.name, r.version);
            return Ok(());
        }
    }

    println!("retificando os registros (fonte): {} {}", r.name, r.version);
    let artifacts = fetch::ensure_artifacts(ctx, r)?;

    let work = ctx
        .root
        .join("tmp")
        .join(format!("minitrue-build-{}", r.name));
    let _ = fs::remove_dir_all(&work);
    let src_dir = work.join("src");
    let stage = work.join("stage");
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&stage)?;
    let be = setup_toolchain(ctx, &work, r)?;
    fs::create_dir_all(ctx.cache_dir().join("zig"))?;
    // A receita é copiada para dentro do work (montado no chroot), então fica
    // acessível lá como /tmp/minitrue-build-<nome>/recipe.
    fs::copy(&r.path, work.join("recipe"))?;
    // EPOCH default fixo (2024-01-01) sobreponível pela receita (SPEC-0010).
    let epoch = r.epoch.clone().unwrap_or_else(|| "1704067200".into());

    let mut cmd = build_command(ctx, &be, r.retries, &work, &epoch, &artifacts);
    let out = cmd.output().map_err(|e| {
        let hint = if ctx.root != Path::new("/") {
            " — build em rootfs usa bwrap; instale-o no host"
        } else {
            ""
        };
        crate::Fail {
            code: 1,
            msg: format!("não consegui rodar o build: {e}{hint}"),
        }
    })?;
    if !out.status.success() {
        room101(ctx, r, &out.stdout, &out.stderr)?;
        let _ = fs::remove_dir_all(&work);
        return fail(
            1,
            format!(
                "{}: build() falhou — o interrogatório completo está em {}",
                r.name,
                ctx.room101()
                    .join(format!("{}-{}.log", r.name, r.version))
                    .display()
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
        // Colisão é doublethink, EXCETO quando o dono é um provisional que esta
        // receita declarou superseder (SPEC-0003 §7) — aí a cópia cede.
        if let Some((n, v, _)) = claims.iter().find(|(n, _, set)| {
            *n != r.name
                && set.contains(&virt)
                && !(is_provisional(ctx, n) && r.supersedes.iter().any(|s| s == n))
        }) {
            let _ = fs::remove_dir_all(&work);
            return fail(
                4,
                format!("doublethink detectado: {virt} já pertence a {n} {v}"),
            );
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
                if let Some(prov) = adopt_provisional_path(ctx, &virt, &r.name, &r.supersedes) {
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
    let new_set: HashSet<&str> = manifest.iter().map(String::as_str).collect();
    for old in read_manifest(&rec_dir) {
        let path = manifest_path(&old);
        if !new_set.contains(path) {
            let p = ctx.root.join(path.trim_start_matches('/'));
            let _ = fs::remove_file(&p);
            if let Some(par) = p.parent() {
                prune_empty(&ctx.root, par);
            }
        }
    }
    let _ = fs::remove_dir_all(&work);

    write_record(ctx, &rec_dir, r, "B", &mut manifest)?;
    if explicit {
        world_add(ctx, &r.name)?;
    }
    println!(
        "{} {} — compilado e retificado. doubleplusgood.",
        r.name, r.version
    );
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
        let rel = path
            .strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .into_owned();
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
        let empty = fs::read_dir(&p)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
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
    let _lock = acquire_lock(ctx)?; // segurado até o fim da operação
    let removing: HashSet<&str> = names.iter().map(String::as_str).collect();
    for name in names {
        let rec_dir = ctx.records_dir().join(name);
        if !rec_dir.is_dir() {
            return fail(
                2,
                format!("{name}: não há registro — talvez nunca tenha existido"),
            );
        }
        for (other, _, _) in all_manifests(ctx) {
            if removing.contains(other.as_str()) {
                continue;
            }
            let deps = read_meta(&ctx.records_dir().join(&other))
                .and_then(|m| m.get("DEPS").cloned())
                .unwrap_or_default();
            if deps.split_whitespace().any(|d| d == name) {
                return fail(
                    1,
                    format!("{name} ainda sustenta {other} — memoryhole recusado"),
                );
            }
        }

        let world = read_meta(&rec_dir)
            .and_then(|m| m.get("WORLD").cloned())
            .unwrap_or_else(|| "A".into());
        if world == "A" {
            for line in read_manifest(&rec_dir) {
                let path = manifest_path(&line);
                if path.starts_with("/usr/") {
                    let p = ctx.root.join(path.trim_start_matches('/'));
                    if let Ok(t) = fs::read_link(&p) {
                        if t.to_string_lossy().contains(&format!("/opt/{name}/")) {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
            let _ = fs::remove_dir_all(ctx.opt(name));
        } else {
            let mut lines = read_manifest(&rec_dir);
            lines.sort_by(|a, b| manifest_path(a).cmp(manifest_path(b)));
            for line in lines.iter().rev() {
                let path = manifest_path(line);
                let p = ctx.root.join(path.trim_start_matches('/'));
                // Veredito intacto×modificado (SPEC-0003 §4): arquivo cujo
                // conteúdo diverge do hash registrado foi mexido pelo usuário —
                // preserva por padrão, com aviso. `-` (virou symlink/dir ou
                // ficou ilegível) também é divergência: um regular registrado
                // não deveria ter mudado de tipo.
                if let Some(recorded) = manifest_hash(line) {
                    if file_hash(&p) != recorded {
                        println!("  {path}: modificado desde a instalação — preservado");
                        continue;
                    }
                }
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
    let mut claimed: HashSet<String> = HashSet::new();
    if let Ok(entries) = fs::read_dir(ctx.records_dir()) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            for line in read_manifest(&e.path()) {
                let path = manifest_path(&line);
                claimed.insert(path.to_string());
                let p = ctx.root.join(path.trim_start_matches('/'));
                if fs::symlink_metadata(&p).is_err() {
                    println!("wrongthink: {path} (de {name}) sumiu do filesystem");
                    problems += 1;
                    continue;
                }
                // Integridade por arquivo (manifesto v1): conteúdo vs. hash
                // registrado. `-` (regular virou symlink/dir ou ficou ilegível)
                // também é divergência. Legado v0 (sem hash) só confere presença.
                if let Some(recorded) = manifest_hash(&line) {
                    if file_hash(&p) != recorded {
                        println!("wrongthink: {path} (de {name}) foi modificado — hash/tipo difere do registro");
                        problems += 1;
                    }
                }
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
                println!(
                    "wrongthink: {virt} é órfão (aponta {} sem dono em manifesto)",
                    t.display()
                );
                problems += 1;
            }
        }
    }
    if problems == 0 {
        println!("thinkpol: nenhum wrongthink.");
        Ok(())
    } else {
        fail(
            1,
            format!("{problems} problema(s) — nada foi apagado sem ordem"),
        )
    }
}

pub fn newspeak_show(ctx: &Ctx, name: &str) -> Result<()> {
    let path = recipe::find(ctx, name)?;
    println!("# origem: {}", path.display());
    print!("{}", fs::read_to_string(&path)?);
    Ok(())
}

// ---------- registros e world ----------

fn write_record(
    ctx: &Ctx,
    rec_dir: &Path,
    r: &Recipe,
    world: &str,
    manifest: &mut Vec<String>,
) -> Result<()> {
    fs::create_dir_all(rec_dir)?;
    manifest.sort();
    manifest.dedup();
    // ORIGIN: quando os canais (SPEC-0009) chegarem, a instalação de canal grava
    // `canal:<nome>` (+ TRUST, CHANNEL_SHA256); por ora deriva do mundo.
    let origin = if world == "A" { "vendor" } else { "fonte" };
    let meta = format!(
        "RECORD_FORMAT={RECORD_FORMAT}\nNAME={}\nVERSION={}\nKIND={}\nWORLD={}\nORIGIN={}\nSHA256={}\nDEPS={}\nFINGERPRINT={}\nINSTALLED_AT={}\n{}",
        r.name,
        r.version,
        if r.kind == Kind::Binary { "binary" } else { "source" },
        world,
        origin,
        r.sha256.join(" "),
        r.deps.join(" "),
        r.fingerprint()?,
        iso_now(),
        if r.provisional { "PROVISIONAL=1\n" } else { "" }
    );
    // Manifesto v1: cada linha vira `<sha256>␠␠<caminho>` (hash do arquivo real;
    // `-` p/ symlink/diretório). É o que dá integridade por arquivo ao `verify`
    // e o veredito intacto×modificado ao `memoryhole` (SPEC-0003 §4/§6).
    let decorated: Vec<String> = manifest
        .iter()
        .map(|p| {
            format!(
                "{}  {p}",
                file_hash(&ctx.root.join(p.trim_start_matches('/')))
            )
        })
        .collect();
    let body = decorated.join("\n") + "\n";
    // Tudo por temporário + rename (atômico). O `meta` é gravado **por último**:
    // é a marca de commit do registro — um crash entre o manifest e o meta deixa
    // um registro sem meta, que `read_meta` trata como não-instalado (⇒ reinstala
    // no próximo rectify), em vez de um registro meio-escrito tido por bom.
    write_atomic(&rec_dir.join("manifest"), body.as_bytes())?;
    write_atomic(
        &rec_dir.join(format!("manifest@{}", r.version)),
        body.as_bytes(),
    )?;
    let recipe_bytes = fs::read(&r.path)?;
    write_atomic(&rec_dir.join("recipe"), &recipe_bytes)?;
    write_atomic(
        &rec_dir.join(format!("recipe@{}", r.version)),
        &recipe_bytes,
    )?;
    write_atomic(&rec_dir.join("meta"), meta.as_bytes())?;
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
fn adopt_provisional_path(
    ctx: &Ctx,
    virt: &str,
    myself: &str,
    supersedes: &[String],
) -> Option<String> {
    for e in fs::read_dir(ctx.records_dir()).ok()?.flatten() {
        let owner = e.file_name().to_string_lossy().into_owned();
        // Só cede de provisional que ESTA receita declarou superseder
        // (SPEC-0003 §7). Provisional não-declarado não é cedido — vira
        // doublethink no check de colisão.
        if owner == myself
            || !is_provisional(ctx, &owner)
            || !supersedes.iter().any(|s| *s == owner)
        {
            continue;
        }
        let mut m = read_manifest(&e.path());
        if let Some(pos) = m.iter().position(|l| manifest_path(l) == virt) {
            m.remove(pos);
            let _ = write_atomic(&e.path().join("manifest"), (m.join("\n") + "\n").as_bytes());
            return Some(owner);
        }
    }
    None
}

fn read_meta(rec_dir: &Path) -> Option<HashMap<String, String>> {
    let txt = fs::read_to_string(rec_dir.join("meta")).ok()?;
    Some(
        txt.lines()
            .filter_map(|l| {
                l.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect(),
    )
}

fn read_manifest(rec_dir: &Path) -> Vec<String> {
    fs::read_to_string(rec_dir.join("manifest"))
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// O caminho de uma linha de manifesto. Registro **v1**: `<sha256>␠␠<caminho>`;
/// legado v0 (linha sem os dois espaços): a própria linha. Retrocompatível.
fn manifest_path(line: &str) -> &str {
    line.split_once("  ").map(|(_, p)| p).unwrap_or(line)
}

/// O hash gravado de uma linha de manifesto v1, se houver (`-` e ausência ⇒ None).
fn manifest_hash(line: &str) -> Option<&str> {
    line.split_once("  ")
        .map(|(h, _)| h)
        .filter(|h| *h != "-" && h.len() == 64)
}

/// sha256 (hex) de um arquivo regular, em streaming; `-` para symlink, diretório
/// ou ausente. É o hash por arquivo do manifesto v1 (SPEC-0003 §6).
fn file_hash(path: &Path) -> String {
    let Ok(md) = fs::symlink_metadata(path) else {
        return "-".into();
    };
    if !md.file_type().is_file() {
        return "-".into();
    }
    let Ok(mut f) = fs::File::open(path) else {
        return "-".into();
    };
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return "-".into(),
        }
    }
    hex::encode(h.finalize())
}

fn all_manifests(ctx: &Ctx) -> Vec<(String, String, HashSet<String>)> {
    let mut v = Vec::new();
    if let Ok(entries) = fs::read_dir(ctx.records_dir()) {
        for e in entries.flatten() {
            // Registro sem `meta` = instalação não-commitada (crash entre o
            // manifest e o meta): ignora, para não reivindicar caminhos que
            // pertencem a um pacote meio-instalado (SPEC-0003 §6).
            let Some(meta) = read_meta(&e.path()) else {
                continue;
            };
            let name = e.file_name().to_string_lossy().into_owned();
            let ver = meta.get("VERSION").cloned().unwrap_or_else(|| "?".into());
            let set: HashSet<String> = read_manifest(&e.path())
                .iter()
                .map(|l| manifest_path(l).to_string())
                .collect();
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
        write_atomic(&p, (lines.join("\n") + "\n").as_bytes())?;
    }
    Ok(())
}

fn world_remove(ctx: &Ctx, name: &str) -> Result<()> {
    let p = ctx.world_path();
    if let Ok(txt) = fs::read_to_string(&p) {
        let lines: Vec<&str> = txt.lines().filter(|l| l.trim() != name).collect();
        write_atomic(&p, (lines.join("\n") + "\n").as_bytes())?;
    }
    Ok(())
}

// ---------- explain / why: a proveniência como comando (SPEC-0003 §6) ----------

/// Resolve o alvo do `explain` para um caminho virtual absoluto: caminho
/// absoluto → como está; nome simples (sem `/`) → comando em `/usr/bin`;
/// relativo com `/` → absolutizado.
fn resolve_virt(target: &str) -> String {
    if target.starts_with('/') {
        target.to_string()
    } else if !target.contains('/') {
        format!("/usr/bin/{target}")
    } else {
        format!("/{target}")
    }
}

/// Dado um caminho virtual, o nome do pacote cujo manifesto o reivindica.
/// Cobre o desvio de `/etc` para a fábrica (`/usr/share/factory/etc/…`).
/// O manifesto guarda caminhos (ou `<sha256>␠␠<caminho>` no v1); casa o sufixo.
fn owner_of(ctx: &Ctx, virt: &str) -> Option<String> {
    let mut wanted = vec![virt.to_string()];
    if let Some(sub) = virt.strip_prefix("/etc/") {
        wanted.push(format!("/usr/share/factory/etc/{sub}"));
    }
    let claims = |line: &str| -> bool {
        let path = line.rsplit("  ").next().unwrap_or(line);
        wanted.iter().any(|w| w == path || w == line)
    };
    let mut owners: Vec<String> = Vec::new();
    for e in fs::read_dir(ctx.records_dir()).ok()?.flatten() {
        if read_manifest(&e.path()).iter().any(|l| claims(l)) {
            owners.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    // Um provisório e um sucessor podem "reivindicar" o mesmo caminho no
    // manifesto se a cessão ainda não foi limpa; o dono real é o não-provisório.
    owners.sort();
    owners
        .iter()
        .find(|n| !is_provisional(ctx, n))
        .or_else(|| owners.first())
        .cloned()
}

/// Pacotes instalados que listam `name` em `DEPS` (dependência reversa). Lê o
/// `DEPS=` do `meta` do registro (gravado por `write_record`).
fn dependents_of(ctx: &Ctx, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(ctx.records_dir()) {
        for e in entries.flatten() {
            let other = e.file_name().to_string_lossy().into_owned();
            if other == name {
                continue;
            }
            let deps = read_meta(&e.path())
                .and_then(|m| m.get("DEPS").cloned())
                .unwrap_or_default();
            if deps.split_whitespace().any(|d| d == name) {
                out.push(other);
            }
        }
    }
    out.sort();
    out
}

/// O conjunto `world` (intenção explícita do administrador), um pacote por
/// linha; `#` comenta. Ausente ⇒ vazio.
fn read_world(ctx: &Ctx) -> HashSet<String> {
    fs::read_to_string(ctx.world_path())
        .map(|t| {
            t.lines()
                .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn world_label(meta: &HashMap<String, String>) -> &'static str {
    match meta.get("WORLD").map(String::as_str) {
        Some("A") => "A — binário do mantenedor (em /opt, links em /usr)",
        Some("B") => "B — compilado da fonte (árvore em /usr)",
        _ => "?",
    }
}

/// De onde veio o artefato (campo `ORIGIN`; canais em SPEC-0009 gravam
/// `canal:<nome>`). Sem `ORIGIN` (registro legado), deriva de `WORLD`.
fn origin_label(meta: &HashMap<String, String>) -> String {
    match meta.get("ORIGIN").map(String::as_str) {
        Some("vendor") => "binário de vendor (upstream)".into(),
        Some("fonte") => "compilado localmente da fonte".into(),
        Some(o) if o.starts_with("canal:") => format!("canal binário «{}» (SPEC-0009)", &o[6..]),
        Some(o) => o.to_string(),
        None => match meta.get("WORLD").map(String::as_str) {
            Some("A") => "binário de vendor (upstream)".into(),
            Some("B") => "compilado localmente da fonte".into(),
            _ => "desconhecida".into(),
        },
    }
}

/// Extrai o `REPROCORR` (hash reprodutível pinado) de uma cópia de receita no
/// registro — a base da corroboração (SPEC-0009 §6, SPEC-0010). None se ausente.
fn reprocorr_of(rec_dir: &Path) -> Option<String> {
    let recipe = rec_dir.join("recipe");
    if !recipe.is_file() {
        return None;
    }
    let out = Command::new("sh")
        .arg("-c")
        .arg(". \"$1\"; printf '%s' \"${REPROCORR:-}\"")
        .arg("sh")
        .arg(&recipe)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// `explain <caminho>` — quem é o dono de um arquivo e toda a sua proveniência.
pub fn explain(ctx: &Ctx, target: &str) -> Result<()> {
    let virt = resolve_virt(target);
    match owner_of(ctx, &virt) {
        Some(name) => {
            let rec = ctx.records_dir().join(&name);
            let meta = read_meta(&rec).unwrap_or_default();
            let field = |k: &str| meta.get(k).map(String::as_str).unwrap_or("?");
            println!("{virt}");
            println!("  pacote:      {name} {}", field("VERSION"));
            println!("  mundo:       {}", world_label(&meta));
            println!("  origem:      {}", origin_label(&meta));
            // Confiança e corroboração (SPEC-0009 §6/§8): TRUST e CHANNEL_SHA256
            // são gravados pela instalação de canal (ainda por vir); o REPROCORR
            // vem da receita e é a base da corroboração por reprodução.
            if let Some(trust) = meta.get("TRUST") {
                println!("  confiança:   {trust}");
            }
            match reprocorr_of(&rec) {
                Some(rc) => println!(
                    "  reprocorr:   {} — corroborável por reprodução (SPEC-0010 §5)",
                    &rc[..rc.len().min(16)]
                ),
                None => println!("  reprocorr:   (a receita não pina hash reprodutível ainda)"),
            }
            if let Some(corr) = meta.get("CORROBORADORES") {
                println!("  corroborado: {corr}");
            }
            if field("PROVISIONAL") == "1" {
                println!("  provisório:  sim — cede o caminho a um sucessor (SPEC-0003 §3)");
            }
            if let Some(fp) = meta.get("FINGERPRINT") {
                println!("  fingerprint: {}", &fp[..fp.len().min(16)]);
            }
            // Hash do próprio arquivo no manifesto v1 (integridade por arquivo).
            if let Some(line) = read_manifest(&rec).iter().find(|l| {
                let p = manifest_path(l);
                p == virt
                    || virt
                        .strip_prefix("/etc/")
                        .map(|s| p == format!("/usr/share/factory/etc/{s}"))
                        .unwrap_or(false)
            }) {
                if let Some(h) = manifest_hash(line) {
                    println!("  hash-arq:    {}", &h[..16]);
                }
            }
            println!("  instalado:   {}", field("INSTALLED_AT"));
            println!("  receita:     {}", rec.join("recipe").display());
            if let Some(about) = about_of(&rec) {
                println!("  é:           {about}");
            }
            if virt.starts_with("/etc/") {
                println!("  nota:        default de /etc (a fábrica é a fonte; a sua cópia pode divergir — SPEC-0002 §6)");
            }
            let real = ctx.root.join(virt.trim_start_matches('/'));
            if let Ok(t) = fs::read_link(&real) {
                println!("  link →       {}", t.display());
            }
            Ok(())
        }
        None => {
            let real = ctx.root.join(virt.trim_start_matches('/'));
            if real.symlink_metadata().is_ok() {
                println!(
                    "{virt}: existe, mas nenhum registro o reivindica — wrongthink (veja `verify`)"
                );
            } else {
                println!("{virt}: nenhum registro o reivindica, e não há nada aí.");
            }
            Ok(())
        }
    }
}

/// `why <pacote>` — por que este pacote está no sistema.
pub fn why(ctx: &Ctx, name: &str) -> Result<()> {
    let rec = ctx.records_dir().join(name);
    let meta = match read_meta(&rec) {
        Some(m) => m,
        None => return fail(2, format!("{name}: não está registrado (não instalado)")),
    };
    println!(
        "{name} {}",
        meta.get("VERSION").map(String::as_str).unwrap_or("?")
    );
    let explicit = read_world(ctx).contains(name);
    let dependents = dependents_of(ctx, name);
    if explicit {
        println!("  desejado:    explicitamente (consta no world — SPEC-0003 §2)");
    }
    if !dependents.is_empty() {
        println!("  requerido por: {}", dependents.join(", "));
    }
    if !explicit && dependents.is_empty() {
        println!("  órfão:       nem explícito nem dependência de outro (candidato a `memoryhole --orfaos`)");
    }
    println!("  origem:      {}", origin_label(&meta));
    if meta.get("PROVISIONAL").map(String::as_str) == Some("1") {
        println!("  provisório:  sim — scaffolding que cede a um sucessor (SPEC-0003 §3)");
    }
    Ok(())
}

/// Extrai o `ABOUT` de uma cópia de receita no registro (uma linha).
fn about_of(rec_dir: &Path) -> Option<String> {
    let recipe = rec_dir.join("recipe");
    if !recipe.is_file() {
        return None;
    }
    let out = Command::new("sh")
        .arg("-c")
        .arg(". \"$1\"; printf '%s' \"${ABOUT:-}\"")
        .arg("sh")
        .arg(&recipe)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Núcleo transacional: write_atomic grava certo e não deixa `.tmp`; o
    /// lock por rootfs é exclusivo (segundo pedido falha enquanto o 1º vive).
    #[test]
    fn atomico_e_lock() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-tx-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let p = root.join("meta");
        write_atomic(&p, b"conteudo\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "conteudo\n");
        write_atomic(&p, b"novo\n").unwrap(); // sobrescreve
        assert_eq!(fs::read_to_string(&p).unwrap(), "novo\n");
        // nenhum temporário sobrou
        let leftovers: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "sobrou temporário");

        // lock: o primeiro guarda segura; o segundo falha
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let g1 = acquire_lock(&ctx).expect("1º lock");
        assert!(acquire_lock(&ctx).is_err(), "2º lock deveria falhar");
        drop(g1);
        assert!(acquire_lock(&ctx).is_ok(), "após soltar, relockeia");
        let _ = fs::remove_dir_all(&root);
    }

    /// Manifesto v1: parsing de `<sha256>␠␠<caminho>`, retrocompat com v0
    /// (linha sem hash), e file_hash streaming.
    #[test]
    fn manifesto_v1_parsing_e_hash() {
        let h = "b".repeat(64);
        let v1 = format!("{h}  /usr/bin/x");
        assert_eq!(manifest_path(&v1), "/usr/bin/x");
        assert_eq!(manifest_hash(&v1), Some(h.as_str()));
        // symlink/dir → "-"
        assert_eq!(manifest_path("-  /opt/foo/current"), "/opt/foo/current");
        assert_eq!(manifest_hash("-  /opt/foo/current"), None);
        // legado v0: a própria linha é o caminho, sem hash
        assert_eq!(manifest_path("/usr/lib/libc.so.6"), "/usr/lib/libc.so.6");
        assert_eq!(manifest_hash("/usr/lib/libc.so.6"), None);

        // file_hash: arquivo regular hasheia; symlink/ausente → "-"
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("mt-fh-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a"), b"conteudo\n").unwrap();
        symlink("a", dir.join("l")).unwrap();
        let ha = file_hash(&dir.join("a"));
        assert_eq!(ha.len(), 64);
        assert_eq!(file_hash(&dir.join("a")), ha, "determinístico");
        assert_eq!(file_hash(&dir.join("l")), "-", "symlink → -");
        assert_eq!(file_hash(&dir.join("ausente")), "-");
        let _ = fs::remove_dir_all(&dir);
    }

    /// explain/why: owner_of acha o dono (incl. desvio de /etc→fábrica) e
    /// prefere o não-provisório; dependents_of acha a dependência reversa;
    /// read_world lê a intenção explícita.
    #[test]
    fn explain_why_proveniencia() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-expl-{}-{n}", std::process::id()));
        let recs = root.join("var/lib/minitrue/records");
        // glibc (mundo B) dona de /usr/lib/libc.so.6, dep de ninguém explícito
        fs::create_dir_all(recs.join("glibc")).unwrap();
        fs::write(
            recs.join("glibc/meta"),
            "NAME=glibc\nVERSION=2.42\nWORLD=B\nDEPS=\n",
        )
        .unwrap();
        fs::write(recs.join("glibc/manifest"), "/usr/lib/libc.so.6\n").unwrap();
        // gcc (mundo B) depende de glibc; dona do default /etc (via fábrica)
        fs::create_dir_all(recs.join("gcc")).unwrap();
        fs::write(
            recs.join("gcc/meta"),
            "NAME=gcc\nVERSION=15.3.0\nWORLD=B\nDEPS=glibc\n",
        )
        .unwrap();
        fs::write(
            recs.join("gcc/manifest"),
            "/usr/bin/gcc\n/usr/share/factory/etc/gcc.conf\n",
        )
        .unwrap();
        // busybox provisional também "reivindica" /usr/bin/gcc (cessão não limpa)
        fs::create_dir_all(recs.join("busybox")).unwrap();
        fs::write(
            recs.join("busybox/meta"),
            "NAME=busybox\nVERSION=1.35\nWORLD=A\nPROVISIONAL=1\n",
        )
        .unwrap();
        fs::write(recs.join("busybox/manifest"), "/usr/bin/gcc\n").unwrap();
        // world: glibc é explícito
        fs::create_dir_all(root.join("etc/minitrue")).unwrap();
        fs::write(root.join("etc/minitrue/world"), "glibc\n# comentário\n").unwrap();

        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        // dono direto
        assert_eq!(
            owner_of(&ctx, "/usr/lib/libc.so.6").as_deref(),
            Some("glibc")
        );
        // /etc/gcc.conf resolve pela fábrica
        assert_eq!(owner_of(&ctx, "/etc/gcc.conf").as_deref(), Some("gcc"));
        // caminho reivindicado por gcc E pela busybox provisional → vence o não-provisório
        assert_eq!(owner_of(&ctx, "/usr/bin/gcc").as_deref(), Some("gcc"));
        // caminho sem dono
        assert_eq!(owner_of(&ctx, "/usr/bin/inexistente"), None);
        // dependência reversa
        assert_eq!(dependents_of(&ctx, "glibc"), vec!["gcc".to_string()]);
        assert!(dependents_of(&ctx, "gcc").is_empty());
        // world
        assert!(read_world(&ctx).contains("glibc"));
        assert!(!read_world(&ctx).contains("gcc"));
        let _ = fs::remove_dir_all(&root);
    }

    /// Supersessão provisional (SPEC-0005 §4): um pacote-semente PROVISIONAL
    /// (gmp/binutils/gcc musl) cede seus caminhos ao rebuild-glibc que os
    /// reivindica — sem doublethink — como busybox cede a coreutils.
    #[test]
    fn provisional_cede_ao_rebuild() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-prov-{}-{n}", std::process::id()));
        let recs = root.join("var/lib/minitrue/records");
        // semente provisional (gmp) com dois caminhos
        fs::create_dir_all(recs.join("gmp")).unwrap();
        fs::write(
            recs.join("gmp/meta"),
            "NAME=gmp\nVERSION=6.3.0\nPROVISIONAL=1\n",
        )
        .unwrap();
        fs::write(
            recs.join("gmp/manifest"),
            "/usr/lib/libgmp.so.10\n/usr/lib/libgmp.so\n",
        )
        .unwrap();
        // pacote real (não-provisional) para contraste
        fs::create_dir_all(recs.join("outro")).unwrap();
        fs::write(recs.join("outro/meta"), "NAME=outro\nVERSION=1\n").unwrap();
        fs::write(recs.join("outro/manifest"), "/usr/lib/liboutro.so\n").unwrap();

        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        assert!(is_provisional(&ctx, "gmp"), "gmp deveria ser provisional");
        assert!(!is_provisional(&ctx, "outro"), "outro NÃO é provisional");

        // quem NÃO declara superseder gmp NÃO cede (viraria doublethink)
        assert_eq!(
            adopt_provisional_path(&ctx, "/usr/lib/libgmp.so.10", "estranho", &[]),
            None,
            "sem SUPERSEDES, não cede"
        );
        // o rebuild-glibc que DECLARA superseder gmp cede
        let sup = vec!["gmp".to_string()];
        let owner = adopt_provisional_path(&ctx, "/usr/lib/libgmp.so.10", "mathlibs-glibc", &sup);
        assert_eq!(owner.as_deref(), Some("gmp"));
        let m = read_manifest(&recs.join("gmp"));
        assert!(
            !m.contains(&"/usr/lib/libgmp.so.10".to_string()),
            "caminho cedido some do manifesto"
        );
        assert!(
            m.contains(&"/usr/lib/libgmp.so".to_string()),
            "os outros caminhos ficam"
        );

        // caminho de pacote NÃO-provisional não é cedido (viraria doublethink)
        assert_eq!(
            adopt_provisional_path(&ctx, "/usr/lib/liboutro.so", "x", &["outro".to_string()]),
            None
        );
        let _ = fs::remove_dir_all(&root);
    }

    fn be() -> BuildEnv {
        BuildEnv {
            cc: "x-gcc".into(),
            cxx: "x-g++".into(),
            ar: "x-ar".into(),
            ranlib: "x-ranlib".into(),
            ld: "x-ld".into(),
            nm: "x-nm".into(),
            path_prefix: vec![PathBuf::from("/root/tmp/b/.tc")],
        }
    }
    fn ctx(root: &str) -> Ctx {
        Ctx {
            root: PathBuf::from(root),
            offline: false,
            tofu: false,
            jobs: 4,
        }
    }
    fn args_of(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }
    fn has_pair(a: &[String], k: &str, v: &str) -> bool {
        a.windows(2).any(|w| w[0] == k && w[1] == v)
    }

    #[test]
    fn rootfs_usa_bwrap_hermetico() {
        let ctx = ctx("/root");
        let work = PathBuf::from("/root/tmp/b");
        let cmd = build_command(
            &ctx,
            &be(),
            50,
            &work,
            "1704067200",
            &[(
                PathBuf::from("/root/var/cache/minitrue/deadbeef"),
                "deadbeef".into(),
            )],
        );
        assert_eq!(cmd.get_program().to_string_lossy(), "bwrap");
        let a = args_of(&cmd);
        // rootfs montado em /
        let bind = a.iter().position(|x| x == "--bind").unwrap();
        assert_eq!(a[bind + 1], "/root");
        assert_eq!(a[bind + 2], "/");
        // hermético
        assert!(a.contains(&"--unshare-net".to_string()));
        assert!(a.contains(&"--clearenv".to_string()));
        // variáveis em forma de CHROOT, não caminho do host
        assert!(has_pair(&a, "STAGE", "/tmp/b/stage"));
        assert!(has_pair(&a, "RECIPE", "/tmp/b/recipe"));
        assert!(has_pair(&a, "ROOT", "/"));
        assert!(has_pair(&a, "CC", "x-gcc"));
        assert!(has_pair(&a, "AR", "x-ar"));
        assert!(has_pair(&a, "DL", "/var/cache/minitrue/deadbeef"));
        // PATH: prefixo em chroot + /usr/bin:/bin, sem PATH do host
        assert!(
            has_pair(&a, "PATH", "/tmp/b/.tc:/usr/bin:/bin"),
            "PATH errado: {a:?}"
        );
        assert!(
            !a.iter().any(|x| x.contains("/root/tmp")),
            "vazou caminho do host: {a:?}"
        );
        // termina em /bin/sh -ec <preâmbulo>
        assert_eq!(a[a.len() - 3], "/bin/sh");
        assert_eq!(a[a.len() - 2], "-ec");
        assert_eq!(a[a.len() - 1], BUILD_PREAMBLE);
    }

    #[test]
    fn root_slash_roda_direto() {
        let ctx = ctx("/");
        let work = PathBuf::from("/tmp/b");
        let cmd = build_command(&ctx, &be(), 0, &work, "1704067200", &[]);
        assert_eq!(cmd.get_program().to_string_lossy(), "sh");
        let cc = cmd
            .get_envs()
            .find(|(k, _)| *k == "CC")
            .and_then(|(_, v)| v)
            .map(|v| v.to_string_lossy().into_owned());
        assert_eq!(cc.as_deref(), Some("x-gcc"));
    }
}
