use crate::profile::{write_new, ResolvedProfile};
use crate::tree::{self, Entry, EntryKind};
use anyhow::{bail, Context, Result};
use sha2::Digest;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub struct InstallOptions {
    pub target: PathBuf,
    pub minitrue: Option<PathBuf>,
    pub offline: bool,
    pub from_source: bool,
    pub only_binary: bool,
    pub resume: bool,
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(name))
            .find(|candidate| {
                fs::symlink_metadata(candidate).is_ok_and(|metadata| metadata.file_type().is_file())
            })
    })
}

fn minitrue_path(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    let path = explicit
        .clone()
        .or_else(|| find_in_path("minitrue"))
        .ok_or_else(|| anyhow::anyhow!("--minitrue ou MINITRUE é obrigatório"))?;
    crate::ensure_real_file(&path, "minitrue")?;
    Ok(fs::canonicalize(path)?)
}

struct ExecutableSnapshot {
    file: fs::File,
}

impl ExecutableSnapshot {
    fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

fn snapshot_executable(path: &Path) -> Result<(ExecutableSnapshot, String)> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use rustix::io::Errno;

    let mut source = fs::File::open(path)
        .with_context(|| format!("não abri executável para snapshot: {}", path.display()))?;
    let metadata = source.metadata()?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "o snapshot exige arquivo regular executável: {}",
            path.display()
        );
    }
    let descriptor = match memfd_create(
        "distropica-minitrue",
        MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::INVAL) => memfd_create("distropica-minitrue", MemfdFlags::ALLOW_SEALING)?,
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    let mut file = fs::File::from(descriptor);
    std::io::copy(&mut source, &mut file)?;
    file.flush()?;
    file.set_permissions(fs::Permissions::from_mode(0o700))?;
    fcntl_add_seals(
        &file,
        SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
    )?;
    let snapshot = ExecutableSnapshot { file };
    let hash = sha256_file(&snapshot.path())?;
    Ok((snapshot, hash))
}

fn persist_executor(snapshot: &ExecutableSnapshot, target: &Path, name: &str) -> Result<()> {
    let destination = target.join("usr/bin").join(name);
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("executor sem diretório pai"))?;
    crate::ensure_real_dir(parent, "diretório de executores instalados")?;
    match fs::symlink_metadata(&destination) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.nlink() == 1
                && sha256_file(&destination)? == sha256_file(&snapshot.path())? =>
        {
            if metadata.permissions().mode() & 0o7777 != 0o755 {
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))?;
            }
            return Ok(());
        }
        Ok(_) => bail!(
            "executor instalado diverge ou não é arquivo regular sem hardlinks: {}",
            destination.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = temporary_sibling(&destination)?;
    if fs::symlink_metadata(&temporary).is_ok() {
        bail!("temporário já existe: {}", temporary.display());
    }
    let mut source = fs::File::open(snapshot.path())?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&temporary)?;
    std::io::copy(&mut source, &mut output)?;
    output.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
    crate::publish_noreplace(&temporary, &destination)?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn target_is_empty(path: &Path) -> Result<bool> {
    let mut names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.retain(|name| name != "lost+found");
    Ok(names.is_empty())
}

fn read_state_file(path: &Path, what: &str) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.nlink() == 1 => {
            Ok(Some(fs::read(path)?))
        }
        Ok(_) => bail!(
            "{what} precisa ser arquivo regular real sem hardlinks: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn prepare_target(options: &InstallOptions) -> Result<PathBuf> {
    let target = crate::absolute_path(&options.target)?;
    if target == Path::new("/") {
        bail!("--target / é recusado; use uma raiz alternativa explicitamente montada");
    }
    if fs::symlink_metadata(&target).is_err() {
        let parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("target sem pai"))?;
        crate::ensure_real_dir(parent, "pai do target")?;
        fs::create_dir(&target)?;
    }
    crate::ensure_real_dir(&target, "target")?;
    let target = fs::canonicalize(target)?;
    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    if cwd == target || cwd.starts_with(&target) {
        bail!("target não pode ser o diretório de trabalho nem um ancestral dele");
    }
    let marker = target.join("var/lib/minipax/profile.lock");
    let pending = target.join("var/lib/minipax/profile.lock.pending");
    let early = target.join(".minipax-profile.lock.pending");
    let marker_exists = read_state_file(&marker, "profile.lock")?.is_some();
    let pending_exists = read_state_file(&pending, "profile.lock.pending")?.is_some();
    let early_exists = read_state_file(&early, "marcador inicial")?.is_some();
    if [marker_exists, pending_exists, early_exists]
        .into_iter()
        .filter(|exists| *exists)
        .count()
        > 1
    {
        bail!("target contém mais de um marcador de instalação do minipax");
    }
    if options.resume {
        if !marker_exists && !pending_exists && !early_exists {
            bail!("--resume exige um target previamente marcado pelo minipax");
        }
    } else if !target_is_empty(&target)? {
        bail!("target não está vazio; use --resume somente para instalação marcada");
    }
    Ok(target)
}

fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => bail!("esperava diretório real: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn scaffold(target: &Path) -> Result<()> {
    for (relative, mode) in [
        ("usr", 0o755),
        ("usr/bin", 0o755),
        ("usr/lib", 0o755),
        ("usr/share", 0o755),
        ("etc", 0o755),
        ("etc/minitrue", 0o755),
        ("opt", 0o755),
        ("proc", 0o555),
        ("sys", 0o555),
        ("dev", 0o755),
        ("tmp", 0o1777),
        ("run", 0o755),
        ("root", 0o700),
        ("home", 0o755),
        ("srv", 0o755),
        ("boot", 0o755),
        ("var", 0o755),
        ("var/cache", 0o755),
        ("var/cache/minitrue", 0o755),
        ("var/lib", 0o755),
        ("var/lib/minitrue", 0o755),
        ("var/lib/minipax", 0o755),
        ("var/log", 0o755),
        ("var/log/room101", 0o755),
    ] {
        let mut current = target.to_path_buf();
        for component in Path::new(relative).components() {
            let Component::Normal(component) = component else {
                unreachable!()
            };
            current.push(component);
            let final_mode = if current == target.join(relative) {
                mode
            } else {
                0o755
            };
            ensure_dir(&current, final_mode)?;
        }
    }
    for (link, destination) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/bin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib"),
        ("usr/lib64", "lib"),
    ] {
        let path = target.join(link);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && fs::read_link(&path)? == Path::new(destination) => {}
            Ok(_) => bail!("usr-merge incompatível em {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                symlink(destination, path)?
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_real_ancestors(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut destination = root.to_path_buf();
    if relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        bail!("caminho não canônico ao aplicar árvore: {relative:?}");
    }
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(component) = component else {
            unreachable!()
        };
        destination.push(component);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!("ancestral não é diretório real: {}", destination.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&destination)?;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(root.join(relative))
}

fn temporary_sibling(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("destino sem nome"))?
        .to_string_lossy();
    Ok(path.with_file_name(format!(".{name}.minipax-new-{}", std::process::id())))
}

fn apply_entries(root: &Path, entries: &[Entry], replace: bool) -> Result<()> {
    for entry in entries {
        let destination = ensure_real_ancestors(root, &entry.relative)?;
        match &entry.kind {
            EntryKind::Directory => {
                ensure_dir(&destination, entry.mode)?;
            }
            EntryKind::Regular(content) => {
                if let Ok(metadata) = fs::symlink_metadata(&destination) {
                    if !metadata.file_type().is_file() {
                        bail!("colisão ao aplicar árvore: {}", destination.display());
                    }
                    if !replace {
                        let same_mode = metadata.permissions().mode() & 0o7777 == entry.mode;
                        if same_mode && fs::read(&destination)? == *content {
                            continue;
                        }
                        bail!("colisão ao aplicar árvore: {}", destination.display());
                    }
                }
                let temporary = temporary_sibling(&destination)?;
                if fs::symlink_metadata(&temporary).is_ok() {
                    bail!("temporário já existe: {}", temporary.display());
                }
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(entry.mode)
                    .open(&temporary)?;
                file.write_all(content)?;
                file.sync_all()?;
                fs::set_permissions(&temporary, fs::Permissions::from_mode(entry.mode))?;
                fs::rename(&temporary, &destination)?;
            }
            EntryKind::Symlink(target) => {
                if let Ok(metadata) = fs::symlink_metadata(&destination) {
                    if !replace
                        && metadata.file_type().is_symlink()
                        && fs::read_link(&destination)? == *target
                    {
                        continue;
                    }
                    if !replace {
                        bail!("colisão ao aplicar symlink: {}", destination.display());
                    }
                }
                let temporary = temporary_sibling(&destination)?;
                if fs::symlink_metadata(&temporary).is_ok() {
                    bail!("temporário já existe: {}", temporary.display());
                }
                symlink(target, &temporary)?;
                fs::rename(&temporary, &destination)?;
            }
        }
    }
    Ok(())
}

fn install_snapshot(target: &Path, relative: &str, entries: &[Entry]) -> Result<()> {
    let destination = target.join(relative);
    let temporary = destination.with_file_name(format!(
        ".{}.minipax-new-{}",
        destination.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    if fs::symlink_metadata(&temporary).is_ok() {
        bail!("temporário já existe: {}", temporary.display());
    }
    fs::create_dir(&temporary)?;
    apply_entries(&temporary, entries, false)?;
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::rename(&temporary, &destination)?
        }
        Ok(metadata) if metadata.file_type().is_dir() => {
            let current = crate::tree::collect(&destination, crate::tree::TreePolicy::Newspeak)?;
            let current_tar = crate::tree::pack(&current, 0)?;
            let wanted_tar = crate::tree::pack(entries, 0)?;
            if current_tar != wanted_tar {
                fs::remove_dir_all(&temporary)?;
                bail!("snapshot existente diverge em {}", destination.display());
            }
            fs::remove_dir_all(&temporary)?;
        }
        Ok(_) => bail!("snapshot não é diretório real: {}", destination.display()),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn run_minitrue(
    path: &Path,
    target: &Path,
    arguments: &[&str],
    options: &InstallOptions,
    epoch: u64,
) -> Result<()> {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/")
        .env("TMPDIR", "/tmp")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("NEWSPEAK_PATH", "var/lib/minitrue/newspeak")
        .env("SOURCE_DATE_EPOCH", epoch.to_string())
        .arg("--root")
        .arg(target);
    for variable in [
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    ] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    if options.offline {
        command.arg("--offline");
    }
    if arguments.first() == Some(&"rectify") {
        if options.from_source {
            command.arg("--no-binary");
        }
        if options.only_binary {
            command.arg("--only-binary");
        }
    }
    command.args(arguments);
    let status = command.status().context("não consegui executar minitrue")?;
    if !status.success() {
        bail!("minitrue falhou com status {status}");
    }
    Ok(())
}

pub fn install(profile: &ResolvedProfile, options: &InstallOptions) -> Result<()> {
    if options.from_source && options.only_binary {
        bail!("--from-source e --only-binary são mutuamente exclusivos");
    }
    if !profile.install_ready {
        bail!(
            "o perfil {} declara INSTALL_READY=no; faltam os canais/toolchain necessários para materializar um target vazio",
            profile.name
        );
    }
    let artifacts = profile.artifacts()?;
    let packages = artifacts.target_world.lines().collect::<Vec<_>>();
    if packages.is_empty() {
        bail!("target.world não pode ser vazio");
    }
    if options.offline && profile.cache_is_channel_bootstrap {
        bail!(
            "instalação --offline exige --cache DIR completo; channel-bootstrap/ contém apenas metadados"
        );
    }
    if options.offline && artifacts.cache_entries.is_empty() {
        bail!("instalação --offline exige --cache DIR não vazio");
    }
    if options.only_binary && !options.offline {
        tree::validate_channel_bootstrap(&artifacts.cache_entries).context(
            "instalação online --only-binary exige bootstrap de canal fechado no perfil",
        )?;
    }
    let target = prepare_target(options)?;
    let minitrue_source = minitrue_path(&options.minitrue)?;
    let (minitrue_snapshot, minitrue_hash) = snapshot_executable(&minitrue_source)?;
    let (minipax_snapshot, minipax_hash) = snapshot_executable(&std::env::current_exe()?)?;
    let install_class = if artifacts.class == "official-inputs"
        && profile.official_minitrue_sha256.as_deref() == Some(minitrue_hash.as_str())
    {
        "official-inputs"
    } else if artifacts.class == "development" {
        "development"
    } else {
        "custom"
    };
    let manifest = format!(
        "INSTALL_MANIFEST_FORMAT=1\nPROFILE_LOCK_SHA256={}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nINSTALL_CLASS={}\nARCH={}\nOVERLAY_SHA256={}\nMINITRUE_SHA256={}\nMINITRUE_INSTALLED_PATH=/usr/bin/minitrue\nMINIPAX_VERSION={}\nMINIPAX_EXECUTABLE_SHA256={}\nMINIPAX_INSTALLED_PATH=/usr/bin/minipax\nOFFLINE={}\nFROM_SOURCE={}\nONLY_BINARY={}\n",
        artifacts.lock_hash,
        profile.name,
        artifacts.class,
        install_class,
        profile.arch,
        hex::encode(sha2::Sha256::digest(&artifacts.overlay_tar)),
        minitrue_hash,
        crate::VERSION,
        minipax_hash,
        options.offline,
        options.from_source,
        options.only_binary,
    );
    let state = target.join("var/lib/minipax");
    let committed = state.join("profile.lock");
    let pending = state.join("profile.lock.pending");
    let early = target.join(".minipax-profile.lock.pending");
    let manifest_path = state.join("install.manifest");
    let committed_state = read_state_file(&committed, "profile.lock")?;
    let pending_state = read_state_file(&pending, "profile.lock.pending")?;
    let early_state = read_state_file(&early, "marcador inicial")?;
    let existing_manifest = read_state_file(&manifest_path, "install.manifest")?;
    let existing_locks = [
        committed_state.as_deref(),
        pending_state.as_deref(),
        early_state.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if existing_locks.len() > 1 {
        bail!("target contém mais de um marcador de instalação do minipax");
    }
    if let Some(existing) = existing_locks.first() {
        if !options.resume {
            bail!("marcador de instalação apareceu sem --resume");
        }
        if *existing != artifacts.lock.as_bytes() {
            bail!("--resume recebeu perfil diferente da instalação marcada");
        }
    } else if options.resume {
        bail!("marcador de --resume desapareceu durante a validação");
    }
    if existing_manifest
        .as_deref()
        .is_some_and(|existing| existing != manifest.as_bytes())
    {
        bail!("install.manifest existente diverge do perfil ou do executor");
    }
    if existing_locks.is_empty() {
        write_new(&early, artifacts.lock.as_bytes())?;
    }
    scaffold(&target)?;
    if read_state_file(&early, "marcador inicial")?.is_some() {
        crate::publish_noreplace(&early, &pending)?;
    }
    install_snapshot(
        &target,
        "var/lib/minitrue/newspeak",
        &artifacts.newspeak_entries,
    )?;
    if !artifacts.cache_entries.is_empty() {
        apply_entries(
            &target.join("var/cache/minitrue"),
            &artifacts.cache_entries,
            false,
        )?;
    }
    let mut rectify = Vec::with_capacity(packages.len() + 1);
    rectify.push("rectify");
    rectify.extend(packages);
    run_minitrue(
        &minitrue_snapshot.path(),
        &target,
        &rectify,
        options,
        profile.epoch,
    )?;
    run_minitrue(
        &minitrue_snapshot.path(),
        &target,
        &["verify"],
        options,
        profile.epoch,
    )?;
    apply_entries(&target, &artifacts.overlay_entries, true)?;
    run_minitrue(
        &minitrue_snapshot.path(),
        &target,
        &["verify"],
        options,
        profile.epoch,
    )?;
    // O sistema resultante precisa conseguir continuar a se retificar depois
    // do primeiro reboot. Persistimos exatamente os dois snapshots medidos,
    // sem reler executáveis mutáveis do host entre hash e cópia.
    persist_executor(&minitrue_snapshot, &target, "minitrue")?;
    persist_executor(&minipax_snapshot, &target, "minipax")?;
    if existing_manifest.is_none() {
        write_new(&manifest_path, manifest.as_bytes())?;
    }
    if read_state_file(&pending, "profile.lock.pending")?.is_some() {
        crate::publish_noreplace(&pending, &committed)?;
    }
    println!(
        "perfil {} / instalação {} ({}) materializado em {}",
        profile.name,
        install_class,
        artifacts.lock_hash,
        target.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileOverrides;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn persist_executor_restaura_modo_executavel_no_fast_path() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("executor-source");
        let target = temp.path().join("target");
        fs::create_dir_all(target.join("usr/bin")).unwrap();
        fs::write(&source, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        let (snapshot, _) = snapshot_executable(&source).unwrap();

        let installed = target.join("usr/bin/minitrue");
        fs::write(&installed, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o644)).unwrap();
        persist_executor(&snapshot, &target, "minitrue").unwrap();

        assert_eq!(
            fs::symlink_metadata(installed)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }

    #[test]
    fn install_invoca_mesmo_world_e_recusa_target_sujo() {
        let temp = tempfile::tempdir().unwrap();
        let profile_dir = temp.path().join("profile");
        let newspeak = temp.path().join("newspeak");
        let target = temp.path().join("target");
        fs::create_dir(&profile_dir).unwrap();
        fs::create_dir(&newspeak).unwrap();
        fs::create_dir(&target).unwrap();
        let calls = temp.path().join("calls");
        fs::write(
            profile_dir.join("profile"),
            "PROFILE_FORMAT=1\nNAME=test\nARCH=x86_64\nSOURCE_DATE_EPOCH=10\nSTATUS=development\n",
        )
        .unwrap();
        fs::write(profile_dir.join("target.world"), "z\na\n").unwrap();
        fs::write(profile_dir.join("live.world"), "busybox\n").unwrap();
        let fake = temp.path().join("minitrue");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$NEWSPEAK_PATH\" \"$SOURCE_DATE_EPOCH\" \"$*\" >> '{}'\nexit 0\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("NEWSPEAK_PATH", "/receitas/nao-pinar");
        let mut profile = ResolvedProfile::load(
            &profile_dir,
            ProfileOverrides {
                newspeak: Some(newspeak),
                ..Default::default()
            },
        )
        .unwrap();
        let sem_canal = temp.path().join("sem-canal");
        assert!(install(
            &profile,
            &InstallOptions {
                target: sem_canal.clone(),
                minitrue: Some(fake.clone()),
                offline: false,
                from_source: false,
                only_binary: true,
                resume: false,
            },
        )
        .is_err());
        assert!(
            !sem_canal.exists(),
            "gate de canal precisa ocorrer antes de criar/tocar o target"
        );

        let bootstrap = profile_dir.join("channel-bootstrap");
        fs::create_dir_all(bootstrap.join("channel-config")).unwrap();
        fs::create_dir_all(bootstrap.join("channels/oficial")).unwrap();
        fs::write(bootstrap.join("channel-config/oficial"), b"config\n").unwrap();
        fs::write(bootstrap.join("channels/oficial/index"), b"index\n").unwrap();
        fs::write(
            bootstrap.join("channels/oficial/index.minisig"),
            b"assinatura\n",
        )
        .unwrap();
        let bootstrap_profile = ResolvedProfile::load(
            &profile_dir,
            ProfileOverrides {
                newspeak: Some(temp.path().join("newspeak")),
                ..Default::default()
            },
        )
        .unwrap();
        let bootstrap_offline = temp.path().join("bootstrap-offline");
        let error = install(
            &bootstrap_profile,
            &InstallOptions {
                target: bootstrap_offline.clone(),
                minitrue: Some(fake.clone()),
                offline: true,
                from_source: false,
                only_binary: true,
                resume: false,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("apenas metadados"));
        assert!(
            !bootstrap_offline.exists(),
            "bootstrap online não pode preparar um target offline"
        );

        install(
            &profile,
            &InstallOptions {
                target: target.clone(),
                minitrue: Some(fake.clone()),
                offline: false,
                from_source: true,
                only_binary: false,
                resume: false,
            },
        )
        .unwrap();
        let calls = fs::read_to_string(calls).unwrap();
        std::env::remove_var("NEWSPEAK_PATH");
        assert!(calls.contains("var/lib/minitrue/newspeak|10|--root"));
        assert!(calls.contains("--no-binary rectify a z"));
        assert!(target.join("var/lib/minipax/profile.lock").is_file());
        assert_eq!(
            fs::read(target.join("usr/bin/minitrue")).unwrap(),
            fs::read(&fake).unwrap()
        );
        assert!(target.join("usr/bin/minipax").is_file());
        assert!(target.join("sys").is_dir());

        fs::copy(
            target.join("var/lib/minipax/profile.lock"),
            target.join("var/lib/minipax/profile.lock.pending"),
        )
        .unwrap();
        assert!(prepare_target(&InstallOptions {
            target: target.clone(),
            minitrue: None,
            offline: false,
            from_source: false,
            only_binary: false,
            resume: true,
        })
        .is_err());

        let dirty = temp.path().join("dirty");
        fs::create_dir(&dirty).unwrap();
        fs::write(dirty.join("x"), b"x").unwrap();
        let options = InstallOptions {
            target: dirty,
            minitrue: None,
            offline: false,
            from_source: false,
            only_binary: false,
            resume: false,
        };
        assert!(prepare_target(&options).is_err());

        profile.install_ready = false;
        let blocked = temp.path().join("blocked");
        assert!(install(
            &profile,
            &InstallOptions {
                target: blocked.clone(),
                minitrue: None,
                offline: false,
                from_source: false,
                only_binary: false,
                resume: false,
            },
        )
        .is_err());
        assert!(!blocked.exists());
    }
}
