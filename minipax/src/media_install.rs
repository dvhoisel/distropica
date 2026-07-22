use crate::install::{self, InstallOptions};
use crate::media::{canonical_profile, validate_boot_efi};
use crate::profile::{normalize_world, ProfileOverrides, ResolvedProfile};
use crate::tree::{self, TreePolicy};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_CONTROL_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 192 * 1024 * 1024;
const MAX_CACHE_ARCHIVE_BYTES: u64 = 416 * 1024 * 1024;
const MAX_BOOT_EFI_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 50_000;

const META_FIELDS: &[&str] = &[
    "MEDIA_FORMAT",
    "PROFILE_NAME",
    "PROFILE_CLASS",
    "MEDIA_CLASS",
    "PROFILE_LOCK_SHA256",
    "ARCH",
    "MODE",
    "BOOT_EFI_SHA256",
    "MINIPAX_VERSION",
];

const LOCK_FIELDS: &[&str] = &[
    "PROFILE_LOCK_FORMAT",
    "PROFILE_NAME",
    "PROFILE_CLASS",
    "PROFILE_CONTENT_SHA256",
    "OFFICIAL_CONTENT_SHA256",
    "ARCH",
    "SOURCE_DATE_EPOCH",
    "MEDIA_SIZE_MIB",
    "INSTALL_READY",
    "OFFICIAL_BOOT_EFI_SHA256",
    "OFFICIAL_MINITRUE_SHA256",
    "TARGET_WORLD_SHA256",
    "LIVE_WORLD_SHA256",
    "CACHE_WORLD_SHA256",
    "OVERLAY_SHA256",
    "NEWSPEAK_SHA256",
    "CACHE_SHA256",
];

pub struct MediaInstallOptions {
    pub source: PathBuf,
    pub target: PathBuf,
    pub minitrue: Option<PathBuf>,
    pub offline: bool,
    pub from_source: bool,
    pub only_binary: bool,
    pub resume: bool,
    pub export_boot_efi: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeclaredMode {
    Online,
    Offline,
}

struct MediaSnapshot {
    profile: Vec<u8>,
    lock: Vec<u8>,
    target_world: Vec<u8>,
    live_world: Vec<u8>,
    cache_world: Vec<u8>,
    overlay: Vec<u8>,
    newspeak: Vec<u8>,
    cache: Option<Vec<u8>>,
    metadata: BTreeMap<String, String>,
    lock_fields: BTreeMap<String, String>,
    mode: DeclaredMode,
    boot: Vec<u8>,
    boot_hash: String,
}

#[derive(Debug)]
enum DecodedKind {
    Directory,
    Regular(Vec<u8>),
    Symlink(PathBuf),
}

#[derive(Debug)]
struct DecodedEntry {
    path: PathBuf,
    mode: u32,
    kind: DecodedKind,
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_regular(path: &Path, what: &str, limit: u64) -> Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("não abri {what}: {}", path.display()))?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        bail!(
            "{what} precisa ser arquivo regular real sem hardlinks: {}",
            path.display()
        );
    }
    if metadata.len() > limit {
        bail!("{what} excede {limit} bytes: {}", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{what} cresceu além de {limit} bytes durante a leitura");
    }
    Ok(bytes)
}

fn parse_fields(bytes: &[u8], what: &str, allowed: &[&str]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{what} não é UTF-8"))?;
    if !text.ends_with('\n') {
        bail!("{what} não termina em newline canônico");
    }
    let mut fields = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        if raw.is_empty() || raw.trim() != raw {
            bail!("{what} tem linha não canônica em {}", index + 1);
        }
        let (key, value) = raw
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{what} linha {} não é KEY=VALUE", index + 1))?;
        if !allowed.contains(&key) {
            bail!("{what} contém campo desconhecido {key:?}");
        }
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'=')
        {
            bail!("{what} contém valor inválido para {key}");
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            bail!("{what} repete o campo {key}");
        }
    }
    for required in allowed {
        if !fields.contains_key(*required) {
            bail!("{what} não declara {required}");
        }
    }
    Ok(fields)
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_class(value: &str, what: &str) -> Result<()> {
    if !matches!(value, "development" | "official-inputs" | "custom") {
        bail!("{what} inválida: {value:?}");
    }
    Ok(())
}

fn load_media(source: &Path) -> Result<MediaSnapshot> {
    crate::ensure_real_dir(source, "raiz da mídia")?;
    let source = fs::canonicalize(source)?;
    let payload = source.join("distropica");
    let efi_dir = source.join("EFI/BOOT");
    crate::ensure_real_dir(&payload, "diretório distropica da mídia")?;
    crate::ensure_real_dir(&efi_dir, "diretório EFI/BOOT da mídia")?;

    let metadata_bytes =
        read_regular(&payload.join("media.meta"), "media.meta", MAX_CONTROL_BYTES)?;
    let metadata = parse_fields(&metadata_bytes, "media.meta", META_FIELDS)?;
    if metadata["MEDIA_FORMAT"] != "1" {
        bail!("MEDIA_FORMAT desconhecido; esta versão aceita apenas 1");
    }
    if metadata["ARCH"] != "x86_64" {
        bail!("mídia ARCH={} não é suportada", metadata["ARCH"]);
    }
    validate_class(&metadata["PROFILE_CLASS"], "PROFILE_CLASS")?;
    validate_class(&metadata["MEDIA_CLASS"], "MEDIA_CLASS")?;
    if !is_hash(&metadata["PROFILE_LOCK_SHA256"]) || !is_hash(&metadata["BOOT_EFI_SHA256"]) {
        bail!("media.meta contém SHA-256 inválido");
    }
    let mode = match metadata["MODE"].as_str() {
        "online" => DeclaredMode::Online,
        "offline" => DeclaredMode::Offline,
        value => bail!("MODE inválido em media.meta: {value:?}"),
    };

    let lock = read_regular(
        &payload.join("profile.lock"),
        "profile.lock",
        MAX_CONTROL_BYTES,
    )?;
    if sha256(&lock) != metadata["PROFILE_LOCK_SHA256"] {
        bail!("profile.lock não confere com PROFILE_LOCK_SHA256 de media.meta");
    }
    let lock_fields = parse_fields(&lock, "profile.lock", LOCK_FIELDS)?;
    if lock_fields["PROFILE_LOCK_FORMAT"] != "2" {
        bail!("PROFILE_LOCK_FORMAT desconhecido; esta versão aceita apenas 2");
    }
    validate_class(&lock_fields["PROFILE_CLASS"], "PROFILE_CLASS do lock")?;
    for field in [
        "PROFILE_CONTENT_SHA256",
        "TARGET_WORLD_SHA256",
        "LIVE_WORLD_SHA256",
        "CACHE_WORLD_SHA256",
        "OVERLAY_SHA256",
        "NEWSPEAK_SHA256",
    ] {
        if !is_hash(&lock_fields[field]) {
            bail!("profile.lock contém SHA-256 inválido em {field}");
        }
    }
    for field in [
        "OFFICIAL_CONTENT_SHA256",
        "OFFICIAL_BOOT_EFI_SHA256",
        "OFFICIAL_MINITRUE_SHA256",
        "CACHE_SHA256",
    ] {
        if lock_fields[field] != "-" && !is_hash(&lock_fields[field]) {
            bail!("profile.lock contém SHA-256 inválido em {field}");
        }
    }
    for field in ["PROFILE_NAME", "PROFILE_CLASS", "ARCH"] {
        if metadata[field] != lock_fields[field] {
            bail!("media.meta diverge de profile.lock em {field}");
        }
    }

    let boot = read_regular(
        &efi_dir.join("BOOTX64.EFI"),
        "BOOTX64.EFI",
        MAX_BOOT_EFI_BYTES,
    )?;
    validate_boot_efi(&boot)?;
    let boot_hash = sha256(&boot);
    if boot_hash != metadata["BOOT_EFI_SHA256"] {
        bail!("BOOTX64.EFI não confere com BOOT_EFI_SHA256 de media.meta");
    }

    let cache_path = payload.join("cache.tar");
    // Offline: objetos fechados. Online: somente bootstrap de canal, validado
    // estruturalmente depois da extração. Nos dois casos o tar está preso por
    // CACHE_SHA256 no profile.lock antes de qualquer escrita no target.
    let cache = Some(read_regular(
        &cache_path,
        "cache.tar",
        MAX_CACHE_ARCHIVE_BYTES,
    )?);
    if (cache.is_some() && lock_fields["CACHE_SHA256"] == "-")
        || (cache.is_none() && lock_fields["CACHE_SHA256"] != "-")
    {
        bail!("presença de cache.tar diverge de CACHE_SHA256 no lock");
    }

    Ok(MediaSnapshot {
        profile: read_regular(&payload.join("profile"), "profile", MAX_CONTROL_BYTES)?,
        lock,
        target_world: read_regular(
            &payload.join("target.world"),
            "target.world",
            MAX_CONTROL_BYTES,
        )?,
        live_world: read_regular(&payload.join("live.world"), "live.world", MAX_CONTROL_BYTES)?,
        cache_world: read_regular(
            &payload.join("cache.world"),
            "cache.world",
            MAX_CONTROL_BYTES,
        )?,
        overlay: read_regular(
            &payload.join("overlay.tar"),
            "overlay.tar",
            MAX_ARCHIVE_BYTES,
        )?,
        newspeak: read_regular(
            &payload.join("newspeak.tar"),
            "newspeak.tar",
            MAX_ARCHIVE_BYTES,
        )?,
        cache,
        metadata,
        lock_fields,
        mode,
        boot,
        boot_hash,
    })
}

fn validate_relative(path: &Path, what: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.as_os_str().as_bytes().len() > 4096
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || path.to_str().is_none()
    {
        bail!("{what} contém caminho não canônico: {path:?}");
    }
    Ok(())
}

fn overlay_path_allowed(path: &Path) -> bool {
    let Some(top) = path
        .components()
        .next()
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
    else {
        return false;
    };
    matches!(top, "etc" | "root" | "home" | "srv")
        && path != Path::new("etc/minitrue")
        && !path.starts_with("etc/minitrue/")
}

fn normalized_target(parent: &Path, target: &Path) -> Option<PathBuf> {
    if target.is_absolute() {
        return None;
    }
    let mut stack: Vec<&OsStr> = parent
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect();
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => stack.push(value),
            Component::ParentDir => {
                stack.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let mut normalized = PathBuf::new();
    for component in stack {
        normalized.push(component);
    }
    Some(normalized)
}

fn validate_symlink(path: &Path, target: &Path, policy: TreePolicy) -> Result<()> {
    if policy != TreePolicy::Overlay {
        bail!(
            "arquivo TAR contém symlink fora de overlay: {}",
            path.display()
        );
    }
    if target.as_os_str().is_empty()
        || target.as_os_str().as_bytes().contains(&0)
        || target.to_str().is_none()
    {
        bail!("symlink inválido em {}", path.display());
    }
    let normalized = normalized_target(path.parent().unwrap_or_else(|| Path::new("")), target)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "symlink {} -> {} escapa do overlay",
                path.display(),
                target.display()
            )
        })?;
    if !overlay_path_allowed(&normalized) {
        bail!(
            "symlink {} -> {} alcança namespace não administrativo",
            path.display(),
            target.display()
        );
    }
    Ok(())
}

fn decode_archive(bytes: &[u8], policy: TreePolicy, what: &str) -> Result<Vec<DecodedEntry>> {
    let mut archive = tar::Archive::new(bytes);
    let mut decoded = Vec::new();
    let mut paths = BTreeMap::new();
    let mut content_bytes = 0u64;
    for item in archive
        .entries()
        .with_context(|| format!("não li {what}"))?
    {
        let mut item = item.with_context(|| format!("entrada inválida em {what}"))?;
        if decoded.len() >= MAX_TREE_ENTRIES {
            bail!("{what} excede {MAX_TREE_ENTRIES} entradas");
        }
        let path = item
            .path()
            .with_context(|| format!("caminho inválido em {what}"))?
            .into_owned();
        validate_relative(&path, what)?;
        if policy == TreePolicy::Overlay && !overlay_path_allowed(&path) {
            bail!(
                "overlay da mídia só pode escrever em /etc, /root, /home ou /srv: /{}",
                path.display()
            );
        }
        let mode = item.header().mode()?;
        if mode > 0o7777 {
            bail!("{what} contém modo inválido em {}", path.display());
        }
        let entry_type = item.header().entry_type();
        let kind = if entry_type == tar::EntryType::Directory {
            if item.size() != 0 {
                bail!("diretório com conteúdo em {what}: {}", path.display());
            }
            DecodedKind::Directory
        } else if entry_type == tar::EntryType::Regular {
            let limit = tree::max_tree_bytes(policy);
            let remaining = limit.saturating_sub(content_bytes);
            let declared_size = item.size();
            if declared_size > remaining {
                bail!("{what} excede {} MiB", limit / 1024 / 1024);
            }
            let mut content = Vec::with_capacity(declared_size as usize);
            (&mut item).take(remaining + 1).read_to_end(&mut content)?;
            if content.len() as u64 != declared_size || content.len() as u64 > remaining {
                bail!(
                    "conteúdo truncado ou excessivo em {what}: {}",
                    path.display()
                );
            }
            content_bytes += content.len() as u64;
            DecodedKind::Regular(content)
        } else if entry_type == tar::EntryType::Symlink {
            if item.size() != 0 {
                bail!("symlink com conteúdo em {what}: {}", path.display());
            }
            let target = item
                .link_name()?
                .ok_or_else(|| anyhow::anyhow!("symlink sem alvo em {what}"))?
                .into_owned();
            validate_symlink(&path, &target, policy)?;
            DecodedKind::Symlink(target)
        } else {
            bail!("{what} contém tipo TAR não permitido em {}", path.display());
        };
        let is_directory = matches!(kind, DecodedKind::Directory);
        if paths.insert(path.clone(), is_directory).is_some() {
            bail!("{what} repete o caminho {}", path.display());
        }
        decoded.push(DecodedEntry { path, mode, kind });
    }

    for path in paths.keys() {
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor.filter(|parent| !parent.as_os_str().is_empty()) {
            if paths.get(parent).is_some_and(|is_directory| !is_directory) {
                bail!(
                    "{what} põe uma entrada sob ancestral que não é diretório: {}",
                    path.display()
                );
            }
            ancestor = parent.parent();
        }
    }
    Ok(decoded)
}

fn materialize_archive(
    bytes: &[u8],
    destination: &Path,
    policy: TreePolicy,
    what: &str,
) -> Result<()> {
    let mut entries = decode_archive(bytes, policy, what)?;
    fs::create_dir(destination)?;
    entries.sort_by(|left, right| {
        left.path
            .components()
            .count()
            .cmp(&right.path.components().count())
            .then_with(|| {
                left.path
                    .as_os_str()
                    .as_bytes()
                    .cmp(right.path.as_os_str().as_bytes())
            })
    });

    for entry in entries
        .iter()
        .filter(|entry| matches!(entry.kind, DecodedKind::Directory))
    {
        let path = destination.join(&entry.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                crate::ensure_real_dir(&path, "diretório extraído")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    for entry in entries
        .iter()
        .filter(|entry| matches!(entry.kind, DecodedKind::Regular(_)))
    {
        let path = destination.join(&entry.path);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent)?;
        crate::ensure_real_dir(parent, "pai de arquivo extraído")?;
        let DecodedKind::Regular(content) = &entry.kind else {
            unreachable!()
        };
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        output.write_all(content)?;
        output.set_permissions(fs::Permissions::from_mode(entry.mode))?;
    }
    for entry in entries
        .iter()
        .filter(|entry| matches!(entry.kind, DecodedKind::Symlink(_)))
    {
        let path = destination.join(&entry.path);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent)?;
        crate::ensure_real_dir(parent, "pai de symlink extraído")?;
        let DecodedKind::Symlink(target) = &entry.kind else {
            unreachable!()
        };
        symlink(target, path)?;
    }
    for entry in entries
        .iter()
        .rev()
        .filter(|entry| matches!(entry.kind, DecodedKind::Directory))
    {
        fs::set_permissions(
            destination.join(&entry.path),
            fs::Permissions::from_mode(entry.mode),
        )?;
    }
    Ok(())
}

fn write_temporary(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn resolved_from_media(snapshot: &MediaSnapshot, workspace: &Path) -> Result<ResolvedProfile> {
    let profile_dir = workspace.join("profile");
    let newspeak_dir = workspace.join("newspeak");
    let overlay_dir = profile_dir.join("overlay");
    let cache_dir = workspace.join("cache");
    fs::create_dir(&profile_dir)?;
    write_temporary(&profile_dir.join("profile"), &snapshot.profile)?;
    write_temporary(&profile_dir.join("target.world"), &snapshot.target_world)?;
    write_temporary(&profile_dir.join("live.world"), &snapshot.live_world)?;
    write_temporary(&profile_dir.join("cache.world"), &snapshot.cache_world)?;
    materialize_archive(
        &snapshot.newspeak,
        &newspeak_dir,
        TreePolicy::Newspeak,
        "newspeak.tar",
    )?;
    materialize_archive(
        &snapshot.overlay,
        &overlay_dir,
        TreePolicy::Overlay,
        "overlay.tar",
    )?;
    if let Some(cache) = &snapshot.cache {
        materialize_archive(cache, &cache_dir, TreePolicy::Cache, "cache.tar")?;
    }

    let mut profile = ResolvedProfile::load(
        &profile_dir,
        ProfileOverrides {
            newspeak: Some(newspeak_dir),
            cache: snapshot.cache.as_ref().map(|_| cache_dir),
            ..Default::default()
        },
    )?;
    if canonical_profile(&profile) != snapshot.profile {
        bail!("profile da mídia não está na representação canônica");
    }
    if normalize_world(&profile.target_world_path)?.as_bytes() != snapshot.target_world
        || normalize_world(&profile.live_world_path)?.as_bytes() != snapshot.live_world
        || profile
            .cache_world_path
            .as_deref()
            .map(normalize_world)
            .transpose()?
            .unwrap_or_default()
            .as_bytes()
            != snapshot.cache_world
    {
        bail!("world da mídia não está normalizado canonicamente");
    }
    profile.customized = snapshot.lock_fields["PROFILE_CLASS"] == "custom";
    let artifacts = profile.artifacts()?;
    if snapshot.mode == DeclaredMode::Online {
        tree::validate_channel_bootstrap(&artifacts.cache_entries)?;
    }
    if artifacts.lock.as_bytes() != snapshot.lock {
        bail!("payload extraído não reproduz profile.lock byte a byte");
    }
    let expected_media_class = if artifacts.class == "official-inputs"
        && profile.official_boot_efi_sha256.as_deref() == Some(snapshot.boot_hash.as_str())
    {
        "official-inputs"
    } else if artifacts.class == "development" {
        "development"
    } else {
        "custom"
    };
    for (field, expected) in [
        ("PROFILE_NAME", profile.name.as_str()),
        ("PROFILE_CLASS", artifacts.class.as_str()),
        ("MEDIA_CLASS", expected_media_class),
        ("PROFILE_LOCK_SHA256", artifacts.lock_hash.as_str()),
        ("ARCH", profile.arch.as_str()),
    ] {
        if snapshot.metadata[field] != expected {
            bail!("media.meta diverge do payload resolvido em {field}");
        }
    }
    Ok(profile)
}

pub fn install_media(options: &MediaInstallOptions) -> Result<()> {
    let snapshot = load_media(&options.source)?;
    if options.offline && snapshot.mode == DeclaredMode::Online {
        bail!("--offline não pode usar uma mídia declarada MODE=online sem cache");
    }
    let workspace = tempfile::Builder::new()
        .prefix("minipax-media-")
        .tempdir()?;
    let profile = resolved_from_media(&snapshot, workspace.path())?;
    let exported = if let Some(destination) = &options.export_boot_efi {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(destination)
            .with_context(|| {
                format!(
                    "não reservei a exportação de BOOTX64.EFI em {}",
                    destination.display()
                )
            })?;
        let result = (|| -> Result<()> {
            output.write_all(&snapshot.boot)?;
            output.flush()?;
            output.set_permissions(fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(destination);
        }
        result?;
        Some(destination)
    } else {
        None
    };

    let installed = install::install(
        &profile,
        &InstallOptions {
            target: options.target.clone(),
            minitrue: options.minitrue.clone(),
            offline: snapshot.mode == DeclaredMode::Offline,
            from_source: options.from_source,
            only_binary: options.only_binary,
            resume: options.resume,
        },
    );
    if installed.is_err() {
        if let Some(destination) = exported {
            let _ = fs::remove_file(destination);
        }
    }
    installed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fixture {
        _temp: tempfile::TempDir,
        source: PathBuf,
        target: PathBuf,
        minitrue: PathBuf,
        calls: PathBuf,
        expected_lock: Vec<u8>,
    }

    fn fake_efi() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x80 + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&10u16.to_le_bytes());
        bytes
    }

    fn media_fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let profile_dir = temp.path().join("input-profile");
        let newspeak = temp.path().join("input-newspeak");
        let source = temp.path().join("media");
        let target = temp.path().join("target");
        fs::create_dir(&profile_dir).unwrap();
        fs::create_dir(&newspeak).unwrap();
        fs::create_dir_all(source.join("distropica")).unwrap();
        fs::create_dir_all(source.join("EFI/BOOT")).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(
            profile_dir.join("profile"),
            "PROFILE_FORMAT=1\nNAME=official\nARCH=x86_64\nSOURCE_DATE_EPOCH=10\nMEDIA_SIZE_MIB=64\nSTATUS=development\n",
        )
        .unwrap();
        fs::write(profile_dir.join("target.world"), "base\n").unwrap();
        fs::write(profile_dir.join("live.world"), "busybox\n").unwrap();
        fs::write(profile_dir.join("cache.world"), "zig\n").unwrap();
        let bootstrap = profile_dir.join("channel-bootstrap");
        fs::create_dir_all(bootstrap.join("channel-config")).unwrap();
        fs::create_dir_all(bootstrap.join("channels/oficial")).unwrap();
        fs::write(
            bootstrap.join("channel-config/oficial"),
            b"URL=https://channel.example.invalid/\nKEY=pinada\nPRIORITY=100\nTRUST=oficial\n",
        )
        .unwrap();
        fs::write(
            bootstrap.join("channels/oficial/index"),
            b"indice assinado\n",
        )
        .unwrap();
        fs::write(
            bootstrap.join("channels/oficial/index.minisig"),
            b"assinatura\n",
        )
        .unwrap();
        let custom_world = temp.path().join("custom.world");
        fs::write(&custom_world, "z\na\n").unwrap();
        for package in ["a", "z"] {
            fs::create_dir(newspeak.join(package)).unwrap();
            fs::write(
                newspeak.join(package).join("recipe"),
                format!("NAME={package}\n"),
            )
            .unwrap();
        }
        let profile = ResolvedProfile::load(
            &profile_dir,
            ProfileOverrides {
                target_world: Some(custom_world),
                newspeak: Some(newspeak),
                ..Default::default()
            },
        )
        .unwrap();
        let artifacts = profile.artifacts().unwrap();
        assert_eq!(artifacts.class, "custom");
        let boot = fake_efi();
        let boot_hash = sha256(&boot);
        let meta = format!(
            "MEDIA_FORMAT=1\nPROFILE_NAME=official\nPROFILE_CLASS=custom\nMEDIA_CLASS=custom\nPROFILE_LOCK_SHA256={}\nARCH=x86_64\nMODE=online\nBOOT_EFI_SHA256={boot_hash}\nMINIPAX_VERSION={}\n",
            artifacts.lock_hash,
            crate::VERSION,
        );
        let payload = source.join("distropica");
        fs::write(payload.join("profile"), canonical_profile(&profile)).unwrap();
        fs::write(payload.join("profile.lock"), artifacts.lock.as_bytes()).unwrap();
        fs::write(
            payload.join("target.world"),
            artifacts.target_world.as_bytes(),
        )
        .unwrap();
        fs::write(payload.join("live.world"), artifacts.live_world.as_bytes()).unwrap();
        fs::write(
            payload.join("cache.world"),
            artifacts.cache_world.as_bytes(),
        )
        .unwrap();
        fs::write(payload.join("overlay.tar"), &artifacts.overlay_tar).unwrap();
        fs::write(payload.join("newspeak.tar"), &artifacts.newspeak_tar).unwrap();
        fs::write(
            payload.join("cache.tar"),
            artifacts.cache_tar.as_ref().unwrap(),
        )
        .unwrap();
        fs::write(payload.join("media.meta"), meta).unwrap();
        fs::write(source.join("EFI/BOOT/BOOTX64.EFI"), &boot).unwrap();

        let calls = temp.path().join("calls");
        let minitrue = temp.path().join("minitrue");
        fs::write(
            &minitrue,
            format!(
                "#!/bin/sh\n[ -f \"$2/var/cache/minitrue/channel-config/oficial\" ] || exit 90\nprintf '%s\\n' \"$*\" >> '{}'\nexit 0\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&minitrue, fs::Permissions::from_mode(0o755)).unwrap();
        Fixture {
            _temp: temp,
            source,
            target,
            minitrue,
            calls,
            expected_lock: artifacts.lock.into_bytes(),
        }
    }

    #[test]
    fn instala_payload_validado_e_preserva_classe_custom() {
        let fixture = media_fixture();
        let exported_efi = fixture._temp.path().join("exported-BOOTX64.EFI");
        install_media(&MediaInstallOptions {
            source: fixture.source,
            target: fixture.target.clone(),
            minitrue: Some(fixture.minitrue),
            offline: false,
            from_source: false,
            only_binary: true,
            resume: false,
            export_boot_efi: Some(exported_efi.clone()),
        })
        .unwrap();
        assert_eq!(
            fs::read(fixture.target.join("var/lib/minipax/profile.lock")).unwrap(),
            fixture.expected_lock
        );
        let calls = fs::read_to_string(fixture.calls).unwrap();
        assert!(calls.contains("--only-binary rectify a z"));
        assert!(fixture
            .target
            .join("var/cache/minitrue/channel-config/oficial")
            .is_file());
        assert_eq!(fs::read(&exported_efi).unwrap(), fake_efi());
        assert_eq!(
            fs::metadata(exported_efi).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn adulteracao_falha_antes_de_tocar_no_target() {
        let fixture = media_fixture();
        fs::write(
            fixture.source.join("distropica/target.world"),
            "adulterado\n",
        )
        .unwrap();
        assert!(install_media(&MediaInstallOptions {
            source: fixture.source,
            target: fixture.target.clone(),
            minitrue: Some(fixture.minitrue),
            offline: false,
            from_source: false,
            only_binary: false,
            resume: false,
            export_boot_efi: None,
        })
        .is_err());
        assert!(fs::read_dir(fixture.target).unwrap().next().is_none());
    }

    #[test]
    fn adulteracao_de_cache_world_falha_antes_de_tocar_no_target() {
        let fixture = media_fixture();
        fs::write(fixture.source.join("distropica/cache.world"), "outro\n").unwrap();
        assert!(install_media(&MediaInstallOptions {
            source: fixture.source,
            target: fixture.target.clone(),
            minitrue: Some(fixture.minitrue),
            offline: false,
            from_source: false,
            only_binary: false,
            resume: false,
            export_boot_efi: None,
        })
        .is_err());
        assert!(fs::read_dir(fixture.target).unwrap().next().is_none());
    }

    #[test]
    fn export_efi_invalido_falha_antes_de_instalar_o_target() {
        let fixture = media_fixture();
        let export = fixture._temp.path().join("ja-existe.EFI");
        fs::write(&export, b"NAO-SOBRESCREVER").unwrap();
        assert!(install_media(&MediaInstallOptions {
            source: fixture.source,
            target: fixture.target.clone(),
            minitrue: Some(fixture.minitrue),
            offline: false,
            from_source: false,
            only_binary: true,
            resume: false,
            export_boot_efi: Some(export.clone()),
        })
        .is_err());
        assert_eq!(fs::read(export).unwrap(), b"NAO-SOBRESCREVER");
        assert!(fs::read_dir(fixture.target).unwrap().next().is_none());
        assert!(!fixture.calls.exists());
    }

    #[test]
    fn efi_autoconsistente_mas_nao_executavel_falha_antes_do_target() {
        let fixture = media_fixture();
        let invalid = b"nao-e-pe-coff";
        fs::write(fixture.source.join("EFI/BOOT/BOOTX64.EFI"), invalid).unwrap();
        let metadata_path = fixture.source.join("distropica/media.meta");
        let metadata = fs::read_to_string(&metadata_path).unwrap();
        let old_hash = metadata
            .lines()
            .find_map(|line| line.strip_prefix("BOOT_EFI_SHA256="))
            .unwrap();
        fs::write(metadata_path, metadata.replace(old_hash, &sha256(invalid))).unwrap();

        assert!(install_media(&MediaInstallOptions {
            source: fixture.source,
            target: fixture.target.clone(),
            minitrue: Some(fixture.minitrue),
            offline: false,
            from_source: false,
            only_binary: false,
            resume: false,
            export_boot_efi: None,
        })
        .is_err());
        assert!(fs::read_dir(fixture.target).unwrap().next().is_none());
    }

    fn hostile_tar(path: &[u8], target: Option<&str>) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.as_mut_bytes()[..path.len()].copy_from_slice(path);
            header.set_mode(0o755);
            if let Some(target) = target {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_link_name(target).unwrap();
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            } else {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(1);
                header.set_cksum();
                builder.append(&header, Cursor::new(b"x")).unwrap();
            }
            builder.finish().unwrap();
        }
        bytes
    }

    #[test]
    fn extrator_recusa_traversal_e_symlink_que_escapa() {
        let traversal = hostile_tar(b"../escape", None);
        assert!(decode_archive(&traversal, TreePolicy::Cache, "hostil.tar").is_err());

        let symlink = hostile_tar(b"etc/a/link", Some("../../../usr/bin"));
        assert!(decode_archive(&symlink, TreePolicy::Overlay, "hostil.tar").is_err());
    }
}
