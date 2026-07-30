use crate::tree::{self, Entry, TreePolicy};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const PROFILE_LOCK_FORMAT: &str = "2";
const MAX_PROFILE_FILE: u64 = 1024 * 1024;

#[derive(Default)]
pub struct ProfileOverrides {
    pub target_world: Option<PathBuf>,
    pub live_world: Option<PathBuf>,
    pub overlay: Option<PathBuf>,
    pub newspeak: Option<PathBuf>,
    pub cache: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileStatus {
    Development,
    Release,
}

#[derive(Debug)]
pub struct ResolvedProfile {
    pub directory: PathBuf,
    pub name: String,
    pub arch: String,
    pub epoch: u64,
    pub media_size_mib: u64,
    pub install_ready: bool,
    pub status: ProfileStatus,
    pub official_content_sha256: Option<String>,
    pub official_boot_efi_sha256: Option<String>,
    pub official_minitrue_sha256: Option<String>,
    pub target_world_path: PathBuf,
    pub live_world_path: PathBuf,
    pub cache_world_path: Option<PathBuf>,
    pub overlay_path: Option<PathBuf>,
    pub newspeak_path: PathBuf,
    pub cache_path: Option<PathBuf>,
    /// `true` somente para o `channel-bootstrap/` autodetectado no perfil.
    /// Ele fecha descoberta online, mas não é um cache offline completo.
    pub cache_is_channel_bootstrap: bool,
    pub customized: bool,
}

pub struct ProfileArtifacts {
    pub target_world: String,
    pub live_world: String,
    pub cache_world: String,
    pub overlay_entries: Vec<Entry>,
    pub overlay_tar: Vec<u8>,
    pub newspeak_entries: Vec<Entry>,
    pub newspeak_tar: Vec<u8>,
    pub cache_entries: Vec<Entry>,
    /// O `cache.tar` mora em DISCO, não em memória: é o único artefato do
    /// perfil que pode ter centenas de MiB. O temporário é apagado quando este
    /// `ProfileArtifacts` morre, o que dá exatamente a vida útil certa — a
    /// composição da mídia acontece com ele vivo, e nada sobra depois.
    pub cache_tar: Option<CacheArchive>,
    pub lock: String,
    pub lock_hash: String,
    pub class: String,
}

/// O `cache.tar` escrito em disco, com o hash já calculado.
///
/// O tar é montado UMA vez, direto no arquivo temporário, e o sha256 sai do
/// mesmo fluxo — não há segunda passada nem segunda cópia. `NamedTempFile`
/// apaga o arquivo no `Drop`, então quem segurar este valor segura o payload.
pub struct CacheArchive {
    file: tempfile::NamedTempFile,
    len: u64,
    hash: String,
}

impl CacheArchive {
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }
}

/// Um `Write` que repassa os bytes adiante e vai somando o sha256 no caminho.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_small_regular(path: &Path, what: &str) -> Result<Vec<u8>> {
    crate::ensure_real_file(path, what)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_PROFILE_FILE {
        bail!("{what} excede {MAX_PROFILE_FILE} bytes: {}", path.display());
    }
    fs::read(path).with_context(|| format!("não li {what} {}", path.display()))
}

fn safe_atom(value: &str, what: &str) -> Result<()> {
    let mut chars = value.chars();
    let first = chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric());
    if !first
        || value.len() > 128
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        bail!("{what} inválido: {value:?}");
    }
    Ok(())
}

fn parse_config(path: &Path) -> Result<BTreeMap<String, String>> {
    let bytes = read_small_regular(path, "profile")?;
    let text = std::str::from_utf8(&bytes).context("profile não é UTF-8")?;
    let allowed = [
        "PROFILE_FORMAT",
        "NAME",
        "ARCH",
        "SOURCE_DATE_EPOCH",
        "MEDIA_SIZE_MIB",
        "INSTALL_READY",
        "STATUS",
        "OFFICIAL_CONTENT_SHA256",
        "OFFICIAL_BOOT_EFI_SHA256",
        "OFFICIAL_MINITRUE_SHA256",
    ];
    let mut fields = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if raw != line {
            bail!("profile contém whitespace externo na linha {}", index + 1);
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("profile linha {} não é KEY=VALUE", index + 1))?;
        if !allowed.contains(&key) {
            bail!("profile contém campo desconhecido {key:?}");
        }
        if key.trim() != key || value.trim() != value || value.is_empty() {
            bail!("profile contém valor não canônico na linha {}", index + 1);
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            bail!("profile repete o campo {key}");
        }
    }
    for required in [
        "PROFILE_FORMAT",
        "NAME",
        "ARCH",
        "SOURCE_DATE_EPOCH",
        "STATUS",
    ] {
        if !fields.contains_key(required) {
            bail!("profile não declara {required}");
        }
    }
    if fields.get("PROFILE_FORMAT").map(String::as_str) != Some("1") {
        bail!("PROFILE_FORMAT desconhecido; esta versão aceita apenas 1");
    }
    Ok(fields)
}

pub fn normalize_world(path: &Path) -> Result<String> {
    let bytes = read_small_regular(path, "world")?;
    let text = std::str::from_utf8(&bytes).context("world não é UTF-8")?;
    let mut names = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let name = raw.split('#').next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        safe_atom(name, "nome de pacote no world")?;
        if !names.insert(name.to_string()) {
            bail!("world repete {name:?} na linha {}", index + 1);
        }
    }
    let mut output = names.into_iter().collect::<Vec<_>>().join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    Ok(output)
}

impl ResolvedProfile {
    pub fn load(directory: &Path, overrides: ProfileOverrides) -> Result<Self> {
        crate::ensure_real_dir(directory, "perfil")?;
        let directory = fs::canonicalize(directory)?;
        let fields = parse_config(&directory.join("profile"))?;
        let name = fields["NAME"].clone();
        safe_atom(&name, "NAME")?;
        let arch = fields["ARCH"].clone();
        if arch != "x86_64" {
            bail!("ARCH={arch:?} ainda não é suportada (somente x86_64)");
        }
        let epoch = fields["SOURCE_DATE_EPOCH"]
            .parse::<u64>()
            .context("SOURCE_DATE_EPOCH não é inteiro")?;
        let media_size_mib = fields
            .get("MEDIA_SIZE_MIB")
            .map(String::as_str)
            .unwrap_or("128")
            .parse::<u64>()
            .context("MEDIA_SIZE_MIB não é inteiro")?;
        if !(64..=65_536).contains(&media_size_mib) {
            bail!("MEDIA_SIZE_MIB precisa ficar entre 64 e 65536");
        }
        let install_ready = match fields.get("INSTALL_READY").map(String::as_str) {
            None | Some("yes") => true,
            Some("no") => false,
            Some(value) => bail!("INSTALL_READY inválido: {value:?} (yes|no)"),
        };
        let status = match fields["STATUS"].as_str() {
            "development" => ProfileStatus::Development,
            "release" => ProfileStatus::Release,
            value => bail!("STATUS inválido: {value:?} (development|release)"),
        };
        let official_content_sha256 = fields.get("OFFICIAL_CONTENT_SHA256").cloned();
        let official_boot_efi_sha256 = fields.get("OFFICIAL_BOOT_EFI_SHA256").cloned();
        let official_minitrue_sha256 = fields.get("OFFICIAL_MINITRUE_SHA256").cloned();
        for (field, hash) in [
            ("OFFICIAL_CONTENT_SHA256", official_content_sha256.as_ref()),
            (
                "OFFICIAL_BOOT_EFI_SHA256",
                official_boot_efi_sha256.as_ref(),
            ),
            (
                "OFFICIAL_MINITRUE_SHA256",
                official_minitrue_sha256.as_ref(),
            ),
        ] {
            let Some(hash) = hash else { continue };
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("{field} precisa ser 64 hex minúsculos");
            }
        }
        if status == ProfileStatus::Release
            && (official_content_sha256.is_none()
                || official_boot_efi_sha256.is_none()
                || official_minitrue_sha256.is_none())
        {
            bail!(
                "STATUS=release exige OFFICIAL_CONTENT_SHA256, OFFICIAL_BOOT_EFI_SHA256 e OFFICIAL_MINITRUE_SHA256 pinados"
            );
        }
        if status == ProfileStatus::Release && !install_ready {
            bail!("STATUS=release exige INSTALL_READY=yes");
        }
        let explicit_cache = overrides.cache.is_some();
        let customized = overrides.target_world.is_some()
            || overrides.live_world.is_some()
            || overrides.overlay.is_some()
            || explicit_cache;
        let target_world_path = overrides
            .target_world
            .unwrap_or_else(|| directory.join("target.world"));
        let live_world_path = overrides
            .live_world
            .unwrap_or_else(|| directory.join("live.world"));
        let cache_world_path = match fs::symlink_metadata(directory.join("cache.world")) {
            Ok(metadata) if metadata.file_type().is_file() => Some(directory.join("cache.world")),
            Ok(_) => bail!("cache.world precisa ser arquivo regular real"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let overlay_path = overrides.overlay.or_else(|| {
            directory
                .join("overlay")
                .is_dir()
                .then(|| directory.join("overlay"))
        });
        let newspeak_path = overrides
            .newspeak
            .or_else(|| std::env::var_os("DISTROPICA_NEWSPEAK").map(PathBuf::from))
            .ok_or_else(|| anyhow::anyhow!("--newspeak ou DISTROPICA_NEWSPEAK é obrigatório"))?;
        // Um perfil pode versionar apenas o bootstrap do canal. Ele usa o
        // mesmo snapshot de cache (e portanto o mesmo CACHE_SHA256 do lock),
        // mas mídias online o restringem estruturalmente a config+índice
        // assinado. `--cache` continua vencendo para builds custom/offline.
        let cache_path = overrides.cache.or_else(|| {
            directory
                .join("channel-bootstrap")
                .is_dir()
                .then(|| directory.join("channel-bootstrap"))
        });
        let cache_is_channel_bootstrap = cache_path.is_some() && !explicit_cache;
        crate::ensure_real_file(&target_world_path, "target.world")?;
        crate::ensure_real_file(&live_world_path, "live.world")?;
        crate::ensure_real_dir(&newspeak_path, "árvore newspeak")?;
        if let Some(path) = &overlay_path {
            crate::ensure_real_dir(path, "overlay")?;
        }
        if let Some(path) = &cache_path {
            crate::ensure_real_dir(path, "cache")?;
        }
        Ok(Self {
            directory,
            name,
            arch,
            epoch,
            media_size_mib,
            install_ready,
            status,
            official_content_sha256,
            official_boot_efi_sha256,
            official_minitrue_sha256,
            target_world_path,
            live_world_path,
            cache_world_path,
            overlay_path,
            newspeak_path,
            cache_path,
            cache_is_channel_bootstrap,
            customized,
        })
    }

    pub fn artifacts(&self) -> Result<ProfileArtifacts> {
        let target_world = normalize_world(&self.target_world_path)?;
        let live_world = normalize_world(&self.live_world_path)?;
        let cache_world = self
            .cache_world_path
            .as_deref()
            .map(normalize_world)
            .transpose()?
            .unwrap_or_default();
        let (overlay_entries, overlay_tar) = match &self.overlay_path {
            Some(path) => tree::snapshot(path, TreePolicy::Overlay, self.epoch)?,
            None => (Vec::new(), tree::pack(&[], self.epoch)?),
        };
        let (newspeak_entries, newspeak_tar) =
            tree::snapshot(&self.newspeak_path, TreePolicy::Newspeak, self.epoch)?;
        let (cache_entries, cache_tar) = match &self.cache_path {
            Some(path) => {
                // Streaming: `collect` devolve os arquivos regulares do cache
                // por REFERÊNCIA, e `pack_into` os copia direto para o
                // temporário enquanto o hash se forma. Em nenhum momento o
                // payload inteiro existe na memória.
                let entries = tree::collect(path, TreePolicy::Cache)?;
                let mut sink = HashingWriter {
                    inner: std::io::BufWriter::new(tempfile::NamedTempFile::new()?),
                    hasher: Sha256::new(),
                    written: 0,
                };
                tree::pack_into(&entries, self.epoch, &mut sink)?;
                let HashingWriter {
                    inner,
                    hasher,
                    written,
                } = sink;
                let file = inner.into_inner().map_err(|error| {
                    anyhow::anyhow!("não terminei de escrever o cache.tar: {error}")
                })?;
                file.as_file().sync_all()?;
                (
                    entries,
                    Some(CacheArchive {
                        file,
                        len: written,
                        hash: hex::encode(hasher.finalize()),
                    }),
                )
            }
            None => (Vec::new(), None),
        };
        let target_world_hash = sha256(target_world.as_bytes());
        let live_world_hash = sha256(live_world.as_bytes());
        let cache_world_hash = sha256(cache_world.as_bytes());
        let overlay_hash = sha256(&overlay_tar);
        let newspeak_hash = sha256(&newspeak_tar);
        let cache_hash = cache_tar
            .as_ref()
            .map(|archive| archive.hash().to_string())
            .unwrap_or_else(|| "-".into());
        let content = format!(
            "PROFILE_CONTENT_FORMAT=2\nPROFILE_NAME={}\nARCH={}\nSOURCE_DATE_EPOCH={}\nMEDIA_SIZE_MIB={}\nINSTALL_READY={}\nTARGET_WORLD_SHA256={target_world_hash}\nLIVE_WORLD_SHA256={live_world_hash}\nCACHE_WORLD_SHA256={cache_world_hash}\nOVERLAY_SHA256={overlay_hash}\nNEWSPEAK_SHA256={newspeak_hash}\nCACHE_SHA256={cache_hash}\n",
            self.name,
            self.arch,
            self.epoch,
            self.media_size_mib,
            if self.install_ready { "yes" } else { "no" },
        );
        let content_hash = sha256(content.as_bytes());
        let class = if self.customized || self.name != "official" {
            "custom"
        } else if self.status == ProfileStatus::Development {
            "development"
        } else if self.official_content_sha256.as_deref() == Some(content_hash.as_str()) {
            "official-inputs"
        } else {
            "custom"
        }
        .to_string();
        let lock = format!(
            "PROFILE_LOCK_FORMAT={PROFILE_LOCK_FORMAT}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nPROFILE_CONTENT_SHA256={}\nOFFICIAL_CONTENT_SHA256={}\nARCH={}\nSOURCE_DATE_EPOCH={}\nMEDIA_SIZE_MIB={}\nINSTALL_READY={}\nOFFICIAL_BOOT_EFI_SHA256={}\nOFFICIAL_MINITRUE_SHA256={}\nTARGET_WORLD_SHA256={}\nLIVE_WORLD_SHA256={}\nCACHE_WORLD_SHA256={}\nOVERLAY_SHA256={}\nNEWSPEAK_SHA256={}\nCACHE_SHA256={}\n",
            self.name,
            class,
            content_hash,
            self.official_content_sha256.as_deref().unwrap_or("-"),
            self.arch,
            self.epoch,
            self.media_size_mib,
            if self.install_ready { "yes" } else { "no" },
            self.official_boot_efi_sha256.as_deref().unwrap_or("-"),
            self.official_minitrue_sha256.as_deref().unwrap_or("-"),
            target_world_hash,
            live_world_hash,
            cache_world_hash,
            overlay_hash,
            newspeak_hash,
            cache_hash,
        );
        let lock_hash = sha256(lock.as_bytes());
        Ok(ProfileArtifacts {
            target_world,
            live_world,
            cache_world,
            overlay_entries,
            overlay_tar,
            newspeak_entries,
            newspeak_tar,
            cache_entries,
            cache_tar,
            lock,
            lock_hash,
            class,
        })
    }

    pub fn lock(&self) -> Result<String> {
        Ok(self.artifacts()?.lock)
    }
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let path = crate::absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("saída sem diretório pai: {}", path.display()))?;
    crate::ensure_real_dir(parent, "diretório de saída")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)
        .with_context(|| {
            format!(
                "não criei {} (saídas nunca são sobrescritas)",
                path.display()
            )
        })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("profile"),
            "PROFILE_FORMAT=1\nNAME=official\nARCH=x86_64\nSOURCE_DATE_EPOCH=10\nSTATUS=development\n",
        )
        .unwrap();
        fs::write(temp.path().join("target.world"), "z\na\n").unwrap();
        fs::write(temp.path().join("live.world"), "busybox\n").unwrap();
        fs::create_dir(temp.path().join("newspeak")).unwrap();
        temp
    }

    #[test]
    fn parser_recusa_duplicata_e_world_normaliza() {
        let temp = fixture();
        assert_eq!(
            normalize_world(&temp.path().join("target.world")).unwrap(),
            "a\nz\n"
        );
        fs::write(temp.path().join("target.world"), "a\na\n").unwrap();
        assert!(normalize_world(&temp.path().join("target.world")).is_err());

        fs::write(
            temp.path().join("profile"),
            "PROFILE_FORMAT=1\nNAME=official\nNAME=x\nARCH=x86_64\nSOURCE_DATE_EPOCH=10\nSTATUS=development\n",
        )
        .unwrap();
        assert!(ResolvedProfile::load(
            temp.path(),
            ProfileOverrides {
                newspeak: Some(temp.path().join("newspeak")),
                ..Default::default()
            }
        )
        .is_err());
    }

    #[test]
    fn cache_world_opcional_normaliza_e_entra_no_lock() {
        let temp = fixture();
        let load = || {
            ResolvedProfile::load(
                temp.path(),
                ProfileOverrides {
                    newspeak: Some(temp.path().join("newspeak")),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let absent = load().artifacts().unwrap();
        assert!(absent.cache_world.is_empty());
        assert!(absent
            .lock
            .contains(&format!("CACHE_WORLD_SHA256={}\n", sha256(b""))));

        fs::write(
            temp.path().join("cache.world"),
            "zig\n# disponível, não instalado\nripgrep\n",
        )
        .unwrap();
        let declared = load().artifacts().unwrap();
        assert_eq!(declared.cache_world, "ripgrep\nzig\n");
        assert_ne!(absent.lock, declared.lock);
        assert!(declared.lock.contains(&format!(
            "CACHE_WORLD_SHA256={}\n",
            sha256(declared.cache_world.as_bytes())
        )));

        fs::write(temp.path().join("cache.world"), "zig\nzig\n").unwrap();
        assert!(load().artifacts().is_err());
    }

    #[test]
    fn override_remove_identidade_oficial() {
        let temp = fixture();
        let custom = temp.path().join("custom.world");
        fs::write(&custom, "a\n").unwrap();
        let profile = ResolvedProfile::load(
            temp.path(),
            ProfileOverrides {
                target_world: Some(custom),
                newspeak: Some(temp.path().join("newspeak")),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(profile.artifacts().unwrap().class, "custom");
    }

    #[test]
    fn bootstrap_de_canal_versionado_entra_no_lock_do_perfil() {
        let temp = fixture();
        let bootstrap = temp.path().join("channel-bootstrap");
        fs::create_dir_all(bootstrap.join("channel-config")).unwrap();
        fs::create_dir_all(bootstrap.join("channels/oficial")).unwrap();
        fs::write(bootstrap.join("channel-config/oficial"), b"config\n").unwrap();
        fs::write(bootstrap.join("channels/oficial/index"), b"index-a\n").unwrap();
        fs::write(
            bootstrap.join("channels/oficial/index.minisig"),
            b"assinatura\n",
        )
        .unwrap();
        let load = || {
            ResolvedProfile::load(
                temp.path(),
                ProfileOverrides {
                    newspeak: Some(temp.path().join("newspeak")),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let profile = load();
        assert_eq!(profile.cache_path.as_deref(), Some(bootstrap.as_path()));
        let first = profile.lock().unwrap();
        assert!(!first.contains("CACHE_SHA256=-\n"));

        fs::write(bootstrap.join("channels/oficial/index"), b"index-b\n").unwrap();
        assert_ne!(first, load().lock().unwrap());
    }

    #[test]
    fn release_so_e_oficial_quando_conteudo_coincide_com_pin() {
        let temp = fixture();
        let overrides = || ProfileOverrides {
            newspeak: Some(temp.path().join("newspeak")),
            ..Default::default()
        };
        let development = ResolvedProfile::load(temp.path(), overrides()).unwrap();
        let lock = development.lock().unwrap();
        let content_hash = lock
            .lines()
            .find_map(|line| line.strip_prefix("PROFILE_CONTENT_SHA256="))
            .unwrap();
        fs::write(
            temp.path().join("profile"),
            format!(
                "PROFILE_FORMAT=1\nNAME=official\nARCH=x86_64\nSOURCE_DATE_EPOCH=10\nSTATUS=release\nOFFICIAL_CONTENT_SHA256={content_hash}\nOFFICIAL_BOOT_EFI_SHA256={}\nOFFICIAL_MINITRUE_SHA256={}\n",
                "0".repeat(64),
                "1".repeat(64),
            ),
        )
        .unwrap();
        let release = ResolvedProfile::load(temp.path(), overrides()).unwrap();
        let release_artifacts = release.artifacts().unwrap();
        assert_eq!(release_artifacts.class, "official-inputs");
        assert!(release_artifacts
            .lock
            .contains(&format!("OFFICIAL_CONTENT_SHA256={content_hash}\n")));

        fs::write(temp.path().join("target.world"), "outro\n").unwrap();
        assert_eq!(release.artifacts().unwrap().class, "custom");
    }

    #[test]
    fn release_recusa_perfil_nao_pronto_para_instalar() {
        let temp = fixture();
        fs::write(
            temp.path().join("profile"),
            format!(
                "PROFILE_FORMAT=1\nNAME=official\nARCH=x86_64\nSOURCE_DATE_EPOCH=10\nINSTALL_READY=no\nSTATUS=release\nOFFICIAL_CONTENT_SHA256={}\nOFFICIAL_BOOT_EFI_SHA256={}\nOFFICIAL_MINITRUE_SHA256={}\n",
                "0".repeat(64),
                "1".repeat(64),
                "2".repeat(64),
            ),
        )
        .unwrap();
        assert!(ResolvedProfile::load(
            temp.path(),
            ProfileOverrides {
                newspeak: Some(temp.path().join("newspeak")),
                ..Default::default()
            },
        )
        .is_err());
    }
}
