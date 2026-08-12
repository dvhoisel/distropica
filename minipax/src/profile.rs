use crate::tree::{self, Entry, TreePolicy};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const PROFILE_LOCK_FORMAT: &str = "4";
const MAX_PROFILE_FILE: u64 = 1024 * 1024;
/// O PLAN_LOCK cresce com a closure: 175 receitas produzem NODE/EDGE/ARTIFACT
/// e as tabelas de ABI. O teto é folgado para a árvore atual e ainda impede que
/// um arquivo arbitrário entre no perfil como se fosse um plano.
const MAX_PLAN_LOCK_FILE: u64 = 8 * 1024 * 1024;
const MAX_NEWSPEAK_ORIGIN_FILE: u64 = 16 * 1024;

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
    /// Snapshot pequeno e versionado que leva endpoint, chave pinada e o
    /// índice assinado usado como semente. É deliberadamente separado do
    /// cache offline: `--cache` não pode mais fazê-lo desaparecer da mídia.
    pub channel_bootstrap_path: Option<PathBuf>,
    /// A resolução que o Minitrue congelou para esta mídia
    /// (`minitrue plan --media`). O perfil a PRENDE; quem a produz e a valida
    /// semanticamente é o Minitrue.
    pub plan_lock_path: Option<PathBuf>,
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
    pub channel_bootstrap_entries: Vec<Entry>,
    pub channel_bootstrap_tar: Option<Vec<u8>>,
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

    pub fn is_empty(&self) -> bool {
        self.len == 0
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

/// Valida o bootstrap completo da 0.13 sem ampliar o formato do cache de
/// pacotes. `tree` continua responsável pelo layout do canal; este módulo
/// acrescenta a origem da árvore gerida, que também precisa sobreviver no alvo.
pub(crate) fn validate_channel_bootstrap(entries: &[Entry]) -> Result<()> {
    let origin_path = Path::new("newspeak-origem");
    let mut channel_entries = Vec::with_capacity(entries.len());
    let mut origin = None;
    for entry in entries {
        if entry.relative != origin_path {
            channel_entries.push(entry.clone());
            continue;
        }
        let bytes = match &entry.kind {
            tree::EntryKind::Regular(bytes) => bytes.clone(),
            tree::EntryKind::RegularAt { source, len } => {
                if *len > MAX_NEWSPEAK_ORIGIN_FILE {
                    bail!("newspeak-origem excede {MAX_NEWSPEAK_ORIGIN_FILE} bytes");
                }
                read_small_regular(source, "newspeak-origem")?
            }
            _ => bail!("newspeak-origem precisa ser arquivo regular"),
        };
        if bytes.len() as u64 > MAX_NEWSPEAK_ORIGIN_FILE {
            bail!("newspeak-origem excede {MAX_NEWSPEAK_ORIGIN_FILE} bytes");
        }
        origin = Some(bytes);
    }
    tree::validate_channel_bootstrap(&channel_entries)?;

    let bytes = origin.ok_or_else(|| {
        anyhow::anyhow!("bootstrap de canal não contém newspeak-origem com URL e chave pinada")
    })?;
    let text = std::str::from_utf8(&bytes).context("newspeak-origem não é UTF-8")?;
    let mut url = None;
    let mut key = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once('=') {
            Some(("URL", value)) if !value.trim().is_empty() => url = Some(value.trim()),
            Some(("KEY", value)) if !value.trim().is_empty() => key = Some(value.trim()),
            _ => {}
        }
    }
    let url = url.ok_or_else(|| anyhow::anyhow!("newspeak-origem não contém URL="))?;
    if !url.starts_with("https://") {
        bail!("newspeak-origem exige URL HTTPS");
    }
    if key.is_none() {
        bail!("newspeak-origem não contém KEY=");
    }
    Ok(())
}

fn read_small_regular(path: &Path, what: &str) -> Result<Vec<u8>> {
    crate::ensure_real_file(path, what)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_PROFILE_FILE {
        bail!("{what} excede {MAX_PROFILE_FILE} bytes: {}", path.display());
    }
    fs::read(path).with_context(|| format!("não li {what} {}", path.display()))
}

/// Confere que este PLAN_LOCK é a resolução DESTE perfil.
///
/// O `profile.lock` prendia os worlds — que são as RAÍZES — e nunca a
/// resolução. Duas resoluções diferentes dos mesmos worlds (outra seleção de
/// canal, outro resultado de ABI) produziam exatamente o mesmo lock de perfil,
/// então ele não identificava o que seria de fato instalado.
///
/// A AUTORIDADE SEMÂNTICA DO FORMATO É DO MINITRUE, que valida NODE, EDGE,
/// ARTIFACT, ABI e a proveniência inteira. Aqui se confere apenas o VÍNCULO:
/// que o plano é de mídia, estrito, desta arquitetura, e que suas raízes são
/// exatamente estes worlds. Prender só o hash não bastaria — um plano de outro
/// perfil prenderia igual, e o lock voltaria a não dizer nada sobre o que será
/// instalado.
fn validate_plan_lock(
    bytes: &[u8],
    arch: &str,
    target_world: &str,
    cache_world: &str,
) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("plan.lock não é UTF-8")?;
    if text.contains('\r') {
        bail!("plan.lock contém CR não canônico");
    }
    if !text.ends_with('\n') {
        bail!("plan.lock não termina em nova linha");
    }
    let mut cabecalho = BTreeMap::new();
    let mut raizes = BTreeSet::new();
    for line in text.lines() {
        if let Some(campos) = line.strip_prefix("ROOT\t") {
            let (papel, nome) = campos
                .split_once('\t')
                .ok_or_else(|| anyhow::anyhow!("plan.lock tem ROOT sem papel e pacote"))?;
            if !matches!(papel, "install" | "availability") {
                bail!("plan.lock tem ROOT com papel desconhecido: {papel:?}");
            }
            // Nomes de pacote válidos não sofrem escape na serialização do
            // Minitrue, então comparar cru é suficiente: um nome escapado
            // simplesmente não casa com nenhum world e a conferência recusa.
            if !raizes.insert((papel.to_string(), nome.to_string())) {
                bail!("plan.lock repete a raiz {nome}");
            }
            continue;
        }
        if line.contains('\t') {
            continue;
        }
        if let Some((chave, valor)) = line.split_once('=') {
            cabecalho.insert(chave.to_string(), valor.to_string());
        }
    }
    let exigido = |chave: &str, esperado: &str| -> Result<()> {
        match cabecalho.get(chave) {
            Some(valor) if valor == esperado => Ok(()),
            Some(valor) => bail!("plan.lock tem {chave}={valor}; o perfil exige {esperado}"),
            None => bail!("plan.lock não declara {chave}"),
        }
    };
    exigido("PLAN_LOCK_FORMAT", "1")?;
    exigido("ARCH", arch)?;
    // Um plano de rectify ou de sync descreve a convergência de uma máquina, e
    // não a composição de uma mídia; em ABI development ele aceitaria pendência
    // e deixaria de descrever o que o alvo vai encontrar.
    exigido("PURPOSE", "media")?;
    exigido("ABI_POLICY", "strict")?;

    let mut esperadas = BTreeSet::new();
    for (world, papel) in [(target_world, "install"), (cache_world, "availability")] {
        for nome in world.lines().filter(|line| !line.is_empty()) {
            esperadas.insert((papel.to_string(), nome.to_string()));
        }
    }
    if raizes != esperadas {
        let faltando: Vec<String> = esperadas
            .difference(&raizes)
            .map(|(papel, nome)| format!("{nome}({papel})"))
            .collect();
        let sobrando: Vec<String> = raizes
            .difference(&esperadas)
            .map(|(papel, nome)| format!("{nome}({papel})"))
            .collect();
        bail!(
            "plan.lock não resolve os worlds deste perfil; faltando: [{}]; sobrando: [{}]",
            faltando.join(" "),
            sobrando.join(" ")
        );
    }
    Ok(())
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
        let customized = overrides.target_world.is_some()
            || overrides.live_world.is_some()
            || overrides.overlay.is_some();
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
        // Cache de pacotes e bootstrap de canal têm ciclos de vida distintos.
        // O primeiro pode ser um override grande e efêmero de uma composição
        // offline; o segundo é parte versionada do perfil e precisa sobreviver
        // ao override para ser instalado no alvo depois que o cache for usado.
        let cache_path = overrides.cache;
        let channel_bootstrap_path = directory
            .join("channel-bootstrap")
            .is_dir()
            .then(|| directory.join("channel-bootstrap"));
        let plan_lock_path = directory
            .join("plan.lock")
            .is_file()
            .then(|| directory.join("plan.lock"));
        crate::ensure_real_file(&target_world_path, "target.world")?;
        crate::ensure_real_file(&live_world_path, "live.world")?;
        crate::ensure_real_dir(&newspeak_path, "árvore newspeak")?;
        if let Some(path) = &overlay_path {
            crate::ensure_real_dir(path, "overlay")?;
        }
        if let Some(path) = &cache_path {
            crate::ensure_real_dir(path, "cache")?;
        }
        if let Some(path) = &channel_bootstrap_path {
            crate::ensure_real_dir(path, "channel-bootstrap")?;
        }
        if let Some(path) = &plan_lock_path {
            crate::ensure_real_file(path, "plan.lock")?;
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
            channel_bootstrap_path,
            plan_lock_path,
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
        let (channel_bootstrap_entries, channel_bootstrap_tar) = match &self.channel_bootstrap_path
        {
            Some(path) => {
                let (entries, archive) = tree::snapshot(path, TreePolicy::Cache, self.epoch)?;
                validate_channel_bootstrap(&entries)?;
                (entries, Some(archive))
            }
            None => (Vec::new(), None),
        };
        let (cache_entries, cache_tar) = match &self.cache_path {
            Some(path) => {
                // Streaming: `collect` devolve os arquivos regulares do cache
                // por REFERÊNCIA, e `pack_into` os copia direto para o
                // temporário enquanto o hash se forma. Em nenhum momento o
                // payload inteiro existe na memória.
                let entries = tree::collect(path, TreePolicy::Cache)?;
                // O temporário nasce AO LADO do cache, e não no TMPDIR, e isso
                // não é detalhe: no instalador vivo o TMPDIR é tmpfs, ou seja
                // MEMÓRIA. Empacotar 664 MiB de cache para lá enquanto 2 GiB
                // de escrita estão pendentes numa máquina de 4 GiB sem swap
                // não trava — deixa o sistema em pressão de memória, e a
                // instalação parece congelada logo depois do último `verify`.
                //
                // O cache já vive no disco de destino (o `install-media` cria
                // seu espaço de trabalho dentro do `--target`), então o irmão
                // dele está no mesmo sistema de arquivos e no lugar certo.
                let scratch = path.parent().unwrap_or(path.as_path());
                let mut sink = HashingWriter {
                    inner: std::io::BufWriter::new(tempfile::NamedTempFile::new_in(scratch)?),
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
        let channel_bootstrap_hash = channel_bootstrap_tar
            .as_deref()
            .map(sha256)
            .unwrap_or_else(|| "-".into());
        // A validação acontece ANTES de o hash entrar no lock: prender um plano
        // que não resolve estes worlds seria pior que não prender nenhum,
        // porque daria a aparência de vínculo.
        let plan_lock_hash = match &self.plan_lock_path {
            Some(path) => {
                crate::ensure_real_file(path, "plan.lock")?;
                let metadata = fs::metadata(path)?;
                if metadata.len() > MAX_PLAN_LOCK_FILE {
                    bail!(
                        "plan.lock excede {MAX_PLAN_LOCK_FILE} bytes: {}",
                        path.display()
                    );
                }
                let bytes = fs::read(path)
                    .with_context(|| format!("não li plan.lock {}", path.display()))?;
                validate_plan_lock(&bytes, &self.arch, &target_world, &cache_world)?;
                sha256(&bytes)
            }
            None => "-".into(),
        };
        let content = format!(
            "PROFILE_CONTENT_FORMAT=4\nPROFILE_NAME={}\nARCH={}\nSOURCE_DATE_EPOCH={}\nMEDIA_SIZE_MIB={}\nINSTALL_READY={}\nTARGET_WORLD_SHA256={target_world_hash}\nLIVE_WORLD_SHA256={live_world_hash}\nCACHE_WORLD_SHA256={cache_world_hash}\nOVERLAY_SHA256={overlay_hash}\nNEWSPEAK_SHA256={newspeak_hash}\nCACHE_SHA256={cache_hash}\nCHANNEL_BOOTSTRAP_SHA256={channel_bootstrap_hash}\nPLAN_LOCK_SHA256={plan_lock_hash}\n",
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
            "PROFILE_LOCK_FORMAT={PROFILE_LOCK_FORMAT}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nPROFILE_CONTENT_SHA256={}\nOFFICIAL_CONTENT_SHA256={}\nARCH={}\nSOURCE_DATE_EPOCH={}\nMEDIA_SIZE_MIB={}\nINSTALL_READY={}\nOFFICIAL_BOOT_EFI_SHA256={}\nOFFICIAL_MINITRUE_SHA256={}\nTARGET_WORLD_SHA256={}\nLIVE_WORLD_SHA256={}\nCACHE_WORLD_SHA256={}\nOVERLAY_SHA256={}\nNEWSPEAK_SHA256={}\nCACHE_SHA256={}\nCHANNEL_BOOTSTRAP_SHA256={}\nPLAN_LOCK_SHA256={}\n",
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
            channel_bootstrap_hash,
            plan_lock_hash,
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
            channel_bootstrap_entries,
            channel_bootstrap_tar,
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

    /// Um PLAN_LOCK plausível para a fixture: `target.world` tem `a` e `z`.
    /// Só os campos que o perfil confere precisam ser fiéis; o resto do formato
    /// é competência do Minitrue.
    fn plano_de_midia(cabecalho: &[(&str, &str)], raizes: &[(&str, &str)]) -> Vec<u8> {
        let mut texto = String::new();
        for (chave, valor) in cabecalho {
            texto.push_str(&format!("{chave}={valor}\n"));
        }
        for (papel, nome) in raizes {
            texto.push_str(&format!("ROOT\t{papel}\t{nome}\n"));
        }
        texto.push_str("NODE\ta\t1\tsource\tB\tkeep\tfonte\n");
        texto.into_bytes()
    }

    fn cabecalho_de_midia() -> Vec<(&'static str, &'static str)> {
        vec![
            ("PLAN_LOCK_FORMAT", "1"),
            ("TREE_SHA256", "00"),
            ("ARCH", "x86_64"),
            ("PURPOSE", "media"),
            ("BINARY_POLICY", "binary-only"),
            ("ABI_POLICY", "strict"),
            ("ROOT_COUNT", "2"),
        ]
    }

    #[test]
    fn plano_resolvido_entra_no_lock_e_o_perfil_sem_plano_nao_mente() {
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
        // Sem plano o campo existe e diz "-": ausência declarada, não campo
        // faltando que um leitor antigo interpretaria como qualquer coisa.
        let sem_plano = load();
        assert!(sem_plano.plan_lock_path.is_none());
        assert!(sem_plano.lock().unwrap().contains("PLAN_LOCK_SHA256=-\n"));

        let plano = plano_de_midia(&cabecalho_de_midia(), &[("install", "a"), ("install", "z")]);
        fs::write(temp.path().join("plan.lock"), &plano).unwrap();
        let com_plano = load().lock().unwrap();
        assert!(com_plano.contains(&format!("PLAN_LOCK_SHA256={}\n", sha256(&plano))));
        assert!(com_plano.contains("PROFILE_LOCK_FORMAT=4\n"));

        // Resolver de novo e obter outro plano precisa mudar o lock do perfil:
        // é exatamente a diferença que o lock antigo não enxergava.
        let outro = plano_de_midia(&cabecalho_de_midia(), &[("install", "a"), ("install", "z")]);
        let mut outro = outro;
        outro.extend_from_slice(b"NODE\tz\t2\tsource\tB\tkeep\tfonte\n");
        fs::write(temp.path().join("plan.lock"), &outro).unwrap();
        assert_ne!(com_plano, load().lock().unwrap());
    }

    #[test]
    fn plano_de_outro_perfil_ou_de_outro_proposito_nao_prende() {
        let temp = fixture();
        fs::write(temp.path().join("cache.world"), "zig\n").unwrap();
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
        let escreve = |bytes: &[u8]| fs::write(temp.path().join("plan.lock"), bytes).unwrap();

        // Raízes certas, papéis certos: target instala, cache disponibiliza.
        escreve(&plano_de_midia(
            &cabecalho_de_midia(),
            &[("install", "a"), ("install", "z"), ("availability", "zig")],
        ));
        assert!(load().artifacts().is_ok());

        // Faltando uma raiz do target.world.
        escreve(&plano_de_midia(
            &cabecalho_de_midia(),
            &[("install", "a"), ("availability", "zig")],
        ));
        assert!(load().artifacts().is_err());

        // Raiz estrangeira que este perfil não pediu.
        escreve(&plano_de_midia(
            &cabecalho_de_midia(),
            &[
                ("install", "a"),
                ("install", "z"),
                ("install", "gimp"),
                ("availability", "zig"),
            ],
        ));
        assert!(load().artifacts().is_err());

        // Papel trocado: instalar o que era só para estar disponível muda o que
        // a mídia entrega, e o conjunto de nomes sozinho não acusaria.
        escreve(&plano_de_midia(
            &cabecalho_de_midia(),
            &[("install", "a"), ("install", "z"), ("install", "zig")],
        ));
        assert!(load().artifacts().is_err());

        let certas = [("install", "a"), ("install", "z"), ("availability", "zig")];
        for (chave, valor) in [
            ("PURPOSE", "rectify"),
            ("ABI_POLICY", "development"),
            ("ARCH", "aarch64"),
            ("PLAN_LOCK_FORMAT", "2"),
        ] {
            let cabecalho: Vec<(&str, &str)> = cabecalho_de_midia()
                .into_iter()
                .map(|(k, v)| if k == chave { (k, valor) } else { (k, v) })
                .collect();
            escreve(&plano_de_midia(&cabecalho, &certas));
            assert!(
                load().artifacts().is_err(),
                "{chave}={valor} não podia ser aceito"
            );
        }
    }

    #[test]
    fn bootstrap_de_canal_versionado_entra_no_lock_do_perfil() {
        let temp = fixture();
        let bootstrap = temp.path().join("channel-bootstrap");
        fs::create_dir_all(bootstrap.join("channel-config")).unwrap();
        fs::create_dir_all(bootstrap.join("channels/oficial")).unwrap();
        fs::write(
            bootstrap.join("newspeak-origem"),
            b"URL=https://example.invalid/newspeak/\nKEY=pinada\n",
        )
        .unwrap();
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
        assert!(profile.cache_path.is_none());
        assert_eq!(
            profile.channel_bootstrap_path.as_deref(),
            Some(bootstrap.as_path())
        );
        let first = profile.lock().unwrap();
        assert!(first.contains("CACHE_SHA256=-\n"));
        assert!(!first.contains("CHANNEL_BOOTSTRAP_SHA256=-\n"));

        fs::write(bootstrap.join("channels/oficial/index"), b"index-b\n").unwrap();
        assert_ne!(first, load().lock().unwrap());

        fs::remove_file(bootstrap.join("newspeak-origem")).unwrap();
        assert!(load().artifacts().is_err());
    }

    #[test]
    fn cache_offline_nao_substitui_bootstrap_versionado() {
        let temp = fixture();
        let bootstrap = temp.path().join("channel-bootstrap");
        fs::create_dir_all(bootstrap.join("channel-config")).unwrap();
        fs::create_dir_all(bootstrap.join("channels/oficial")).unwrap();
        fs::write(
            bootstrap.join("newspeak-origem"),
            b"URL=https://example.invalid/newspeak/\nKEY=pinada\n",
        )
        .unwrap();
        fs::write(bootstrap.join("channel-config/oficial"), b"config\n").unwrap();
        fs::write(bootstrap.join("channels/oficial/index"), b"index\n").unwrap();
        fs::write(
            bootstrap.join("channels/oficial/index.minisig"),
            b"assinatura\n",
        )
        .unwrap();
        let cache = temp.path().join("cache-offline");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("objeto"), b"payload").unwrap();

        let profile = ResolvedProfile::load(
            temp.path(),
            ProfileOverrides {
                newspeak: Some(temp.path().join("newspeak")),
                cache: Some(cache.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(profile.cache_path.as_deref(), Some(cache.as_path()));
        assert_eq!(
            profile.channel_bootstrap_path.as_deref(),
            Some(bootstrap.as_path())
        );
        let artifacts = profile.artifacts().unwrap();
        assert!(!artifacts.cache_entries.is_empty());
        assert!(!artifacts.channel_bootstrap_entries.is_empty());
        assert!(!artifacts.lock.contains("CACHE_SHA256=-\n"));
        assert!(!artifacts.lock.contains("CHANNEL_BOOTSTRAP_SHA256=-\n"));
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
    fn cache_pinado_pode_ser_oficial_e_qualquer_byte_divergente_rebaixa() {
        let temp = fixture();
        let cache = temp.path().join("cache");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("objeto"), b"bytes pinados").unwrap();
        let overrides = || ProfileOverrides {
            newspeak: Some(temp.path().join("newspeak")),
            cache: Some(cache.clone()),
            ..Default::default()
        };

        let development = ResolvedProfile::load(temp.path(), overrides()).unwrap();
        let lock = development.lock().unwrap();
        assert!(!lock.contains("CACHE_SHA256=-\n"));
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
        assert_eq!(release.artifacts().unwrap().class, "official-inputs");

        fs::write(cache.join("objeto"), b"um byte diferente").unwrap();
        assert_eq!(
            release.artifacts().unwrap().class,
            "custom",
            "CACHE_SHA256 divergente altera o conteúdo e precisa rebaixar"
        );
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
