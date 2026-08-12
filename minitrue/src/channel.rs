//! Canais binários imutáveis do mundo B (SPEC-0009).
//!
//! A configuração decide em quais chaves confiar. A rede só entrega um índice
//! assinado e objetos presos por SHA-256; a resolução de uma operação produz
//! um lock de conteúdo endereçado por hash.

use crate::recipe::{self, Recipe};
use crate::{fail, Ctx};
use anyhow::{bail, Context, Result};
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

const CHANNEL_INDEX_FORMAT: &str = "4";
const CHANNEL_LOCK_FORMAT: &str = "4";
const ARCH: &str = "x86_64";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_PRODUCER_PLAN_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCK_ENTRIES: usize = 50_000;
static CACHE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trust {
    Oficial,
    Corroborado,
    Builder,
}

impl Trust {
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Oficial => "oficial",
            Trust::Corroborado => "corroborado",
            Trust::Builder => "builder",
        }
    }
}

#[derive(Clone, Debug)]
struct Config {
    name: String,
    url: Url,
    key: String,
    priority: i64,
    trust: Trust,
}

#[derive(Clone, Debug)]
struct IndexEntry {
    name: String,
    version: String,
    arch: String,
    recipe_fingerprint: String,
    path: String,
    sha256: String,
    reprocorr: Option<String>,
    producer_plan_lock_sha256: Option<String>,
}

#[derive(Clone, Debug)]
struct Snapshot {
    config: Config,
    key_sha256: String,
    index_sha256: String,
    index: Vec<u8>,
    signature: Vec<u8>,
    index_format: u8,
    release_root: bool,
    entries: HashMap<(String, String, String), IndexEntry>,
}

/// A leitura de catálogo é sempre autenticada, mas a capacidade de publicar o
/// snapshot/lock fica explícita. `ReadOnly` é usada por `plan` e pelas provas
/// de cache; nenhuma delas pode transformar uma consulta em estado local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadMode {
    ReadOnly,
    Mutating,
}

/// Seleção congelada. A instalação nunca volta ao índice para tomar outra
/// decisão: estes campos são a escolha inteira daquela operação.
#[derive(Clone, Debug)]
pub struct Selection {
    pub package: String,
    pub version: String,
    pub recipe_fingerprint: String,
    pub channel: String,
    pub trust: Trust,
    pub index_sha256: String,
    pub path: String,
    pub artifact_url: String,
    pub artifact_sha256: String,
    pub index_reprocorr: Option<String>,
    pub index_format: u8,
    pub release_root: bool,
    pub producer_plan_lock_sha256: Option<String>,
    pub producer_plan_url: Option<String>,
    pub legacy_development: bool,
    pub lock_sha256: String,
}

pub struct Resolution {
    selections: HashMap<String, Selection>,
    lock_body: Option<Vec<u8>>,
    lock_sha256: Option<String>,
    snapshots: Vec<Snapshot>,
    mode: LoadMode,
}

impl Resolution {
    pub(crate) fn empty(mode: LoadMode) -> Self {
        Self {
            selections: HashMap::new(),
            lock_body: None,
            lock_sha256: None,
            snapshots: Vec::new(),
            mode,
        }
    }

    pub fn get(&self, package: &str) -> Option<&Selection> {
        self.selections.get(package)
    }

    pub fn lock_sha256(&self) -> Option<&str> {
        self.lock_sha256.as_deref()
    }

    pub(crate) fn authenticate_producer_plans(
        &self,
        ctx: &Ctx,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut authenticated = BTreeMap::new();
        let used: BTreeSet<&str> = self
            .selections
            .values()
            .map(|selection| selection.channel.as_str())
            .collect();
        for snapshot in self
            .snapshots
            .iter()
            .filter(|snapshot| used.contains(snapshot.config.name.as_str()))
        {
            if snapshot.index_format < 4 {
                if snapshot.config.trust != Trust::Builder
                    || !self.selections.values().all(|s| {
                        s.channel != snapshot.config.name
                            || (s.legacy_development && !s.release_root)
                    })
                {
                    bail!("canal legado escapou da fronteira builder/development");
                }
                continue;
            }
            let mut groups: BTreeMap<String, Vec<(String, String, String, String)>> =
                BTreeMap::new();
            for entry in snapshot.entries.values() {
                if entry.arch != ARCH {
                    bail!(
                        "canal {}: índice v4 mistura arquitetura incompatível {}",
                        snapshot.config.name,
                        entry.arch
                    );
                }
                let producer = entry
                    .producer_plan_lock_sha256
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("índice v4 não prende PLAN_LOCK produtor"))?;
                let reprocorr = entry
                    .reprocorr
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("índice v4 não prende REPROCORR"))?;
                groups.entry(producer.clone()).or_default().push((
                    entry.name.clone(),
                    entry.version.clone(),
                    entry.recipe_fingerprint.clone(),
                    reprocorr.clone(),
                ));
            }
            for (producer, mut expected) in groups {
                expected.sort();
                let url = snapshot
                    .config
                    .url
                    .join(&format!("plans/{producer}.lock"))?;
                let path = crate::fetch::ensure_pinned_url(ctx, url.as_str(), &producer)?;
                let bytes = read_bounded_regular(&path, MAX_PRODUCER_PLAN_BYTES)?;
                crate::plan::verify_channel_producer_plan(
                    &bytes,
                    &producer,
                    snapshot.release_root,
                    &expected,
                )
                .with_context(|| {
                    format!(
                        "canal {}: PLAN_LOCK produtor não explica exatamente o índice",
                        snapshot.config.name
                    )
                })?;
                if let Some(existing) = authenticated.get(&producer) {
                    if existing != &bytes {
                        bail!("hash de PLAN_LOCK produtor nomeia bytes divergentes");
                    }
                } else {
                    authenticated.insert(producer, bytes);
                }
            }
        }
        Ok(authenticated)
    }

    /// Publica somente depois que o resolvedor global terminou todas as suas
    /// autenticações e precondições. Até aqui, índice e CHANNEL_LOCK existem
    /// apenas nos bytes presos por esta `Resolution`.
    pub fn persist(&self, ctx: &Ctx) -> Result<()> {
        if self.mode != LoadMode::Mutating {
            bail!("resolução read-only de canal não pode ser persistida");
        }
        if !ctx.offline {
            for snapshot in &self.snapshots {
                persist_pair(ctx, &snapshot.config, &snapshot.index, &snapshot.signature)?;
            }
        }
        if let (Some(body), Some(expected)) = (&self.lock_body, &self.lock_sha256) {
            let obtained = persist_lock(ctx, body)?;
            if &obtained != expected {
                bail!("CHANNEL_LOCK publicado com hash diferente do plano em memória");
            }
        }
        Ok(())
    }
}

impl Default for Resolution {
    fn default() -> Self {
        Self::empty(LoadMode::ReadOnly)
    }
}

pub struct Catalog {
    snapshots: Vec<Snapshot>,
    selections: HashMap<String, Selection>,
    mode: LoadMode,
    allow_legacy: bool,
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_bounded_regular(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("{} não é arquivo regular", path.display());
    }
    if metadata.len() > max {
        bail!("{} excede o limite de {max} bytes", path.display());
    }
    let capacity = usize::try_from(metadata.len().min(max)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        bail!("{} excede o limite de {max} bytes", path.display());
    }
    Ok(bytes)
}

fn parse_config(name: &str, bytes: &[u8]) -> Result<Config> {
    recipe::validate_name(name)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("canal {name}: configuração não é UTF-8"))?;
    let mut fields = HashMap::new();
    for (line_number, raw) in text.lines().enumerate() {
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        if raw != raw.trim() || raw.chars().any(char::is_control) {
            bail!("canal {name}: linha {} não é canônica", line_number + 1);
        }
        let (key, value) = raw
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("canal {name}: linha {} sem =", line_number + 1))?;
        if !matches!(key, "URL" | "KEY" | "PRIORITY" | "TRUST") {
            bail!("canal {name}: campo desconhecido {key}");
        }
        if value.is_empty() || value != value.trim() {
            bail!("canal {name}: {key} vazio ou não canônico");
        }
        if fields.insert(key, value).is_some() {
            bail!("canal {name}: campo duplicado {key}");
        }
    }
    let required = |key: &str| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("canal {name}: falta {key}"))
    };
    let mut url =
        Url::parse(required("URL")?).with_context(|| format!("canal {name}: URL inválida"))?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("canal {name}: URL deve ser base HTTPS sem credenciais/query/fragment");
    }
    if !url.path().ends_with('/') {
        let normalized = format!("{}/", url.path());
        url.set_path(&normalized);
    }
    let key = required("KEY")?.to_string();
    PublicKey::from_base64(&key)
        .map_err(|error| anyhow::anyhow!("canal {name}: KEY minisign inválida: {error}"))?;
    let priority = required("PRIORITY")?
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("canal {name}: PRIORITY não é inteiro"))?;
    let trust = match required("TRUST")? {
        "oficial" => Trust::Oficial,
        "corroborado" => Trust::Corroborado,
        "builder" => Trust::Builder,
        other => bail!("canal {name}: TRUST={other} inválido"),
    };
    Ok(Config {
        name: name.to_string(),
        url,
        key,
        priority,
        trust,
    })
}

pub(crate) fn validate_artifact_path(channel: &str, path: &str) -> Result<()> {
    let candidate = Path::new(path);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|component| component.is_empty())
        // O valor também será passado a `Url::join`. Restringir o alfabeto
        // impede que `:`, `?`, `#` ou `%2e%2e` transformem um path aparentemente
        // relativo em outro esquema/origem, query ou travessia URL.
        || !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'~' | b'-')
        })
        || !path.ends_with(".tar.zst")
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("canal {channel}: caminho de artefato não canônico: {path:?}");
    }
    Ok(())
}

type IndexEntries = HashMap<(String, String, String), IndexEntry>;

fn parse_index(
    channel: &str,
    trust: Trust,
    allow_legacy: bool,
    bytes: &[u8],
) -> Result<(u8, bool, IndexEntries)> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("canal {channel}: índice não é UTF-8"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        bail!("canal {channel}: índice não termina em LF");
    }
    let mut lines = text.lines();
    let first = lines.clone().next();
    let (index_format, release_root, header_lines) = match first {
        Some("CHANNEL_INDEX_FORMAT=4") => {
            lines.next();
            let release = lines
                .next()
                .ok_or_else(|| anyhow::anyhow!("canal {channel}: índice v4 sem RELEASE_ROOT"))?;
            let release_root = match release {
                "RELEASE_ROOT=yes" => true,
                "RELEASE_ROOT=no" => false,
                _ => bail!("canal {channel}: RELEASE_ROOT não é yes/no canônico"),
            };
            (4, release_root, 2usize)
        }
        Some("CHANNEL_INDEX_FORMAT=3") => {
            if trust != Trust::Builder || !allow_legacy {
                bail!(
                    "canal {channel}: índice v3 legado só é aceito para TRUST=builder/development"
                );
            }
            lines.next();
            (3, false, 1usize)
        }
        _ => {
            if trust != Trust::Builder || !allow_legacy {
                bail!(
                    "canal {channel}: índice v2 legado só é aceito para TRUST=builder/development"
                );
            }
            (2, false, 0usize)
        }
    };
    let mut entries = HashMap::new();
    let mut previous_identity: Option<(String, String, String)> = None;
    for (offset, line) in lines.enumerate() {
        let line_number = offset + header_lines + 1;
        if line.is_empty()
            || line.starts_with('#')
            || line.trim() != line
            || line.contains('\t')
            || line.contains("  ")
        {
            bail!(
                "canal {channel}: índice linha {} não é canônica",
                line_number + 1
            );
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let valid_arity = if index_format >= 3 {
            fields.len() == 8
        } else {
            fields.len() == 6 || fields.len() == 7
        };
        if !valid_arity {
            bail!(
                "canal {channel}: índice linha {} malformada",
                line_number + 1
            );
        }
        let name = fields[0];
        let version = fields[1];
        let arch = fields[2];
        let recipe_fingerprint = fields[3];
        let path = fields[4];
        let sha256 = fields[5];
        recipe::validate_name(name)?;
        recipe::validate_version(name, version)?;
        if arch.is_empty()
            || !arch
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            bail!("canal {channel}: arquitetura inválida: {arch:?}");
        }
        if !lower_hex(recipe_fingerprint) {
            bail!("canal {channel}: fingerprint inválido para {name} {version}");
        }
        validate_artifact_path(channel, path)?;
        if !lower_hex(sha256) {
            bail!("canal {channel}: sha256 inválido para {name} {version}");
        }
        let reprocorr = fields.get(6).map(|value| (*value).to_string());
        if reprocorr.as_deref().is_some_and(|hash| !lower_hex(hash)) {
            bail!("canal {channel}: reprocorr inválido para {name} {version}");
        }
        let producer_plan_lock_sha256 = fields.get(7).map(|value| (*value).to_string());
        if producer_plan_lock_sha256
            .as_deref()
            .is_some_and(|hash| !lower_hex(hash))
        {
            bail!("canal {channel}: PLAN_LOCK produtor inválido para {name} {version}");
        }
        let entry = IndexEntry {
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
            recipe_fingerprint: recipe_fingerprint.to_string(),
            path: path.to_string(),
            sha256: sha256.to_string(),
            reprocorr,
            producer_plan_lock_sha256,
        };
        let identity = (
            entry.name.clone(),
            entry.version.clone(),
            entry.arch.clone(),
        );
        if index_format >= 3
            && previous_identity
                .as_ref()
                .is_some_and(|previous| previous >= &identity)
        {
            bail!("canal {channel}: índice tipado não ordena identidades canonicamente");
        }
        previous_identity = Some(identity.clone());
        if entries.insert(identity, entry).is_some() {
            bail!("canal {channel}: entrada duplicada para {name} {version} {arch}");
        }
    }
    Ok((index_format, release_root, entries))
}

fn verify_index(config: &Config, index: &[u8], signature: &[u8]) -> Result<()> {
    let signature_text = std::str::from_utf8(signature).map_err(|_| crate::Fail {
        code: 7,
        msg: format!("canal {}: index.minisig não é UTF-8", config.name),
    })?;
    let signature = Signature::decode(signature_text).map_err(|error| crate::Fail {
        code: 7,
        msg: format!("canal {}: index.minisig malformado: {error}", config.name),
    })?;
    let key = PublicKey::from_base64(&config.key).map_err(|error| crate::Fail {
        code: 7,
        msg: format!("canal {}: chave minisign inválida: {error}", config.name),
    })?;
    key.verify(index, &signature, false).map_err(|error| {
        crate::Fail {
            code: 7,
            msg: format!(
                "crimestop (índice): canal {} não foi assinado pela chave pinada ({error})",
                config.name
            ),
        }
        .into()
    })
}

fn cache_paths(ctx: &Ctx, channel: &str) -> (PathBuf, PathBuf) {
    let directory = ctx.cache_dir().join("channels").join(channel);
    (directory.join("index"), directory.join("index.minisig"))
}

fn final_https(original: &Url, value: &str) -> Result<Url> {
    let final_url = Url::parse(value).map_err(|error| crate::Fail {
        code: 6,
        msg: format!("resposta de {original} trouxe URL final inválida: {error}"),
    })?;
    if final_url.scheme() != "https" || !final_url.has_host() {
        return fail(
            6,
            format!("redirecionamento de {original} rebaixou o transporte para {final_url}"),
        );
    }
    Ok(final_url)
}

fn download_bounded(url: &Url, max: usize) -> Result<Vec<u8>> {
    let response = ureq::get(url.as_str())
        .call()
        .map_err(|error| crate::Fail {
            code: 6,
            msg: format!("rede falhou em {url}: {error}"),
        })?;
    final_https(url, response.get_url())?;
    if response
        .header("Content-Length")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|size| size > max)
    {
        return fail(6, format!("resposta de {url} excede {max} bytes"));
    }
    let mut reader = response.into_reader().take((max as u64) + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| crate::Fail {
            code: 6,
            msg: format!("rede caiu no meio de {url}: {error}"),
        })?;
    if bytes.len() > max {
        return fail(6, format!("resposta de {url} excede {max} bytes"));
    }
    Ok(bytes)
}

fn exchange_directories(left: &Path, right: &Path) -> Result<()> {
    let left = CString::new(left.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("caminho temporário do canal contém NUL"))?;
    let right = CString::new(right.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("caminho do snapshot do canal contém NUL"))?;
    crate::linux::renameat2(
        libc::AT_FDCWD,
        &left,
        libc::AT_FDCWD,
        &right,
        libc::RENAME_EXCHANGE,
    )
    .context("trocando atomicamente o snapshot do canal")?;
    Ok(())
}

fn write_snapshot_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Publica índice + assinatura como UMA geração. Dois renames de arquivos
/// poderiam deixar `index` novo pareado à assinatura velha após uma queda; o
/// diretório inteiro é trocado com RENAME_EXCHANGE, então consumidores veem o
/// par antigo ou o novo.
fn persist_pair(ctx: &Ctx, config: &Config, index: &[u8], signature: &[u8]) -> Result<()> {
    let parent = ctx.cache_dir().join("channels");
    crate::install::ensure_real_directory_or_absent(
        &ctx.root,
        &parent,
        "diretório de snapshots de canal",
    )?;
    fs::create_dir_all(&parent)?;
    crate::install::ensure_real_directory_or_absent(
        &ctx.root,
        &parent,
        "diretório de snapshots de canal",
    )?;
    let destination = parent.join(&config.name);
    crate::install::ensure_real_directory_or_absent(&ctx.root, &destination, "snapshot do canal")?;

    for _ in 0..128 {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{}.minitrue-channel-{}-{serial}",
            config.name,
            std::process::id()
        ));
        match fs::create_dir(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
        let result = (|| -> Result<()> {
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
            write_snapshot_file(&temporary.join("index"), index)?;
            write_snapshot_file(&temporary.join("index.minisig"), signature)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
            fs::File::open(&temporary)?.sync_all()?;
            match fs::symlink_metadata(&destination) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    exchange_directories(&temporary, &destination)?;
                    // `temporary` agora contém a geração antiga. Uma queda
                    // antes desta limpeza não afeta o nome autoritativo.
                    let _ = fs::remove_dir_all(&temporary);
                }
                Ok(_) => bail!(
                    "snapshot do canal precisa ser diretório real: {}",
                    destination.display()
                ),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    fs::rename(&temporary, &destination)?;
                }
                Err(error) => return Err(error.into()),
            }
            fs::File::open(&parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary);
        }
        return result;
    }
    bail!(
        "não consegui reservar temporário para o canal {}",
        config.name
    )
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == ErrorKind::NotFound)
}

fn cached_pair(ctx: &Ctx, config: &Config) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let channels = ctx.cache_dir().join("channels");
    let directory = channels.join(&config.name);
    crate::install::ensure_real_directory_or_absent(&ctx.root, &channels, "snapshots de canais")?;
    crate::install::ensure_real_directory_or_absent(&ctx.root, &directory, "snapshot do canal")?;
    let (index_path, signature_path) = cache_paths(ctx, &config.name);
    let index = match read_bounded_regular(&index_path, MAX_INDEX_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(error) if not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let signature = match read_bounded_regular(&signature_path, MAX_SIGNATURE_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(error) if not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some((index, signature)))
}

/// Offline usa exatamente o snapshot assinado que a mídia/cache fechou.
/// Online consulta o endpoint em TODA operação: o índice embarcado é semente
/// confiável para operação sem rede, não uma fotografia eterna que esconda
/// pacotes publicados depois da mídia.
fn current_pair<F>(
    offline: bool,
    config: &Config,
    cached: Option<(Vec<u8>, Vec<u8>)>,
    fetch: F,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    F: FnOnce() -> Result<(Vec<u8>, Vec<u8>)>,
{
    if offline {
        return match cached {
            Some((index, signature)) if verify_index(config, &index, &signature).is_ok() => {
                Ok((index, signature))
            }
            Some(_) | None => fail(
                7,
                format!(
                    "--offline e snapshot assinado ausente/inválido para o canal {}",
                    config.name
                ),
            ),
        };
    }

    let (index, signature) = fetch()?;
    verify_index(config, &index, &signature)?;
    Ok((index, signature))
}

fn fetch_pair(config: &Config) -> Result<(Vec<u8>, Vec<u8>)> {
    let index_url = config.url.join("index")?;
    let signature_url = config.url.join("index.minisig")?;
    let index = download_bounded(&index_url, MAX_INDEX_BYTES)?;
    let signature = download_bounded(&signature_url, MAX_SIGNATURE_BYTES)?;
    verify_index(config, &index, &signature)?;
    Ok((index, signature))
}

fn load_snapshot(ctx: &Ctx, config: Config, allow_legacy: bool) -> Result<Snapshot> {
    // Nem mesmo o modo mutante publica durante a resolução: a operação global
    // ainda pode falhar em outra receita/ABI. A publicação pareada acontece em
    // `Resolution::persist`, depois do preflight inteiro.
    let cached = cached_pair(ctx, &config)?;
    let (index, signature) = current_pair(ctx.offline, &config, cached, || fetch_pair(&config))?;
    verify_index(&config, &index, &signature)?;
    let (index_format, release_root, entries) =
        parse_index(&config.name, config.trust, allow_legacy, &index)?;
    let index_sha256 = hex::encode(Sha256::digest(&index));
    let key_sha256 = hex::encode(Sha256::digest(config.key.as_bytes()));
    Ok(Snapshot {
        config,
        key_sha256,
        index_sha256,
        index,
        signature,
        index_format,
        release_root,
        entries,
    })
}

fn load_configs_from(ctx: &Ctx, directory: &Path, label: &str) -> Result<Vec<Config>> {
    crate::install::ensure_real_directory_or_absent(&ctx.root, directory, label)?;
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut configs = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("nome de canal não é UTF-8"))?;
        if name.starts_with('.') {
            continue;
        }
        if !entry.file_type()?.is_file() {
            bail!(
                "configuração de canal não é arquivo regular: {}",
                entry.path().display()
            );
        }
        let bytes = read_bounded_regular(&entry.path(), MAX_CONFIG_BYTES)?;
        configs.push(parse_config(&name, &bytes)?);
    }
    configs.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(configs)
}

fn load_configs(ctx: &Ctx) -> Result<Vec<Config>> {
    let administrative = ctx.root.join("etc/minitrue/channels");
    crate::install::ensure_real_directory_or_absent(
        &ctx.root,
        &administrative,
        "configuração administrativa de canais",
    )?;
    match fs::symlink_metadata(&administrative) {
        Ok(_) => {
            // A existência do diretório é a decisão administrativa. Vazio
            // significa "nenhum canal" e nunca reativa implicitamente a seed.
            return load_configs_from(
                ctx,
                &administrative,
                "configuração administrativa de canais",
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Mídia offline pode semear configuração e chave dentro do cache fechado
    // somente enquanto a autoridade administrativa não existe.
    let seeded = ctx.root.join("var/cache/minitrue/channel-config");
    load_configs_from(ctx, &seeded, "configuração de canais semeada no cache")
}

#[derive(Clone, Copy)]
enum OldSnapshotState {
    Valid,
    Absent,
    Invalid,
}

impl OldSnapshotState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Absent => "absent",
            Self::Invalid => "invalid",
        }
    }
}

struct RefreshPlan {
    config: Config,
    index: Vec<u8>,
    signature: Vec<u8>,
    old_state: OldSnapshotState,
    old_hash: Option<String>,
    new_hash: String,
    removed: Vec<String>,
    added: Vec<String>,
}

fn canonical_lines(index: &[u8]) -> BTreeSet<String> {
    // O chamador só chega aqui depois de `parse_index`, logo UTF-8 e forma
    // canônica já são invariantes conferidos.
    std::str::from_utf8(index)
        .expect("índice já validado como UTF-8")
        .lines()
        .map(str::to_string)
        .collect()
}

/// Núcleo injetável do refresh: testes fornecem a rede como closure, enquanto
/// produção usa HTTPS. O comando explícito é a autorização administrativa;
/// ele imprime e FLUSHA todos os diffs antes da primeira troca de snapshot.
fn refresh_with<W, F>(ctx: &Ctx, names: &[String], out: &mut W, mut fetch: F) -> Result<()>
where
    W: Write,
    F: FnMut(&Config) -> Result<(Vec<u8>, Vec<u8>)>,
{
    if ctx.offline {
        return fail(6, "channel refresh não está disponível com --offline");
    }
    let _lock = crate::install::acquire_lock(ctx)?;
    let mut configs = load_configs(ctx)?;
    if configs.is_empty() {
        return fail(6, "channel refresh: nenhum canal configurado");
    }

    if !names.is_empty() {
        let mut requested = BTreeSet::new();
        for name in names {
            recipe::validate_name(name)?;
            if !requested.insert(name.clone()) {
                return fail(1, format!("channel refresh: canal repetido {name}"));
            }
        }
        let configured: HashSet<&str> = configs.iter().map(|config| config.name.as_str()).collect();
        if let Some(name) = requested
            .iter()
            .find(|name| !configured.contains(name.as_str()))
        {
            return fail(6, format!("channel refresh: canal não configurado {name}"));
        }
        configs.retain(|config| requested.contains(&config.name));
    }

    let mut plans = Vec::with_capacity(configs.len());
    for config in configs {
        let cached = cached_pair(ctx, &config)?;
        let (old_state, old_hash, old_lines) = match cached {
            Some((old_index, old_signature)) => {
                let old_hash = hex::encode(Sha256::digest(&old_index));
                if verify_index(&config, &old_index, &old_signature).is_ok()
                    && parse_index(&config.name, config.trust, true, &old_index).is_ok()
                {
                    (
                        OldSnapshotState::Valid,
                        Some(old_hash),
                        canonical_lines(&old_index),
                    )
                } else {
                    (OldSnapshotState::Invalid, Some(old_hash), BTreeSet::new())
                }
            }
            None => (OldSnapshotState::Absent, None, BTreeSet::new()),
        };

        let (index, signature) = fetch(&config)?;
        verify_index(&config, &index, &signature)?;
        parse_index(&config.name, config.trust, false, &index)?;
        let new_lines = canonical_lines(&index);
        let removed = old_lines.difference(&new_lines).cloned().collect();
        let added = new_lines.difference(&old_lines).cloned().collect();
        plans.push(RefreshPlan {
            config,
            new_hash: hex::encode(Sha256::digest(&index)),
            index,
            signature,
            old_state,
            old_hash,
            removed,
            added,
        });
    }

    writeln!(out, "CHANNEL_REFRESH_FORMAT=1")?;
    writeln!(out, "CHANNEL_COUNT={}", plans.len())?;
    for plan in &plans {
        writeln!(out, "CHANNEL={}", plan.config.name)?;
        writeln!(out, "OLD_STATE={}", plan.old_state.as_str())?;
        writeln!(
            out,
            "OLD_INDEX_SHA256={}",
            plan.old_hash.as_deref().unwrap_or("-")
        )?;
        writeln!(out, "NEW_INDEX_SHA256={}", plan.new_hash)?;
        writeln!(
            out,
            "CHANGE_COUNT={}",
            plan.removed.len() + plan.added.len()
        )?;
        for line in &plan.removed {
            writeln!(out, "- {line}")?;
        }
        for line in &plan.added {
            writeln!(out, "+ {line}")?;
        }
        writeln!(out, "END_CHANNEL")?;
    }
    out.flush()?;

    for plan in &plans {
        persist_pair(ctx, &plan.config, &plan.index, &plan.signature)?;
    }
    writeln!(out, "REFRESHED={}", plans.len())?;
    out.flush()?;
    Ok(())
}

/// Busca, autentica, mostra o diff e só então avança os snapshots selecionados.
/// Não resolve receita, não cria channel lock e não instala pacote algum.
pub fn refresh(ctx: &Ctx, names: &[String]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    refresh_with(ctx, names, &mut out, fetch_pair)
}

impl Catalog {
    pub fn load_mode(ctx: &Ctx, mode: LoadMode, allow_legacy: bool) -> Result<Self> {
        let configs = load_configs(ctx)?;
        let mut snapshots = Vec::with_capacity(configs.len());
        for config in configs {
            snapshots.push(load_snapshot(ctx, config, allow_legacy)?);
        }
        Ok(Self {
            snapshots,
            selections: HashMap::new(),
            mode,
            allow_legacy,
        })
    }

    /// Seleciona o primeiro canal aceitável, já ordenado por prioridade.
    pub fn select(&mut self, recipe: &Recipe, fingerprint: &str) -> Result<bool> {
        if self.selections.contains_key(&recipe.name) {
            return Ok(true);
        }
        let identity = (
            recipe.name.clone(),
            recipe.version.clone(),
            ARCH.to_string(),
        );
        for snapshot in &self.snapshots {
            let Some(entry) = snapshot.entries.get(&identity) else {
                continue;
            };
            if entry.recipe_fingerprint != fingerprint {
                return fail(
                    8,
                    format!(
                        "crimestop (identidade): canal {} oferece {} {} para fingerprint {}, mas a receita efetiva exige {}",
                        snapshot.config.name,
                        recipe.name,
                        recipe.version,
                        entry.recipe_fingerprint,
                        fingerprint,
                    ),
                );
            }
            if let (Some(recipe_hash), Some(index_hash)) =
                (recipe.reprocorr.as_deref(), entry.reprocorr.as_deref())
            {
                if recipe_hash != index_hash {
                    return fail(
                        8,
                        format!(
                            "crimestop (reprodução): canal {} declara {} para {} {}, mas a receita pina {}",
                            snapshot.config.name,
                            index_hash,
                            recipe.name,
                            recipe.version,
                            recipe_hash
                        ),
                    );
                }
            }
            if snapshot.config.trust == Trust::Corroborado && recipe.reprocorr.is_none() {
                continue;
            }
            let artifact_url = snapshot.config.url.join(&entry.path)?.to_string();
            let producer_plan_url = entry
                .producer_plan_lock_sha256
                .as_ref()
                .map(|hash| snapshot.config.url.join(&format!("plans/{hash}.lock")))
                .transpose()?
                .map(|url| url.to_string());
            self.selections.insert(
                recipe.name.clone(),
                Selection {
                    package: recipe.name.clone(),
                    version: recipe.version.clone(),
                    // Este valor veio do índice assinado e acabou de ser
                    // comparado com a identidade local efetiva.
                    recipe_fingerprint: entry.recipe_fingerprint.clone(),
                    channel: snapshot.config.name.clone(),
                    trust: snapshot.config.trust,
                    index_sha256: snapshot.index_sha256.clone(),
                    path: entry.path.clone(),
                    artifact_url,
                    artifact_sha256: entry.sha256.clone(),
                    index_reprocorr: entry.reprocorr.clone(),
                    index_format: snapshot.index_format,
                    release_root: snapshot.release_root,
                    producer_plan_lock_sha256: entry.producer_plan_lock_sha256.clone(),
                    producer_plan_url,
                    legacy_development: snapshot.index_format < 4 && self.allow_legacy,
                    lock_sha256: String::new(),
                },
            );
            return Ok(true);
        }
        Ok(false)
    }

    pub fn finish(self) -> Result<Resolution> {
        if self.selections.is_empty() {
            return Ok(Resolution {
                mode: self.mode,
                ..Resolution::default()
            });
        }
        let mut selections: Vec<Selection> = self.selections.into_values().collect();
        let body = lock_body(&self.snapshots, &selections)?;
        let body = body.into_bytes();
        let lock_sha256 = hex::encode(Sha256::digest(&body));
        let mut by_package = HashMap::new();
        for mut selection in selections.drain(..) {
            selection.lock_sha256 = lock_sha256.clone();
            by_package.insert(selection.package.clone(), selection);
        }
        Ok(Resolution {
            selections: by_package,
            lock_body: Some(body),
            lock_sha256: Some(lock_sha256),
            snapshots: self.snapshots,
            mode: self.mode,
        })
    }
}

fn append_lock_fragment(body: &mut String, fragment: &str) -> Result<()> {
    if body
        .len()
        .checked_add(fragment.len())
        .is_none_or(|length| length > MAX_LOCK_BYTES as usize)
    {
        bail!("lock de canal excede {} bytes", MAX_LOCK_BYTES);
    }
    body.push_str(fragment);
    Ok(())
}

fn lock_body(snapshots: &[Snapshot], selections: &[Selection]) -> Result<String> {
    let used: HashSet<&str> = selections
        .iter()
        .map(|selection| selection.channel.as_str())
        .collect();
    let mut channels: Vec<&Snapshot> = snapshots
        .iter()
        .filter(|snapshot| used.contains(snapshot.config.name.as_str()))
        .collect();
    channels.sort_by(|a, b| a.config.name.cmp(&b.config.name));
    let mut packages: Vec<&Selection> = selections.iter().collect();
    packages.sort_by(|a, b| a.package.cmp(&b.package));
    if channels.len() > MAX_LOCK_ENTRIES || packages.len() > MAX_LOCK_ENTRIES {
        bail!("lock de canal excede o limite de {MAX_LOCK_ENTRIES} entradas");
    }

    let mut body = format!(
        "CHANNEL_LOCK_FORMAT={CHANNEL_LOCK_FORMAT}\nARCH={ARCH}\nCHANNEL_COUNT={}\n",
        channels.len()
    );
    if body.len() > MAX_LOCK_BYTES as usize {
        bail!("lock de canal excede {} bytes", MAX_LOCK_BYTES);
    }
    for (index, channel) in channels.iter().enumerate() {
        append_lock_fragment(&mut body, &format!(
            "CHANNEL.{index}.NAME={}\nCHANNEL.{index}.URL={}\nCHANNEL.{index}.KEY_SHA256={}\nCHANNEL.{index}.INDEX_SHA256={}\nCHANNEL.{index}.RELEASE_ROOT={}\nCHANNEL.{index}.TRUST={}\n",
            channel.config.name,
            channel.config.url,
            channel.key_sha256,
            channel.index_sha256,
            if channel.release_root { "yes" } else { "no" },
            channel.config.trust.as_str(),
        ))?;
    }
    append_lock_fragment(&mut body, &format!("PACKAGE_COUNT={}\n", packages.len()))?;
    for (index, package) in packages.iter().enumerate() {
        append_lock_fragment(&mut body, &format!(
            "PACKAGE.{index}.NAME={}\nPACKAGE.{index}.VERSION={}\nPACKAGE.{index}.RECIPE_FINGERPRINT={}\nPACKAGE.{index}.CHANNEL={}\nPACKAGE.{index}.PATH={}\nPACKAGE.{index}.SHA256={}\nPACKAGE.{index}.REPROCORR={}\nPACKAGE.{index}.INDEX_FORMAT={}\nPACKAGE.{index}.PRODUCER_PLAN_LOCK_SHA256={}\nPACKAGE.{index}.TRUST={}\n",
            package.package,
            package.version,
            package.recipe_fingerprint,
            package.channel,
            package.path,
            package.artifact_sha256,
            package.index_reprocorr.as_deref().unwrap_or("-"),
            package.index_format,
            package.producer_plan_lock_sha256.as_deref().unwrap_or("-"),
            package.trust.as_str(),
        ))?;
    }
    Ok(body)
}

#[derive(Debug)]
struct LockedChannel {
    index_sha256: String,
    release_root: bool,
    trust: Trust,
}

#[derive(Debug)]
struct LockedPackage {
    name: String,
    version: String,
    recipe_fingerprint: String,
    channel: String,
    path: String,
    artifact_sha256: String,
    reprocorr: Option<String>,
    index_format: u8,
    producer_plan_lock_sha256: Option<String>,
    trust: Trust,
}

#[derive(Debug)]
struct ParsedLock {
    channels: HashMap<String, LockedChannel>,
    packages: HashMap<String, LockedPackage>,
}

struct LockLines<'a> {
    lines: std::str::Lines<'a>,
    number: usize,
}

impl<'a> LockLines<'a> {
    fn field(&mut self, expected: &str, allow_empty: bool) -> Result<&'a str> {
        let line = self
            .lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("lock de canal truncado; falta {expected}"))?;
        self.number += 1;
        if line.is_empty() || line.trim() != line || line.chars().any(char::is_control) {
            bail!("lock de canal tem linha não canônica em {}", self.number);
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("lock de canal linha {} não é KEY=VALUE", self.number)
        })?;
        if key != expected {
            bail!(
                "lock de canal esperava {expected} na linha {}, encontrou {key}",
                self.number
            );
        }
        if !allow_empty && value.is_empty() {
            bail!("lock de canal contém {expected} vazio");
        }
        Ok(value)
    }

    fn finish(mut self) -> Result<()> {
        if self.lines.next().is_some() {
            bail!("lock de canal contém campos extras");
        }
        Ok(())
    }
}

fn parse_lock_count(value: &str, field: &str) -> Result<usize> {
    let count = value
        .parse::<usize>()
        .with_context(|| format!("lock de canal contém {field} inválido"))?;
    if count.to_string() != value || count > MAX_LOCK_ENTRIES {
        bail!("lock de canal contém {field} não canônico ou excessivo");
    }
    Ok(count)
}

fn parse_trust(value: &str, what: &str) -> Result<Trust> {
    match value {
        "oficial" => Ok(Trust::Oficial),
        "corroborado" => Ok(Trust::Corroborado),
        "builder" => Ok(Trust::Builder),
        _ => bail!("{what} contém confiança inválida: {value:?}"),
    }
}

fn validate_lock_url(value: &str) -> Result<()> {
    let url = Url::parse(value).context("lock de canal contém URL inválida")?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
        || url.as_str() != value
    {
        bail!("lock de canal contém URL não canônica: {value:?}");
    }
    Ok(())
}

fn parse_lock(bytes: &[u8]) -> Result<ParsedLock> {
    if bytes.len() as u64 > MAX_LOCK_BYTES {
        bail!("lock de canal excede {MAX_LOCK_BYTES} bytes");
    }
    let text = std::str::from_utf8(bytes).context("lock de canal não é UTF-8")?;
    if text.as_bytes().contains(&b'\r') {
        bail!("lock de canal contém CR");
    }
    if !text.ends_with('\n') {
        bail!("lock de canal não termina em LF");
    }
    let mut cursor = LockLines {
        lines: text.lines(),
        number: 0,
    };
    let lock_format = match cursor.field("CHANNEL_LOCK_FORMAT", false)? {
        "4" => 4,
        "3" => 3,
        "2" => 2,
        _ => bail!("CHANNEL_LOCK_FORMAT desconhecido"),
    };
    if cursor.field("ARCH", false)? != ARCH {
        bail!("lock de canal é de arquitetura incompatível");
    }
    let channel_count = parse_lock_count(cursor.field("CHANNEL_COUNT", false)?, "CHANNEL_COUNT")?;
    if lock_format == 4 && channel_count == 0 {
        bail!("lock de canal v4 exige CHANNEL_COUNT maior que zero");
    }
    let mut channels = HashMap::with_capacity(channel_count);
    let mut previous_channel: Option<String> = None;
    for index in 0..channel_count {
        let name = cursor.field(&format!("CHANNEL.{index}.NAME"), false)?;
        recipe::validate_name(name)?;
        if previous_channel
            .as_deref()
            .is_some_and(|previous| previous >= name)
        {
            bail!("lock de canal não ordena nomes de canal canonicamente");
        }
        previous_channel = Some(name.to_string());
        let url = cursor.field(&format!("CHANNEL.{index}.URL"), false)?;
        validate_lock_url(url)?;
        let key_sha256 = cursor.field(&format!("CHANNEL.{index}.KEY_SHA256"), false)?;
        let index_sha256 = cursor.field(&format!("CHANNEL.{index}.INDEX_SHA256"), false)?;
        if !lower_hex(key_sha256) || !lower_hex(index_sha256) {
            bail!("lock de canal contém hash de canal inválido para {name}");
        }
        let release_root = if lock_format == 4 {
            match cursor.field(&format!("CHANNEL.{index}.RELEASE_ROOT"), false)? {
                "yes" => true,
                "no" => false,
                _ => bail!("lock de canal contém RELEASE_ROOT inválido para {name}"),
            }
        } else {
            false
        };
        let trust = parse_trust(
            cursor.field(&format!("CHANNEL.{index}.TRUST"), false)?,
            "lock de canal",
        )?;
        if channels
            .insert(
                name.to_string(),
                LockedChannel {
                    index_sha256: index_sha256.to_string(),
                    release_root,
                    trust,
                },
            )
            .is_some()
        {
            bail!("lock de canal repete o canal {name}");
        }
    }

    let package_count = parse_lock_count(cursor.field("PACKAGE_COUNT", false)?, "PACKAGE_COUNT")?;
    if lock_format == 4 && package_count == 0 {
        bail!("lock de canal v4 exige PACKAGE_COUNT maior que zero");
    }
    let mut packages = HashMap::with_capacity(package_count);
    let mut previous_package: Option<String> = None;
    for index in 0..package_count {
        let name = cursor.field(&format!("PACKAGE.{index}.NAME"), false)?;
        recipe::validate_name(name)?;
        if previous_package
            .as_deref()
            .is_some_and(|previous| previous >= name)
        {
            bail!("lock de canal não ordena pacotes canonicamente");
        }
        previous_package = Some(name.to_string());
        let version = cursor.field(&format!("PACKAGE.{index}.VERSION"), false)?;
        recipe::validate_version(name, version)?;
        let recipe_fingerprint =
            cursor.field(&format!("PACKAGE.{index}.RECIPE_FINGERPRINT"), false)?;
        if !lower_hex(recipe_fingerprint) {
            bail!("lock de canal contém fingerprint inválido para {name}");
        }
        let channel = cursor.field(&format!("PACKAGE.{index}.CHANNEL"), false)?;
        recipe::validate_name(channel)?;
        let path = cursor.field(&format!("PACKAGE.{index}.PATH"), false)?;
        validate_artifact_path("lock", path)?;
        let artifact_sha256 = cursor.field(&format!("PACKAGE.{index}.SHA256"), false)?;
        if !lower_hex(artifact_sha256) {
            bail!("lock de canal contém hash de artefato inválido para {name}");
        }
        let reprocorr = cursor.field(&format!("PACKAGE.{index}.REPROCORR"), lock_format == 2)?;
        if !matches!(reprocorr, "" | "-") && !lower_hex(reprocorr) {
            bail!("lock de canal contém reprocorr inválido para {name}");
        }
        let (index_format, producer_plan_lock_sha256) = if lock_format >= 3 {
            let index_format =
                match cursor.field(&format!("PACKAGE.{index}.INDEX_FORMAT"), false)? {
                    "2" => 2,
                    "3" => 3,
                    "4" => 4,
                    _ => bail!("lock de canal contém INDEX_FORMAT inválido para {name}"),
                };
            let producer =
                cursor.field(&format!("PACKAGE.{index}.PRODUCER_PLAN_LOCK_SHA256"), false)?;
            if producer != "-" && !lower_hex(producer) {
                bail!("lock de canal contém PLAN_LOCK produtor inválido para {name}");
            }
            (
                index_format,
                (producer != "-").then(|| producer.to_string()),
            )
        } else {
            (2, None)
        };
        let trust = parse_trust(
            cursor.field(&format!("PACKAGE.{index}.TRUST"), false)?,
            "lock de canal",
        )?;
        let locked_channel = channels.get(channel).ok_or_else(|| {
            anyhow::anyhow!("lock de canal: pacote {name} referencia canal ausente")
        })?;
        if trust != locked_channel.trust {
            bail!("lock de canal: confiança de {name} diverge do canal {channel}");
        }
        if index_format >= 3 {
            if !lower_hex(reprocorr) || producer_plan_lock_sha256.is_none() {
                bail!("lock de canal: índice tipado de {name} não fecha REPROCORR/plano produtor");
            }
        } else if producer_plan_lock_sha256.is_some() {
            bail!("lock de canal: índice v2 não pode declarar plano produtor");
        }
        if index_format < 4 && (trust != Trust::Builder || locked_channel.release_root) {
            bail!("lock de canal: índice legado só pode ser builder/non-release");
        }
        if locked_channel.release_root && index_format != 4 {
            bail!("lock de canal: RELEASE_ROOT exige índice v4");
        }
        if packages
            .insert(
                name.to_string(),
                LockedPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    recipe_fingerprint: recipe_fingerprint.to_string(),
                    channel: channel.to_string(),
                    path: path.to_string(),
                    artifact_sha256: artifact_sha256.to_string(),
                    reprocorr: (!matches!(reprocorr, "" | "-")).then(|| reprocorr.to_string()),
                    index_format,
                    producer_plan_lock_sha256,
                    trust,
                },
            )
            .is_some()
        {
            bail!("lock de canal repete o pacote {name}");
        }
    }
    cursor.finish()?;
    Ok(ParsedLock { channels, packages })
}

pub(crate) struct RecordedProvenance<'a> {
    pub package: &'a str,
    pub version: &'a str,
    pub recipe_fingerprint: &'a str,
    pub channel: &'a str,
    pub path: &'a str,
    pub trust: &'a str,
    pub artifact_sha256: &'a str,
    pub index_sha256: &'a str,
    pub artifact_reprocorr: &'a str,
    pub recipe_reprocorr: Option<&'a str>,
    pub index_format: u8,
    pub release_root: bool,
    pub producer_plan_lock_sha256: Option<&'a str>,
}

pub(crate) fn verify_lock_provenance(
    bytes: &[u8],
    recorded: &RecordedProvenance<'_>,
) -> Result<()> {
    let parsed = parse_lock(bytes)?;
    let package = parsed.packages.get(recorded.package).ok_or_else(|| {
        anyhow::anyhow!(
            "lock de canal não contém a seleção registrada de {}",
            recorded.package
        )
    })?;
    let locked_channel = parsed.channels.get(&package.channel).ok_or_else(|| {
        anyhow::anyhow!("lock de canal perdeu o canal da seleção {}", package.name)
    })?;
    if package.version != recorded.version
        || package.recipe_fingerprint != recorded.recipe_fingerprint
        || package.channel != recorded.channel
        || package.path != recorded.path
        || package.trust.as_str() != recorded.trust
        || package.artifact_sha256 != recorded.artifact_sha256
        || locked_channel.index_sha256 != recorded.index_sha256
        || locked_channel.release_root != recorded.release_root
        || package.index_format != recorded.index_format
        || package.producer_plan_lock_sha256.as_deref() != recorded.producer_plan_lock_sha256
    {
        bail!(
            "lock de canal diverge da proveniência registrada de {}",
            recorded.package
        );
    }
    if package
        .reprocorr
        .as_deref()
        .is_some_and(|expected| expected != recorded.artifact_reprocorr)
    {
        bail!(
            "lock de canal diverge do reprocorr instalado de {}",
            recorded.package
        );
    }
    if recorded
        .recipe_reprocorr
        .is_some_and(|expected| expected != recorded.artifact_reprocorr)
    {
        bail!(
            "registro diverge do REPROCORR pinado de {}",
            recorded.package
        );
    }
    Ok(())
}

fn persist_lock(ctx: &Ctx, body: &[u8]) -> Result<String> {
    if body.len() as u64 > MAX_LOCK_BYTES {
        bail!("lock de canal excede {MAX_LOCK_BYTES} bytes");
    }
    let hash = hex::encode(Sha256::digest(body));
    let directory = ctx.root.join("var/lib/minitrue/channel-locks");
    crate::install::ensure_real_directory_or_absent(&ctx.root, &directory, "locks de canal")?;
    fs::create_dir_all(&directory)?;
    crate::install::ensure_real_directory_or_absent(&ctx.root, &directory, "locks de canal")?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let directory_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&directory)?;
    let directory_metadata = directory_file.metadata()?;
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.uid() != unsafe { libc::geteuid() }
        || directory_metadata.mode() & 0o022 != 0
    {
        bail!("diretório de CHANNEL_LOCK não é privado/confiável");
    }
    let final_name = CString::new(format!("{hash}.lock"))?;
    match read_lock_at(&directory_file, &final_name)? {
        Some(existing) if existing == body => return Ok(hash),
        Some(_) => bail!("CHANNEL_LOCK existente diverge do próprio hash {hash}"),
        None => {}
    }

    for _ in 0..128 {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_name =
            CString::new(format!(".{hash}.lock.{}-{serial}.tmp", std::process::id()))?;
        let mut file = match openat_lock(
            &directory_file,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<()> {
            file.write_all(body)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            let staged = file.metadata()?;
            if !channel_lock_metadata_valid(&staged) || staged.len() != body.len() as u64 {
                bail!("temporário de CHANNEL_LOCK não preservou owner/mode/nlink/tamanho");
            }
            match crate::linux::renameat2(
                directory_file.as_raw_fd(),
                &temporary_name,
                directory_file.as_raw_fd(),
                &final_name,
                libc::RENAME_NOREPLACE,
            ) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if read_lock_at(&directory_file, &final_name)?.as_deref() != Some(body) {
                        bail!("CHANNEL_LOCK concorrente diverge do próprio hash {hash}");
                    }
                }
                Err(error) => return Err(error.into()),
            }
            directory_file.sync_all()?;
            Ok(())
        })();
        unlinkat_lock(&directory_file, &temporary_name);
        result?;
        if read_lock_at(&directory_file, &final_name)?.as_deref() != Some(body) {
            bail!("CHANNEL_LOCK publicado diverge do próprio hash {hash}");
        }
        return Ok(hash);
    }
    bail!("não reservei temporário para CHANNEL_LOCK")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LockMetadata {
    dev: u64,
    ino: u64,
    nlink: u64,
    len: u64,
    mode: u32,
    uid: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl LockMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

fn openat_lock(
    directory: &fs::File,
    name: &CString,
    flags: i32,
    mode: u32,
) -> std::io::Result<fs::File> {
    // SAFETY: `name` é uma C string viva, o dirfd permanece aberto e o fd
    // retornado recebe dono único em `File`.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn open_lock_directory_anchored(path: &Path) -> Result<fs::File> {
    let mut directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => CString::new(name.as_bytes())?,
            Component::ParentDir | Component::Prefix(_) => {
                bail!("caminho de CHANNEL_LOCK contém componente de escape")
            }
        };
        directory = openat_lock(
            &directory,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
    }
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        bail!("diretório histórico de CHANNEL_LOCK não é real/confiável");
    }
    Ok(directory)
}

fn channel_lock_metadata_valid(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o644
        && metadata.len() <= MAX_LOCK_BYTES
}

fn read_lock_at(directory: &fs::File, name: &CString) -> Result<Option<Vec<u8>>> {
    let mut file = match openat_lock(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let before = file.metadata()?;
    if !channel_lock_metadata_valid(&before) {
        bail!("CHANNEL_LOCK existente tem tipo/owner/mode/nlink/limite inválido");
    }
    let snapshot = LockMetadata::from(&before);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_LOCK_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = LockMetadata::from(&file.metadata()?);
    let reopened = openat_lock(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let at_path = LockMetadata::from(&reopened.metadata()?);
    if snapshot != after || after != at_path || bytes.len() as u64 != before.len() {
        bail!("CHANNEL_LOCK existente mudou durante a leitura");
    }
    Ok(Some(bytes))
}

fn unlinkat_lock(directory: &fs::File, name: &CString) {
    // SAFETY: tentativa best-effort em nome relativo validado e dirfd vivo.
    let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
}

pub(crate) fn read_persisted_lock(ctx: &Ctx, hash: &str) -> Result<Vec<u8>> {
    if !lower_hex(hash) {
        bail!("hash histórico de CHANNEL_LOCK não é canônico");
    }
    let directory = open_lock_directory_anchored(&ctx.root.join("var/lib/minitrue/channel-locks"))?;
    let name = CString::new(format!("{hash}.lock"))?;
    let bytes = read_lock_at(&directory, &name)?
        .ok_or_else(|| anyhow::anyhow!("CHANNEL_LOCK histórico referenciado não existe"))?;
    if hex::encode(Sha256::digest(&bytes)) != hash {
        bail!("CHANNEL_LOCK histórico diverge do próprio hash");
    }
    parse_lock(&bytes)?;
    Ok(bytes)
}

pub fn index_line(
    name: &str,
    version: &str,
    recipe_fingerprint: &str,
    path: &str,
    sha256: &str,
    reprocorr: &str,
    producer_plan_lock_sha256: &str,
) -> Result<String> {
    recipe::validate_name(name)?;
    recipe::validate_version(name, version)?;
    validate_artifact_path("emit", path)?;
    if !lower_hex(recipe_fingerprint)
        || !lower_hex(sha256)
        || !lower_hex(reprocorr)
        || !lower_hex(producer_plan_lock_sha256)
    {
        bail!("emit: hash não canônico para {name} {version}");
    }
    Ok(format!(
        "{name} {version} {ARCH} {recipe_fingerprint} {path} {sha256} {reprocorr} {producer_plan_lock_sha256}\n"
    ))
}

pub fn index_header_for(release_root: bool) -> String {
    format!(
        "CHANNEL_INDEX_FORMAT={CHANNEL_INDEX_FORMAT}\nRELEASE_ROOT={}\n",
        if release_root { "yes" } else { "no" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use blake2::Blake2b512;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(message: &[u8]) -> (String, Vec<u8>) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let key_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut key = Vec::from(*b"ED");
        key.extend_from_slice(&key_id);
        key.extend_from_slice(&signing.verifying_key().to_bytes());
        let key = base64::engine::general_purpose::STANDARD.encode(key);

        let digest = Blake2b512::digest(message);
        let signature = signing.sign(&digest);
        let trusted = "timestamp:0\tfile:index";
        let mut global_body = Vec::from(signature.to_bytes());
        global_body.extend_from_slice(trusted.as_bytes());
        let global = signing.sign(&global_body);
        let mut first = Vec::from(*b"ED");
        first.extend_from_slice(&key_id);
        first.extend_from_slice(&signature.to_bytes());
        let text = format!(
            "untrusted comment: teste\n{}\ntrusted comment: {}\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(first),
            trusted,
            base64::engine::general_purpose::STANDARD.encode(global.to_bytes())
        );
        (key, text.into_bytes())
    }

    fn canonical_v4_lock() -> String {
        format!(
            "CHANNEL_LOCK_FORMAT=4\n\
ARCH={ARCH}\n\
CHANNEL_COUNT=1\n\
CHANNEL.0.NAME=oficial\n\
CHANNEL.0.URL=https://example.invalid/\n\
CHANNEL.0.KEY_SHA256={}\n\
CHANNEL.0.INDEX_SHA256={}\n\
CHANNEL.0.RELEASE_ROOT=yes\n\
CHANNEL.0.TRUST=oficial\n\
PACKAGE_COUNT=1\n\
PACKAGE.0.NAME=pkg\n\
PACKAGE.0.VERSION=1\n\
PACKAGE.0.RECIPE_FINGERPRINT={}\n\
PACKAGE.0.CHANNEL=oficial\n\
PACKAGE.0.PATH=pool/pkg-1-x86_64.tar.zst\n\
PACKAGE.0.SHA256={}\n\
PACKAGE.0.REPROCORR={}\n\
PACKAGE.0.INDEX_FORMAT=4\n\
PACKAGE.0.PRODUCER_PLAN_LOCK_SHA256={}\n\
PACKAGE.0.TRUST=oficial\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        )
    }

    #[test]
    fn channel_lock_v4_exige_mundos_nao_vazios_e_contagens_canonicas() {
        let canonical = canonical_v4_lock();
        parse_lock(canonical.as_bytes()).expect("lock v4 canônico");

        let zero_channels = canonical.replacen("CHANNEL_COUNT=1\n", "CHANNEL_COUNT=0\n", 1);
        let error = parse_lock(zero_channels.as_bytes()).expect_err("v4 sem canal");
        assert!(error.to_string().contains("CHANNEL_COUNT maior que zero"));

        let zero_packages = canonical.replacen("PACKAGE_COUNT=1\n", "PACKAGE_COUNT=0\n", 1);
        let error = parse_lock(zero_packages.as_bytes()).expect_err("v4 sem pacote");
        assert!(error.to_string().contains("PACKAGE_COUNT maior que zero"));

        for noncanonical in [
            canonical.replacen("CHANNEL_COUNT=1\n", "CHANNEL_COUNT=01\n", 1),
            canonical.replacen("PACKAGE_COUNT=1\n", "PACKAGE_COUNT=01\n", 1),
        ] {
            assert!(
                parse_lock(noncanonical.as_bytes()).is_err(),
                "contagem não canônica foi aceita"
            );
        }

        // A proibição é uma propriedade nova do formato 4; leitores
        // históricos continuam podendo validar locks vazios v2/v3.
        for format in ["2", "3"] {
            let legacy = format!(
                "CHANNEL_LOCK_FORMAT={format}\nARCH={ARCH}\nCHANNEL_COUNT=0\nPACKAGE_COUNT=0\n"
            );
            parse_lock(legacy.as_bytes()).expect("lock legado vazio continua legível");
        }
    }

    #[test]
    fn assinatura_e_indice_sao_fail_closed() {
        let fingerprint = "c".repeat(64);
        let producer = "d".repeat(64);
        let index = format!(
            "{}pkg 1 x86_64 {fingerprint} pool/pkg-1-x86_64.tar.zst {} {} {producer}\n",
            index_header_for(false),
            "a".repeat(64),
            "b".repeat(64)
        );
        let (key, signature) = signed(index.as_bytes());
        let config = parse_config(
            "oficial",
            format!(
                "URL=https://example.invalid/channel\nKEY={key}\nPRIORITY=100\nTRUST=oficial\n"
            )
            .as_bytes(),
        )
        .unwrap();
        verify_index(&config, index.as_bytes(), &signature).unwrap();
        assert_eq!(
            parse_index("oficial", Trust::Oficial, false, index.as_bytes())
                .unwrap()
                .2
                .len(),
            1
        );

        let mut changed = index.into_bytes();
        changed[0] = b'P';
        assert!(verify_index(&config, &changed, &signature).is_err());
        // O layout anterior não autenticava o fingerprint e não pode ser
        // interpretado silenciosamente como o formato novo.
        assert!(parse_index(
            "oficial",
            Trust::Oficial,
            false,
            format!(
                "pkg 1 x86_64 pool/pkg-1-x86_64.tar.zst {} {}\n",
                "a".repeat(64),
                "b".repeat(64),
            )
            .as_bytes(),
        )
        .is_err());
        assert!(parse_index(
            "oficial",
            Trust::Oficial,
            false,
            format!(
                "{}pkg 1 x86_64 {fingerprint} ../escape.tar.zst {} {} {producer}\n",
                index_header_for(false),
                "a".repeat(64),
                "b".repeat(64)
            )
            .as_bytes()
        )
        .is_err());
        for path in [
            "https:escape.tar.zst",
            "pool/%2e%2e/escape.tar.zst",
            "pool//escape.tar.zst",
            "pool/pkg?redirect.tar.zst",
            "pool/pkg#fragment.tar.zst",
        ] {
            assert!(parse_index(
                "oficial",
                Trust::Oficial,
                false,
                format!(
                    "{}pkg 1 x86_64 {fingerprint} {path} {} {} {producer}\n",
                    index_header_for(false),
                    "a".repeat(64),
                    "b".repeat(64)
                )
                .as_bytes()
            )
            .is_err());
        }
        assert!(parse_index(
            "oficial",
            Trust::Oficial,
            false,
            format!(
                "{}# comentário\npkg 1 x86_64 {fingerprint} p.tar.zst {} {} {producer}\n",
                index_header_for(false),
                "a".repeat(64),
                "b".repeat(64)
            )
            .as_bytes()
        )
        .is_err());
        assert!(parse_index(
            "oficial",
            Trust::Oficial,
            false,
            format!(
                "{}pkg 1 x86_64 {fingerprint} p.tar.zst {} {} {producer}\npkg 1 x86_64 {fingerprint} q.tar.zst {} {} {producer}\n",
                index_header_for(false),
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                "b".repeat(64)
            )
            .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn online_busca_indice_fresco_mesmo_com_seed_valida() {
        let old = b"CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 1 x86_64 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc pool/pkg-1-x86_64.tar.zst aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1111111111111111111111111111111111111111111111111111111111111111\n";
        let new = b"CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 2 x86_64 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd pool/pkg-2-x86_64.tar.zst eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 2222222222222222222222222222222222222222222222222222222222222222\n";
        let (key, old_signature) = signed(old);
        let (_, new_signature) = signed(new);
        let config = parse_config(
            "oficial",
            format!("URL=https://example.invalid/\nKEY={key}\nPRIORITY=100\nTRUST=oficial\n")
                .as_bytes(),
        )
        .unwrap();
        let mut fetched = false;
        let (index, signature) =
            current_pair(false, &config, Some((old.to_vec(), old_signature)), || {
                fetched = true;
                Ok((new.to_vec(), new_signature))
            })
            .unwrap();
        assert!(fetched, "a seed válida não pode congelar o canal online");
        assert_eq!(index, new);
        verify_index(&config, &index, &signature).unwrap();
    }

    #[test]
    fn offline_usa_seed_assinada_sem_consultar_rede() {
        let index = b"CHANNEL_INDEX_FORMAT=3\npkg 1 x86_64 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc pool/pkg-1-x86_64.tar.zst aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1111111111111111111111111111111111111111111111111111111111111111\n";
        let (key, signature) = signed(index);
        let config = parse_config(
            "oficial",
            format!("URL=https://example.invalid/\nKEY={key}\nPRIORITY=100\nTRUST=oficial\n")
                .as_bytes(),
        )
        .unwrap();
        let (observed, _) = current_pair(true, &config, Some((index.to_vec(), signature)), || {
            panic!("modo offline tentou consultar a rede")
        })
        .unwrap();
        assert_eq!(observed, index);
    }

    #[test]
    fn refresh_mostra_diff_antes_de_persistir_e_nao_instala() {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-channel-refresh-{}-{serial}",
            std::process::id()
        ));
        let config_dir = root.join("var/cache/minitrue/channel-config");
        let snapshot_dir = root.join("var/cache/minitrue/channels/oficial");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&snapshot_dir).unwrap();
        let old = b"CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 1 x86_64 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc pool/pkg-1-x86_64.tar.zst aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1111111111111111111111111111111111111111111111111111111111111111\n";
        let new = b"CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 2 x86_64 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd pool/pkg-2-x86_64.tar.zst eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 2222222222222222222222222222222222222222222222222222222222222222\n";
        let (key, old_signature) = signed(old);
        let (_, new_signature) = signed(new);
        fs::write(
            config_dir.join("oficial"),
            format!("URL=https://example.invalid/\nKEY={key}\nPRIORITY=100\nTRUST=oficial\n"),
        )
        .unwrap();
        fs::write(snapshot_dir.join("index"), old).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), &old_signature).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        let mut output = Vec::new();
        refresh_with(&ctx, &[], &mut output, |_| {
            Ok((new.to_vec(), new_signature.clone()))
        })
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("CHANNEL_REFRESH_FORMAT=1\nCHANNEL_COUNT=1\n"));
        assert!(output.contains(&format!(
            "OLD_INDEX_SHA256={}",
            hex::encode(Sha256::digest(old))
        )));
        assert!(output.contains(&format!(
            "NEW_INDEX_SHA256={}",
            hex::encode(Sha256::digest(new))
        )));
        assert!(output.contains(&format!(
            "- {}",
            std::str::from_utf8(old).unwrap().lines().nth(2).unwrap()
        )));
        assert!(output.contains(&format!(
            "+ {}",
            std::str::from_utf8(new).unwrap().lines().nth(2).unwrap()
        )));
        assert!(output.ends_with("END_CHANNEL\nREFRESHED=1\n"));
        assert_eq!(fs::read(snapshot_dir.join("index")).unwrap(), new);
        assert_eq!(
            fs::read(snapshot_dir.join("index.minisig")).unwrap(),
            new_signature
        );
        assert!(!root.join("etc/minitrue/world").exists());
        assert!(!root.join("var/lib/minitrue/records").exists());
        assert!(!root.join("opt").exists());

        // A rede adulterada falha antes de imprimir/persistir qualquer plano.
        let before_index = fs::read(snapshot_dir.join("index")).unwrap();
        let before_signature = fs::read(snapshot_dir.join("index.minisig")).unwrap();
        let mut bad_signature = signed(b"outro").1;
        bad_signature.push(b'\n');
        let mut rejected_output = Vec::new();
        assert!(refresh_with(&ctx, &[], &mut rejected_output, |_| {
            Ok((old.to_vec(), bad_signature.clone()))
        })
        .is_err());
        assert!(rejected_output.is_empty());
        assert_eq!(fs::read(snapshot_dir.join("index")).unwrap(), before_index);
        assert_eq!(
            fs::read(snapshot_dir.join("index.minisig")).unwrap(),
            before_signature
        );

        let offline = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        assert!(refresh_with(&offline, &[], &mut Vec::new(), |_| {
            panic!("refresh offline tentou rede")
        })
        .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn config_recusa_http_campos_e_chave_ruim() {
        let (key, _) = signed(b"x");
        assert!(parse_config(
            "x",
            format!("URL=http://example.invalid\nKEY={key}\nPRIORITY=1\nTRUST=oficial\n")
                .as_bytes()
        )
        .is_err());
        assert!(parse_config(
            "x",
            format!(
                "URL=https://example.invalid\nKEY={key}\nPRIORITY=1\nTRUST=oficial\nSURPRESA=1\n"
            )
            .as_bytes()
        )
        .is_err());
        assert!(parse_config(
            "x",
            b"URL=https://example.invalid\nKEY=lixo\nPRIORITY=1\nTRUST=oficial\n"
        )
        .is_err());
    }

    #[test]
    fn refresh_nao_aceita_redirect_para_http() {
        let original = Url::parse("https://example.invalid/canal/index").unwrap();
        assert!(final_https(&original, "http://mirror.invalid/index").is_err());
        assert!(final_https(&original, "https://cdn.example.invalid/index").is_ok());
    }

    #[test]
    fn linha_de_indice_e_canonica() {
        let line = index_line(
            "pkg",
            "1.0",
            &"c".repeat(64),
            "pool/pkg-1.0-x86_64.tar.zst",
            &"a".repeat(64),
            &"b".repeat(64),
            &"d".repeat(64),
        )
        .unwrap();
        assert_eq!(line.split_whitespace().count(), 8);
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn configuracao_administrativa_vence_bootstrap_da_midia_por_inteiro() {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-channel-precedence-{}-{serial}",
            std::process::id()
        ));
        let seeded = root.join("var/cache/minitrue/channel-config");
        fs::create_dir_all(&seeded).unwrap();
        let (key, _) = signed(b"indice\n");
        fs::write(
            seeded.join("midia"),
            format!("URL=https://media.example.invalid/\nKEY={key}\nPRIORITY=10\nTRUST=oficial\n"),
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let configs = load_configs(&ctx).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "midia");

        let administrative = root.join("etc/minitrue/channels");
        fs::create_dir_all(&administrative).unwrap();
        let configs = load_configs(&ctx).unwrap();
        assert!(
            configs.is_empty(),
            "diretório administrativo vazio precisa desabilitar a seed"
        );
        fs::write(
            administrative.join("admin"),
            format!("URL=https://admin.example.invalid/\nKEY={key}\nPRIORITY=1\nTRUST=builder\n"),
        )
        .unwrap();
        // Se houvesse mescla, esta semente corrompida faria a leitura falhar.
        // /etc presente deve torná-la completamente irrelevante.
        fs::write(seeded.join("midia"), b"NAO_E_CONFIG\n").unwrap();
        let configs = load_configs(&ctx).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "admin");
        assert_eq!(configs[0].trust, Trust::Builder);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn channel_lock_content_addressed_recusa_nlink_residual() {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-channel-lock-nlink-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let body = b"CHANNEL_LOCK_FORMAT=2\nARCH=x86_64\nCHANNEL_COUNT=0\nPACKAGE_COUNT=0\n";
        let hash = persist_lock(&ctx, body).unwrap();
        let directory = root.join("var/lib/minitrue/channel-locks");
        let lock = directory.join(format!("{hash}.lock"));
        assert_eq!(fs::metadata(&lock).unwrap().nlink(), 1);
        let alias = directory.join("alias.lock");
        fs::hard_link(&lock, &alias).unwrap();
        assert!(persist_lock(&ctx, body).is_err());
        fs::remove_file(alias).unwrap();
        assert_eq!(persist_lock(&ctx, body).unwrap(), hash);
        let _ = fs::remove_dir_all(root);
    }
}
