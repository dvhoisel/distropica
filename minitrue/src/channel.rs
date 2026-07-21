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
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

// O formato 2 distingue locks cujo fingerprint veio do índice assinado. Locks
// v1 continham o mesmo campo, mas ele era copiado apenas da receita local.
const CHANNEL_LOCK_FORMAT: &str = "2";
const ARCH: &str = "x86_64";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
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
}

#[derive(Clone, Debug)]
struct Snapshot {
    config: Config,
    key_sha256: String,
    index_sha256: String,
    entries: HashMap<(String, String, String), IndexEntry>,
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
    pub lock_sha256: String,
}

#[derive(Default)]
pub struct Resolution {
    selections: HashMap<String, Selection>,
}

impl Resolution {
    pub fn get(&self, package: &str) -> Option<&Selection> {
        self.selections.get(package)
    }
}

pub struct Catalog {
    snapshots: Vec<Snapshot>,
    selections: HashMap<String, Selection>,
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

fn parse_index(
    channel: &str,
    bytes: &[u8],
) -> Result<HashMap<(String, String, String), IndexEntry>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("canal {channel}: índice não é UTF-8"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        bail!("canal {channel}: índice não termina em LF");
    }
    let mut entries = HashMap::new();
    for (line_number, line) in text.lines().enumerate() {
        // O hash do snapshot é sobre estes bytes. Um v2 canônico contém
        // somente entradas; comentários e linhas vazias criariam grafias
        // alternativas sem semântica e dificultariam diffs auditáveis.
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
        // v2 acrescenta o fingerprint da receita à identidade assinada.
        // Não há fallback posicional para o índice antigo: sem esse vínculo,
        // um artefato de uma receita anterior com a mesma versão pareceria
        // corresponder à receita efetiva local.
        if !(fields.len() == 6 || fields.len() == 7) {
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
        let entry = IndexEntry {
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
            recipe_fingerprint: recipe_fingerprint.to_string(),
            path: path.to_string(),
            sha256: sha256.to_string(),
            reprocorr,
        };
        let identity = (
            entry.name.clone(),
            entry.version.clone(),
            entry.arch.clone(),
        );
        if entries.insert(identity, entry).is_some() {
            bail!("canal {channel}: entrada duplicada para {name} {version} {arch}");
        }
    }
    Ok(entries)
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

fn download_bounded(url: &Url, max: usize) -> Result<Vec<u8>> {
    let response = ureq::get(url.as_str())
        .call()
        .map_err(|error| crate::Fail {
            code: 6,
            msg: format!("rede falhou em {url}: {error}"),
        })?;
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

fn write_atomic_cache(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cache sem diretório pai"))?;
    let leaf = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("cache");
    for _ in 0..128 {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{leaf}.minitrue-channel-{}-{serial}",
            std::process::id()
        ));
        let mut file = match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.flush()?;
            drop(file);
            fs::rename(&temporary, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    bail!("não consegui reservar temporário para {}", path.display())
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == ErrorKind::NotFound)
}

fn cached_pair(ctx: &Ctx, config: &Config) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
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

fn load_snapshot(ctx: &Ctx, config: Config) -> Result<Snapshot> {
    let cache_directory = ctx.cache_dir().join("channels").join(&config.name);
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache_directory, "cache do canal")?;
    fs::create_dir_all(&cache_directory)?;
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache_directory, "cache do canal")?;

    let (index, signature) = match cached_pair(ctx, &config)? {
        Some((index, signature)) if verify_index(&config, &index, &signature).is_ok() => {
            (index, signature)
        }
        Some(_) | None if ctx.offline => {
            return fail(
                7,
                format!(
                    "--offline e snapshot assinado ausente/inválido para o canal {}",
                    config.name
                ),
            )
        }
        Some(_) | None => {
            let index_url = config.url.join("index")?;
            let signature_url = config.url.join("index.minisig")?;
            let index = download_bounded(&index_url, MAX_INDEX_BYTES)?;
            let signature = download_bounded(&signature_url, MAX_SIGNATURE_BYTES)?;
            verify_index(&config, &index, &signature)?;
            let (index_path, signature_path) = cache_paths(ctx, &config.name);
            write_atomic_cache(&index_path, &index)?;
            write_atomic_cache(&signature_path, &signature)?;
            (index, signature)
        }
    };
    verify_index(&config, &index, &signature)?;
    let index_sha256 = hex::encode(Sha256::digest(&index));
    let key_sha256 = hex::encode(Sha256::digest(config.key.as_bytes()));
    let entries = parse_index(&config.name, &index)?;
    Ok(Snapshot {
        config,
        key_sha256,
        index_sha256,
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

impl Catalog {
    pub fn load(ctx: &Ctx) -> Result<Self> {
        let configs = load_configs(ctx)?;
        let mut snapshots = Vec::with_capacity(configs.len());
        for config in configs {
            snapshots.push(load_snapshot(ctx, config)?);
        }
        Ok(Self {
            snapshots,
            selections: HashMap::new(),
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
                    lock_sha256: String::new(),
                },
            );
            return Ok(true);
        }
        Ok(false)
    }

    pub fn finish(self, ctx: &Ctx) -> Result<Resolution> {
        if self.selections.is_empty() {
            return Ok(Resolution::default());
        }
        let mut selections: Vec<Selection> = self.selections.into_values().collect();
        let body = lock_body(&self.snapshots, &selections)?;
        let lock_sha256 = persist_lock(ctx, body.as_bytes())?;
        let mut by_package = HashMap::new();
        for mut selection in selections.drain(..) {
            selection.lock_sha256 = lock_sha256.clone();
            by_package.insert(selection.package.clone(), selection);
        }
        Ok(Resolution {
            selections: by_package,
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
            "CHANNEL.{index}.NAME={}\nCHANNEL.{index}.URL={}\nCHANNEL.{index}.KEY_SHA256={}\nCHANNEL.{index}.INDEX_SHA256={}\nCHANNEL.{index}.TRUST={}\n",
            channel.config.name,
            channel.config.url,
            channel.key_sha256,
            channel.index_sha256,
            channel.config.trust.as_str(),
        ))?;
    }
    append_lock_fragment(&mut body, &format!("PACKAGE_COUNT={}\n", packages.len()))?;
    for (index, package) in packages.iter().enumerate() {
        append_lock_fragment(&mut body, &format!(
            "PACKAGE.{index}.NAME={}\nPACKAGE.{index}.VERSION={}\nPACKAGE.{index}.RECIPE_FINGERPRINT={}\nPACKAGE.{index}.CHANNEL={}\nPACKAGE.{index}.PATH={}\nPACKAGE.{index}.SHA256={}\nPACKAGE.{index}.REPROCORR={}\nPACKAGE.{index}.TRUST={}\n",
            package.package,
            package.version,
            package.recipe_fingerprint,
            package.channel,
            package.path,
            package.artifact_sha256,
            package.index_reprocorr.as_deref().unwrap_or(""),
            package.trust.as_str(),
        ))?;
    }
    Ok(body)
}

#[derive(Debug)]
struct LockedChannel {
    index_sha256: String,
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
    if cursor.field("CHANNEL_LOCK_FORMAT", false)? != CHANNEL_LOCK_FORMAT {
        bail!("CHANNEL_LOCK_FORMAT desconhecido");
    }
    if cursor.field("ARCH", false)? != ARCH {
        bail!("lock de canal é de arquitetura incompatível");
    }
    let channel_count = parse_lock_count(cursor.field("CHANNEL_COUNT", false)?, "CHANNEL_COUNT")?;
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
        let trust = parse_trust(
            cursor.field(&format!("CHANNEL.{index}.TRUST"), false)?,
            "lock de canal",
        )?;
        if channels
            .insert(
                name.to_string(),
                LockedChannel {
                    index_sha256: index_sha256.to_string(),
                    trust,
                },
            )
            .is_some()
        {
            bail!("lock de canal repete o canal {name}");
        }
    }

    let package_count = parse_lock_count(cursor.field("PACKAGE_COUNT", false)?, "PACKAGE_COUNT")?;
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
        let reprocorr = cursor.field(&format!("PACKAGE.{index}.REPROCORR"), true)?;
        if !reprocorr.is_empty() && !lower_hex(reprocorr) {
            bail!("lock de canal contém reprocorr inválido para {name}");
        }
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
                    reprocorr: (!reprocorr.is_empty()).then(|| reprocorr.to_string()),
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
    let path = directory.join(format!("{hash}.lock"));
    match read_bounded_regular(&path, MAX_LOCK_BYTES) {
        Ok(existing) if existing == body => return Ok(hash),
        Ok(_) => bail!("lock de canal existente não corresponde ao próprio hash: {hash}"),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }

    let mut temporary = None;
    for _ in 0..128 {
        let serial = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = directory.join(format!(".{hash}.lock.{}-{serial}.tmp", std::process::id()));
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(mut file) => {
                let result = (|| -> Result<()> {
                    file.write_all(body)?;
                    file.flush()?;
                    file.set_permissions(fs::Permissions::from_mode(0o644))?;
                    Ok(())
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&candidate);
                }
                result?;
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let temporary = temporary.ok_or_else(|| anyhow::anyhow!("não reservei temporário do lock"))?;
    let publish = fs::hard_link(&temporary, &path);
    let result = match publish {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            match read_bounded_regular(&path, MAX_LOCK_BYTES) {
                Ok(existing) if existing == body => Ok(()),
                Ok(_) => Err(anyhow::anyhow!(
                    "lock de canal existente não corresponde ao próprio hash: {hash}"
                )),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error.into()),
    };
    let _ = fs::remove_file(&temporary);
    result?;
    if read_bounded_regular(&path, MAX_LOCK_BYTES)? != body {
        let _ = fs::remove_file(&path);
        bail!("lock de canal publicado não corresponde ao próprio hash: {hash}");
    }
    Ok(hash)
}

pub(crate) fn read_lock_file(path: &Path) -> Result<Vec<u8>> {
    read_bounded_regular(path, MAX_LOCK_BYTES)
}

pub fn index_line(
    name: &str,
    version: &str,
    recipe_fingerprint: &str,
    path: &str,
    sha256: &str,
    reprocorr: &str,
) -> Result<String> {
    recipe::validate_name(name)?;
    recipe::validate_version(name, version)?;
    validate_artifact_path("emit", path)?;
    if !lower_hex(recipe_fingerprint) || !lower_hex(sha256) || !lower_hex(reprocorr) {
        bail!("emit: hash não canônico para {name} {version}");
    }
    Ok(format!(
        "{name} {version} {ARCH} {recipe_fingerprint} {path} {sha256} {reprocorr}\n"
    ))
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

    #[test]
    fn assinatura_e_indice_sao_fail_closed() {
        let fingerprint = "c".repeat(64);
        let index = format!(
            "pkg 1 x86_64 {fingerprint} pool/pkg-1-x86_64.tar.zst {} {}\n",
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
        assert_eq!(parse_index("oficial", index.as_bytes()).unwrap().len(), 1);

        let mut changed = index.into_bytes();
        changed[0] = b'P';
        assert!(verify_index(&config, &changed, &signature).is_err());
        // O layout anterior não autenticava o fingerprint e não pode ser
        // interpretado silenciosamente como o formato novo.
        assert!(parse_index(
            "oficial",
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
            format!(
                "pkg 1 x86_64 {fingerprint} ../escape.tar.zst {}\n",
                "a".repeat(64)
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
                format!("pkg 1 x86_64 {fingerprint} {path} {}\n", "a".repeat(64)).as_bytes()
            )
            .is_err());
        }
        assert!(parse_index(
            "oficial",
            format!(
                "# comentário\npkg 1 x86_64 {fingerprint} p.tar.zst {}\n",
                "a".repeat(64)
            )
            .as_bytes()
        )
        .is_err());
        assert!(parse_index(
            "oficial",
            format!(
                "pkg 1 x86_64 {fingerprint} p.tar.zst {}\npkg 1 x86_64 {fingerprint} q.tar.zst {}\n",
                "a".repeat(64),
                "b".repeat(64)
            )
            .as_bytes()
        )
        .is_err());
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
    fn linha_de_indice_e_canonica() {
        let line = index_line(
            "pkg",
            "1.0",
            &"c".repeat(64),
            "pool/pkg-1.0-x86_64.tar.zst",
            &"a".repeat(64),
            &"b".repeat(64),
        )
        .unwrap();
        assert_eq!(line.split_whitespace().count(), 7);
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
}
