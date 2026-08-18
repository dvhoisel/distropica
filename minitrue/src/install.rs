use crate::channel;
use crate::elf::{self, Object};
use crate::recipe::{self, Kind, Recipe, Toolchain};
use crate::{fail, fetch, iso_now, Ctx};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
    symlink, DirBuilderExt, FileExt as UnixFileExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// O payload é preparado como v3. Só o fechamento factual do PLAN_LOCK promove
/// o `meta` para v4; assim um crash nunca transforma um build ainda não
/// auditado em estado atestável.
const RECORD_FORMAT: &str = "3";
const FINAL_RECORD_FORMAT: &str = "4";
const PREVIOUS_TYPED_RECORD_FORMAT: &str = "2";
const JOURNAL_FORMAT: &str = "2";

static TX_COUNTER: AtomicU64 = AtomicU64::new(0);
static MOVE_COUNTER: AtomicU64 = AtomicU64::new(0);
static ATOMIC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Escreve `bytes` em `path` **atomicamente**: grava num temporário irmão e
/// `rename` por cima (atômico no mesmo filesystem). Um leitor nunca vê um
/// arquivo meio-escrito, e um crash não deixa `path` corrompido (SPEC-0003 §6).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("x");
    for _ in 0..128 {
        let serial = ATOMIC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_file_name(format!(
            ".{name}.minitrue-atomic-{}-{serial}",
            std::process::id()
        ));
        let mut file = match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.flush()?;
            drop(file);
            fs::rename(&tmp, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        return result;
    }
    bail!(
        "não consegui reservar temporário atômico irmão de {}",
        path.display()
    )
}

/// Cria um snapshot novo sem seguir um symlink no nome final. Usado para a
/// receita executável dentro de WORK, cujo nome é reservado em `files/`.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

const MAX_RECORD_FILE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordStableMetadata {
    dev: u64,
    ino: u64,
    nlink: u64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl RecordStableMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

fn openat_record_file(
    directory: &fs::File,
    name: &CString,
    flags: i32,
) -> std::io::Result<fs::File> {
    // SAFETY: `directory` e `name` permanecem vivos durante a syscall e o fd
    // retornado é imediatamente transferido para um único `File`.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn open_anchored_record_directory(path: &Path) -> Result<(fs::File, fs::File, CString)> {
    let mut directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(CString::new(name.as_bytes())?),
            Component::ParentDir | Component::Prefix(_) => {
                bail!("caminho de record contém componente de escape")
            }
        }
    }
    let leaf = names
        .pop()
        .ok_or_else(|| anyhow::anyhow!("caminho de record não possui folha"))?;
    for name in names {
        directory = openat_record_file(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    let record = openat_record_file(&directory, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
    Ok((record, directory, leaf))
}

#[derive(Debug)]
struct HistoricalFileSnapshot {
    name: CString,
    bytes: Vec<u8>,
    metadata: RecordStableMetadata,
}

fn read_historical_file_at(
    directory: &fs::File,
    name: CString,
    label: &str,
) -> Result<HistoricalFileSnapshot> {
    let mut file = openat_record_file(directory, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let before = file.metadata()?;
    let snapshot = RecordStableMetadata::from(&before);
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > MAX_RECORD_FILE {
        bail!("{label} histórico não é regular nlink=1 dentro do limite");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_RECORD_FILE + 1)
        .read_to_end(&mut bytes)?;
    let after = RecordStableMetadata::from(&file.metadata()?);
    let reopened = openat_record_file(directory, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let at_path = RecordStableMetadata::from(&reopened.metadata()?);
    if snapshot != after || after != at_path || bytes.len() as u64 != snapshot.len {
        bail!("{label} histórico mudou durante a leitura");
    }
    Ok(HistoricalFileSnapshot {
        name,
        bytes,
        metadata: snapshot,
    })
}

struct HistoricalRecordSnapshot {
    directory: fs::File,
    parent: fs::File,
    directory_name: CString,
    directory_metadata: RecordStableMetadata,
    meta: HashMap<String, String>,
    meta_file: HistoricalFileSnapshot,
    current_recipe: HistoricalFileSnapshot,
    versioned_recipe: HistoricalFileSnapshot,
    manifest: HistoricalFileSnapshot,
    baseline: HistoricalFileSnapshot,
}

impl HistoricalRecordSnapshot {
    fn capture(rec_dir: &Path, expected_name: &str) -> Result<Self> {
        let (directory, parent, directory_name) = open_anchored_record_directory(rec_dir)?;
        let directory_metadata = RecordStableMetadata::from(&directory.metadata()?);
        if directory_metadata.mode & libc::S_IFMT != libc::S_IFDIR {
            bail!("record histórico não é diretório real");
        }
        let meta_file = read_historical_file_at(&directory, CString::new("meta")?, "meta")?;
        let meta = parse_meta_bytes(&meta_file.bytes)?;
        let version = meta
            .get("VERSION")
            .ok_or_else(|| anyhow::anyhow!("record histórico sem VERSION"))?;
        recipe::validate_version(expected_name, version)?;
        let current_recipe =
            read_historical_file_at(&directory, CString::new("recipe")?, "recipe")?;
        let versioned_recipe = read_historical_file_at(
            &directory,
            CString::new(format!("recipe@{version}"))?,
            "recipe versionada",
        )?;
        let manifest = read_historical_file_at(&directory, CString::new("manifest")?, "manifest")?;
        let baseline = read_historical_file_at(
            &directory,
            CString::new(format!("manifest@{version}"))?,
            "baseline",
        )?;
        let snapshot = Self {
            directory,
            parent,
            directory_name,
            directory_metadata,
            meta,
            meta_file,
            current_recipe,
            versioned_recipe,
            manifest,
            baseline,
        };
        // Uma publicação que coexistiu com o primeiro passe nunca é aceita:
        // todos os nomes são reabertos e comparados antes de expor o snapshot.
        snapshot.revalidate()?;
        Ok(snapshot)
    }

    fn revalidate_file(&self, original: &HistoricalFileSnapshot, label: &str) -> Result<()> {
        let observed = read_historical_file_at(&self.directory, original.name.clone(), label)?;
        if observed.metadata != original.metadata || observed.bytes != original.bytes {
            bail!("{label} histórico mudou entre snapshots");
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<()> {
        for (file, label) in [
            (&self.meta_file, "meta"),
            (&self.current_recipe, "recipe"),
            (&self.versioned_recipe, "recipe versionada"),
            (&self.manifest, "manifest"),
            (&self.baseline, "baseline"),
        ] {
            self.revalidate_file(file, label)?;
        }
        let after = RecordStableMetadata::from(&self.directory.metadata()?);
        let reopened = openat_record_file(
            &self.parent,
            &self.directory_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let at_path = RecordStableMetadata::from(&reopened.metadata()?);
        if self.directory_metadata != after || after != at_path {
            bail!("diretório do record histórico mudou durante o snapshot");
        }
        Ok(())
    }
}

/// Lê uma folha regular sem seguir symlink no nome final. Diretórios de
/// registro já são validados como reais nos fluxos críticos; `O_NOFOLLOW`
/// fecha a assimetria restante para meta/manifest/recipe.
fn read_regular_nofollow(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("{} não é arquivo regular", path.display());
    }
    if metadata.len() > MAX_RECORD_FILE {
        bail!("{} excede o limite de registro", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_RECORD_FILE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_FILE {
        bail!("{} excede o limite de registro", path.display());
    }
    Ok(bytes)
}

fn read_regular_text_nofollow(path: &Path) -> Result<String> {
    String::from_utf8(read_regular_nofollow(path)?)
        .map_err(|_| anyhow::anyhow!("{} não é UTF-8", path.display()))
}

/// Trava exclusiva **por rootfs** — impede dois `minitrue` mutando o mesmo
/// sistema ao mesmo tempo. É advisory (`flock`) e **auto-liberada quando o
/// processo sai**, então um crash não deixa o lock preso. O guarda devolvido é
/// o guarda: segure-o pela operação inteira; soltá-lo libera a trava.
pub(crate) struct RootLock(Vec<fs::File>);

impl Drop for RootLock {
    fn drop(&mut self) {
        // Explicita a fronteira inclusive em retornos antecipados. O close do
        // File também liberaria o flock, mas o unlock evita que temporários de
        // erro/postergamento de drop tornem um relock sequencial intermitente.
        for file in self.0.iter().rev() {
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn lock_root_anchor(ctx: &Ctx, operation: i32) -> Result<fs::File> {
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&ctx.root)
        .with_context(|| format!("abrindo rootfs {} para lock", ctx.root.display()))?;
    if !root.metadata()?.file_type().is_dir() {
        bail!("rootfs do lock não é diretório real");
    }
    if unsafe { libc::flock(root.as_raw_fd(), operation | libc::LOCK_NB) } != 0 {
        return Err(crate::Fail {
            code: 1,
            msg: "outro minitrue já opera este sistema (lock do rootfs)".into(),
        }
        .into());
    }
    Ok(root)
}

/// Lock compartilhado ancorado no diretório do rootfs. Não cria
/// `/var/lib/minitrue`, arquivo de lock ou qualquer outro estado; leitores do
/// plano podem portanto congelar world/records/árvore sem efeito colateral.
pub(crate) fn acquire_read_lock(ctx: &Ctx) -> Result<RootLock> {
    Ok(RootLock(vec![lock_root_anchor(ctx, libc::LOCK_SH)?]))
}

pub(crate) fn acquire_lock(ctx: &Ctx) -> Result<RootLock> {
    let root_anchor = lock_root_anchor(ctx, libc::LOCK_EX)?;
    let dir = ctx.root.join("var/lib/minitrue");
    ensure_real_directory_or_absent(&ctx.root, &dir, "estado do minitrue")?;
    fs::create_dir_all(&dir)?;
    let f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(dir.join("lock"))?;
    if !f.metadata()?.file_type().is_file() {
        bail!("lock do minitrue precisa ser arquivo regular");
    }
    // flock direto pelo libc, e não pela crate fs2, de propósito: a fs2 existe
    // para abstrair travamento entre Unix e Windows, e esta é uma ferramenta
    // Linux. O preço da abstração não era teórico — a fs2 arrastava a winapi,
    // que sozinha respondia por 106 dos 295 MB das crates vendorizadas, um
    // terço da árvore, para duas chamadas que o libc já exposto aqui faz.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(crate::Fail {
            code: 1,
            msg: "outro minitrue já opera este sistema (lock em var/lib/minitrue/lock)".into(),
        }
        .into());
    }
    Ok(RootLock(vec![root_anchor, f]))
}

// ---------- rectify ----------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryPolicy {
    PreferBinary,
    SourceOnly,
    BinaryOnly,
}

/// Imprime `<pacote> <fingerprint>` para a closure de identidade dos nomes
/// pedidos, um por linha e em ordem estável.
///
/// Existe para que OUTRO programa possa perguntar "que fingerprint esta árvore
/// de receitas exige?" sem reimplementar a regra. O fingerprint é transitivo
/// sobre o texto da receita e sobre DEPS/BUILD_DEPS (SPEC-0011 §4), e quem o
/// conhece é este crate; qualquer segunda implementação divergiria no primeiro
/// detalhe que mudasse aqui.
///
/// O consumidor concreto é o `minipax media build`: ele embarca uma árvore de
/// receitas ao lado de um cache de pacotes, e as duas coisas podem vir de
/// lugares diferentes. Se divergirem, o `crimestop` recusa a instalação na
/// máquina de quem recebeu a mídia — depois de a mídia existir, ter sido
/// distribuída e o disco já ter sido apagado. Com isto, a mesma pergunta é
/// feita enquanto a mídia ainda está sendo composta.
///
/// Usa a MESMA closure que o `rectify` congela, BUILD_DEPS inclusive, porque é
/// dela que o fingerprint sai; um subconjunto daria outro número.
pub fn fingerprint(ctx: &Ctx, names: &[String]) -> Result<()> {
    let mut identity: Vec<Recipe> = Vec::new();
    let mut seen = HashSet::new();
    for name in names {
        collect_identity(ctx, name, &mut seen, &mut Vec::new(), &mut identity)?;
    }
    let fingerprints = recipe::build_fingerprints(&identity)?;
    let mut nomes: Vec<&String> = fingerprints.keys().collect();
    nomes.sort();
    for nome in nomes {
        println!("{nome} {}", fingerprints[nome]);
    }
    Ok(())
}

/// Confere que os insumos pinados de cada pacote já estão no cache, incluindo
/// assinaturas destacadas, sem baixar nem instalar nada. O contexto offline
/// local torna essa promessa independente das flags fornecidas pelo chamador.
pub fn cache_verify(ctx: &Ctx, names: &[String]) -> Result<()> {
    let offline = Ctx {
        root: ctx.root.clone(),
        offline: true,
        tofu: false,
        jobs: ctx.jobs,
    };
    for name in names {
        let recipe = recipe::load(&offline, name)?;
        fetch::ensure_artifacts(&offline, &recipe)?;
        println!("cache íntegro: {} {}", recipe.name, recipe.version);
    }
    Ok(())
}

const BUILD_LINT_FORMAT: &str = "2";

/// Aliases de ferramentas cuja grafia executada não coincide com o nome do
/// pacote canônico. São apenas candidatos para o estado `DESCONHECIDO`: sem
/// claim factual o lint jamais os promove a sucesso.
const BUILD_COMMAND_PROVIDER_ALIASES: &[(&str, &[&str])] = &[
    ("msgfmt", &["gettext"]),
    ("pkg-config", &["pkgconf"]),
    ("python3", &["python-glibc", "python"]),
];

#[derive(Default)]
struct BuildCommandProviders {
    by_name: BTreeMap<String, BTreeSet<String>>,
    by_path: BTreeMap<String, BTreeSet<String>>,
}

fn effective_recipe_names(ctx: &Ctx) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for tree in ctx.newspeak_paths() {
        if !recipe::validate_newspeak_tree(&tree)? {
            continue;
        }
        let entries = match fs::read_dir(&tree) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut candidates = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.path().join("recipe").is_file() {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nome de receita não UTF-8 em {}", tree.display()))?;
            recipe::validate_name(&name)?;
            candidates.push(name);
        }
        candidates.sort();
        for name in candidates {
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
    }
    names.sort();
    Ok(names)
}

fn installed_build_command_providers(ctx: &Ctx) -> Result<BuildCommandProviders> {
    let mut providers = BuildCommandProviders::default();
    let mut command_directories = Vec::new();
    for directory in recipe::BUILD_EXEC_DIRS {
        if let Some(directory) = canonical_build_directory(ctx, directory)? {
            if !command_directories.contains(&directory) {
                command_directories.push(directory);
            }
        }
    }
    let records = ctx.records_dir();
    let entries = match fs::read_dir(&records) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(providers),
        Err(error) => return Err(error.into()),
    };
    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            directories.push(entry.path());
        }
    }
    directories.sort();
    for record in directories {
        let name = record
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow::anyhow!("registro com nome não UTF-8"))?;
        recipe::validate_name(name)?;
        let Some(meta) = read_meta_strict(&record)? else {
            continue;
        };
        ensure_supported_record_format(&meta, name)?;
        let manifest = read_manifest_strict(&record)
            .with_context(|| format!("{name}: manifesto para lint de build"))?;
        let mut executables = BTreeMap::new();
        for line in manifest {
            validate_manifest_line_for_record(&meta, name, &line)?;
            let path = canonical_virtual_path(&ctx.root, manifest_path(&line))?;
            let tree = manifest_integrity(&line).is_some_and(|tag| tag.starts_with("d:"));
            collect_claim_executables(ctx, &path, tree, name, &mut executables)?;
        }
        for path in executables.into_keys() {
            let in_command_directory = command_directories
                .iter()
                .any(|directory| path_under(&path, directory));
            providers
                .by_path
                .entry(path.clone())
                .or_default()
                .insert(name.to_string());
            if in_command_directory {
                let Some(command) = Path::new(&path).file_name().and_then(OsStr::to_str) else {
                    continue;
                };
                providers
                    .by_name
                    .entry(command.to_string())
                    .or_default()
                    .insert(name.to_string());
            }
        }
    }
    Ok(providers)
}

/// Diz se o record factual de um provedor já representa exatamente o snapshot
/// que a resolução congelada pretende usar. `SUPERSEDES` sozinho não prova que
/// o sucessor entregará um comando: antes do build dele só sabemos que ele pode
/// tomar a claim do provisional, não que de fato a tomará.
fn exact_build_provider_record(
    ctx: &Ctx,
    provider: &Recipe,
    expected_fingerprint: &str,
) -> Result<bool> {
    let record = ctx.records_dir().join(&provider.name);
    let Some(meta) = read_meta_strict(&record)? else {
        return Ok(false);
    };
    ensure_supported_record_format(&meta, &provider.name)?;
    Ok(meta.get("VERSION") == Some(&provider.version)
        && meta.get("FINGERPRINT").map(String::as_str) == Some(expected_fingerprint)
        && record_is_intact(ctx, &record, provider))
}

struct AllowedProviderProof {
    exact: bool,
    pending: Vec<String>,
}

/// Prova uma claim cujo dono atual já está na closure. A mera coincidência de
/// nome não basta: se VERSION/fingerprint/record estão stale, o plano vai
/// reconstruir esse provedor antes do consumidor e o manifesto resultante
/// ainda não é conhecido.
fn allowed_provider_proof(
    ctx: &Ctx,
    current_providers: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
    recipes: &HashMap<&str, &Recipe>,
    fingerprints: &HashMap<String, String>,
) -> Result<AllowedProviderProof> {
    let mut proof = AllowedProviderProof {
        exact: false,
        pending: Vec::new(),
    };
    for name in current_providers
        .iter()
        .filter(|name| allowed.contains(*name))
    {
        let provider = recipes
            .get(name.as_str())
            .copied()
            .ok_or_else(|| crate::Fail {
                code: 2,
                msg: format!("snapshot de lint sem receita para {name}"),
            })?;
        let fingerprint = fingerprints.get(name).ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("snapshot de lint sem fingerprint para {name}"),
        })?;
        if exact_build_provider_record(ctx, provider, fingerprint)? {
            proof.exact = true;
        } else {
            proof.pending.push(name.clone());
        }
    }
    Ok(proof)
}

/// Candidatos permitidos para um comando que ainda não possui claim factual.
/// O caso comum é nome do pacote == basename do comando; aliases excepcionais
/// ficam explícitos acima. Isto só distingue "aresta existe, falta rebuild"
/// de "nenhuma aresta conhecida" — disponibilidade continua exigindo record,
/// fingerprint e claim exatos em [`allowed_provider_proof`].
fn unproved_allowed_provider_candidates(command: &str, allowed: &BTreeSet<String>) -> Vec<String> {
    let basename = Path::new(command)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(command);
    let mut candidates = Vec::new();
    if allowed.contains(basename) {
        candidates.push(basename.to_string());
    }
    if let Some((_, aliases)) = BUILD_COMMAND_PROVIDER_ALIASES
        .iter()
        .find(|(name, _)| *name == basename)
    {
        for provider in aliases.iter().copied() {
            if allowed.contains(provider) {
                candidates.push(provider.to_string());
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

/// Retorna sucessores permitidos cuja claim final ainda não pode ser provada.
///
/// O mapa de comandos descreve as claims *atuais*. Quando uma aresta permitida
/// aponta para um pacote que declara `SUPERSEDES=<dono atual>`, mas esse pacote
/// ainda não tem record íntegro no fingerprint congelado, o plano o materializa
/// antes do consumidor e o ownership pode mudar. Classificar o dono provisional
/// atual como uma aresta ausente seria um falso positivo; classificar o comando
/// como disponível também seria uma promessa sem claim. O estado correto e
/// fail-closed é `DESCONHECIDO` até o sucessor produzir o record exato.
fn pending_allowed_superseders(
    ctx: &Ctx,
    current_providers: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
    recipes: &HashMap<&str, &Recipe>,
    fingerprints: &HashMap<String, String>,
) -> Result<Vec<String>> {
    let mut pending = Vec::new();
    for name in allowed {
        let Some(candidate) = recipes.get(name.as_str()).copied() else {
            continue;
        };
        if !candidate
            .supersedes
            .iter()
            .any(|cedent| current_providers.contains(cedent))
        {
            continue;
        }
        let fingerprint = fingerprints.get(name).ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("snapshot de lint sem fingerprint para {name}"),
        })?;
        if !exact_build_provider_record(ctx, candidate, fingerprint)? {
            pending.push(name.clone());
        }
    }
    Ok(pending)
}

fn shell_function_names(text: &str) -> BTreeSet<String> {
    let mut functions = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim_start();
        let Some(open) = line.find("()") else {
            continue;
        };
        let name = &line[..open];
        if !name.is_empty()
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
            && line[open + 2..].trim_start().starts_with('{')
        {
            functions.insert(name.to_string());
        }
    }
    functions
}

fn build_function_body(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("build()") && trimmed.contains('{')
    })?;
    // O formato Newspeak exige `build()` como a última definição da receita
    // fonte. Tomar até EOF evita interpretar `}` dentro de heredocs como o fim
    // da função; o próprio `recipe::load` já validou a sintaxe com o shell.
    Some(lines[start..].join("\n") + "\n")
}

#[derive(Debug)]
enum ShellToken {
    Word(String),
    Separator,
    CommandSubStart,
    CommandSubEnd,
    OpenParen,
    CloseParen,
    CaseEnd,
}

fn consume_shell_arithmetic(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let mut depth = 1usize;
    while let Some(character) = chars.next() {
        match character {
            '(' => depth += 1,
            ')' if depth == 1 && chars.peek() == Some(&')') => {
                chars.next();
                break;
            }
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
}

fn consume_shell_parameter(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let mut depth = 1usize;
    for character in chars.by_ref() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
}

fn shell_tokens_without_heredocs(body: &str) -> Vec<ShellToken> {
    let mut filtered = String::new();
    let mut heredocs: Vec<String> = Vec::new();
    for line in body.lines() {
        if let Some(delimiter) = heredocs.first() {
            let candidate = line.trim_start_matches('\t');
            if candidate == delimiter {
                heredocs.remove(0);
            }
            continue;
        }
        filtered.push_str(line);
        filtered.push('\n');
        let bytes = line.as_bytes();
        let mut offset = 0usize;
        while offset + 1 < bytes.len() {
            if bytes[offset] != b'<' || bytes[offset + 1] != b'<' {
                offset += 1;
                continue;
            }
            offset += 2;
            if bytes.get(offset) == Some(&b'-') {
                offset += 1;
            }
            while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
                offset += 1;
            }
            let quote = bytes
                .get(offset)
                .copied()
                .filter(|byte| matches!(byte, b'\'' | b'"'));
            if quote.is_some() {
                offset += 1;
            }
            let start = offset;
            while let Some(byte) = bytes.get(offset) {
                if quote.is_some_and(|quote| *byte == quote)
                    || (quote.is_none()
                        && (byte.is_ascii_whitespace() || b";&|()<>".contains(byte)))
                {
                    break;
                }
                offset += 1;
            }
            if offset > start {
                heredocs.push(String::from_utf8_lossy(&bytes[start..offset]).into_owned());
            }
            if quote.is_some() && bytes.get(offset) == quote.as_ref() {
                offset += 1;
            }
        }
    }

    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let flush = |tokens: &mut Vec<ShellToken>, word: &mut String| {
        if !word.is_empty() {
            tokens.push(ShellToken::Word(std::mem::take(word)));
        }
    };
    let mut chars = filtered.chars().peekable();
    let mut command_substitution_depth = 0usize;
    // O scanner consome lookahead do mesmo iterador para `$(`, escapes e
    // operadores compostos; um `for` manteria o empréstimo durante o corpo.
    #[allow(clippy::while_let_on_iterator)]
    while let Some(character) = chars.next() {
        if escaped {
            word.push(character);
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                } else {
                    word.push(character);
                }
            }
            Some('"') => match character {
                '"' => quote = None,
                '\\' => escaped = true,
                '$' if chars.peek() == Some(&'(') => {
                    chars.next();
                    if chars.peek() == Some(&'(') {
                        chars.next();
                        consume_shell_arithmetic(&mut chars);
                        word.push('$');
                    } else {
                        flush(&mut tokens, &mut word);
                        command_substitution_depth += 1;
                        tokens.push(ShellToken::CommandSubStart);
                    }
                }
                '$' if chars.peek() == Some(&'{') => {
                    chars.next();
                    consume_shell_parameter(&mut chars);
                    word.push('$');
                }
                _ => word.push(character),
            },
            Some(_) => unreachable!(),
            None => match character {
                '\'' | '"' => quote = Some(character),
                '\\' => escaped = true,
                '#' if word.is_empty() => {
                    for next in chars.by_ref() {
                        if next == '\n' {
                            tokens.push(ShellToken::Separator);
                            break;
                        }
                    }
                }
                '$' if chars.peek() == Some(&'(') => {
                    chars.next();
                    if chars.peek() == Some(&'(') {
                        chars.next();
                        consume_shell_arithmetic(&mut chars);
                        word.push('$');
                    } else {
                        flush(&mut tokens, &mut word);
                        command_substitution_depth += 1;
                        tokens.push(ShellToken::CommandSubStart);
                    }
                }
                '$' if chars.peek() == Some(&'{') => {
                    chars.next();
                    consume_shell_parameter(&mut chars);
                    word.push('$');
                }
                character if character.is_whitespace() => {
                    flush(&mut tokens, &mut word);
                    if character == '\n' {
                        tokens.push(ShellToken::Separator);
                    }
                }
                ')' => {
                    flush(&mut tokens, &mut word);
                    if command_substitution_depth == 0 {
                        tokens.push(ShellToken::CloseParen);
                    } else {
                        command_substitution_depth -= 1;
                        tokens.push(ShellToken::CommandSubEnd);
                    }
                }
                '(' => {
                    flush(&mut tokens, &mut word);
                    tokens.push(ShellToken::OpenParen);
                }
                ';' if chars.peek() == Some(&';') => {
                    flush(&mut tokens, &mut word);
                    chars.next();
                    if chars.peek() == Some(&'&') {
                        chars.next();
                    }
                    tokens.push(ShellToken::CaseEnd);
                }
                '{' if chars.peek() == Some(&'}') => {
                    word.push('{');
                    chars.next();
                    word.push('}');
                }
                ';' | '|' | '&' | '{' | '}' => {
                    flush(&mut tokens, &mut word);
                    tokens.push(ShellToken::Separator);
                    if matches!(character, '|' | '&') && chars.peek() == Some(&character) {
                        chars.next();
                    }
                }
                '<' | '>' => {
                    // `2>/dev/null` e `>&2` são redirecionamentos, não
                    // comandos chamados `2`. O alvo continua deliberadamente
                    // fora do scanner: abrir arquivo não concede executável.
                    if word.chars().all(|byte| byte.is_ascii_digit()) {
                        word.clear();
                    } else {
                        flush(&mut tokens, &mut word);
                    }
                    while chars.peek().is_some_and(|next| matches!(next, '<' | '>')) {
                        chars.next();
                    }
                    if chars.peek() == Some(&'&') {
                        chars.next();
                        while chars
                            .peek()
                            .is_some_and(|next| next.is_ascii_digit() || *next == '-')
                        {
                            chars.next();
                        }
                    }
                }
                _ => word.push(character),
            },
        }
    }
    flush(&mut tokens, &mut word);
    tokens
}

fn shell_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn static_build_commands(recipe: &Recipe) -> BTreeSet<String> {
    let text = String::from_utf8_lossy(&recipe.recipe_bytes);
    let functions = shell_function_names(&text);
    let Some(body) = build_function_body(&text) else {
        return BTreeSet::new();
    };
    let builtins: BTreeSet<&str> = [
        ":", ".", "[", "alias", "bg", "break", "cd", "continue", "echo", "eval", "exit", "export",
        "false", "fc", "fg", "getopts", "hash", "jobs", "kill", "let", "local", "printf", "pwd",
        "read", "readonly", "return", "set", "shift", "source", "test", "times", "trap", "true",
        "type", "ulimit", "umask", "unalias", "unset", "wait",
    ]
    .into_iter()
    .collect();
    let control: BTreeSet<&str> = [
        "build", "if", "then", "elif", "else", "fi", "while", "until", "for", "select", "in", "do",
        "done", "case", "esac", "function", "time", "coproc",
    ]
    .into_iter()
    .collect();
    let prefixes: BTreeSet<&str> = ["!", "command", "exec", "retry"].into_iter().collect();
    let mut commands = BTreeSet::new();
    let mut expect_command = true;
    let mut command_substitutions = Vec::new();
    let mut for_header = false;
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum CaseState {
        AwaitIn,
        AwaitPattern,
        InBranch,
    }
    let mut cases = Vec::new();
    for token in shell_tokens_without_heredocs(&body) {
        match token {
            ShellToken::CaseEnd => {
                if let Some(state) = cases.last_mut() {
                    *state = CaseState::AwaitPattern;
                    expect_command = false;
                } else {
                    expect_command = true;
                }
            }
            ShellToken::CloseParen if cases.last().copied() == Some(CaseState::AwaitPattern) => {
                *cases.last_mut().unwrap() = CaseState::InBranch;
                expect_command = true;
            }
            ShellToken::Word(word) if word == "esac" && !cases.is_empty() => {
                let _ = cases.pop();
                expect_command = false;
            }
            ShellToken::Word(word) if cases.last().copied() == Some(CaseState::AwaitIn) => {
                if word == "in" {
                    *cases.last_mut().unwrap() = CaseState::AwaitPattern;
                }
                expect_command = false;
            }
            ShellToken::Word(_) | ShellToken::Separator | ShellToken::OpenParen
                if cases.last().copied() == Some(CaseState::AwaitPattern) => {}
            ShellToken::Separator => expect_command = true,
            ShellToken::CommandSubStart => {
                command_substitutions.push(expect_command);
                expect_command = true;
            }
            ShellToken::CommandSubEnd => {
                let _ = command_substitutions.pop();
                // O resultado de `$(...)` ocupa uma palavra no comando
                // externo, ainda que apareça na primeira posição e seja
                // portanto dinâmico demais para o lint estático.
                expect_command = false;
            }
            ShellToken::OpenParen => expect_command = true,
            ShellToken::CloseParen => expect_command = false,
            ShellToken::Word(word) if for_header => {
                if word == "do" {
                    for_header = false;
                    expect_command = true;
                }
            }
            ShellToken::Word(word) if !expect_command => {
                if matches!(word.as_str(), "then" | "elif" | "else" | "do") {
                    expect_command = true;
                }
            }
            ShellToken::Word(word) if shell_assignment(&word) => {}
            ShellToken::Word(word) if word == "case" => {
                cases.push(CaseState::AwaitIn);
                expect_command = false;
            }
            ShellToken::Word(word) if word == "for" || word == "select" => {
                for_header = true;
            }
            ShellToken::Word(word) if control.contains(word.as_str()) => {}
            ShellToken::Word(word) if prefixes.contains(word.as_str()) => {}
            ShellToken::Word(word) if word.starts_with('-') => {}
            ShellToken::Word(word)
                if builtins.contains(word.as_str()) || functions.contains(&word) =>
            {
                expect_command = false;
            }
            ShellToken::Word(word) => {
                expect_command = false;
                if word.contains('$')
                    || word.chars().any(char::is_whitespace)
                    || word.starts_with("./")
                    || word.starts_with("../")
                    || (!word.starts_with('/') && word.contains('/'))
                    || word == "!"
                {
                    continue;
                }
                commands.insert(word);
            }
        }
    }
    commands
}

fn toolchain_literal_commands(toolchain: Toolchain) -> BTreeSet<&'static str> {
    match toolchain {
        Toolchain::None => BTreeSet::new(),
        Toolchain::Seed => ["cc", "gcc", "c++", "g++", "ld", "ar", "ranlib"]
            .into_iter()
            .collect(),
        // O perfil cross injeta somente os mesmos shims host do seed. Os
        // executáveis prefixados continuam vindo dos BUILD_DEPS declarados e
        // portanto precisam aparecer na auditoria estática.
        Toolchain::Cross => ["cc", "gcc", "c++", "g++", "ld", "ar", "ranlib"]
            .into_iter()
            .collect(),
        Toolchain::Native => BTreeSet::new(),
    }
}

/// Auditoria estática de comandos da receita. É deliberadamente um limite
/// inferior: o confinamento continua sendo a autoridade quando configure/make
/// executam ramos que não aparecem literalmente no `build()`.
pub fn lint_build(ctx: &Ctx, requested: &[String]) -> Result<()> {
    // O mapa de provedores e os manifests precisam pertencer ao mesmo estado
    // factual. Sem o lock, um rectify concorrente poderia fazer a auditoria
    // atribuir comando e closure a snapshots diferentes.
    let _lock = acquire_lock(ctx)?;
    let (names, catalog) = if requested.is_empty() {
        let names = effective_recipe_names(ctx)?;
        // Carregar a árvore efetiva uma vez evita reavaliar a mesma receita
        // para cada consumidor durante a auditoria global. Além de mais
        // rápido, dá ao relatório um único snapshot lógico do catálogo.
        let catalog = names
            .iter()
            .map(|name| recipe::load(ctx, name))
            .collect::<Result<Vec<_>>>()?;
        (names, catalog)
    } else {
        let mut catalog = Vec::new();
        let mut seen = HashSet::new();
        for name in requested {
            collect_identity(ctx, name, &mut seen, &mut Vec::new(), &mut catalog)?;
        }
        (requested.to_vec(), catalog)
    };
    let by_name: HashMap<&str, &Recipe> = catalog
        .iter()
        .map(|recipe| (recipe.name.as_str(), recipe))
        .collect();
    let fingerprints = recipe::build_fingerprints(&catalog)?;
    let command_providers = installed_build_command_providers(ctx)?;
    let mut missing = 0usize;
    let mut unresolved = 0usize;
    let mut inspected = 0usize;
    println!("BUILD_LINT_FORMAT={BUILD_LINT_FORMAT}");
    println!("BUILD_RUNNER_FORMAT={}", recipe::BUILD_RUNNER_FORMAT);
    println!("BUILD_VIEW_FORMAT={}", recipe::BUILD_VIEW_FORMAT);
    println!("BUILD_SYSROOT_FORMAT={}", recipe::BUILD_SYSROOT_FORMAT);
    println!(
        "BUILD_CONTRACT_SHA256={}",
        sha256_bytes(recipe::build_runner_material().as_bytes())
    );
    for name in names {
        let recipe = by_name
            .get(name.as_str())
            .copied()
            .ok_or_else(|| crate::Fail {
                code: 2,
                msg: format!("receita não encontrada para lint: {name}"),
            })?;
        if recipe.kind != Kind::Source {
            continue;
        }
        inspected += 1;
        let allowed: BTreeSet<String> = build_provider_closure(recipe, &by_name)?
            .into_keys()
            .collect();
        let shims = toolchain_literal_commands(recipe.toolchain);
        let runner_shell = canonical_virtual_path(&ctx.root, "/bin/sh").ok();
        for command in static_build_commands(recipe) {
            if recipe::BUILD_BASE_COMMANDS.contains(&command.as_str()) {
                continue;
            }
            let (lookup, display) = if command.starts_with('/') {
                let path = canonical_virtual_path(&ctx.root, &command).unwrap_or(command.clone());
                if runner_shell.as_deref() == Some(path.as_str()) {
                    continue;
                }
                (command_providers.by_path.get(&path), command.clone())
            } else {
                (command_providers.by_name.get(&command), command.clone())
            };
            if shims.contains(command.as_str()) {
                continue;
            }
            match lookup {
                Some(providers) => {
                    let allowed_proof =
                        allowed_provider_proof(ctx, providers, &allowed, &by_name, &fingerprints)?;
                    if allowed_proof.exact {
                        continue;
                    }
                    let pending = pending_allowed_superseders(
                        ctx,
                        providers,
                        &allowed,
                        &by_name,
                        &fingerprints,
                    )?;
                    if allowed_proof.pending.is_empty() && pending.is_empty() {
                        missing += 1;
                        println!(
                            "ERRO\t{name}\t{display}\t{}\tadicione o provedor a DEPS ou BUILD_DEPS",
                            providers.iter().cloned().collect::<Vec<_>>().join(",")
                        );
                    } else {
                        unresolved += 1;
                        let mut pending_providers = allowed_proof.pending;
                        pending_providers.extend(pending);
                        pending_providers.sort();
                        pending_providers.dedup();
                        println!(
                            "DESCONHECIDO\t{name}\t{display}\t?\tclaims atuais de {}; provedor(es) permitido(s) {} ainda sem record íntegro no fingerprint esperado",
                            providers.iter().cloned().collect::<Vec<_>>().join(","),
                            pending_providers.join(",")
                        );
                    }
                }
                None => {
                    let candidates = unproved_allowed_provider_candidates(&command, &allowed);
                    if candidates.is_empty() {
                        missing += 1;
                        println!(
                            "ERRO\t{name}\t{display}\t?\tnenhum provedor permitido conhecido; adicione-o a DEPS ou BUILD_DEPS"
                        );
                    } else {
                        unresolved += 1;
                        println!(
                            "DESCONHECIDO\t{name}\t{display}\t?\tprovedor(es) permitido(s) {} ainda sem record/claim factual",
                            candidates.join(",")
                        );
                    }
                }
            }
        }
    }
    println!("SUMMARY\treceitas={inspected}\tfaltantes={missing}\tdesconhecidos={unresolved}");
    if missing != 0 || unresolved != 0 {
        return fail(
            5,
            format!(
                "lint de build encontrou {missing} ferramenta(s) sem aresta e {unresolved} sem provedor conhecido"
            ),
        );
    }
    Ok(())
}

pub fn rectify(ctx: &Ctx, names: &[String], policy: BinaryPolicy) -> Result<()> {
    let _lock = acquire_lock(ctx)?; // segurado até o fim da operação
                                    // Uma transação órfã de outro pacote pode ter substituído justamente um
                                    // caminho que o pacote pedido pretende tomar. Resolva-a antes de carregar
                                    // ownership, executar builds ou fazer qualquer mutação nova.
    Journal::recover_all(ctx)?;
    ensure_real_directory_or_absent(
        &ctx.root,
        &ctx.root.join("etc/minitrue"),
        "configuração do minitrue",
    )?;
    ensure_no_internal_claims(ctx)?;
    let explicit: HashSet<&str> = names.iter().map(String::as_str).collect();
    let mut plan = crate::plan::resolve(
        ctx,
        names,
        policy,
        crate::plan::AbiPolicy::Development,
        channel::LoadMode::Mutating,
    )?;
    // Nenhum lock/snapshot é publicado antes de todos os objetos ativos e
    // assinaturas terem sido autenticados contra exatamente esta seleção.
    plan.authenticate_objects(ctx, false)?;
    plan.revalidate_tree(ctx)?;
    // Esta é a última fronteira antes de qualquer payload/record da operação:
    // todos os namespaces de lock, slice, record, receipt e current são
    // abertos sem seguir symlink e inspecionados por inteiro.
    plan.preflight_publication(ctx)?;
    // O record de canal precisa do CHANNEL_LOCK durante a instalação, mas o
    // PLAN_LOCK só pode nascer depois que payload e ABI forem reobservados.
    plan.persist_channels(ctx)?;

    let frozen_build_graph = FrozenBuildGraph::new(&plan);
    let mut interrompida: Option<anyhow::Error> = None;
    for name in &plan.order {
        let node = plan
            .nodes
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("plano perdeu o nó {name}"))?;
        if node.materiality != crate::plan::Materiality::Runtime {
            continue;
        }
        let r = frozen_build_graph
            .recipes
            .get(name.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("plano perdeu a receita {name}"))?;
        if node.action == crate::plan::PlanAction::Keep {
            // Keep v3 não passa pelo fast-path genérico: ele só será aceito
            // pela reauditoria/finalização deste ResolvedPlan e não vira
            // provider de build desta operação.
            continue;
        }
        let fingerprint = plan.fingerprints.get(&r.name).ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("snapshot sem fingerprint para {}", r.name),
        })?;
        // A falha de UM pacote não pode mais custar tudo o que já foi
        // construído. Ela é capturada aqui para que o fechamento parcial rode
        // antes de o erro subir — e o erro original sobe intacto depois.
        if let Err(erro) = install_one(
            ctx,
            r,
            explicit.contains(r.name.as_str()),
            fingerprint,
            policy,
            plan.channels.get(&r.name),
            &frozen_build_graph,
        )
        .and_then(|()| frozen_build_graph.observe_written_record(ctx, &r.name))
        {
            interrompida = Some(erro);
            break;
        }
    }
    let written_records = frozen_build_graph.intermediate_records.borrow().clone();
    if let Some(erro) = interrompida {
        // FECHAMENTO PARCIAL. Sem ele, tudo o que esta execução construiu fica
        // em RECORD_FORMAT=3, e v3 não é elegível para `keep`: a próxima
        // execução reconstruiria os mesmos pacotes do zero — inclusive um
        // superseder como o gawk, que não reconstrói depois de ter tomado o
        // /usr/bin/awk do busybox, e por isso a árvore inteira era descartada a
        // cada falha. Medido: 12 pacotes numa raiz interrompida, e o plano de
        // retomada propunha reconstruir 10.
        //
        // As raízes são os pacotes que TERMINARAM, e a closure deles está
        // completa por construção, porque dependência instala antes de
        // dependente. O que falhou não está entre elas.
        if written_records.is_empty() {
            return Err(erro);
        }
        let raizes: Vec<String> = written_records.iter().cloned().collect();
        match crate::plan::finalize_applied(
            ctx,
            &raizes,
            crate::plan::PlanPurpose::Rectify,
            policy,
            crate::plan::AbiPolicy::Development,
            &written_records,
            crate::plan::AppliedClosure::Partial,
        ) {
            Ok(parcial) => eprintln!(
                "  fechamento parcial: {} pacote(s) preservados para a próxima execução ({})",
                written_records.len(),
                parcial.lock_sha256
            ),
            // O fechamento parcial é conveniência, não correção: se ele falhar,
            // o estado continua exatamente o que era e a próxima execução
            // reconstrói. O que não pode acontecer é a falha dele ESCONDER a
            // falha real do build, que é o que o usuário precisa ler.
            Err(secundario) => eprintln!(
                "  aviso: fechamento parcial não pôde ser feito ({secundario:#}); \
                 a próxima execução reconstruirá o que esta fez"
            ),
        }
        return Err(erro);
    }
    let finalized = crate::plan::finalize_applied(
        ctx,
        names,
        crate::plan::PlanPurpose::Rectify,
        policy,
        crate::plan::AbiPolicy::Development,
        &written_records,
        crate::plan::AppliedClosure::Complete,
    )?;
    eprintln!(
        "  plano aplicado fechado: {} ({} material(is))",
        finalized.lock_sha256,
        finalized.identities.len()
    );
    // AQUI HAVIA UM RESUMO DE "correções não aplicadas", e o fato de ele não
    // existir mais é o conserto inteiro contado em uma linha.
    //
    // Ele foi escrito quando um provisional que já cedeu caminhos não podia ser
    // reconstruído: o rectify comparava a impressão digital, via que a receita
    // tinha mudado, e seguia adiante — de modo que toda correção escrita num
    // dos nove provisionais desde o bootstrap ficava inerte. O resumo tornava
    // isso VISÍVEL, que era metade do conserto; a outra metade era aplicar a
    // correção, e é o que o refresh agora faz.
    //
    // Reconstruir sempre foi possível — bastava não retomar o que foi cedido.
    // Com o refresh no lugar, `anotar_correcao_descartada` ficou sem chamador
    // nenhum, e foi o compilador quem apontou isso.
    Ok(())
}

fn collect_identity(
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
    // DEPS (runtime), BUILD_DEPS e a dependência implicada pela TOOLCHAIN
    // precisam existir antes deste pacote compilar; só as DEPS entram no meta
    // como dependências de runtime.
    for d in r.deps.iter().chain(r.build_deps.iter()) {
        collect_identity(ctx, d, seen, stack, out)?;
    }
    for d in r.toolchain_build_deps() {
        collect_identity(ctx, d, seen, stack, out)?;
    }
    for d in r.runner_build_deps() {
        collect_identity(ctx, d, seen, stack, out)?;
    }
    for d in r.ccache_build_deps() {
        collect_identity(ctx, d, seen, stack, out)?;
    }
    stack.pop();
    out.push(r);
    Ok(())
}

#[cfg(test)]
pub(crate) fn binary_needs_install(ctx: &Ctx, recipe: &Recipe, fingerprint: &str) -> Result<bool> {
    binary_needs_install_for_plan(ctx, recipe, fingerprint, false)
}

pub(crate) fn binary_needs_install_for_plan(
    ctx: &Ctx,
    recipe: &Recipe,
    fingerprint: &str,
    allow_intermediate: bool,
) -> Result<bool> {
    let rec_dir = ctx.records_dir().join(&recipe.name);
    let opt = ctx.opt(&recipe.name);
    let Some(meta) = read_meta_strict(&rec_dir)? else {
        return Ok(true);
    };
    ensure_supported_record_format(&meta, &recipe.name)?;
    Ok(!(meta.get("VERSION") == Some(&recipe.version)
        && meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint)
        && fs::read_link(opt.join("current")).ok() == Some(PathBuf::from(&recipe.version))
        && opt.join(&recipe.version).is_dir()
        && record_is_intact_for_plan(ctx, &rec_dir, recipe, allow_intermediate)))
}

/// Uma cessão sem dono atual só pode atravessar até a prova do novo STAGE
/// quando há duas identidades factuais e elas diferem. Campo ausente não prova
/// mudança: registro legado ou truncado permanece fail-closed neste caso.
fn installed_identity_changed(
    meta: &HashMap<String, String>,
    recipe: &Recipe,
    fingerprint: &str,
) -> bool {
    match (meta.get("VERSION"), meta.get("FINGERPRINT")) {
        (Some(version), Some(installed_fingerprint)) => {
            version != &recipe.version || installed_fingerprint != fingerprint
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) fn source_needs_install(
    ctx: &Ctx,
    recipe: &Recipe,
    fingerprint: &str,
    policy: BinaryPolicy,
) -> Result<bool> {
    source_needs_install_for_plan(ctx, recipe, fingerprint, policy, false)
}

pub(crate) fn source_needs_install_for_plan(
    ctx: &Ctx,
    recipe: &Recipe,
    fingerprint: &str,
    policy: BinaryPolicy,
    allow_intermediate: bool,
) -> Result<bool> {
    let rec_dir = ctx.records_dir().join(&recipe.name);
    let Some(meta) = read_meta_strict(&rec_dir)? else {
        return Ok(true);
    };
    ensure_supported_record_format(&meta, &recipe.name)?;
    if meta.get("VERSION") == Some(&recipe.version)
        && meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint)
        && record_is_intact_for_plan(ctx, &rec_dir, recipe, allow_intermediate)
    {
        let came_from_channel = meta
            .get("ORIGIN")
            .is_some_and(|origin| origin.starts_with("canal:"));
        return Ok(policy == BinaryPolicy::SourceOnly && came_from_channel);
    }
    match provisional_cession_state(ctx, &rec_dir, recipe)? {
        // Uma cessao integra torna o registro utilizavel apenas enquanto ele
        // ainda descreve ESTA identidade. VERSION e FINGERPRINT diferentes
        // pedem refresh como em qualquer outro pacote; a diferenca e que o
        // refresh preservara `baseline - ativo` em vez de retomar os caminhos
        // dos sucessores.
        ProvisionalCession::Intact => Ok((!allow_intermediate
            && meta.get("RECORD_FORMAT").map(String::as_str) == Some(RECORD_FORMAT))
            || meta.get("VERSION") != Some(&recipe.version)
            || meta.get("FINGERPRINT").map(String::as_str) != Some(fingerprint)),
        ProvisionalCession::Unproved if installed_identity_changed(&meta, recipe, fingerprint) => {
            let _ = cessoes_sem_sucessor_ausentes(ctx, &rec_dir, &recipe.name)?;
            Ok(true)
        }
        ProvisionalCession::Unproved => bail!(
            "{}: cessão provisional perdeu o sucessor sem mudança comprovada de identidade",
            recipe.name
        ),
        ProvisionalCession::Incoherent => bail!(
            "{}: cessão provisional incoerente; rode verify e repare os registros",
            recipe.name
        ),
        ProvisionalCession::NotCeded => Ok(true),
    }
}

pub(crate) fn meta_needs_install_for_plan(
    ctx: &Ctx,
    recipe: &Recipe,
    fingerprint: &str,
    allow_intermediate: bool,
) -> Result<bool> {
    let rec_dir = ctx.records_dir().join(&recipe.name);
    let Some(meta) = read_meta_strict(&rec_dir)? else {
        return Ok(true);
    };
    ensure_supported_record_format(&meta, &recipe.name)?;
    Ok(!(meta.get("VERSION") == Some(&recipe.version)
        && meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint)
        && record_is_intact_for_plan(ctx, &rec_dir, recipe, allow_intermediate)))
}

struct FrozenBuildGraph<'plan> {
    plan: &'plan crate::plan::ResolvedPlan,
    recipes: HashMap<&'plan str, &'plan Recipe>,
    intermediate_records: RefCell<BTreeSet<String>>,
}

impl<'plan> FrozenBuildGraph<'plan> {
    fn new(plan: &'plan crate::plan::ResolvedPlan) -> Self {
        Self {
            plan,
            recipes: plan
                .recipes
                .values()
                .map(|recipe| (recipe.name.as_str(), recipe))
                .collect(),
            intermediate_records: RefCell::new(BTreeSet::new()),
        }
    }

    /// Registra um v3 somente na fronteira da aplicação que possui este
    /// ResolvedPlan. O nome não é uma autorização: ação, materialidade,
    /// identidade e claims são revalidados antes de entrar no snapshot que a
    /// próxima view poderá consumir.
    fn observe_written_record(&self, ctx: &Ctx, name: &str) -> Result<()> {
        let node = self
            .plan
            .nodes
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("{name}: aplicação escreveu nó fora do plano"))?;
        if node.materiality != crate::plan::Materiality::Runtime
            || node.action == crate::plan::PlanAction::Keep
        {
            bail!("{name}: aplicação não autorizava escrever record material");
        }
        let recipe = self
            .recipes
            .get(name)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("{name}: recipe ausente do ResolvedPlan"))?;
        let fingerprint = self
            .plan
            .fingerprints
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("{name}: fingerprint ausente do ResolvedPlan"))?;
        let record = ctx.records_dir().join(name);
        let meta = read_meta_strict(&record)?
            .ok_or_else(|| anyhow::anyhow!("{name}: aplicação não publicou record"))?;
        if meta.get("RECORD_FORMAT").map(String::as_str) != Some(RECORD_FORMAT)
            || meta.get("VERSION") != Some(&recipe.version)
            || meta.get("FINGERPRINT") != Some(fingerprint)
            || !record_is_intact_with_intermediate(ctx, &record, recipe, true)
        {
            bail!("{name}: record escrito não corresponde ao ResolvedPlan ativo");
        }
        self.intermediate_records
            .borrow_mut()
            .insert(name.to_string());
        Ok(())
    }
}

fn install_one(
    ctx: &Ctx,
    r: &Recipe,
    explicit: bool,
    fingerprint: &str,
    policy: BinaryPolicy,
    selection: Option<&channel::Selection>,
    frozen: &FrozenBuildGraph<'_>,
) -> Result<()> {
    // Vale inclusive se uma receita mudou de mundo B para A: nenhum fast path
    // pode observar/declarar sucesso enquanto há transação anterior por resolver.
    Journal::recover_all(ctx)?;
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
        Kind::Binary => install_binary(ctx, r, explicit, fingerprint),
        Kind::Source => install_source(ctx, r, explicit, fingerprint, policy, selection, frozen),
        Kind::Meta => install_meta(ctx, r, explicit, fingerprint),
    }
}

// ---------- mundo M: conjunto declarativo sem payload ----------

fn install_meta(ctx: &Ctx, r: &Recipe, explicit: bool, fingerprint: &str) -> Result<()> {
    let rec_dir = ctx.records_dir().join(&r.name);
    ensure_real_directory_or_absent(&ctx.root, &rec_dir, "registro do metapacote")?;
    let installed_meta = read_meta_strict(&rec_dir)?;
    if installed_meta.is_none()
        && rec_dir.is_dir()
        && fs::read_dir(&rec_dir)?.next().transpose()?.is_some()
    {
        return fail(
            4,
            format!(
                "{}: diretório de registro preexistente não tem meta; adoção recusada",
                r.name
            ),
        );
    }
    if let Some(meta) = installed_meta {
        ensure_supported_record_format(&meta, &r.name)?;
        if meta.get("VERSION") == Some(&r.version)
            && meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint)
        {
            migrate_legacy_record(ctx, &rec_dir, r, fingerprint)?;
            if record_is_intact(ctx, &rec_dir, r) {
                if explicit {
                    world_add(ctx, &r.name)?;
                }
                println!("os registros já estão corretos: {} {}", r.name, r.version);
                return Ok(());
            }
        }
        let manifest = read_manifest_strict(&rec_dir)?;
        if meta.get("KIND").map(String::as_str) != Some("meta")
            || meta.get("WORLD").map(String::as_str) != Some("M")
            || !manifest.is_empty()
        {
            return fail(
                4,
                format!(
                    "{}: registro existente tem payload ou outro mundo; migração para meta recusada",
                    r.name
                ),
            );
        }
    }

    let mut manifest = Vec::new();
    write_record(
        ctx,
        &rec_dir,
        r,
        "M",
        &mut manifest,
        RecordWrite {
            artifact_hash: None,
            fingerprint,
            manifest_typed: true,
            source_origin: SourceRecordOrigin::Local,
            journal: None,
            baseline_extra: None,
        },
    )?;
    if explicit {
        world_add(ctx, &r.name)?;
    }
    println!(
        "{} {} — conjunto declarativo retificado. doubleplusgood.",
        r.name, r.version
    );
    Ok(())
}

// ---------- mundo A: binário do mantenedor ----------

fn install_binary(ctx: &Ctx, r: &Recipe, explicit: bool, fingerprint: &str) -> Result<()> {
    let rec_dir = ctx.records_dir().join(&r.name);
    let opt = ctx.opt(&r.name);
    ensure_real_directory_or_absent(&ctx.root, &rec_dir, "registro do pacote")?;
    ensure_real_directory_or_absent(&ctx.root, &opt, "prefixo mundo A")?;
    // Caminho canônico -> linha do baseline antigo, para o que este provisional
    // já cedeu aos sucessores. Vazio em toda instalação que não seja o refresh
    // de um provisional cedido, que é o caso de absolutamente todo pacote fora
    // do busybox da semente.
    let mut cedidos: Vec<(String, String)> = Vec::new();
    if let Some(meta) = read_meta_strict(&rec_dir)? {
        ensure_supported_record_format(&meta, &r.name)?;
        if meta.get("VERSION") == Some(&r.version)
            && meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint)
            && fs::read_link(opt.join("current")).ok() == Some(PathBuf::from(&r.version))
            && opt.join(&r.version).is_dir()
        {
            migrate_legacy_record(ctx, &rec_dir, r, fingerprint)?;
            if record_is_intact(ctx, &rec_dir, r) {
                if explicit {
                    world_add(ctx, &r.name)?;
                }
                println!("os registros já estão corretos: {} {}", r.name, r.version);
                return Ok(());
            }
        }
        // Um provisional que já cedeu parte do baseline não pode ser
        // reconstruído do jeito comum, porque a reconstrução comum reivindica
        // tudo o que o build produz — inclusive o que os sucessores já tomaram.
        // v2 com identidade atual passou primeiro pelo fast path forte acima.
        match provisional_cession_state(ctx, &rec_dir, r)? {
            ProvisionalCession::Intact => {
                if explicit {
                    world_add(ctx, &r.name)?;
                }
                let versao = meta.get("VERSION").map(String::as_str).unwrap_or("?");
                // Chegar aqui significa que o fast path acima nao valeu, e isso
                // acontece por tres motivos bem diferentes:
                //
                //   fingerprint IGUAL     o registro so nao esta "intacto"
                //                         porque a cessao encolheu o manifesto.
                //                         Nao ha nada a fazer, e "baseline
                //                         preservado" descreve bem.
                //   fingerprint DIFERENTE alguem corrigiu a receita. A correcao
                //                         ENTRA, sobre os caminhos que ainda
                //                         sao deste pacote.
                //   SEM fingerprint       registro legado v1, anterior a
                //                         identidade por closure. NAO SE SABE
                //                         se corresponde a receita de hoje, e
                //                         "nao sei provar" nao e "corresponde".
                //                         Refresca tambem — foi este o caso que
                //                         manteve o `chmod 4755` do busybox
                //                         fora do rootfs da semente enquanto a
                //                         primeira versao deste conserto so
                //                         olhava o ramo do meio.
                match meta.get("FINGERPRINT") {
                    gravado_opt if gravado_opt.map(String::as_str) != Some(fingerprint) => {
                        let gravado = gravado_opt.map(String::as_str).unwrap_or("legado-v1");
                        // A SEGUNDA METADE DO CONSERTO. Antes disto a correção
                        // era só ANOTADA como descartada: o aviso era honesto,
                        // mas o que a receita mandava nunca chegava ao disco, e
                        // a única saída era um bootstrap do zero. Foi assim que
                        // o `chmod 4755` do busybox ficou seis versões fora do
                        // rootfs de build enquanto a receita o pedia.
                        //
                        // Reconstruir é seguro desde que não se retome o que foi
                        // cedido. O conjunto cedido é exatamente
                        // `baseline - ativo`, e ele desce daqui para o caminho
                        // de reconstrução comum, que passa a PULAR esses
                        // caminhos em vez de reivindicá-los.
                        cedidos = caminhos_cedidos(ctx, &rec_dir, versao)?;
                        let motivo = if gravado_opt.is_none() {
                            "registro legado sem identidade".to_string()
                        } else {
                            format!(
                                "receita mudou ({}… -> {}…)",
                                &gravado[..12.min(gravado.len())],
                                &fingerprint[..12.min(fingerprint.len())]
                            )
                        };
                        println!(
                            "provisório {} {}: {motivo}; refrescando o que ainda é dele, \
                             {} caminho(s) cedido(s) intocado(s)",
                            r.name,
                            versao,
                            cedidos.len()
                        );
                        for (caminho, _) in &cedidos {
                            println!("  cedido, preservado: {caminho}");
                        }
                        // e cai para a reconstrução, abaixo
                    }
                    _ => {
                        println!(
                            "provisório {} {} já cedeu caminhos; baseline preservado.",
                            r.name, versao
                        );
                        return Ok(());
                    }
                }
            }
            ProvisionalCession::Incoherent => bail!(
                "{}: cessão provisional incoerente; rode verify e repare os registros antes de reconstruir",
                r.name
            ),
            ProvisionalCession::Unproved => bail!(
                "{}: cessão provisional perdeu o sucessor; refresh binário não tem STAGE selado para provar aposentadoria",
                r.name
            ),
            ProvisionalCession::NotCeded => {}
        }
    }

    println!("retificando os registros: {} {}", r.name, r.version);
    let artifacts = fetch::ensure_artifacts(ctx, r)?;

    let staging = opt.join(format!(".{}.tmp", r.version));
    let work = ctx
        .root
        .join("tmp")
        .join(format!("minitrue-work-{}", r.name));
    ensure_paths_unclaimed(
        ctx,
        &r.name,
        &[(&opt, "prefixo mundo A"), (&work, "workspace mundo A")],
    )?;
    fs::create_dir_all(&opt)?;
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    ensure_mutation_confined(&ctx.root, &work)?;
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work)?;
    r.materialize_files(&work)?;
    let recipe_snapshot = work.join("recipe");
    write_new(&recipe_snapshot, &r.recipe_bytes)?;

    let mut cmd = Command::new("sh");
    cmd.arg("-ec")
        .arg(". \"$RECIPE\"\ninstall_pkg")
        .current_dir(&work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &work)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("RECIPE", &recipe_snapshot)
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

    // Falhas determinísticas de topologia/permissão do payload precisam surgir
    // antes de trocar `current`. O hash final ainda é recalculado no registro.
    let _ = crate::pack::pack_deterministic(&staging, 0, std::io::sink())?;

    let verdir = opt.join(&r.version);
    let previous = read_meta_strict(&rec_dir)?
        .and_then(|m| m.get("VERSION").cloned())
        .filter(|v| *v != r.version);
    let pairs: Vec<(String, String)> = if r.links.is_empty() {
        let bin = staging.join("bin");
        let mut v = Vec::new();
        if bin.is_dir() {
            for e in fs::read_dir(&bin)? {
                let name = e?
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{}: comando não UTF-8 em bin/", r.name))?;
                v.push((name.clone(), format!("bin/{name}")));
            }
        }
        v.sort();
        v
    } else {
        r.links.clone()
    };
    for (command, relative) in &pairs {
        recipe::validate_link(&r.name, command, relative)?;
    }

    let old_links: HashSet<String> = if rec_dir.join("meta").is_file() {
        read_manifest_strict(&rec_dir)?
    } else {
        Vec::new()
    }
    .iter()
    .map(|l| manifest_path(l).to_string())
    .filter(|l| l.starts_with("/usr/"))
    .collect();
    let claims = all_manifests(ctx)?;
    let mut manifest: Vec<String> = vec![
        format!("/opt/{}/{}", r.name, r.version),
        format!("/opt/{}/current", r.name),
    ];
    let mut takeovers = HashSet::new();
    // Conjunto de consulta rápida do que este pacote já cedeu. No refresh de um
    // provisional cedido, cada caminho daqui é do SUCESSOR: pular é o ponto
    // inteiro da operação. Fora desse caso o conjunto é vazio e os dois laços
    // abaixo se comportam exatamente como antes.
    let cedidos_set: HashSet<&str> = cedidos.iter().map(|(c, _)| c.as_str()).collect();
    // Ownership é decidido antes de tocar qualquer link e independe de os
    // bytes/alvo atuais coincidirem. Alvo idêntico com outro dono ainda é
    // doublethink; objeto idêntico sem dono não é adotado implicitamente.
    for (cmdname, _) in &pairs {
        let raw_virt = format!("/usr/bin/{cmdname}");
        let virt = canonical_virtual_path(&ctx.root, &raw_virt)?;
        if cedidos_set.contains(virt.as_str()) {
            continue;
        }
        let owners: Vec<&str> = claims
            .iter()
            .filter(|(_, _, set)| set.contains(&virt))
            .map(|(owner, _, _)| owner.as_str())
            .collect();
        let external: Vec<&str> = owners
            .iter()
            .copied()
            .filter(|owner| *owner != r.name)
            .collect();
        if external.len() == 1
            && is_provisional(ctx, external[0])
            && r.supersedes.iter().any(|name| name == external[0])
        {
            takeovers.insert(virt.clone());
        } else if !external.is_empty() {
            return fail(
                4,
                format!(
                    "doublethink detectado: {virt} tem donos incompatíveis: {}",
                    external.join(", ")
                ),
            );
        }
        let owned = owners.iter().any(|owner| *owner == r.name) || takeovers.contains(&virt);
        if confined_exists(&ctx.root, &raw_virt)? && !owned {
            return fail(
                4,
                format!("doublethink detectado: {virt} já existe sem dono compatível"),
            );
        }
    }

    let directory_claims = all_directory_claims(ctx)?;
    for (raw, is_directory) in [
        (format!("/opt/{}/{}", r.name, r.version), true),
        (format!("/opt/{}/current", r.name), false),
    ] {
        let virt = canonical_virtual_path(&ctx.root, &raw)?;
        let owned_by_self = claims
            .iter()
            .any(|(owner, _, set)| owner == &r.name && set.contains(&virt));
        if let Some((owner, version, path)) = claims.iter().find_map(|(owner, version, set)| {
            (owner != &r.name)
                .then(|| {
                    set.iter().find(|path| {
                        path.as_str() == virt
                            || (is_directory
                                && path
                                    .strip_prefix(virt.as_str())
                                    .is_some_and(|suffix| suffix.starts_with('/')))
                    })
                })
                .flatten()
                .map(|path| (owner, version, path))
        }) {
            return fail(
                4,
                format!("doublethink detectado: {virt} sobrepõe {path} de {owner} {version}"),
            );
        }
        if let Some((owner, version, directory)) =
            directory_claims.iter().find(|(owner, _, directory)| {
                owner != &r.name
                    && (virt == directory.as_str()
                        || virt
                            .strip_prefix(directory.as_str())
                            .is_some_and(|suffix| suffix.starts_with('/')))
            })
        {
            return fail(
                4,
                format!(
                    "doublethink detectado: {virt} está sob diretório {directory} de {owner} {version}"
                ),
            );
        }
        if confined_exists(&ctx.root, &virt)? && !owned_by_self {
            return fail(
                4,
                format!("doublethink detectado: {virt} já existe sem dono compatível"),
            );
        }
    }

    ensure_mutation_confined(&ctx.root, &ctx.usr_bin())?;
    match fs::symlink_metadata(ctx.usr_bin()) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(metadata) if metadata.file_type().is_symlink() => {
            open_confined(&ctx.root, "/usr/bin", libc::O_PATH | libc::O_DIRECTORY)?;
        }
        Ok(_) => bail!("/usr/bin existe e não é diretório"),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(ctx.usr_bin())?;
        }
        Err(error) => return Err(error.into()),
    }
    for (command, _) in &pairs {
        let virt = format!("/usr/bin/{command}");
        if let Ok(fd) = open_confined(&ctx.root, &virt, libc::O_PATH | libc::O_NOFOLLOW) {
            if fs::File::from(fd).metadata()?.file_type().is_dir() {
                bail!("{virt} é diretório e não pode virar link de comando");
            }
        }
    }
    let current_path = opt.join("current");
    if fs::symlink_metadata(&current_path).is_ok_and(|metadata| metadata.file_type().is_dir()) {
        bail!(
            "{} é diretório e não pode virar symlink",
            current_path.display()
        );
    }
    let tmp_cur = move_temp_path(&current_path)?;
    symlink(&r.version, &tmp_cur)?;

    // A fase de decisão termina antes de publicar a versão. Uma colisão ou
    // registro corrompido deixa `current`, verdir e links antigos intocados.
    if verdir.exists() {
        fs::remove_dir_all(&verdir)?;
    }
    fs::rename(&staging, &verdir)?;
    fs::rename(&tmp_cur, &current_path)?;

    for (cmdname, rel) in &pairs {
        let linkpath = ctx.usr_bin().join(cmdname);
        ensure_mutation_confined(&ctx.root, &linkpath)?;
        let target = format!("../../opt/{}/current/{}", r.name, rel);
        let raw_virt = format!("/usr/bin/{cmdname}");
        let virt = canonical_virtual_path(&ctx.root, &raw_virt)?;
        // Cedido: o link em /usr/bin já aponta para o sucessor e o manifesto
        // ativo não o reivindica. Sobrescrevê-lo aqui apagaria o `ar` do
        // binutils e o substituiria por um applet do busybox — silenciosamente,
        // e com dois pacotes achando que são donos do mesmo caminho.
        if cedidos_set.contains(virt.as_str()) {
            continue;
        }
        if takeovers.contains(&virt) {
            let owner = adopt_provisional_path(ctx, &virt, &r.name, &r.supersedes, None)?
                .ok_or_else(|| {
                    anyhow::anyhow!("{virt}: dono provisional mudou durante a operação")
                })?;
            eprintln!("  {virt}: assume o controle de {owner} (provisório)");
        }
        if confined_exists(&ctx.root, &raw_virt)? {
            remove_confined(&ctx.root, &raw_virt, false)?;
        }
        symlink(&target, &linkpath)?;
        manifest.push(raw_virt);
    }

    for l in &old_links {
        if !manifest.contains(l) {
            rooted_path(&ctx.root, l)?;
            if let Ok(target) = readlink_confined(&ctx.root, l) {
                if String::from_utf8_lossy(&target).contains(&format!("/opt/{}/", r.name)) {
                    remove_confined(&ctx.root, l, false)?;
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

    // As linhas cedidas voltam ao baseline exatamente como estavam. Ver a
    // documentação de `RecordWrite::baseline_extra` para por que o baseline não
    // pode encolher junto com o ativo.
    let linhas_cedidas: Vec<String> = cedidos.iter().map(|(_, linha)| linha.clone()).collect();
    write_record(
        ctx,
        &rec_dir,
        r,
        "A",
        &mut manifest,
        RecordWrite {
            artifact_hash: None,
            fingerprint,
            manifest_typed: false,
            source_origin: SourceRecordOrigin::Local,
            journal: None,
            baseline_extra: (!linhas_cedidas.is_empty()).then_some(&linhas_cedidas),
        },
    )?;
    if explicit {
        world_add(ctx, &r.name)?;
    }
    println!("{} {} — retificado. doubleplusgood.", r.name, r.version);
    Ok(())
}

// ---------- mundo B: compilado da fonte ----------

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BuildAuthority {
    Runtime,
    Build,
    Toolchain,
}

impl BuildAuthority {
    fn name(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Build => "build",
            Self::Toolchain => "toolchain",
        }
    }
}

/// A view de um pacote recebe a closure *runtime* de cada raiz autorizada:
/// DEPS, BUILD_DEPS e toolchain. BUILD_DEPS usados para produzir uma dessas
/// raízes podem ter ficado instalados como resíduo, mas não ganham autoridade
/// para contaminar o build seguinte.
fn collect_build_runtime_closure(
    name: &str,
    authority: BuildAuthority,
    recipes: &HashMap<&str, &Recipe>,
    out: &mut BTreeMap<String, BTreeSet<BuildAuthority>>,
    stack: &mut Vec<String>,
) -> Result<()> {
    if stack.iter().any(|item| item == name) {
        return fail(
            2,
            format!(
                "ciclo na closure da view de build: {} -> {name}",
                stack.join(" -> ")
            ),
        );
    }
    let recipe = recipes.get(name).copied().ok_or_else(|| crate::Fail {
        code: 2,
        msg: format!("snapshot da view não contém a dependência {name}"),
    })?;
    let inserted = out.entry(name.to_string()).or_default().insert(authority);
    if !inserted {
        return Ok(());
    }
    stack.push(name.to_string());
    for dependency in &recipe.deps {
        collect_build_runtime_closure(dependency, authority, recipes, out, stack)?;
    }
    stack.pop();
    Ok(())
}

fn build_provider_closure(
    recipe: &Recipe,
    recipes: &HashMap<&str, &Recipe>,
) -> Result<BTreeMap<String, BTreeSet<BuildAuthority>>> {
    let mut providers = BTreeMap::new();
    for (authority, names) in [
        (BuildAuthority::Runtime, recipe.deps.as_slice()),
        (BuildAuthority::Build, recipe.build_deps.as_slice()),
    ] {
        for name in names {
            collect_build_runtime_closure(
                name,
                authority,
                recipes,
                &mut providers,
                &mut Vec::new(),
            )?;
        }
    }
    for name in recipe.toolchain_build_deps() {
        collect_build_runtime_closure(
            name,
            BuildAuthority::Toolchain,
            recipes,
            &mut providers,
            &mut Vec::new(),
        )?;
    }
    for name in recipe.ccache_build_deps() {
        collect_build_runtime_closure(
            name,
            BuildAuthority::Toolchain,
            recipes,
            &mut providers,
            &mut Vec::new(),
        )?;
    }
    Ok(providers)
}

#[derive(Clone, Debug)]
struct BuildClaim {
    owner: String,
    path: String,
    tree: bool,
}

fn build_claim_covers<'a>(claims: &'a [BuildClaim], path: &str) -> Option<&'a str> {
    claims.iter().find_map(|claim| {
        (claim.path == path
            || (claim.tree
                && path
                    .strip_prefix(claim.path.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'))))
        .then_some(claim.owner.as_str())
    })
}

/// Segue links como eles serão vistos dentro do rootfs, inclusive links de
/// diretório do usr-merge. `std::canonicalize(root.join(...))` não serve para
/// um alvo absoluto: ele o resolveria contra o host, não contra `root`.
fn resolve_build_virtual(ctx: &Ctx, virtual_path: &str) -> Result<String> {
    resolve_build_virtual_opt(ctx, virtual_path)?
        .ok_or_else(|| anyhow::anyhow!("{virtual_path}: symlink não resolve dentro do rootfs"))
}

/// Igual ao `resolve_build_virtual`, mas devolve `None` quando o caminho não
/// resolve por PENDURAR — algum componente da travessia não existe.
///
/// A distinção existe porque um symlink pendurado é legítimo em pelo menos um
/// caso real: o fontconfig instala 23 links em
/// `/usr/share/factory/etc/fonts/conf.d/` cujo caminho relativo foi calculado
/// para onde eles VÃO ser copiados. De `/etc/fonts/conf.d` o `../../../usr/…`
/// resolve certo; de onde ficam guardados, não. São gabaritos de `/etc`, e
/// pendurar ali é o comportamento correto deles.
///
/// Quem precisa do caminho de verdade (o shell do runner, o interpretador de um
/// shebang) continua usando o `resolve_build_virtual`, que recusa. Quem só quer
/// saber se há executável a expor usa esta forma: link que não aponta para
/// lugar nenhum não é executável, e isso não é erro.
fn resolve_build_virtual_opt(ctx: &Ctx, virtual_path: &str) -> Result<Option<String>> {
    let normalized = canonical_virtual_path(&ctx.root, virtual_path)?;
    let mut pending: Vec<String> = normalized
        .split('/')
        .filter(|component| !component.is_empty())
        .map(str::to_string)
        .rev()
        .collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0usize;
    while let Some(component) = pending.pop() {
        match component.as_str() {
            "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        let candidate = format!("/{}/{component}", resolved.join("/")).replace("//", "/");
        // O contexto aqui não é enfeite: era exatamente esta linha que chegava
        // ao usuário como "No such file or directory (os error 2)", sem
        // caminho, sem componente e sem pacote, e parava o rebuild sem dizer
        // onde. Agora ou o caminho pendura (e quem chamou decide), ou o erro
        // diz qual travessia falhou.
        let metadata = match fs::symlink_metadata(rooted_path(&ctx.root, &candidate)?) {
            Ok(metadata) => metadata,
            Err(erro) if erro.kind() == ErrorKind::NotFound => return Ok(None),
            Err(erro) => {
                return Err(anyhow::Error::new(erro)
                    .context(format!("{virtual_path}: ao atravessar {candidate}")))
            }
        };
        if !metadata.file_type().is_symlink() {
            resolved.push(component);
            continue;
        }
        hops += 1;
        if hops > 64 {
            bail!("ciclo de symlinks ao resolver {virtual_path}");
        }
        let target = fs::read_link(rooted_path(&ctx.root, &candidate)?)
            .with_context(|| format!("{virtual_path}: ao ler o symlink {candidate}"))?;
        let target = target
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("symlink não UTF-8 em {candidate}"))?;
        if target.starts_with('/') {
            resolved.clear();
        }
        for part in target.split('/').filter(|part| !part.is_empty()).rev() {
            pending.push(part.to_string());
        }
    }
    let result = format!("/{}", resolved.join("/"));
    rooted_path(&ctx.root, &result)?;
    Ok(Some(result))
}

fn canonical_build_directory(ctx: &Ctx, virtual_path: &str) -> Result<Option<String>> {
    let host = rooted_path(&ctx.root, virtual_path)?;
    let metadata = match fs::metadata(&host) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() {
        bail!("{virtual_path}: diretório de executáveis não é diretório");
    }
    let root = fs::canonicalize(&ctx.root)?;
    let directory = fs::canonicalize(host)?;
    let relative = directory
        .strip_prefix(&root)
        .map_err(|_| anyhow::anyhow!("{virtual_path} resolve para fora do rootfs"))?;
    let relative = relative
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{virtual_path} resolve para caminho não UTF-8"))?;
    Ok(Some(format!("/{}", relative.trim_start_matches('/'))))
}

fn path_under(path: &str, directory: &str) -> bool {
    path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn same_build_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.file_type() == after.file_type()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.size() == after.size()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn read_build_xattrs(file: &fs::File, display: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    const MAX_XATTRS: usize = 64;
    const MAX_VALUE: usize = 65_536;
    let size = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
    if size <= 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            _ if size == 0 => Ok(Vec::new()),
            Some(libc::ENOTSUP) | Some(libc::ENODATA) => Ok(Vec::new()),
            _ => Err(anyhow::anyhow!(
                "não listei xattrs de {}: {}",
                display.display(),
                std::io::Error::last_os_error()
            )),
        };
    }
    let mut raw_names = vec![0u8; size as usize];
    let got = unsafe {
        libc::flistxattr(
            file.as_raw_fd(),
            raw_names.as_mut_ptr().cast(),
            raw_names.len(),
        )
    };
    if got < 0 {
        bail!(
            "não listei xattrs de {}: {}",
            display.display(),
            std::io::Error::last_os_error()
        );
    }
    raw_names.truncate(got as usize);
    let mut names = Vec::new();
    for raw in raw_names
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let name = std::str::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("xattr não UTF-8 em {}", display.display()))?;
        if name.starts_with("security.") || name.starts_with("user.") {
            names.push(name.to_string());
        }
    }
    names.sort();
    names.dedup();
    if names.len() > MAX_XATTRS {
        bail!("{} excede {MAX_XATTRS} xattrs", display.display());
    }

    let mut xattrs = Vec::new();
    for name in names {
        let c_name = CString::new(name.as_str())?;
        let size =
            unsafe { libc::fgetxattr(file.as_raw_fd(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            bail!(
                "não li xattr {name} de {}: {}",
                display.display(),
                std::io::Error::last_os_error()
            );
        }
        if size as usize > MAX_VALUE {
            bail!(
                "xattr {name} de {} excede {MAX_VALUE} bytes",
                display.display()
            );
        }
        let mut value = vec![0u8; size as usize];
        let got = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if got < 0 {
            bail!(
                "não li xattr {name} de {}: {}",
                display.display(),
                std::io::Error::last_os_error()
            );
        }
        value.truncate(got as usize);
        xattrs.push((name, value));
    }
    Ok(xattrs)
}

/// Copia uma folha para um inode novo da view e prova que a origem não mudou
/// durante a leitura. Um hardlink para o rootfs/cache deixaria o suposto
/// snapshot mutável por outro nome enquanto o build roda, mesmo com o mount da
/// view somente-leitura.
fn copy_regular_or_link_into_view(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() || fs::symlink_metadata(destination).is_ok() {
        bail!(
            "view de build contém caminho duplicado: {}",
            destination.display()
        );
    }
    if let Some(parent) = destination.parent() {
        if !fs::symlink_metadata(parent)?.file_type().is_dir() {
            bail!(
                "pai da folha da view não é diretório real: {}",
                parent.display()
            );
        }
    }
    let path_before = fs::symlink_metadata(source)?;
    if path_before.file_type().is_symlink() {
        let target_before = fs::read_link(source)?;
        symlink(&target_before, destination)?;
        let path_after = fs::symlink_metadata(source)?;
        let target_after = fs::read_link(source)?;
        if !same_build_snapshot(&path_before, &path_after) || target_before != target_after {
            let _ = fs::remove_file(destination);
            bail!(
                "{} mudou enquanto seu symlink era congelado na view",
                source.display()
            );
        }
        return Ok(());
    }
    if !path_before.file_type().is_file() {
        bail!("{} não é arquivo regular/link", source.display());
    }

    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let descriptor_before = input.metadata()?;
    if !same_build_snapshot(&path_before, &descriptor_before) {
        bail!("{} mudou antes de ser congelado na view", source.display());
    }
    let xattrs_before = read_build_xattrs(&input, source)?;
    let path_after_xattrs = fs::symlink_metadata(source)?;
    if !same_build_snapshot(&path_before, &path_after_xattrs) {
        bail!(
            "{} mudou enquanto seus xattrs eram congelados na view",
            source.display()
        );
    }

    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let result = (|| -> Result<()> {
        // FICLONE cria outro inode e congela os blocos por COW; é seguro como
        // snapshot e evita recopiá-los fisicamente para cada consumidor. Em
        // filesystems sem reflink, a cópia streaming mantém a mesma semântica.
        // O tipo do segundo argumento de `ioctl` NÃO é o mesmo nas duas libc
        // desta distro: `c_ulong` na glibc e `c_int` no musl. Escrever o
        // literal com um tipo fixo compila numa e quebra na outra — e a que
        // quebrava era justamente a musl do binário distribuível, que só falha
        // no stage0. `libc::Ioctl` é o apelido que cada plataforma define.
        const FICLONE_IOCTL: libc::Ioctl = 0x4004_9409 as libc::Ioctl;
        let cloned =
            unsafe { libc::ioctl(output.as_raw_fd(), FICLONE_IOCTL, input.as_raw_fd()) } == 0;
        if !cloned {
            output.set_len(0)?;
            input.seek(SeekFrom::Start(0))?;
            std::io::copy(&mut input, &mut output)?;
        }
        output.set_permissions(fs::Permissions::from_mode(path_before.mode() & 0o7777))?;
        apply_xattrs(&output, destination, &xattrs_before)?;
        output.flush()?;

        let descriptor_after = input.metadata()?;
        let path_after = fs::symlink_metadata(source)?;
        let xattrs_after = read_build_xattrs(&input, source)?;
        if !same_build_snapshot(&descriptor_before, &descriptor_after)
            || !same_build_snapshot(&path_before, &path_after)
            || xattrs_before != xattrs_after
        {
            bail!(
                "{} mudou enquanto seus bytes eram congelados na view",
                source.display()
            );
        }
        Ok(())
    })();
    drop(output);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn set_build_timestamp(path: &Path, epoch: u64) -> Result<()> {
    // O tipo vem do CAMPO que vai ser preenchido, não de `time_t`: o musl está
    // migrando `time_t` para 64 bits e a libc marcou o apelido como obsoleto.
    // Derivar de `tv_sec` mantém a conversão correta nas duas libc sem
    // depender de qual largura cada uma escolheu, e o `try_into` continua
    // recusando um epoch que não caiba.
    // O tipo sai por inferência do CAMPO que vai receber o valor, e não de
    // `libc::time_t`: o musl está migrando `time_t` para 64 bits e a libc já
    // marcou o apelido como obsoleto. Assim a conversão continua correta nas
    // duas libc sem depender da largura que cada uma escolheu, e o `try_into`
    // segue recusando um epoch que não caiba.
    let seconds = epoch
        .try_into()
        .map_err(|_| anyhow::anyhow!("SOURCE_DATE_EPOCH excede o tv_sec desta libc: {epoch}"))?;
    let times = [
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    let metadata = fs::symlink_metadata(path)?;
    let rc = if metadata.file_type().is_symlink() {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("symlink sem pai: {}", path.display()))?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("symlink sem nome: {}", path.display()))?;
        let parent = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let name = CString::new(name.as_bytes())?;
        unsafe {
            libc::utimensat(
                parent.as_raw_fd(),
                name.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        }
    } else if metadata.file_type().is_file() || metadata.file_type().is_dir() {
        let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
        if metadata.file_type().is_dir() {
            flags |= libc::O_DIRECTORY;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)?;
        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }
    } else {
        bail!("tipo especial na view de build: {}", path.display());
    };
    if rc != 0 {
        bail!(
            "não normalizei timestamp de {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Normaliza atime/mtime depois da última leitura/criação da view. Diretórios
/// são tratados de baixo para cima, pois criar ou ajustar uma folha mudaria o
/// mtime do pai. `ctime` é mantido pelo kernel e não é configurável; o contrato
/// de build declara somente os dois timestamps portáveis usados por make e
/// configure.
fn normalize_build_timestamps(root: &Path, epoch: u64) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(path) = pending.pop() {
        if paths.len() >= 200_000 {
            bail!("view de build excede 200000 entradas ao normalizar timestamps");
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            let mut children = fs::read_dir(&path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            children.sort();
            pending.extend(children.into_iter().rev());
        }
        paths.push(path);
    }
    paths.sort_by(|left, right| {
        right
            .components()
            .count()
            .cmp(&left.components().count())
            .then_with(|| left.cmp(right))
    });
    for path in paths {
        set_build_timestamp(&path, epoch)?;
    }
    Ok(())
}

fn ensure_build_view_parent(view_root: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("caminho do sysroot sem pai"))?;
    let relative = parent
        .strip_prefix(view_root)
        .map_err(|_| anyhow::anyhow!("destino escapou do sysroot privado"))?;
    let mut current = view_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("componente não canônico no sysroot privado");
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let relative = current
                    .strip_prefix(view_root)
                    .map_err(|_| anyhow::anyhow!("symlink ancestral escapou da view"))?;
                let virtual_path = format!("/{}", relative.display());
                let expected = recipe::BUILD_SYSROOT_ALIASES
                    .iter()
                    .find_map(|(alias, target)| (*alias == virtual_path).then_some(*target));
                let actual = fs::read_link(&current)?;
                if expected.is_none_or(|target| actual != Path::new(target)) {
                    bail!(
                        "{}: somente aliases usr-merge do contrato podem ser ancestrais na view",
                        current.display()
                    );
                }
            }
            Ok(_) => bail!("{}: pai do sysroot não é diretório", current.display()),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o755))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let canonical_root = fs::canonicalize(view_root)?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(&canonical_root) {
        bail!(
            "{}: pai resolveu para fora do sysroot privado",
            parent.display()
        );
    }
    Ok(())
}

#[derive(Debug)]
struct BuildView {
    root: PathBuf,
    path: String,
    masked_directories: Vec<String>,
    commands: BTreeMap<String, String>,
}

impl BuildView {
    fn host_path(&self, virtual_path: &str) -> PathBuf {
        self.root.join(virtual_path.trim_start_matches('/'))
    }
}

fn executable_mode(ctx: &Ctx, virtual_path: &str) -> Result<Option<u32>> {
    // Symlink PENDURADO não é executável, e não é erro — os 23 gabaritos de
    // /etc que o fontconfig guarda em /usr/share/factory/ são o caso real, e a
    // travessia deles é que estourava. Seguir o link para decidir se há
    // executável a expor está certo; estourar quando ele não resolve, não.
    let Some(resolved) = resolve_build_virtual_opt(ctx, virtual_path)? else {
        return Ok(None);
    };
    let host = rooted_path(&ctx.root, &resolved)?;
    let metadata = fs::symlink_metadata(&host)
        .with_context(|| format!("{virtual_path}: modo de {}", host.display()))?;
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let mode = metadata.permissions().mode();
    Ok((mode & 0o111 != 0).then_some(mode))
}

fn add_view_executable(
    ctx: &Ctx,
    virtual_path: &str,
    owner: &str,
    masked_directories: &[String],
    commands: &mut BTreeMap<String, String>,
) -> Result<()> {
    let canonical = canonical_virtual_path(&ctx.root, virtual_path)?;
    if !masked_directories
        .iter()
        .any(|directory| path_under(&canonical, directory))
    {
        return Ok(());
    }
    if executable_mode(ctx, &canonical)?.is_none() {
        return Ok(());
    }
    if let Some(previous) = commands.insert(canonical.clone(), owner.to_string()) {
        if previous != owner {
            bail!("{canonical}: dois provedores na view: {previous} e {owner}");
        }
        return Ok(());
    }
    Ok(())
}

fn collect_tree_executables(
    ctx: &Ctx,
    tree: &str,
    owner: &str,
    masked_directories: &[String],
    commands: &mut BTreeMap<String, String>,
) -> Result<()> {
    let mut pending = vec![tree.to_string()];
    let mut seen = 0usize;
    while let Some(virtual_path) = pending.pop() {
        seen += 1;
        if seen > 50_000 {
            bail!("{owner}: árvore executável excede 50000 entradas");
        }
        let host = rooted_path(&ctx.root, &virtual_path)?;
        let metadata = fs::symlink_metadata(&host)?;
        if metadata.file_type().is_dir() {
            let mut children = Vec::new();
            for entry in fs::read_dir(&host)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{virtual_path}: nome não UTF-8"))?;
                children.push(format!("{}/{name}", virtual_path.trim_end_matches('/')));
            }
            children.sort();
            pending.extend(children.into_iter().rev());
        } else {
            add_view_executable(ctx, &virtual_path, owner, masked_directories, commands)?;
        }
    }
    Ok(())
}

fn collect_claim_executables(
    ctx: &Ctx,
    virtual_path: &str,
    tree: bool,
    owner: &str,
    executables: &mut BTreeMap<String, String>,
) -> Result<()> {
    let mut pending = vec![virtual_path.to_string()];
    let mut seen = 0usize;
    while let Some(path) = pending.pop() {
        seen += 1;
        if seen > 50_000 {
            bail!("{owner}: árvore da view excede 50000 entradas");
        }
        let host = rooted_path(&ctx.root, &path)?;
        let metadata = fs::symlink_metadata(&host)
            .with_context(|| format!("{owner}: claim {path} da view"))?;
        if tree && metadata.file_type().is_dir() {
            let mut children = Vec::new();
            for entry in
                fs::read_dir(&host).with_context(|| format!("{owner}: árvore {path} da view"))?
            {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{path}: nome não UTF-8"))?;
                children.push(format!("{}/{name}", path.trim_end_matches('/')));
            }
            children.sort();
            pending.extend(children.into_iter().rev());
            continue;
        }
        if executable_mode(ctx, &path)?.is_some() {
            if let Some(previous) = executables.insert(path.clone(), owner.to_string()) {
                if previous != owner {
                    bail!("{path}: dois provedores executáveis: {previous} e {owner}");
                }
            }
        }
    }
    Ok(())
}

struct BuildClaimMaterial<'a> {
    manifest_line: &'a str,
    virtual_path: &'a str,
    tree: bool,
    shared: bool,
    owner: &'a str,
}

fn materialize_build_claim(
    ctx: &Ctx,
    view_root: &Path,
    claim: BuildClaimMaterial<'_>,
    materialized: &mut BTreeMap<String, (String, bool)>,
) -> Result<()> {
    let BuildClaimMaterial {
        manifest_line,
        virtual_path,
        tree,
        shared,
        owner,
    } = claim;
    let mut pending = vec![(virtual_path.to_string(), tree, shared, true)];
    // Relações de hardlink só fazem parte da identidade dentro de uma claim
    // `d:` (o tar canônico as prende). Não propague coincidências de inode
    // factuais entre claims independentes: isso reintroduziria estado do
    // rootfs que o registro não descreve.
    let mut hardlink_snapshots = BTreeMap::new();
    let mut seen = 0usize;
    while let Some((path, descend, shared_directory, claim_root)) = pending.pop() {
        seen += 1;
        if seen > 100_000 {
            bail!("{owner}: árvore do sysroot excede 100000 entradas");
        }
        if let Some((previous, previous_shared)) = materialized.get(&path) {
            if previous != owner && !(*previous_shared && shared_directory) {
                bail!("{path}: dois provedores no sysroot: {previous} e {owner}");
            }
            continue;
        }
        materialized.insert(path.clone(), (owner.to_string(), shared_directory));

        let source = rooted_path(&ctx.root, &path)?;
        let metadata = fs::symlink_metadata(&source)?;
        let destination = view_root.join(path.trim_start_matches('/'));
        ensure_build_view_parent(view_root, &destination)?;
        if metadata.file_type().is_dir() {
            match fs::symlink_metadata(&destination) {
                Ok(existing) if existing.file_type().is_dir() => {}
                Ok(_) => bail!("{path}: diretório colide com estrutura do sysroot"),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    fs::create_dir(&destination)?;
                }
                Err(error) => return Err(error.into()),
            }
            fs::set_permissions(&destination, metadata.permissions())?;
            // `D:` prende deliberadamente somente tipo+modo: copiar xattrs
            // factuais de um diretório compartilhado acrescentaria estado que
            // nenhuma claim autorizou. O xattr da raiz de `d:` também não faz
            // parte de `directory_integrity`; os xattrs dos descendentes sim.
            if !shared_directory && !claim_root {
                let xattrs = crate::pack::read_xattrs(&source)?;
                if !xattrs.is_empty() {
                    let directory = fs::File::open(&destination)?;
                    apply_xattrs(&directory, &destination, &xattrs)?;
                }
            }
            if descend {
                let mut children = Vec::new();
                for entry in fs::read_dir(&source)? {
                    let entry = entry?;
                    let name = entry
                        .file_name()
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("{path}: nome não UTF-8"))?;
                    children.push(format!("{}/{name}", path.trim_end_matches('/')));
                }
                children.sort();
                pending.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|child| (child, true, false, false)),
                );
            }
            continue;
        }
        if metadata.file_type().is_symlink() {
            if let Some((_, target)) = recipe::BUILD_SYSROOT_ALIASES
                .iter()
                .find(|(alias, _)| *alias == path)
            {
                if fs::read_link(&source)? != PathBuf::from(target)
                    || fs::read_link(&destination)? != PathBuf::from(target)
                {
                    return fail(5, format!("{path}: alias do rootfs diverge do contrato"));
                }
                continue;
            }
        }
        if metadata.file_type().is_file() {
            let key = (metadata.dev(), metadata.ino());
            if let Some(first) = hardlink_snapshots.get(&key) {
                fs::hard_link(first, &destination)?;
            } else {
                copy_regular_or_link_into_view(&source, &destination)?;
                hardlink_snapshots.insert(key, destination);
            }
        } else {
            copy_regular_or_link_into_view(&source, &destination)?;
        }
    }
    if confined_claim_matches(manifest_line, view_root, virtual_path)? != Some(true) {
        return fail(
            5,
            format!("{owner}: snapshot da claim {virtual_path} diverge do registro v3"),
        );
    }
    Ok(())
}

struct InstalledBuildClaims {
    meta: HashMap<String, String>,
    manifest: Vec<String>,
    claims: Vec<BuildClaim>,
}

fn installed_build_claims(
    ctx: &Ctx,
    name: &str,
    recipe: &Recipe,
    expected_fingerprint: &str,
    allow_intermediate: bool,
) -> Result<InstalledBuildClaims> {
    let record = ctx.records_dir().join(name);
    let meta = read_meta_strict(&record)?.ok_or_else(|| crate::Fail {
        code: 5,
        msg: format!("{name}: provedor da view não está instalado"),
    })?;
    ensure_supported_record_format(&meta, name)?;
    let format = meta.get("RECORD_FORMAT").map(String::as_str);
    if format != Some(FINAL_RECORD_FORMAT) && !(allow_intermediate && format == Some(RECORD_FORMAT))
    {
        return fail(
            5,
            format!("{name}: provedor da view precisa de v4 ou v3 produzido neste ResolvedPlan"),
        );
    }
    if meta.get("VERSION") != Some(&recipe.version)
        || meta.get("FINGERPRINT").map(String::as_str) != Some(expected_fingerprint)
        || !record_is_intact_with_intermediate(ctx, &record, recipe, allow_intermediate)
    {
        return fail(
            5,
            format!("{name}: identidade/claims instaladas não correspondem ao snapshot da view"),
        );
    }
    let lines = read_manifest_strict(&record)
        .with_context(|| format!("{name}: manifesto do provedor da view"))?;
    let mut claims = Vec::new();
    for line in &lines {
        validate_manifest_line_for_record(&meta, name, line)?;
        let path = canonical_virtual_path(&ctx.root, manifest_path(line))?;
        claims.push(BuildClaim {
            owner: name.to_string(),
            path,
            tree: manifest_integrity(line).is_some_and(|tag| tag.starts_with("d:")),
        });
    }
    Ok(InstalledBuildClaims {
        meta,
        manifest: lines,
        claims,
    })
}

fn validate_view_interpreters(
    ctx: &Ctx,
    executables: &BTreeMap<String, String>,
    path_commands: &BTreeMap<String, String>,
    claims: &[BuildClaim],
    shell_paths: &BTreeSet<String>,
) -> Result<()> {
    let path_command_names: BTreeSet<&str> = path_commands
        .keys()
        .filter_map(|path| Path::new(path).file_name()?.to_str())
        .collect();
    for (path, owner) in executables {
        let resolved = resolve_build_virtual(ctx, path)?;
        let host = rooted_path(&ctx.root, &resolved)?;
        let Object::Script(script) = elf::inspect(&host)? else {
            continue;
        };
        let interpreter_alias = canonical_virtual_path(&ctx.root, &script.interpreter)
            .with_context(|| {
                format!("{owner}: {path} exige interpretador {}", script.interpreter)
            })?;
        let interpreter = resolve_build_virtual(ctx, &script.interpreter).with_context(|| {
            format!("{owner}: {path} exige interpretador {}", script.interpreter)
        })?;
        if !shell_paths.contains(&interpreter_alias)
            && build_claim_covers(claims, &interpreter).is_none()
        {
            return fail(
                5,
                format!(
                    "{owner}: {path} exige {}, cujo provedor não está em DEPS/BUILD_DEPS/toolchain",
                    script.interpreter
                ),
            );
        }
        if script.interpreter.ends_with("/env") {
            let Some(argument) = script.argument.as_deref() else {
                return fail(5, format!("{owner}: {path} usa env sem interpretador"));
            };
            let wanted = argument.split_whitespace().next().unwrap_or("");
            if wanted.is_empty() || wanted.starts_with('-') || !path_command_names.contains(wanted)
            {
                return fail(
                    5,
                    format!("{owner}: {path} usa env para {argument:?}, ausente da view declarada"),
                );
            }
        }
    }
    Ok(())
}

fn create_build_view(
    ctx: &Ctx,
    work: &Path,
    recipe: &Recipe,
    frozen: &FrozenBuildGraph<'_>,
    artifacts: &[(PathBuf, String)],
    epoch: u64,
) -> Result<BuildView> {
    let recipes = &frozen.recipes;
    let fingerprints = &frozen.plan.fingerprints;
    // Nenhum build pode observar nomes acrescentados enquanto a view nasce.
    // A cópia também encerra o borrow antes de qualquer execução externa.
    let intermediate_records = frozen.intermediate_records.borrow().clone();
    let root = work.join(".minitrue-build-view");
    if fs::symlink_metadata(&root).is_ok() {
        return fail(
            2,
            format!(
                "{}: files/ ocupa o nome reservado .minitrue-build-view",
                recipe.name
            ),
        );
    }
    fs::create_dir(&root)?;

    // O sysroot começa vazio. Estrutura sem payload tem modo fixo pelo
    // contrato; bytes, links, headers e bibliotecas entram abaixo somente por
    // claims v3 dos provedores autorizados.
    for directory in [
        "",
        "dev",
        "etc",
        "opt",
        "proc",
        "tmp",
        "usr",
        "usr/bin",
        "usr/include",
        "usr/lib",
        "usr/local",
        "usr/local/bin",
        "usr/local/sbin",
        "usr/share",
        "var",
        "var/cache",
        "var/cache/minitrue",
        "var/cache/minitrue/zig",
        "var/tmp",
    ] {
        let directory = root.join(directory);
        fs::create_dir_all(&directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    for directory in [root.join("tmp"), root.join("var/tmp")] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o1777))?;
    }
    for (alias, target) in recipe::BUILD_SYSROOT_ALIASES {
        let live = rooted_path(&ctx.root, alias)?;
        if fs::read_link(&live).ok().as_deref() != Some(Path::new(target)) {
            return fail(
                5,
                format!("{alias}: alias do sysroot precisa apontar para {target}"),
            );
        }
        symlink(target, root.join(alias.trim_start_matches('/')))?;
    }
    let zig_cache_mountpoint = ctx.cache_dir().join("zig");
    let ccache_cache_mountpoint = ctx.cache_dir().join("ccache");
    let mut view_mountpoints = vec![work, zig_cache_mountpoint.as_path()];
    if recipe::BUILD_CCACHE_VIEW {
        view_mountpoints.push(ccache_cache_mountpoint.as_path());
    }
    for mountpoint in view_mountpoints {
        let virtual_path = in_chroot(&ctx.root, mountpoint);
        let destination = root.join(virtual_path.strip_prefix("/").unwrap_or(&virtual_path));
        ensure_build_view_parent(&root, &destination)?;
        match fs::create_dir(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    }
    let mut input_paths = BTreeSet::new();
    for (artifact, hash) in artifacts {
        let virtual_path = in_chroot(&ctx.root, artifact);
        if !input_paths.insert(virtual_path.clone()) {
            continue;
        }
        if !fs::symlink_metadata(artifact)?.file_type().is_file() {
            return fail(
                5,
                format!(
                    "insumo {hash} não é arquivo regular: {}",
                    artifact.display()
                ),
            );
        }
        let destination = root.join(virtual_path.strip_prefix("/").unwrap_or(&virtual_path));
        ensure_build_view_parent(&root, &destination)?;
        copy_regular_or_link_into_view(artifact, &destination)
            .with_context(|| format!("materializando insumo {hash} no sysroot"))?;
        let actual = fetch::sha256_file(&destination)?;
        if &actual != hash {
            return fail(
                5,
                format!(
                    "snapshot do insumo {} diverge: esperado {hash}, obtido {actual}",
                    artifact.display()
                ),
            );
        }
    }

    let mut masked_directories = Vec::new();
    for directory in recipe::BUILD_EXEC_DIRS {
        if let Some(directory) = canonical_build_directory(ctx, directory)? {
            if !masked_directories.contains(&directory) {
                masked_directories.push(directory);
            }
        }
    }
    masked_directories.sort();
    masked_directories.dedup();
    for directory in &masked_directories {
        fs::create_dir_all(root.join(directory.trim_start_matches('/')))?;
    }

    let mut path_directories = Vec::new();
    for directory in recipe::BUILD_EXEC_DIRS {
        if let Some(directory) = canonical_build_directory(ctx, directory)? {
            if !path_directories.contains(&directory) {
                path_directories.push(directory);
            }
        }
    }
    if path_directories.is_empty() {
        return fail(5, "runner não encontrou /bin ou /usr/bin no rootfs");
    }

    let providers = build_provider_closure(recipe, recipes)?;
    let mut claims = Vec::new();
    let mut manifests = BTreeMap::new();
    let mut metas = BTreeMap::new();
    for (name, authorities) in &providers {
        let provider = recipes
            .get(name.as_str())
            .copied()
            .ok_or_else(|| crate::Fail {
                code: 2,
                msg: format!("snapshot perdeu o provedor {name}"),
            })?;
        let fingerprint = fingerprints.get(name).ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("snapshot perdeu o fingerprint de {name}"),
        })?;
        let installed = installed_build_claims(
            ctx,
            name,
            provider,
            fingerprint,
            intermediate_records.contains(name),
        )?;
        claims.extend(installed.claims);
        manifests.insert(name.clone(), installed.manifest);
        metas.insert(name.clone(), installed.meta);
        let labels = authorities
            .iter()
            .map(|authority| authority.name())
            .collect::<Vec<_>>()
            .join("+");
        eprintln!("  view: {name} ({labels}) {fingerprint}");
    }

    // A aresta runner é validada à parte porque dela só se concede o shell;
    // incluir o manifesto inteiro aqui reabriria todos os applets do BusyBox.
    let runner_name = recipe::BUILD_RUNNER_PACKAGE;
    let runner = recipes
        .get(runner_name)
        .copied()
        .ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("snapshot não contém o runner {runner_name}"),
        })?;
    let runner_fingerprint = fingerprints.get(runner_name).ok_or_else(|| crate::Fail {
        code: 2,
        msg: format!("snapshot não contém fingerprint do runner {runner_name}"),
    })?;
    let runner_claims = installed_build_claims(
        ctx,
        runner_name,
        runner,
        runner_fingerprint,
        intermediate_records.contains(runner_name),
    )?
    .claims;

    let mut commands = BTreeMap::new();
    let mut visible_executables = BTreeMap::new();
    let mut materialized = BTreeMap::new();
    for (name, lines) in &manifests {
        for line in lines {
            let path = canonical_virtual_path(&ctx.root, manifest_path(line))?;
            let integrity = manifest_integrity(line);
            let tree = integrity.is_some_and(|tag| tag.starts_with("d:"));
            let shared = integrity.is_some_and(|tag| tag.starts_with("D:"));
            materialize_build_claim(
                ctx,
                &root,
                BuildClaimMaterial {
                    manifest_line: line,
                    virtual_path: &path,
                    tree,
                    shared,
                    owner: name,
                },
                &mut materialized,
            )?;
            collect_claim_executables(ctx, &path, tree, name, &mut visible_executables)?;
            if tree
                && masked_directories
                    .iter()
                    .any(|directory| path_under(&path, directory))
            {
                collect_tree_executables(ctx, &path, name, &masked_directories, &mut commands)?;
            } else {
                add_view_executable(ctx, &path, name, &masked_directories, &mut commands)?;
            }
        }
    }

    let shell = resolve_build_virtual(ctx, "/bin/sh")?;
    if build_claim_covers(&runner_claims, &shell).is_none() {
        return fail(
            5,
            format!("runner {runner_name} não fornece o shell factual {shell}; build recusado"),
        );
    }
    let shell_source = rooted_path(&ctx.root, &shell)?;
    if executable_mode(ctx, &shell)?.is_none() {
        return fail(5, format!("shell do runner não é executável: {shell}"));
    }
    match elf::inspect(&shell_source)? {
        Object::Elf(object)
            if object.detailed && object.machine == elf::EM_X86_64 && object.is_static() => {}
        _ => {
            return fail(
                5,
                format!("shell do runner precisa ser ELF x86_64 estático: {shell}"),
            );
        }
    }
    let mut shell_paths = BTreeSet::new();
    let virtual_shell = canonical_virtual_path(&ctx.root, "/bin/sh")?;
    for directory in &path_directories {
        let candidate = format!("{}/sh", directory.trim_end_matches('/'));
        if candidate != virtual_shell {
            if let Some(owner) = commands.get(&candidate) {
                return fail(
                    5,
                    format!("{candidate}: {owner} tentou sombrear o shell do runner no PATH"),
                );
            }
        }
    }
    let destination = root.join(virtual_shell.trim_start_matches('/'));
    if let Some(owner) = commands.get(&virtual_shell) {
        if owner != runner_name {
            return fail(
                5,
                format!("{virtual_shell}: {owner} tentou substituir o shell do runner"),
            );
        }
        fs::remove_file(&destination)?;
    }
    copy_regular_or_link_into_view(&shell_source, &destination)?;
    commands.insert(virtual_shell.clone(), format!("runner:{runner_name}"));
    shell_paths.insert(virtual_shell);

    validate_view_interpreters(ctx, &visible_executables, &commands, &claims, &shell_paths)?;

    for (name, meta) in &metas {
        if meta.get("WORLD").map(String::as_str) == Some("A") {
            let version = meta
                .get("VERSION")
                .ok_or_else(|| anyhow::anyhow!("{name}: registro A sem VERSION"))?;
            let expected_tree = format!("/opt/{name}/{version}");
            if build_claim_covers(&claims, &expected_tree) != Some(name.as_str())
                || fs::read_link(root.join("opt").join(name).join("current")).ok()
                    != Some(PathBuf::from(version))
            {
                return fail(
                    5,
                    format!("{name}: prefixo mundo A não corresponde às claims do sysroot"),
                );
            }
        }
    }

    normalize_build_timestamps(&root, epoch)?;

    Ok(BuildView {
        root,
        path: path_directories.join(":"),
        masked_directories,
        commands,
    })
}

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
    /// O build recebe o acelerador de compilação (#68): masquerade no PATH,
    /// CCACHE_* no ambiente e o cache global montado gravável. Só o caminho
    /// GCC nativo com o portão `BUILD_CCACHE_VIEW` ligado; em todo o resto é
    /// false e nada do ccache aparece no ambiente.
    ccache: bool,
}

/// Alvo do gcc/binutils cross que produz glibc (SPEC-0005).
const CROSS_TRIPLE: &str = "x86_64-distropica-linux-gnu";

/// Cria os shims da semente (zig cc/c++/ld/ar…) num diretório e o devolve.
/// `-ffile-prefix-map=$WORK=.` torna a reprodutibilidade independente do
/// caminho de build (SPEC-0010): reescreve o comp_dir/__FILE__ para relativo.
/// Masquerade do ccache (#68): um diretório na frente do PATH em que os nomes
/// dos compiladores são invólucros de uma linha sobre /usr/bin/ccache. Shell
/// legível, como os seed shims — quem investigar por que `gcc` não é o gcc
/// encontra a resposta lendo. O compilador real vai por caminho ABSOLUTO:
/// entregue por nome, o ccache o procuraria no PATH, acharia o próprio
/// masquerade primeiro e recursaria. Só os compiladores entram — ar, ld e
/// ranlib não passam pelo ccache porque ele só entende compilação.
fn ccache_masquerade(work: &Path) -> Result<PathBuf> {
    let tc = work.join(".ccache-tc");
    fs::create_dir_all(&tc)?;
    for (nome, real) in [
        ("cc", "/usr/bin/gcc"),
        ("gcc", "/usr/bin/gcc"),
        ("c++", "/usr/bin/g++"),
        ("g++", "/usr/bin/g++"),
    ] {
        let shim = tc.join(nome);
        write_new(
            &shim,
            format!("#!/bin/sh\nexec /usr/bin/ccache {real} \"$@\"\n").as_bytes(),
        )?;
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))?;
    }
    // Os nomes triplos do binutils/gcc nativo também compilam em muitos
    // configures; mascarar só os curtos deixaria metade dos acertos na mesa.
    for (nome, real) in [
        (
            format!("{CROSS_TRIPLE}-gcc"),
            "/usr/bin/x86_64-distropica-linux-gnu-gcc",
        ),
        (
            format!("{CROSS_TRIPLE}-g++"),
            "/usr/bin/x86_64-distropica-linux-gnu-g++",
        ),
    ] {
        let shim = tc.join(&nome);
        write_new(
            &shim,
            format!("#!/bin/sh\nexec /usr/bin/ccache {real} \"$@\"\n").as_bytes(),
        )?;
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))?;
    }
    Ok(tc)
}

fn seed_shims(ctx: &Ctx, work: &Path, epoch: u64) -> Result<PathBuf> {
    let zig_host = ctx.root.join("opt/zig/current/zig");
    if !zig_host.exists() {
        return fail(
            5,
            "invariante quebrada: o plano seed/cross não materializou o Zig antes do build",
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
    normalize_build_timestamps(&tc, epoch)?;
    Ok(tc)
}

fn setup_toolchain(ctx: &Ctx, work: &Path, r: &Recipe, epoch: u64) -> Result<BuildEnv> {
    match r.toolchain {
        Toolchain::None => Ok(BuildEnv {
            // Uma receita de montagem não recebe compilador pelo contrato.
            // Expor uma falha deliberada faz o uso acidental de CC/CXX/etc.
            // falhar; o PATH normal continua disponível para o userland.
            cc: "false".into(),
            cxx: "false".into(),
            ar: "false".into(),
            ranlib: "false".into(),
            ld: "false".into(),
            nm: "false".into(),
            path_prefix: Vec::new(),
            ccache: false,
        }),
        Toolchain::Seed => {
            let tc = seed_shims(ctx, work, epoch)?;
            Ok(BuildEnv {
                cc: "cc".into(),
                cxx: "c++".into(),
                ar: "ar".into(),
                ranlib: "ranlib".into(),
                ld: "ld".into(),
                nm: "nm".into(),
                path_prefix: vec![tc],
                ccache: false,
            })
        }
        Toolchain::Cross => {
            // gcc da passada 1 vem dos BUILD_DEPS explícitos `gcc` e
            // `binutils-cross`. Não sonde o /usr/bin vivo aqui: a existência
            // factual dentro da view fechada é decidida somente ao executar o
            // comando, e o lint aponta literais sem provedor declarado.
            let tc = seed_shims(ctx, work, epoch)?;
            Ok(BuildEnv {
                cc: format!("{CROSS_TRIPLE}-gcc"),
                cxx: format!("{CROSS_TRIPLE}-g++"),
                ar: format!("{CROSS_TRIPLE}-ar"),
                ranlib: format!("{CROSS_TRIPLE}-ranlib"),
                ld: format!("{CROSS_TRIPLE}-ld"),
                nm: format!("{CROSS_TRIPLE}-nm"),
                path_prefix: vec![tc],
                ccache: false,
            })
        }
        Toolchain::Native => {
            // gcc nativo hospedado na glibc (passada 2), concedido somente
            // pelas arestas explícitas da receita. Com o portão do ccache
            // ligado, o masquerade entra na FRENTE do PATH: `gcc` resolve
            // para o invólucro, que chama /usr/bin/ccache com o compilador
            // REAL por caminho absoluto — absoluto para que o próprio ccache
            // não reencontre o masquerade no PATH e recurse.
            let mut path_prefix = Vec::new();
            let mut ccache = false;
            if recipe::BUILD_CCACHE_VIEW {
                path_prefix.push(ccache_masquerade(work)?);
                ccache = true;
            }
            Ok(BuildEnv {
                cc: "gcc".into(),
                cxx: "g++".into(),
                ar: "ar".into(),
                ranlib: "ranlib".into(),
                ld: "ld".into(),
                nm: "nm".into(),
                path_prefix,
                ccache,
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
const BUILD_PREAMBLE: &str = recipe::BUILD_PREAMBLE;

/// Monta o comando de build. Num rootfs (`--root` != `/`) roda dentro dele via
/// `bwrap`, usando como `/` o sysroot privado materializado das claims v3. Isso
/// é necessário para o perfil `native` — loader, libs e headers absolutos
/// precisam vir da closure — e torna **todo** build hermético: `--clearenv`
/// (só as variáveis do contrato) e `--unshare-net` (nenhum insumo pela rede —
/// SPEC-0004 §3.2; o fetch já ocorreu no host). Vale inclusive no próprio
/// sistema (`--root /`): sem namespace, caminhos absolutos e dados do host
/// reabririam a fronteira que a view promete fechar.
fn build_command(
    ctx: &Ctx,
    be: &BuildEnv,
    view: &BuildView,
    retries: u32,
    work: &Path,
    epoch: &str,
    artifacts: &[(PathBuf, String)],
) -> Command {
    let root = ctx.root.clone();
    let src_dir = work.join("src");
    let stage = work.join("stage");
    let build_tmp = work.join("tmp");
    let zig_cache = ctx.cache_dir().join("zig");
    let c = |p: &Path| in_chroot(&root, p).display().to_string();

    // PATH hermético: shims do perfil + diretórios filtrados da view. Nenhum
    // diretório vivo do rootfs é acrescentado aqui.
    let mut path = String::new();
    for p in &be.path_prefix {
        path.push_str(&c(p));
        path.push(':');
    }
    path.push_str(&view.path);

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
        // As flags saem de `recipe::BUILD_FLAGS`, que é a MESMA fonte que o
        // fingerprint consome. Repeti-las aqui como literal deixaria a
        // identidade prometer uma coisa e o build fazer outra — e a divergência
        // seria invisível até alguém tentar reproduzir um REPROCORR.
        //
        // Descascar depois foi a alternativa considerada e RECUSADA: rodar
        // `strip` sobre o $STAGE faria o manifesto registrar bytes que o
        // build() não escreveu, e nesta árvore o registro é a verdade sobre o
        // que aconteceu. Melhor não produzir o que não se quer guardar.
        //
        // Quem quiser a árvore com símbolos reconstrói do bundle de fontes
        // exportando CFLAGS="-g -O2"; a fonte correspondente existe para isso.
        ("RETRIES".into(), retries.to_string()),
        ("HOME".into(), c(work)),
        ("ZIG_GLOBAL_CACHE_DIR".into(), c(&zig_cache)),
        // Ferramentas que precisam de temporários também ficam dentro da
        // única árvore gravável do build. Sem isto elas tentariam /tmp no
        // rootfs read-only e confundiriam confinamento com falha de pacote.
        ("TMPDIR".into(), c(&build_tmp)),
        ("SOURCE_DATE_EPOCH".into(), epoch.to_string()),
        ("LC_ALL".into(), "C".into()),
        ("LANG".into(), "C".into()),
        ("LANGUAGE".into(), String::new()),
        ("TZ".into(), "UTC".into()),
    ];
    if be.ccache {
        let ccache_cache = ctx.cache_dir().join("ccache");
        envs.push(("CCACHE_DIR".into(), c(&ccache_cache)));
        // BASEDIR reescreve caminhos sob o WORK como relativos ANTES de
        // hashear: sem isto o caminho do work entra na chave e acerto nunca
        // acontece entre dois builds — além de ser a mesma classe de
        // vazamento do session.conf do dbus (#66/#69).
        envs.push(("CCACHE_BASEDIR".into(), c(work)));
        // O compilador entra na chave pelo CONTEÚDO, não pelo mtime: numa
        // view recém-materializada o mtime não diz nada.
        envs.push(("CCACHE_COMPILERCHECK".into(), "content".into()));
        envs.push(("CCACHE_MAXSIZE".into(), "20G".into()));
    }
    for (nome, valor) in recipe::BUILD_FLAGS {
        envs.push(((*nome).into(), (*valor).into()));
    }
    for (i, (p, _)) in artifacts.iter().enumerate() {
        let cp = c(p);
        if i == 0 {
            envs.push(("DL".into(), cp.clone()));
        }
        envs.push((format!("DL_{}", i + 1), cp));
    }

    let mut cmd = Command::new("bwrap");
    // Vale também para --root /: sem o namespace, um caminho absoluto
    // contornaria o PATH privado e a rede continuaria aberta. O sysroot
    // declarado é somente-leitura; WORK e o cache do Zig são os únicos binds
    // graváveis.
    cmd.arg("--ro-bind")
        .arg(&view.root)
        .arg("/")
        .arg("--bind")
        .arg(work)
        .arg(in_chroot(&root, work))
        .arg("--bind")
        .arg(&zig_cache)
        .arg(in_chroot(&root, &zig_cache))
        // WORK é gravável, portanto a cópia original da view e os shims
        // recebem submounts read-only antes de a receita ser executada.
        .arg("--ro-bind")
        .arg(&view.root)
        .arg(in_chroot(&root, &view.root));
    if be.ccache {
        let ccache_cache = ctx.cache_dir().join("ccache");
        cmd.arg("--bind")
            .arg(&ccache_cache)
            .arg(in_chroot(&root, &ccache_cache));
    }
    for prefix in &be.path_prefix {
        cmd.arg("--ro-bind")
            .arg(prefix)
            .arg(in_chroot(&root, prefix));
    }
    for directory in &view.masked_directories {
        cmd.arg("--ro-bind")
            .arg(view.host_path(directory))
            .arg(directory);
    }
    cmd.arg("--proc")
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

/// Reserva um temporário irmão de `dst`. Por estar no mesmo filesystem do
/// destino, a publicação final por `rename` é atômica inclusive no fallback
/// entre mounts. `create_new`/`symlink` recusam colisões em vez de seguir links.
fn move_temp_path(dst: &Path) -> Result<PathBuf> {
    let parent = dst
        .parent()
        .ok_or_else(|| anyhow::anyhow!("destino sem diretório pai: {}", dst.display()))?;
    let name = dst.file_name().and_then(|n| n.to_str()).unwrap_or("path");
    for _ in 0..128 {
        let serial = MOVE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(
            ".{name}.minitrue-move-{}-{serial}",
            std::process::id()
        ));
        if fs::symlink_metadata(&tmp).is_err_and(|e| e.kind() == ErrorKind::NotFound) {
            return Ok(tmp);
        }
    }
    bail!(
        "não consegui reservar temporário irmão de {}",
        dst.display()
    )
}

/// Copia um regular para um temporário e só publica o nome final depois de
/// conteúdo, flush e permissões completos. Uma cópia parcial jamais aparece
/// como `dst`, que é precisamente a distinção de que o rollback depende.
fn copy_regular_atomically<R: Read>(
    source: &mut R,
    dst: &Path,
    permissions: fs::Permissions,
) -> Result<()> {
    let tmp = move_temp_path(dst)?;
    let result = (|| -> Result<()> {
        let mut out = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        std::io::copy(source, &mut out)?;
        out.flush()?;
        out.set_permissions(permissions)?;
        drop(out);
        fs::rename(&tmp, dst)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Congela a saída do build numa imagem tar selada pelo kernel. O hash e a
/// instalação passam a consumir os mesmos bytes; alterações tardias no STAGE
/// original (por processo órfão ou corrida) não mudam o payload atestado.
fn sealed_stage_snapshot(stage: &Path, epoch: u64) -> Result<(fs::File, String)> {
    let name = CString::new("minitrue-stage")?;
    // SAFETY: CString válida; flags são os definidos pelo ABI Linux.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd recém-criado, transferido para File com dono único.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let hash = crate::pack::pack_deterministic(stage, epoch, &mut file)?;
    file.flush()?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: fcntl opera no fd válido e não retém ponteiros.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((file, hash))
}

const MAX_CHANNEL_TAR_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_CHANNEL_TRANSPORT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SEALED_STAGE_ENTRIES: usize = 50_000;
const MAX_SEALED_STAGE_PATH_BYTES: usize = 4096;
// Um PAX canônico carrega no máximo 64 xattrs de 64 KiB, codificados em hex.
// 16 MiB deixa folga para nomes/framing sem permitir que `tar` reserve até o
// teto inteiro do artefato antes de `read_entry_xattrs` poder inspecioná-lo.
const MAX_SEALED_STAGE_PAX_BYTES: u64 = 16 * 1024 * 1024;
const RETAINED_STAGE_DIRECTORY: &str = "channel-stages";

fn canonical_content_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn retained_stage_path(ctx: &Ctx, hash: &str) -> Result<PathBuf> {
    if !canonical_content_hash(hash) {
        bail!("hash de STAGE retido não é SHA-256 canônico: {hash:?}");
    }
    Ok(ctx
        .cache_dir()
        .join(RETAINED_STAGE_DIRECTORY)
        .join(format!("{hash}.tar")))
}

/// Abre e revalida integralmente o tar canônico retido. O nome é só um índice:
/// a autoridade continua sendo o hash dos bytes e o mesmo preflight que uma
/// instalação nova usa. Corrupção presente é erro, não ausência/fallback.
fn retained_stage_image(ctx: &Ctx, expected: &str) -> Result<Option<fs::File>> {
    let path = retained_stage_path(ctx, expected)?;
    let cache = ctx.cache_dir();
    let directory = cache.join(RETAINED_STAGE_DIRECTORY);
    ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    ensure_real_directory_or_absent(&ctx.root, &directory, "STAGEs retidos")?;
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("abrindo {}", path.display())),
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("STAGE retido não é arquivo regular: {}", path.display());
    }
    if metadata.len() > MAX_CHANNEL_TAR_BYTES {
        bail!(
            "STAGE retido {} excede {MAX_CHANNEL_TAR_BYTES} bytes",
            path.display()
        );
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("tamanho do STAGE retido transbordou"))?;
        if total > MAX_CHANNEL_TAR_BYTES {
            bail!(
                "STAGE retido {} excede {MAX_CHANNEL_TAR_BYTES} bytes",
                path.display()
            );
        }
        hasher.update(&buffer[..read]);
    }
    let observed = hex::encode(hasher.finalize());
    if observed != expected {
        bail!(
            "STAGE retido {} tem sha256 {observed}, mas o registro atesta {expected}",
            path.display()
        );
    }
    let _ = preflight_sealed_stage(&ctx.root, &file)
        .with_context(|| format!("STAGE retido {} não é instalável", path.display()))?;
    file.seek(SeekFrom::Start(0))?;
    Ok(Some(file))
}

/// Persiste o memfd selado do build sob o próprio ARTIFACT_HASH. O hard link
/// publica o nome final de uma vez, somente depois de cópia, hash, permissões e
/// fsync completos; um leitor nunca enxerga conteúdo parcial.
fn retain_local_stage(ctx: &Ctx, sealed: &fs::File, expected: &str) -> Result<()> {
    if retained_stage_image(ctx, expected)?.is_some() {
        return Ok(());
    }
    let cache = ctx.cache_dir();
    let directory = cache.join(RETAINED_STAGE_DIRECTORY);
    ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    fs::create_dir_all(&cache)?;
    ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    ensure_real_directory_or_absent(&ctx.root, &directory, "STAGEs retidos")?;
    match fs::DirBuilder::new().mode(0o755).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_real_directory_or_absent(&ctx.root, &directory, "STAGEs retidos")?;
    let destination = retained_stage_path(ctx, expected)?;

    let mut temporary = None;
    for _ in 0..128 {
        let serial = ATOMIC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = directory.join(format!(
            ".{expected}.minitrue-retain-{}-{serial}",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary_path, mut output) = temporary.ok_or_else(|| {
        anyhow::anyhow!(
            "não reservei temporário para reter o STAGE {}",
            destination.display()
        )
    })?;
    let result = (|| -> Result<()> {
        let mut input = sealed.try_clone()?;
        input.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 65_536];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| anyhow::anyhow!("tamanho do STAGE transbordou"))?;
            if total > MAX_CHANNEL_TAR_BYTES {
                bail!("STAGE do build excede {MAX_CHANNEL_TAR_BYTES} bytes");
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        input.seek(SeekFrom::Start(0))?;
        let observed = hex::encode(hasher.finalize());
        if observed != expected {
            bail!("memfd do build tem {observed}, mas o empacotador devolveu {expected}");
        }
        output.flush()?;
        output.sync_all()?;
        output.set_permissions(fs::Permissions::from_mode(0o644))?;
        drop(output);

        match fs::hard_link(&temporary_path, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                // Outro produtor só pode vencer com os mesmos bytes. A
                // revalidação também transforma symlink/corrupção em falha.
                let _ = retained_stage_image(ctx, expected)?
                    .ok_or_else(|| anyhow::anyhow!("STAGE retido sumiu durante publicação"))?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary_path)?;
        let _ = retained_stage_image(ctx, expected)?
            .ok_or_else(|| anyhow::anyhow!("STAGE retido sumiu após publicação"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

/// Congela o objeto comprimido no mesmo descritor selado que será entregue ao
/// decoder. O hash e o limite cobrem exatamente esses bytes, mesmo se outro
/// processo tentar crescer o arquivo de cache depois da abertura.
fn sealed_transport_snapshot(
    mut source: fs::File,
    label: &Path,
    max_bytes: u64,
) -> Result<(fs::File, String)> {
    let metadata = source.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("objeto de cache não é regular: {}", label.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "objeto de cache {} excede {max_bytes} bytes",
            label.display()
        );
    }

    let name = CString::new("minitrue-channel-transport")?;
    // SAFETY: CString válida; flags definidos pelo ABI Linux.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descritor recém-criado e transferido para File com dono único.
    let mut snapshot = unsafe { fs::File::from_raw_fd(descriptor) };
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("objeto de cache excedeu u64"))?;
        if total > max_bytes {
            bail!(
                "objeto de cache {} cresceu além de {max_bytes} bytes",
                label.display()
            );
        }
        hash.update(&buffer[..read]);
        snapshot.write_all(&buffer[..read])?;
    }
    if total == 0 {
        bail!("objeto de cache está vazio: {}", label.display());
    }
    snapshot.flush()?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: fcntl opera no descritor válido e não retém ponteiros.
    if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    snapshot.seek(SeekFrom::Start(0))?;
    Ok((snapshot, hex::encode(hash.finalize())))
}

fn decompress_channel_artifact(
    mut compressed: fs::File,
    label: &Path,
    max_bytes: u64,
) -> Result<(fs::File, String)> {
    let mut decoder =
        ruzstd::decoding::StreamingDecoder::new(&mut compressed).map_err(|error| crate::Fail {
            code: 3,
            msg: format!(
                "crimestop: artefato de canal não é zstd válido ({}): {error}",
                label.display()
            ),
        })?;
    let name = CString::new("minitrue-channel-stage")?;
    // SAFETY: CString válida; flags definidos pelo ABI Linux.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor recém-criado e transferido para File com dono único.
    let mut image = unsafe { fs::File::from_raw_fd(descriptor) };
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let read = decoder.read(&mut buffer).map_err(|error| crate::Fail {
            code: 3,
            msg: format!(
                "crimestop: falha ao descompactar artefato de canal {}: {error}",
                label.display()
            ),
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("tamanho descompactado excedeu u64"))?;
        if total > max_bytes {
            return fail(
                3,
                format!(
                    "crimestop: artefato de canal excede o limite descompactado de {max_bytes} bytes"
                ),
            );
        }
        hasher.update(&buffer[..read]);
        image.write_all(&buffer[..read])?;
    }
    if total == 0 {
        return fail(3, "crimestop: artefato de canal descompacta para vazio");
    }
    image.flush()?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: fcntl opera sobre descriptor válido e não retém ponteiros.
    if unsafe { libc::fcntl(image.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    image.seek(SeekFrom::Start(0))?;
    Ok((image, hex::encode(hasher.finalize())))
}

fn sealed_channel_snapshot(
    ctx: &Ctx,
    recipe: &Recipe,
    selection: &channel::Selection,
) -> Result<(fs::File, String)> {
    if selection.package != recipe.name || selection.version != recipe.version {
        bail!(
            "seleção de canal não corresponde à receita: {} {}",
            recipe.name,
            recipe.version
        );
    }
    match (
        selection.index_format,
        selection.producer_plan_lock_sha256.as_deref(),
        selection.producer_plan_url.as_deref(),
    ) {
        (4, Some(hash), Some(url)) => {
            let plan_path = fetch::ensure_pinned_url(ctx, url, hash)?;
            let bytes = read_regular_nofollow(&plan_path)?;
            crate::plan::verify_lock_bytes(&bytes, hash).map_err(|error| crate::Fail {
                code: 8,
                msg: format!(
                    "crimestop (plano produtor): canal {} não serve o PLAN_LOCK {} íntegro ({error})",
                    selection.channel, hash
                ),
            })?;
        }
        (2 | 3, _, _) if selection.legacy_development && !selection.release_root => {}
        _ => bail!("seleção de canal não prende índice/plano produtor coerente"),
    }
    let path = fetch::ensure_pinned_url(ctx, &selection.artifact_url, &selection.artifact_sha256)?;
    // O fetch conferiu o nome do cache. Abra sem seguir links e confira de novo
    // no mesmo descriptor que o decoder consumirá, fechando a corrida hash-uso.
    let transport = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let (transport, obtained) =
        sealed_transport_snapshot(transport, &path, MAX_CHANNEL_TRANSPORT_BYTES)?;
    if obtained != selection.artifact_sha256 {
        return fail(
            3,
            format!(
                "crimestop: objeto de cache mudou após o fetch; esperado {}, obtido {}",
                selection.artifact_sha256, obtained
            ),
        );
    }
    let (image, reprocorr) = decompress_channel_artifact(transport, &path, MAX_CHANNEL_TAR_BYTES)?;
    if let Some(index_hash) = &selection.index_reprocorr {
        if index_hash != &reprocorr {
            return fail(
                8,
                format!(
                    "crimestop (reprodução): tar interno de {} tem {}, índice assinado declara {}",
                    recipe.name, reprocorr, index_hash
                ),
            );
        }
    }
    if let Some(recipe_hash) = &recipe.reprocorr {
        if recipe_hash != &reprocorr {
            return fail(
                8,
                format!(
                    "crimestop (reprodução): tar interno de {} tem {}, receita pina {}",
                    recipe.name, reprocorr, recipe_hash
                ),
            );
        }
        println!(
            "  reprocorr confere: {} — canal reduzido a espelho",
            &reprocorr[..16]
        );
    }
    Ok((image, reprocorr))
}

/// Preflight compartilhado pelo resolvedor e pela instalação. Autentica os
/// bytes de transporte, o tar interno/reprocorr e a forma passiva do STAGE,
/// mas não aplica nenhuma entrada ao rootfs.
pub(crate) fn preflight_channel_selection(
    ctx: &Ctx,
    recipe: &Recipe,
    selection: &channel::Selection,
) -> Result<String> {
    let (image, reprocorr) = sealed_channel_snapshot(ctx, recipe, selection)?;
    let _ = preflight_sealed_stage(&ctx.root, &image)?;
    Ok(reprocorr)
}

#[derive(Debug)]
enum SealedStageKind {
    Directory {
        mode: u32,
    },
    Symlink {
        target: PathBuf,
    },
    Regular {
        mode: u32,
        offset: u64,
        size: u64,
        integrity: String,
        /// xattrs do `pack` v2, ordenados. Vazio em artefato v1.
        xattrs: Vec<(String, Vec<u8>)>,
    },
}

#[derive(Debug)]
struct SealedStageEntry {
    relative: String,
    kind: SealedStageKind,
}

impl SealedStageEntry {
    fn is_dir(&self) -> bool {
        matches!(self.kind, SealedStageKind::Directory { .. })
    }

    fn mode(&self) -> u32 {
        match self.kind {
            SealedStageKind::Directory { mode } | SealedStageKind::Regular { mode, .. } => mode,
            SealedStageKind::Symlink { .. } => 0o777,
        }
    }

    fn integrity(&self, empty_tree_hash: &str) -> String {
        match &self.kind {
            SealedStageKind::Directory { mode } => {
                format!("d:{}", directory_integrity_mode(*mode, empty_tree_hash))
            }
            SealedStageKind::Symlink { target } => {
                let mut hash = Sha256::new();
                hash.update(target.as_os_str().as_bytes());
                format!("l:{}", hex::encode(hash.finalize()))
            }
            SealedStageKind::Regular {
                mode,
                integrity,
                xattrs,
                ..
            } => format!("f:{}", regular_integrity_xattr(*mode, integrity, xattrs)),
        }
    }

    fn shared_directory_integrity(&self) -> Result<String> {
        match self.kind {
            SealedStageKind::Directory { mode } => {
                Ok(format!("D:{}", shared_directory_integrity_mode(mode)))
            }
            _ => bail!("claim D: só pode ser emitida por diretório do STAGE"),
        }
    }
}

/// Tetos coerentes com os do `pack`.
const MAX_XATTRS_PER_ENTRY: usize = 64;
const MAX_XATTR_VALUE: usize = 65_536;

/// Lê os xattrs de uma entrada a partir das extensões PAX
/// (`DISTROPICA.xattr.<nome>=<hex>`), já validando ordem, namespace e
/// duplicidade. Registro que este leitor não entende é recusa: pode ser
/// exatamente o privilégio que ele deveria aplicar.
fn read_entry_xattrs<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<Vec<(String, Vec<u8>)>> {
    let Some(extensions) = entry.pax_extensions()? else {
        return Ok(Vec::new());
    };
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for extension in extensions {
        let extension = extension?;
        let key = extension
            .key()
            .map_err(|_| anyhow::anyhow!("chave de extensão PAX não é UTF-8"))?;
        let Some(name) = key.strip_prefix(crate::pack::XATTR_PAX_PREFIX) else {
            bail!("cabeçalho PAX por entrada com chave inesperada: {key:?}");
        };
        if !name.starts_with("security.") && !name.starts_with("user.") {
            bail!("artefato traz xattr fora dos namespaces admitidos: {name:?}");
        }
        if out.len() >= MAX_XATTRS_PER_ENTRY {
            bail!("entrada declara mais de {MAX_XATTRS_PER_ENTRY} xattrs");
        }
        let value = extension
            .value()
            .map_err(|_| anyhow::anyhow!("valor do xattr {name} não é UTF-8"))?;
        let value = hex::decode(value)
            .map_err(|_| anyhow::anyhow!("valor do xattr {name} não é hexadecimal"))?;
        if value.len() > MAX_XATTR_VALUE {
            bail!("xattr {name} traz {} bytes", value.len());
        }
        // A ordem é canônica no `pack`; fora de ordem significa tar remontado
        // por outra ferramenta, e o hash da claim não bateria.
        if out
            .last()
            .is_some_and(|(previous, _)| previous.as_str() >= name)
        {
            bail!("xattrs fora de ordem canônica em {name}");
        }
        out.push((name.to_string(), value));
    }
    Ok(out)
}

/// Aplica xattrs no descritor já aberto do arquivo destino.
///
/// Falha fechado de propósito: aplicar `security.capability` exige
/// `CAP_SETFCAP`, e instalar sem ele produziria um sistema que **diverge do
/// artefato atestado** — exatamente o silêncio que o `pack` v2 veio eliminar.
fn apply_xattrs(file: &fs::File, dst: &Path, xattrs: &[(String, Vec<u8>)]) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    for (name, value) in xattrs {
        let c_name = std::ffi::CString::new(name.as_str())?;
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c_name.as_ptr(),
                value.as_ptr().cast(),
                value.len() as libc::size_t,
                0,
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            bail!(
                "não apliquei o xattr {name} em {}: {error}{}",
                dst.display(),
                match error.raw_os_error() {
                    Some(libc::EPERM) => " (aplicar capability exige CAP_SETFCAP)",
                    // ENOTSUP e EOPNOTSUPP são o mesmo valor no Linux.
                    Some(libc::ENOTSUP) => " (o sistema de arquivos do destino não suporta xattr)",
                    _ => "",
                }
            );
        }
    }
    Ok(())
}

fn hash_sealed_range(file: &fs::File, offset: u64, size: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut consumed = 0u64;
    let mut buffer = [0u8; 65_536];
    while consumed < size {
        let wanted = usize::try_from((size - consumed).min(buffer.len() as u64))?;
        let read = file.read_at(&mut buffer[..wanted], offset + consumed)?;
        if read == 0 {
            bail!("imagem selada terminou antes do payload declarado");
        }
        hasher.update(&buffer[..read]);
        consumed += read as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Clone, Copy)]
struct SealedStageLimits {
    tar_bytes: u64,
    regular_bytes: u64,
    entries: usize,
    path_bytes: usize,
    pax_bytes: u64,
}

const SEALED_STAGE_LIMITS: SealedStageLimits = SealedStageLimits {
    tar_bytes: MAX_CHANNEL_TAR_BYTES,
    regular_bytes: MAX_CHANNEL_TAR_BYTES,
    entries: MAX_SEALED_STAGE_ENTRIES,
    path_bytes: MAX_SEALED_STAGE_PATH_BYTES,
    pax_bytes: MAX_SEALED_STAGE_PAX_BYTES,
};

/// Faz uma passagem crua antes de o leitor de `tar` juntar GNU LongName,
/// LongLink ou PAX ao membro seguinte. Sem ela, a biblioteca precisaria
/// reservar o corpo inteiro dessas extensões para só então nos devolver a
/// entrada lógica — tarde demais para um limite de memória servir de defesa.
///
/// A passagem também prende tamanho, quantidade e tipos antes de qualquer
/// caminho poder chegar ao Journal. O segundo passe continua sendo a
/// autoridade semântica/canônica; este é o orçamento fail-closed que o cerca.
fn preflight_sealed_stage_limits(file: &fs::File, limits: SealedStageLimits) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("imagem selada não é arquivo regular");
    }
    let tar_bytes = metadata.len();
    if tar_bytes > limits.tar_bytes {
        bail!(
            "STAGE selado excede o limite de {} bytes do TAR",
            limits.tar_bytes
        );
    }

    // Um payload canônico pode ter, além do membro em si, LongName e uma
    // extensão (PAX para regular, LongLink para symlink), mais o PAX global.
    // Limitar também membros físicos impede um TAR feito só de extensões de
    // consumir CPU ilimitadamente sem jamais aumentar `entries`.
    let max_members = limits.entries.saturating_mul(3).saturating_add(1);
    let mut archive_file = file.try_clone()?;
    archive_file.seek(SeekFrom::Start(0))?;
    let mut archive = tar::Archive::new(archive_file);
    let mut members = 0usize;
    let mut entries = 0usize;
    let mut regular_bytes = 0u64;
    for raw in archive.entries()?.raw(true) {
        let entry = raw?;
        members = members
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("quantidade de membros TAR transbordou"))?;
        if members > max_members {
            bail!("STAGE selado excede {max_members} membros TAR");
        }

        let entry_type = entry.header().entry_type();
        let size = entry.size();
        let data_end = entry
            .raw_file_position()
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("membro TAR declara tamanho que transborda u64"))?;
        if data_end > tar_bytes {
            bail!("membro TAR termina além da imagem selada");
        }

        if entry_type.is_pax_global_extensions() {
            if size > 256 {
                bail!("cabeçalho global DISTROPICA.pack excede 256 bytes");
            }
            continue;
        }
        if entry_type.is_gnu_longname() || entry_type.is_gnu_longlink() {
            // GNU grava um NUL depois do caminho/alvo.
            if size > limits.path_bytes as u64 + 1 {
                bail!("extensão GNU de caminho excede {} bytes", limits.path_bytes);
            }
            continue;
        }
        if entry_type.is_pax_local_extensions() {
            if size > limits.pax_bytes {
                bail!(
                    "cabeçalho PAX por entrada excede {} bytes",
                    limits.pax_bytes
                );
            }
            continue;
        }

        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("quantidade de entradas TAR transbordou"))?;
        if entries > limits.entries {
            bail!("STAGE selado excede {} entradas", limits.entries);
        }
        if entry.path_bytes().len() > limits.path_bytes {
            bail!("STAGE contém caminho acima de {} bytes", limits.path_bytes);
        }

        if entry_type.is_file() {
            regular_bytes = regular_bytes
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("conteúdo regular do STAGE transbordou u64"))?;
            if regular_bytes > limits.regular_bytes {
                bail!(
                    "STAGE selado excede {} bytes de conteúdo regular",
                    limits.regular_bytes
                );
            }
        } else if entry_type.is_dir() || entry_type.is_symlink() {
            if size != 0 {
                bail!("entrada TAR não regular declara payload de {size} bytes");
            }
        } else if entry_type.is_hard_link() {
            bail!("STAGE contém hardlink; instalação ainda não preserva essa topologia");
        } else {
            bail!("STAGE contém tipo de entrada TAR não instalável");
        }
    }
    Ok(())
}

/// Indexa o tar selado sem materializá-lo num diretório gravável. A primeira
/// passagem fornece toda a topologia para o preflight; regulares guardam apenas
/// offset/tamanho e depois são copiados diretamente do descritor selado.
fn index_sealed_stage(file: &fs::File) -> Result<Vec<SealedStageEntry>> {
    index_sealed_stage_with_limits(file, SEALED_STAGE_LIMITS)
}

fn index_sealed_stage_with_limits(
    file: &fs::File,
    limits: SealedStageLimits,
) -> Result<Vec<SealedStageEntry>> {
    preflight_sealed_stage_limits(file, limits)?;
    let mut archive_file = file.try_clone()?;
    archive_file.seek(SeekFrom::Start(0))?;
    let mut archive = tar::Archive::new(archive_file);
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    let mut saw_pack_header = false;
    let mut pack_version = String::new();
    let mut previous_name: Option<Vec<u8>> = None;
    for raw in archive.entries()? {
        let mut entry = raw?;
        let entry_type = entry.header().entry_type();
        if entry_type.as_byte() == b'g' {
            if saw_pack_header || !entries.is_empty() {
                bail!("artefato contém cabeçalho global fora da posição canônica");
            }
            let mut body = Vec::new();
            entry.by_ref().take(256).read_to_end(&mut body)?;
            let Some(separator) = body.iter().position(|byte| *byte == b' ') else {
                bail!("artefato não declara DISTROPICA.pack");
            };
            let (declared, value_with_space) = body.split_at(separator);
            let value = &value_with_space[1..];
            let declared = std::str::from_utf8(declared)
                .ok()
                .and_then(|text| text.parse::<usize>().ok());
            let version = std::str::from_utf8(value)
                .ok()
                .and_then(|text| text.strip_prefix("DISTROPICA.pack="))
                .and_then(|text| text.strip_suffix('\n'))
                .filter(|version| crate::pack::format_supported(version));
            let Some(version) = version.filter(|_| declared == Some(body.len())) else {
                bail!("artefato usa cabeçalho DISTROPICA.pack inválido/desconhecido");
            };
            pack_version = version.to_string();
            saw_pack_header = true;
            continue;
        }
        if !saw_pack_header {
            bail!("artefato não começa com cabeçalho DISTROPICA.pack");
        }
        let path_bytes = entry.path_bytes();
        if path_bytes.len() > limits.path_bytes {
            bail!("STAGE contém caminho acima de {} bytes", limits.path_bytes);
        }
        if previous_name
            .as_deref()
            .is_some_and(|previous| previous >= path_bytes.as_ref())
        {
            bail!("STAGE não está em ordem canônica ou repete caminho");
        }
        previous_name = Some(path_bytes.to_vec());
        let relative = std::str::from_utf8(&path_bytes)
            .map_err(|_| anyhow::anyhow!("STAGE contém nome não UTF-8"))?
            .to_string();
        let relative_path = Path::new(&relative);
        if relative.is_empty()
            || relative.chars().any(char::is_control)
            || relative.split('/').any(|part| part.is_empty())
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("STAGE contém caminho não canônico: {relative:?}");
        }
        if !names.insert(relative.clone()) {
            bail!("STAGE contém entrada duplicada: {relative}");
        }
        let mode = entry.header().mode()? & 0o7777;
        // O cabeçalho PAX por entrada é consumido pelo próprio leitor de tar e
        // reaparece aqui como extensão da entrada a que pertence.
        let xattrs = read_entry_xattrs(&mut entry)?;
        if !xattrs.is_empty() {
            if pack_version != crate::pack::PACK_FORMAT_XATTR {
                bail!("artefato declara pack={pack_version} mas traz xattr em {relative:?}");
            }
            if !entry_type.is_file() {
                bail!("artefato declara xattr para {relative:?}, que não é arquivo regular");
            }
        }
        let kind = if entry_type.is_dir() {
            SealedStageKind::Directory { mode }
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name_bytes()
                .ok_or_else(|| anyhow::anyhow!("symlink sem alvo em {relative}"))?;
            if target.is_empty() || target.len() > limits.path_bytes || target.as_ref().contains(&0)
            {
                bail!(
                    "symlink em {relative:?} tem alvo vazio/inválido/acima de {} bytes",
                    limits.path_bytes
                );
            }
            SealedStageKind::Symlink {
                target: PathBuf::from(OsStr::from_bytes(&target)),
            }
        } else if entry_type.is_file() {
            let offset = entry.raw_file_position();
            let size = entry.size();
            SealedStageKind::Regular {
                mode,
                offset,
                size,
                integrity: hash_sealed_range(file, offset, size)?,
                xattrs,
            }
        } else if entry_type.is_hard_link() {
            bail!(
                "STAGE contém hardlink em {relative:?}; instalação ainda não preserva essa topologia"
            );
        } else {
            bail!("STAGE contém tipo de entrada não instalável em {relative:?}");
        };
        entries.push(SealedStageEntry { relative, kind });
    }
    if !saw_pack_header {
        bail!("artefato não declara DISTROPICA.pack");
    }

    // Um tar pode representar topologias impossíveis numa árvore real, por
    // exemplo `x` como symlink/regular seguido de `x/lock`. Recusar isso na
    // indexação mantém o preflight independente da extração: apply_stage não
    // pode acabar seguindo um ancestral que o próprio payload declarou como
    // não-diretório.
    let directory_by_name: HashMap<&str, bool> = entries
        .iter()
        .map(|entry| (entry.relative.as_str(), entry.is_dir()))
        .collect();
    for entry in &entries {
        let mut ancestor = Path::new(&entry.relative).parent();
        while let Some(path) = ancestor.filter(|path| !path.as_os_str().is_empty()) {
            let name = path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("ancestral de STAGE não UTF-8"))?;
            if directory_by_name.get(name) == Some(&false) {
                bail!(
                    "STAGE declara ancestral não-diretório {name:?} para {:?}",
                    entry.relative
                );
            }
            ancestor = path.parent();
        }
    }
    Ok(entries)
}

fn canonical_stage_topology(
    root: &Path,
    entries: &[SealedStageEntry],
) -> Result<HashMap<String, String>> {
    let mut by_relative = HashMap::new();
    let mut by_virtual: HashMap<String, String> = HashMap::new();
    let directories: HashSet<&str> = entries
        .iter()
        .filter(|entry| entry.is_dir())
        .map(|entry| entry.relative.as_str())
        .collect();
    let has_descendant = |directory: &str| {
        entries.iter().any(|candidate| {
            candidate
                .relative
                .strip_prefix(directory)
                .is_some_and(|suffix| suffix.starts_with('/'))
        })
    };
    let usr_is_scaffold = directories.contains("usr") && has_descendant("usr");
    let usr_share_is_scaffold = directories.contains("usr/share") && has_descendant("usr/share");
    for entry in entries {
        let relative = &entry.relative;
        let raw_virtual = relative
            .strip_prefix("etc/")
            .map(|sub| format!("/usr/share/factory/etc/{sub}"))
            .unwrap_or_else(|| virt_path(relative));
        let virtual_path = canonical_virtual_path(root, &raw_virtual)?;
        if let Some(previous) = by_virtual.insert(virtual_path.clone(), relative.clone()) {
            bail!("doublethink no próprio STAGE: {previous} e {relative} viram {virtual_path}");
        }
        by_relative.insert(relative.clone(), virtual_path);
    }

    for (relative, virtual_path) in &by_relative {
        let mut ancestor = Path::new(virtual_path).parent();
        while let Some(path) = ancestor {
            if path == Path::new("/") {
                break;
            }
            let ancestor_virtual = path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("ancestral canônico não UTF-8"))?;
            if let Some(ancestor_relative) = by_virtual.get(ancestor_virtual) {
                let raw_is_descendant = relative
                    .strip_prefix(ancestor_relative.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'));
                // O redirecionamento de `etc/` para a fábrica converge sob os
                // diretórios estruturais `usr/` e `usr/share/`. Isso permite a
                // um pacote carregar defaults em `etc/` e documentação em
                // `usr/share/` sem abrir a mesma exceção para aliases usr-merge
                // ou para uma árvore que declare `usr/share/factory` por dois
                // nomes. O ancestral também precisa ter descendentes brutos:
                // um diretório vazio seria uma claim `d:` e não mero scaffold.
                // Identidades exatas já foram recusadas acima.
                let factory_structural_ancestor = relative.starts_with("etc/")
                    && match (ancestor_relative.as_str(), ancestor_virtual) {
                        ("usr", "/usr") => usr_is_scaffold,
                        ("usr/share", "/usr/share") => usr_share_is_scaffold,
                        _ => false,
                    };
                if !raw_is_descendant && !factory_structural_ancestor {
                    bail!(
                        "doublethink no próprio STAGE: {ancestor_relative} e {relative} se sobrepõem como {ancestor_virtual} / {virtual_path}"
                    );
                }
            }
            ancestor = path.parent();
        }
    }
    Ok(by_relative)
}

fn virtual_at_or_below(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Payload nunca pode ocupar o plano de controle nem os workspaces efêmeros
/// que o próprio minitrue limpa. Diretórios estruturais ancestrais (`/var`,
/// `/tmp`) continuam válidos; uma folha não-diretório nesses ancestrais não.
fn ensure_stage_avoids_control_plane(
    root: &Path,
    entries: &[SealedStageEntry],
    stage_paths: &HashMap<String, String>,
) -> Result<()> {
    let control_roots = ["/var/lib/minitrue", "/var/cache/minitrue", "/etc/minitrue"]
        .into_iter()
        .map(|path| canonical_virtual_path(root, path))
        .collect::<Result<Vec<_>>>()?;
    let tmp_sentinel = canonical_virtual_path(root, "/tmp/minitrue-namespace-sentinel")?;
    let tmp_root = Path::new(&tmp_sentinel)
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| anyhow::anyhow!("namespace temporário não canônico"))?;
    let tmp_prefix = format!("{tmp_root}/");
    let overlaps_internal = |path: &str, is_dir: bool| {
        let control = control_roots.iter().any(|control| {
            virtual_at_or_below(path, control) || (!is_dir && virtual_at_or_below(control, path))
        });
        let temporary = path
            .strip_prefix(&tmp_prefix)
            .and_then(|suffix| suffix.split('/').next())
            .is_some_and(|component| {
                component.starts_with("minitrue-build-") || component.starts_with("minitrue-work-")
            })
            || (!is_dir && path == tmp_root);
        control || temporary
    };

    for entry in entries {
        let virt = stage_paths
            .get(&entry.relative)
            .ok_or_else(|| anyhow::anyhow!("STAGE sem identidade canônica"))?;
        let raw_etc_control =
            entry.relative == "etc/minitrue" || entry.relative.starts_with("etc/minitrue/");
        let live_etc_internal = if let Some(sub) = entry.relative.strip_prefix("etc/") {
            let live = canonical_virtual_path(root, &format!("/etc/{sub}"))?;
            overlaps_internal(&live, entry.is_dir())
        } else {
            false
        };
        if raw_etc_control || overlaps_internal(virt, entry.is_dir()) || live_etc_internal {
            bail!(
                "STAGE tenta ocupar namespace interno do minitrue: {} ({virt})",
                entry.relative
            );
        }
    }
    Ok(())
}

/// Preflight comum a toda fronteira que aceita ou republica um tar. Isso
/// impede que a emissão de um registro histórico aceite bytes que uma
/// instalação nova recusaria por topologia ou por ocupar o plano de controle.
fn preflight_sealed_stage(
    root: &Path,
    image: &fs::File,
) -> Result<(Vec<SealedStageEntry>, HashMap<String, String>)> {
    let entries = index_sealed_stage(image)?;
    let paths = canonical_stage_topology(root, &entries)?;
    ensure_stage_avoids_control_plane(root, &entries, &paths)?;
    Ok((entries, paths))
}

/// Move um caminho (arquivo ou symlink) preservando a natureza. O caminho
/// comum é um `rename` atômico. Só `EXDEV` ativa o fallback: ele constrói um
/// temporário completo no filesystem de destino, publica-o por `rename` e
/// remove a origem por último. Assim um crash/falha de cópia não transforma
/// bytes parciais em backup aparentemente válido.
fn move_path(src: &Path, dst: &Path) -> Result<()> {
    mkparent(dst)?;
    match fs::rename(src, dst) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == ErrorKind::CrossesDevices => {}
        // O CAMINHO VAI NA MENSAGEM, e isto não é adorno. Este `?` já devolveu
        // um "Resource busy (os error 16)" pelado no meio de uma instalação de
        // 99 pacotes: sem dizer qual arquivo, a única saída era eliminar
        // hipóteses uma a uma — reproduzir no hospedeiro, trocar glibc por
        // musl, comparar 38 corridas de aceite —, e nenhuma delas apontava o
        // lugar. Um erro de IO sem o caminho é meio erro.
        Err(e) => {
            return Err(e)
                .with_context(|| format!("movendo {} para {}", src.display(), dst.display()))
        }
    }

    let md = fs::symlink_metadata(src)?;
    let ft = md.file_type();
    if ft.is_symlink() {
        let tmp = move_temp_path(dst)?;
        let result = (|| -> Result<()> {
            symlink(fs::read_link(src)?, &tmp)?;
            fs::rename(&tmp, dst)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
    } else if ft.is_file() {
        let mut input = fs::File::open(src)?;
        copy_regular_atomically(&mut input, dst, md.permissions())?;
    } else {
        bail!(
            "fallback entre filesystems não suporta diretório/especial: {}",
            src.display()
        );
    }
    fs::remove_file(src)?;
    Ok(())
}

/// Núcleo transacional da cópia mundo-B (SPEC-0003 §4). Cada intenção entra no
/// log **antes** da mutação. O `TRANSACTION_ID` do `meta`, escrito por último, é
/// o ponto de commit: recovery descarta um journal com o mesmo id e reverte os
/// demais. Não há `fsync`; isto protege contra término do processo com o estado
/// já entregue ao kernel, não promete durabilidade diante de perda de energia.
///
/// Formato por linha:
///   `N␉<dst>`        — dst era novo (rollback: remove)
///   `B␉<dst>␉<n>`    — dst existia e será movido para `backup/<n>`
struct Journal {
    dir: PathBuf,
    root: PathBuf,
    rec_dir: PathBuf,
    txid: String,
    log: fs::File,
    next: u32,
    next_tmp: u32,
}

fn new_transaction_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let serial = TX_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{nanos:x}-{serial:x}", std::process::id())
}

fn record_transaction_id(rec_dir: &Path) -> Result<Option<String>> {
    Ok(read_meta_strict(rec_dir)?
        .and_then(|meta| meta.get("TRANSACTION_ID").cloned())
        .filter(|id| !id.is_empty()))
}

fn remove_leaf_if_exists(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_dir() => fs::remove_dir(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn journal_path_text(root: &Path, path: &Path) -> Result<String> {
    if path == root || !path.starts_with(root) {
        bail!(
            "journal recusou caminho fora do root {}: {}",
            root.display(),
            path.display()
        );
    }
    let rel = path
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("caminho fora do root"))?;
    if rel.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        bail!(
            "journal recusou caminho não-normalizado: {}",
            path.display()
        );
    }
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("journal não representa caminho não-UTF-8"))?;
    if text.contains(['\t', '\n', '\r']) {
        bail!("journal recusou TAB/LF/CR no caminho: {}", path.display());
    }
    Ok(text.to_string())
}

/// Confere o pai de uma mutação feita pelas APIs de caminho do std. Symlinks
/// relativos do usr-merge (`/bin -> usr/bin`, `/lib -> usr/lib`) são aceitos
/// quando resolvem dentro do rootfs; alvo absoluto/relativo externo, dangling
/// ou ancestral que não é diretório falha antes de `rename`, `copy` ou unlink.
///
/// O lock global serializa mutações do próprio minitrue. Esta checagem fecha o
/// escape persistente que `starts_with(root)` não detecta; as leituras e
/// remoções factuais usam ainda `openat2(RESOLVE_IN_ROOT)` fd-relative.
fn ensure_mutation_confined(root: &Path, path: &Path) -> Result<()> {
    journal_path_text(root, path)?;
    let root_real = fs::canonicalize(root)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("caminho sem diretório pai: {}", path.display()))?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("caminho fora do root"))?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!("caminho de mutação não-canônico: {}", path.display());
        };
        cursor.push(name);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let resolved = fs::canonicalize(&cursor).map_err(|error| {
                    anyhow::anyhow!(
                        "ancestral symlink inválido em {}: {error}",
                        cursor.display()
                    )
                })?;
                if !resolved.starts_with(&root_real) {
                    bail!(
                        "mutação recusada: ancestral {} resolve fora do root {}",
                        cursor.display(),
                        root.display()
                    );
                }
                if !fs::metadata(&resolved)?.is_dir() {
                    bail!("ancestral não é diretório: {}", cursor.display());
                }
                cursor = resolved;
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => bail!("ancestral não é diretório: {}", cursor.display()),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(crate) fn ensure_real_directory_or_absent(root: &Path, path: &Path, what: &str) -> Result<()> {
    ensure_mutation_confined(root, path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => bail!(
            "{what} precisa ser diretório real, não symlink/arquivo: {}",
            path.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

impl Journal {
    fn active_dir(ctx: &Ctx, pkg: &str) -> PathBuf {
        ctx.root.join("var/lib/minitrue/journal").join(pkg)
    }

    /// Restabelece a fronteira global: sob o lock, nenhuma operação nova pode
    /// começar enquanto existir uma transação anterior. Desde que essa regra
    /// vale, há no máximo um journal ativo. Mais de um representa estado legado
    /// ambíguo (a ordem correta de rollback não é demonstrável), então falha
    /// fechado e preserva todos os backups para reparo explícito.
    fn recover_all(ctx: &Ctx) -> Result<()> {
        let base = ctx.root.join("var/lib/minitrue/journal");
        ensure_real_directory_or_absent(&ctx.root, &base, "diretório de journals")?;
        let entries = match fs::read_dir(&base) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut active = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("journal com nome não UTF-8"))?;
            if name.starts_with('.') {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                bail!(
                    "journal ativo não é diretório real: {}",
                    entry.path().display()
                );
            }
            recipe::validate_name(&name)?;
            active.push(name);
        }
        active.sort();
        match active.as_slice() {
            [] => Ok(()),
            [pkg] => Self::recover(ctx, pkg),
            packages => bail!(
                "mais de um journal ativo ({}) — ordem de rollback ambígua; backups preservados",
                packages.join(", ")
            ),
        }
    }

    /// Resolve um journal órfão. Só o `meta` com o mesmo txid prova commit; sem
    /// ele, todas as mutações (inclusive registros cedentes) são revertidas.
    /// Qualquer falha de rollback deixa o journal e seus backups no lugar.
    fn recover(ctx: &Ctx, pkg: &str) -> Result<()> {
        let dir = Self::active_dir(ctx, pkg);
        ensure_mutation_confined(&ctx.root, &dir)?;
        match fs::symlink_metadata(&dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(md) if !md.file_type().is_dir() => {
                bail!("journal inválido (não é diretório): {}", dir.display())
            }
            Ok(_) => {}
        }

        let format = read_regular_text_nofollow(&dir.join("format")).map_err(|error| {
            anyhow::anyhow!(
                "journal legado/sem formato seguro em {}: {error}; recovery automático recusado",
                dir.display()
            )
        })?;
        if format != format!("{JOURNAL_FORMAT}\n") {
            bail!(
                "journal de formato desconhecido em {}; recovery automático recusado",
                dir.display()
            );
        }
        Self::ensure_control_untouched(&dir)?;
        let txid_text = read_regular_text_nofollow(&dir.join("txid"))?;
        let txid = txid_text.trim().to_string();
        if txid.is_empty()
            || txid_text.lines().count() != 1
            || !txid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            bail!("journal sem transaction id: {}", dir.display());
        }
        let rec_dir = ctx.records_dir().join(pkg);
        if record_transaction_id(&rec_dir)?.as_deref() == Some(txid.as_str()) {
            eprintln!("  journal já commitado de {pkg}: concluindo limpeza");
            return Self::retire(&dir, &txid, "committed");
        }

        Self::ensure_rollback_not_superseded(ctx, pkg, &dir)?;
        eprintln!("  journal órfão de {pkg}: revertendo cópia interrompida");
        Self::replay_rollback(&dir, &ctx.root)?;
        Self::retire(&dir, &txid, "rolled-back")
    }

    /// Versões anteriores ao guard de namespace podiam deixar o próprio
    /// `journal/<pkg>/log` entrar no STAGE. Nesse caso o log original era movido
    /// para `backup/<n>` e o nome público recebia bytes controlados pelo payload.
    /// A linha autorreferente gravada antes do move é uma assinatura inequívoca;
    /// detecte-a antes de confiar em `txid` ou interpretar o log vivo.
    fn ensure_control_untouched(dir: &Path) -> Result<()> {
        let inspect = |path: &Path| -> Result<()> {
            let bytes = read_regular_nofollow(path)?;
            let Ok(text) = std::str::from_utf8(&bytes) else {
                // Backups comuns são executáveis/dados. O log original gerado
                // pelo minitrue é sempre ASCII, portanto um binário não pode ser
                // a prova autorreferente que procuramos aqui.
                return Ok(());
            };
            for line in text.lines() {
                let fields: Vec<&str> = line.split('\t').collect();
                let destination = match fields.as_slice() {
                    ["N", destination] => Some(*destination),
                    ["B", destination, index] if index.parse::<u32>().is_ok() => Some(*destination),
                    _ => None,
                };
                if destination.is_some_and(|destination| {
                    let destination = Path::new(destination);
                    destination == dir || destination.starts_with(dir)
                }) {
                    bail!(
                        "journal alterou o próprio plano de controle; recovery automático recusado em {}",
                        dir.display()
                    );
                }
            }
            Ok(())
        };

        inspect(&dir.join("log"))?;
        let backup = dir.join("backup");
        match fs::symlink_metadata(&backup) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!(
                "backup de journal não é diretório real: {}",
                backup.display()
            ),
            Err(error) => return Err(error.into()),
        }
        for entry in fs::read_dir(&backup)? {
            let entry = entry?;
            if entry.file_type()?.is_file() && entry.metadata()?.len() <= MAX_RECORD_FILE {
                inspect(&entry.path())?;
            }
        }
        Ok(())
    }

    /// Compatibilidade segura com estados criados antes da recuperação global:
    /// se outro pacote já commitou ownership sobre um destino do journal órfão,
    /// reverter agora apagaria o sucessor. Nesse caso não há ordem demonstrável;
    /// conserva journal/backups e exige reparo explícito.
    fn ensure_rollback_not_superseded(ctx: &Ctx, pkg: &str, dir: &Path) -> Result<()> {
        let log = read_regular_text_nofollow(&dir.join("log"))?;
        let mut destinations = Vec::new();
        let mut touched_records = HashSet::new();
        for line in log.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            let dst = match fields.as_slice() {
                ["N", dst] if !dst.is_empty() => *dst,
                ["B", dst, n] if !dst.is_empty() && n.parse::<u32>().is_ok() => *dst,
                _ => bail!("journal inválido: {line:?}"),
            };
            let dst = Path::new(dst);
            journal_path_text(&ctx.root, dst)?;
            if let Ok(relative) = dst.strip_prefix(ctx.records_dir()) {
                if let Some(std::path::Component::Normal(owner)) = relative.components().next() {
                    let owner = owner
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("registro tocado não UTF-8"))?;
                    recipe::validate_name(owner)?;
                    touched_records.insert(owner.to_string());
                }
            }
            destinations.push(dst.to_path_buf());
        }

        let excluded = HashSet::from([pkg.to_string()]);
        let claims = all_manifests_for_recovery(ctx, &excluded, &touched_records)?;
        let external = index_manifest_claims(&claims, None);
        if external.is_empty() {
            return Ok(());
        }
        for dst in destinations {
            let relative = dst
                .strip_prefix(&ctx.root)
                .map_err(|_| anyhow::anyhow!("destino de journal fora do rootfs"))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("destino de journal não UTF-8"))?;
            if relative.is_empty() {
                bail!("journal tentou alterar a raiz do sistema");
            }
            let virt = canonical_virtual_path(&ctx.root, &format!("/{relative}"))?;
            let conflict = indexed_claim_at_or_above(&external, &virt, true)
                .or_else(|| indexed_descendant(&external, &virt));
            if let Some((owner, version, claim)) = conflict {
                bail!(
                    "rollback de {pkg} recusado: {virt} sobrepõe claim commitada {claim} de {owner} {version}; journal e backups preservados"
                );
            }
        }
        Ok(())
    }

    fn begin(ctx: &Ctx, pkg: &str) -> Result<Journal> {
        Self::recover_all(ctx)?;
        let dir = Self::active_dir(ctx, pkg);
        ensure_mutation_confined(&ctx.root, &dir)?;
        let base = dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("journal sem diretório pai"))?;
        fs::create_dir_all(base)?;
        let txid = new_transaction_id();
        let pending = base.join(format!(".new-{txid}"));
        fs::create_dir(&pending)?;
        fs::create_dir(pending.join("backup"))?;
        fs::write(pending.join("format"), format!("{JOURNAL_FORMAT}\n"))?;
        fs::write(pending.join("txid"), format!("{txid}\n"))?;
        let log = fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(pending.join("log"))?;
        // O journal só fica ativo depois de estar completamente inicializado.
        fs::rename(&pending, &dir)?;
        Ok(Journal {
            dir,
            root: ctx.root.clone(),
            rec_dir: ctx.records_dir().join(pkg),
            txid,
            log,
            next: 0,
            next_tmp: 0,
        })
    }

    fn record(&mut self, line: &str) -> Result<()> {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        self.log.write_all(&bytes)?;
        self.log.flush()?;
        Ok(())
    }

    fn record_new_intent(&mut self, dst: &Path) -> Result<()> {
        let dst = journal_path_text(&self.root, dst)?;
        self.record(&format!("N\t{dst}"))
    }

    fn record_backup_intent(&mut self, dst: &Path, n: u32) -> Result<()> {
        let dst = journal_path_text(&self.root, dst)?;
        self.record(&format!("B\t{dst}\t{n}"))
    }

    /// Tira `dst` do caminho. A intenção B é registrada antes de mover o original;
    /// recovery aceita tanto "backup ainda ausente" quanto "backup já criado".
    fn stash(&mut self, dst: &Path, allow_directory: bool) -> Result<()> {
        journal_path_text(&self.root, dst)?;
        ensure_mutation_confined(&self.root, dst)?;
        match fs::symlink_metadata(dst) {
            Ok(metadata) => {
                if metadata.file_type().is_dir() && !allow_directory {
                    bail!(
                        "recusei substituir diretório sem claim d: íntegra: {}",
                        dst.display()
                    );
                }
                let n = self.next;
                self.next += 1;
                let bak = self.dir.join("backup").join(n.to_string());
                ensure_mutation_confined(&self.root, &bak)?;
                self.record_backup_intent(dst, n)?;
                move_path(dst, &bak)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.record_new_intent(dst)?;
            }
            Err(e) => return Err(e).with_context(|| format!("inspecionando {}", dst.display())),
        }
        Ok(())
    }

    fn place_file(&mut self, dst: &Path, src: &Path) -> Result<()> {
        if let Some(parent) = dst.parent().filter(|parent| *parent != self.root) {
            self.ensure_dir(parent, fs::Permissions::from_mode(0o755), false, false)?;
        }
        self.stash(dst, false)?;
        fs::copy(src, dst)
            .with_context(|| format!("copiando {} para {}", src.display(), dst.display()))?;
        Ok(())
    }

    fn place_sealed_file(
        &mut self,
        dst: &Path,
        image: &fs::File,
        offset: u64,
        size: u64,
        mode: u32,
        xattrs: &[(String, Vec<u8>)],
    ) -> Result<()> {
        if let Some(parent) = dst.parent().filter(|parent| *parent != self.root) {
            self.ensure_dir(parent, fs::Permissions::from_mode(0o755), false, false)?;
        }
        self.stash(dst, false)?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dst)?;
        let mut consumed = 0u64;
        let mut buffer = [0u8; 65_536];
        while consumed < size {
            let wanted = usize::try_from((size - consumed).min(buffer.len() as u64))?;
            let read = image.read_at(&mut buffer[..wanted], offset + consumed)?;
            if read == 0 {
                bail!("imagem selada terminou antes de copiar {}", dst.display());
            }
            output.write_all(&buffer[..read])?;
            consumed += read as u64;
        }
        output.set_permissions(fs::Permissions::from_mode(mode))?;
        // Antes do flush final e com o arquivo ainda sob o journal: se a
        // capability não puder ser aplicada, a instalação inteira reverte.
        apply_xattrs(&output, dst, xattrs)?;
        output.flush()?;
        Ok(())
    }

    fn place_symlink(&mut self, dst: &Path, target: &Path) -> Result<()> {
        if let Some(parent) = dst.parent().filter(|parent| *parent != self.root) {
            self.ensure_dir(parent, fs::Permissions::from_mode(0o755), false, false)?;
        }
        self.stash(dst, false)?;
        symlink(target, dst)?;
        Ok(())
    }

    /// Garante diretório sem deixá-lo fora da transação. Componentes pais que
    /// ainda não existam também recebem intenção N; em rollback, filhos saem
    /// primeiro e cada diretório recém-criado é removido quando vazio.
    fn ensure_dir(
        &mut self,
        dst: &Path,
        permissions: fs::Permissions,
        enforce_permissions: bool,
        allow_existing_claim: bool,
    ) -> Result<bool> {
        journal_path_text(&self.root, dst)?;
        ensure_mutation_confined(&self.root, dst)?;
        match fs::symlink_metadata(dst) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                if enforce_permissions {
                    if fs::read_dir(dst)?.next().transpose()?.is_some() {
                        bail!(
                            "diretório {} deveria estar vazio, mas contém dados; claim d: recusada",
                            dst.display()
                        );
                    }
                    if metadata.permissions().mode() & 0o7777 != permissions.mode() & 0o7777 {
                        bail!(
                            "diretório vazio {} existe com modo {:04o}, mas o STAGE exige {:04o}",
                            dst.display(),
                            metadata.permissions().mode() & 0o7777,
                            permissions.mode() & 0o7777
                        );
                    }
                    if !allow_existing_claim {
                        // Infraestrutura vazia preexistente satisfaz o STAGE,
                        // mas não muda de dono. Só um diretório criado nesta
                        // transação ou já reclamado por este pacote vira d:.
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let text = journal_path_text(&self.root, dst)?;
                let relative = Path::new(&text)
                    .strip_prefix(&self.root)
                    .map_err(|_| anyhow::anyhow!("diretório fora do root"))?;
                let virt = format!("/{}", relative.display());
                open_confined(&self.root, &virt, libc::O_PATH | libc::O_DIRECTORY).map_err(
                    |error| {
                        anyhow::anyhow!(
                            "{} é symlink, mas não resolve para diretório interno: {error}",
                            dst.display()
                        )
                    },
                )?;
                // O link do usr-merge é infraestrutura preexistente, não claim
                // do pacote cujo STAGE apenas atravessa esse diretório.
                return Ok(false);
            }
            Ok(_) => bail!("{} existe e não é diretório", dst.display()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(parent) = dst.parent() {
            if parent != self.root && !parent.as_os_str().is_empty() {
                self.ensure_dir(parent, fs::Permissions::from_mode(0o755), false, false)?;
            }
        }
        self.record_new_intent(dst)?;
        fs::create_dir(dst)?;
        fs::set_permissions(dst, permissions)?;
        Ok(true)
    }

    /// Garante uma claim estrutural `D:`. Ao contrário de `d:`, o diretório
    /// pode conter payload de outros pacotes; por isso somente tipo e modo são
    /// conferidos. A declaração explícita permite registrar infraestrutura
    /// preexistente porque a claim nunca autoriza apagar seus filhos.
    fn ensure_shared_dir(
        &mut self,
        dst: &Path,
        permissions: fs::Permissions,
        _allow_existing_claim: bool,
    ) -> Result<bool> {
        journal_path_text(&self.root, dst)?;
        ensure_mutation_confined(&self.root, dst)?;
        match fs::symlink_metadata(dst) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                if metadata.permissions().mode() & 0o7777 != permissions.mode() & 0o7777 {
                    bail!(
                        "diretório compartilhado {} existe com modo {:04o}, mas o STAGE exige {:04o}",
                        dst.display(),
                        metadata.permissions().mode() & 0o7777,
                        permissions.mode() & 0o7777
                    );
                }
                return Ok(true);
            }
            Ok(_) => bail!("{} existe e não é diretório real", dst.display()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(parent) = dst.parent() {
            if parent != self.root && !parent.as_os_str().is_empty() {
                self.ensure_dir(parent, fs::Permissions::from_mode(0o755), false, false)?;
            }
        }
        self.record_new_intent(dst)?;
        fs::create_dir(dst)?;
        fs::set_permissions(dst, permissions)?;
        Ok(true)
    }

    /// Troca um arquivo de registro sem expor conteúdo parcial. O temporário
    /// também recebe intenção N antes de ser criado e é removido no rollback.
    fn place_bytes(&mut self, dst: &Path, bytes: &[u8]) -> Result<()> {
        ensure_mutation_confined(&self.root, dst)?;
        if let Some(parent) = dst.parent().filter(|parent| *parent != self.root) {
            self.ensure_dir(parent, fs::Permissions::from_mode(0o755), false, false)?;
        }
        let name = dst.file_name().and_then(|n| n.to_str()).unwrap_or("record");
        let tmp = dst.with_file_name(format!(".{name}.minitrue-{}-{}", self.txid, self.next_tmp));
        self.next_tmp += 1;
        self.record_new_intent(&tmp)?;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        drop(f);
        self.stash(dst, false)?;
        fs::rename(&tmp, dst)?;
        Ok(())
    }

    /// Remove dst transacionalmente (upgrade: caminhos que sumiram do novo
    /// manifesto). Rollback restaura.
    fn drop_path(&mut self, dst: &Path, allow_directory: bool) -> Result<()> {
        match fs::symlink_metadata(dst) {
            Ok(_) => self.stash(dst, allow_directory)?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// Retira uma claim `D:` sem jamais usar a autoridade recursiva de `d:`.
    /// A cópia movida ao backup é revalidada vazia; uma inserção concorrente
    /// entre a inspeção e o rename provoca rollback, não commit destrutivo.
    fn drop_empty_dir(&mut self, dst: &Path) -> Result<bool> {
        journal_path_text(&self.root, dst)?;
        ensure_mutation_confined(&self.root, dst)?;
        let descriptor = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dst)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
                return Ok(false)
            }
            Err(error) => return Err(error.into()),
        };
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
        if fs::read_dir(&proc_path)?.next().transpose()?.is_some() {
            return Ok(false);
        }
        let backup_index = self.next;
        self.stash(dst, true)?;
        let backup = self.dir.join("backup").join(backup_index.to_string());
        if fs::read_dir(&backup)?.next().transpose()?.is_some() {
            bail!(
                "diretório compartilhado {} ganhou filhos durante a retirada; rollback exigido",
                dst.display()
            );
        }
        Ok(true)
    }

    fn commit(mut self) -> Result<()> {
        self.log.flush()?;
        if record_transaction_id(&self.rec_dir)?.as_deref() != Some(self.txid.as_str()) {
            bail!(
                "recusei commit sem meta TRANSACTION_ID={} em {}",
                self.txid,
                self.rec_dir.display()
            );
        }
        let dir = self.dir.clone();
        let txid = self.txid.clone();
        drop(self.log);
        Self::retire(&dir, &txid, "committed")
    }

    fn rollback(mut self) -> Result<()> {
        self.log.flush()?;
        let dir = self.dir.clone();
        let root = self.root.clone();
        let txid = self.txid.clone();
        drop(self.log);
        Self::replay_rollback(&dir, &root)?;
        Self::retire(&dir, &txid, "rolled-back")
    }

    /// Desfaz um journal (em processo ou órfão): lê o log e reverte na ordem
    /// INVERSA. Idempotente — seguro reexecutar (crash durante o próprio rollback).
    fn replay_rollback(dir: &Path, root: &Path) -> Result<()> {
        let log = read_regular_text_nofollow(&dir.join("log"))?;
        for (rev_idx, line) in log.lines().rev().enumerate() {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                ["N", dst] if !dst.is_empty() => {
                    let dst = Path::new(dst);
                    journal_path_text(root, dst)?;
                    ensure_mutation_confined(root, dst)?;
                    remove_leaf_if_exists(dst)?;
                }
                ["B", dst, n] if !dst.is_empty() => {
                    let dst = Path::new(dst);
                    journal_path_text(root, dst)?;
                    ensure_mutation_confined(root, dst)?;
                    let _: u32 = n
                        .parse()
                        .map_err(|_| anyhow::anyhow!("journal inválido: índice de backup '{n}'"))?;
                    let bak = dir.join("backup").join(n);
                    ensure_mutation_confined(root, &bak)?;
                    match fs::symlink_metadata(&bak) {
                        Ok(_) => {
                            remove_leaf_if_exists(dst)?;
                            move_path(&bak, dst)?;
                        }
                        // Intenção gravada, mas o processo morreu antes do move;
                        // ou esta entrada já foi restaurada por rollback anterior.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            match fs::symlink_metadata(dst) {
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                                    "rollback inseguro: backup {} e destino {} ausentes",
                                    bak.display(),
                                    dst.display()
                                ),
                                Err(e) => return Err(e.into()),
                            }
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                _ => bail!(
                    "journal inválido na entrada reversa {}: {:?}",
                    rev_idx + 1,
                    line
                ),
            }
        }
        Ok(())
    }

    /// Primeiro renomeia o journal para fora do nome ativo. Só se chega aqui
    /// após commit provado ou rollback integral; uma falha anterior preserva o
    /// diretório ativo e todos os backups para nova tentativa/diagnóstico.
    fn retire(dir: &Path, txid: &str, label: &str) -> Result<()> {
        let base = dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("journal sem diretório pai"))?;
        let retired = base.join(format!(".{label}-{txid}"));
        fs::rename(dir, &retired)?;
        fs::remove_dir_all(&retired)?;
        Ok(())
    }
}

fn install_source(
    ctx: &Ctx,
    r: &Recipe,
    explicit: bool,
    fingerprint: &str,
    policy: BinaryPolicy,
    selection: Option<&channel::Selection>,
    frozen: &FrozenBuildGraph<'_>,
) -> Result<()> {
    let rec_dir = ctx.records_dir().join(&r.name);
    ensure_real_directory_or_absent(&ctx.root, &rec_dir, "registro do pacote")?;
    if let Some(meta) = read_meta_strict(&rec_dir)? {
        ensure_supported_record_format(&meta, &r.name)?;
        // Idempotência por FINGERPRINT, não só VERSION (SPEC-0011 §4): uma
        // receita corrigida com a MESMA versão muda o fingerprint e re-builda.
        if meta.get("VERSION") == Some(&r.version)
            && meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint)
        {
            migrate_legacy_record(ctx, &rec_dir, r, fingerprint)?;
            let source_only_rebuild = policy == BinaryPolicy::SourceOnly
                && meta
                    .get("ORIGIN")
                    .is_some_and(|origin| origin.starts_with("canal:"));
            if record_is_intact(ctx, &rec_dir, r) && !source_only_rebuild {
                if explicit {
                    world_add(ctx, &r.name)?;
                }
                println!("os registros já estão corretos: {} {}", r.name, r.version);
                return Ok(());
            }
        }
        match provisional_cession_state(ctx, &rec_dir, r)? {
            ProvisionalCession::Intact => {
                if explicit {
                    world_add(ctx, &r.name)?;
                }
                // Mesma decisão do mundo A, pelo mesmo motivo e com os mesmos
                // três casos. Aqui os provisionais que já cederam são a
                // toolchain da semente — binutils, gcc, gmp, mpfr, mpc,
                // libstdcxx, binutils-cross —, e o gcc chegou a ceder 176 dos
                // seus 185 caminhos. Antes disto, corrigir a receita de
                // qualquer um deles era escrever no vazio.
                let versao = meta.get("VERSION").map(String::as_str).unwrap_or("?");
                if meta.get("FINGERPRINT").map(String::as_str) == Some(fingerprint) {
                    println!(
                        "provisório {} {} já cedeu caminhos; baseline preservado.",
                        r.name, versao
                    );
                    return Ok(());
                }
                let cedidos = caminhos_cedidos(ctx, &rec_dir, versao)?;
                let motivo = match meta.get("FINGERPRINT") {
                    None => "registro legado sem identidade".to_string(),
                    Some(gravado) => format!(
                        "receita mudou ({}… -> {}…)",
                        &gravado[..12.min(gravado.len())],
                        &fingerprint[..12.min(fingerprint.len())]
                    ),
                };
                println!(
                    "provisório {} {}: {motivo}; refrescando o que ainda é dele, \
                     {} caminho(s) cedido(s) intocado(s)",
                    r.name,
                    versao,
                    cedidos.len()
                );
                // e cai para a reconstrução; quem preserva os cedidos dali em
                // diante é o `cedidos_do_registro`, lido de novo no preflight,
                // na materialização e na escrita do registro.
            }
            ProvisionalCession::Incoherent => bail!(
                "{}: cessão provisional incoerente; rode verify e repare os registros antes de reconstruir",
                r.name
            ),
            ProvisionalCession::Unproved
                if installed_identity_changed(&meta, r, fingerprint) =>
            {
                let sem_sucessor = cessoes_sem_sucessor_ausentes(ctx, &rec_dir, &r.name)?;
                println!(
                    "provisório {} {}: identidade mudou e há {} cessão(ões) ausente(s) sem sucessor atual; \
                     o STAGE selado decidirá sem retomar nem apagar",
                    r.name,
                    meta.get("VERSION").map(String::as_str).unwrap_or("?"),
                    sem_sucessor.len()
                );
            }
            ProvisionalCession::Unproved => bail!(
                "{}: cessão provisional perdeu o sucessor sem mudança comprovada de identidade",
                r.name
            ),
            ProvisionalCession::NotCeded => {}
        }
    }

    if let Some(selection) = selection {
        println!(
            "retificando os registros (canal {}): {} {}",
            selection.channel, r.name, r.version
        );
        let (sealed_artifact, reprocorr) = sealed_channel_snapshot(ctx, r, selection)?;
        return install_sealed_source(
            ctx,
            r,
            explicit,
            fingerprint,
            &sealed_artifact,
            &reprocorr,
            SourceRecordOrigin::Channel(selection),
        );
    }
    if policy == BinaryPolicy::BinaryOnly {
        return fail(
            5,
            format!(
                "{} {}: --only-binary sem seleção congelada de canal",
                r.name, r.version
            ),
        );
    }

    println!("retificando os registros (fonte): {} {}", r.name, r.version);
    let artifacts = fetch::ensure_artifacts(ctx, r)?;

    let work = ctx
        .root
        .join("tmp")
        .join(format!("minitrue-build-{}", r.name));
    ensure_paths_unclaimed(ctx, &r.name, &[(&work, "workspace mundo B")])?;
    ensure_mutation_confined(&ctx.root, &work)?;
    let _ = fs::remove_dir_all(&work);
    let src_dir = work.join("src");
    let stage = work.join("stage");
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&stage)?;
    fs::create_dir_all(work.join("tmp"))?;
    let zig_cache = ctx.cache_dir().join("zig");
    ensure_real_directory_or_absent(&ctx.root, &zig_cache, "cache global do zig")?;
    fs::create_dir_all(&zig_cache)?;
    ensure_real_directory_or_absent(&ctx.root, &zig_cache, "cache global do zig")?;
    if recipe::BUILD_CCACHE_VIEW {
        let ccache_cache = ctx.cache_dir().join("ccache");
        ensure_real_directory_or_absent(&ctx.root, &ccache_cache, "cache global do ccache")?;
        fs::create_dir_all(&ccache_cache)?;
        ensure_real_directory_or_absent(&ctx.root, &ccache_cache, "cache global do ccache")?;
    }
    // Receita e auxiliares são os snapshots capturados por `recipe::load`: o
    // build, o fingerprint e o registro observam exatamente os mesmos bytes.
    r.materialize_files(&work)?;
    write_new(&work.join("recipe"), &r.recipe_bytes)?;
    if fs::symlink_metadata(work.join(".tc")).is_ok() {
        return fail(2, format!("{}: files/ ocupa o nome reservado .tc", r.name));
    }
    // EPOCH default fixo (2024-01-01) sobreponível pela receita (SPEC-0010).
    // Também normaliza a view e os shims antes de qualquer build observá-los.
    let epoch = r.epoch.clone().unwrap_or_else(|| "1704067200".into());
    let epoch_u64: u64 = epoch
        .parse()
        .map_err(|_| anyhow::anyhow!("{}: EPOCH inválido: {epoch:?}", r.name))?;
    let be = setup_toolchain(ctx, &work, r, epoch_u64)?;
    let view = create_build_view(ctx, &work, r, frozen, &artifacts, epoch_u64)?;
    eprintln!(
        "  view fechada: runner={} view={} sysroot={}, {} executável(is)",
        recipe::BUILD_RUNNER_FORMAT,
        recipe::BUILD_VIEW_FORMAT,
        recipe::BUILD_SYSROOT_FORMAT,
        view.commands.len()
    );
    let mut cmd = build_command(ctx, &be, &view, r.retries, &work, &epoch, &artifacts);
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

    // Reprodutibilidade como RAIZ de confiança (SPEC-0009 §6, SPEC-0010 §5): o
    // reprocorr é o sha256 do STAGE empacotado deterministicamente (`pack`). Se a
    // receita o pina, o build DEVE reproduzi-lo — divergir é crimestop (build
    // não-determinístico ou adulterado), não um aviso. Gravado no registro sempre,
    // é o que uma attestation assina e a corroboração compara (SPEC-0009 §8).
    let (sealed_artifact, reprocorr) = sealed_stage_snapshot(&stage, epoch_u64)?;
    if let Some(pinned) = &r.reprocorr {
        if pinned != &reprocorr {
            let _ = fs::remove_dir_all(&work);
            return fail(
                8,
                // Os hashes saem INTEIROS. Quem lê este crimestop precisa
                // decidir entre "o build regrediu" e "o pino envelheceu com a
                // toolchain", e no segundo caso precisa do valor novo para
                // repinar. Truncar obrigava a reproduzir o erro com a receita
                // adulterada só para ler o que a ferramenta já sabia.
                format!(
                    "crimestop (reprodução): {} produziu reprocorr {reprocorr} mas a receita pina {pinned}",
                    r.name
                ),
            );
        }
        println!(
            "  reprocorr confere: {} — reprodução corroborada",
            &reprocorr[..16.min(reprocorr.len())]
        );
    }

    // O artefato do próprio build é a única raiz legítima para uma emissão de
    // release. Retê-lo agora, enquanto o memfd ainda está selado, evita que a
    // publicação dependa de remontar o STAGE a partir do sistema já instalado.
    retain_local_stage(ctx, &sealed_artifact, &reprocorr)?;

    let result = install_sealed_source(
        ctx,
        r,
        explicit,
        fingerprint,
        &sealed_artifact,
        &reprocorr,
        SourceRecordOrigin::Local,
    );
    let _ = fs::remove_dir_all(&work);
    result
}

#[derive(Clone, Copy)]
enum SourceRecordOrigin<'a> {
    Local,
    Channel(&'a channel::Selection),
}

fn canonical_shared_roots(ctx: &Ctx, recipe: &Recipe) -> Result<Vec<String>> {
    recipe
        .shared_dirs
        .iter()
        .map(|path| canonical_virtual_path(&ctx.root, path))
        .collect()
}

fn path_is_shared(path: &str, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|root| path == root || virtual_at_or_below(path, root))
}

fn install_sealed_source(
    ctx: &Ctx,
    r: &Recipe,
    explicit: bool,
    fingerprint: &str,
    sealed_artifact: &fs::File,
    reprocorr: &str,
    origin: SourceRecordOrigin<'_>,
) -> Result<()> {
    let rec_dir = ctx.records_dir().join(&r.name);
    // A imagem selada é a fonte única do preflight, das provas e da cópia.
    let (entries, stage_paths) = preflight_sealed_stage(&ctx.root, sealed_artifact)?;
    let shared_roots = canonical_shared_roots(ctx, r)?;
    for root in &shared_roots {
        let declared = entries.iter().any(|entry| {
            entry.is_dir()
                && stage_paths
                    .get(&entry.relative)
                    .is_some_and(|path| path == root)
        });
        if !declared {
            return fail(
                4,
                format!(
                    "{}: SHARED_DIRS declara {root}, mas o STAGE não contém esse diretório",
                    r.name
                ),
            );
        }
    }
    let claims = all_exclusive_manifests(ctx)?;
    let directory_claims = all_directory_claims(ctx)?;
    let shared_directory_claims = all_shared_directory_claims(ctx)?;
    let all_claim_index = index_manifest_claims(&claims, None);
    let external_claim_index = index_manifest_claims(&claims, Some(&r.name));
    // Donos cujos diretórios esta receita pode tomar: provisional declarado em
    // SUPERSEDES, exatamente as mesmas duas condições que o
    // adopt_provisional_path exige para ceder um arquivo.
    let mut ceded_directory_owners = std::collections::HashSet::new();
    for candidate in &r.supersedes {
        if is_provisional(ctx, candidate) {
            ceded_directory_owners.insert(candidate.clone());
        }
    }
    let external_directory_index =
        index_directory_claims(&directory_claims, &r.name, &ceded_directory_owners);
    let external_shared_directory_index =
        index_directory_claims(&shared_directory_claims, &r.name, &HashSet::new());
    let reused_shared_roots: Vec<String> = shared_directory_claims
        .iter()
        .filter(|(owner, _, _)| owner != &r.name && r.deps.iter().any(|dep| dep == owner))
        .map(|(_, _, path)| path.clone())
        .collect();
    // O que ESTE pacote já cedeu, quando ele é um provisional sendo refrescado.
    // Vazio para todo o resto — e é por isso que os três usos abaixo não mudam
    // o comportamento de nenhum pacote comum.
    let mut cedidos = cedidos_do_registro(ctx, &rec_dir)?;
    let sem_sucessor = cessoes_sem_sucessor_ausentes(ctx, &rec_dir, &r.name)?;
    if !sem_sucessor.is_empty() {
        if provisional_cession_state(ctx, &rec_dir, r)? != ProvisionalCession::Unproved {
            bail!(
                "{}: registro não satisfaz a fronteira segura para aposentar cessões",
                r.name
            );
        }
        let meta = read_meta_strict(&rec_dir)?
            .ok_or_else(|| anyhow::anyhow!("{}: registro provisional sumiu", r.name))?;
        if !installed_identity_changed(&meta, r, fingerprint) {
            bail!(
                "{}: cessão sem sucessor não pode ser reparada sem mudança comprovada de identidade",
                r.name
            );
        }
        let stage_set: HashSet<&str> = stage_paths.values().map(String::as_str).collect();
        for path in &sem_sucessor {
            if stage_set.contains(path.as_str()) {
                bail!(
                    "{}: STAGE novo reapresenta {path}, cuja cessão perdeu o sucessor; retomada automática recusada",
                    r.name
                );
            }
        }
        let sem_sucessor_set: HashSet<&str> = sem_sucessor.iter().map(String::as_str).collect();
        cedidos.retain(|(path, _)| !sem_sucessor_set.contains(path.as_str()));
        for path in &sem_sucessor {
            println!("  {path}: claim aposentada — ausente no sucessor, no root e no STAGE novo");
        }
    }
    let cedidos_set: HashSet<String> = cedidos.iter().map(|(c, _)| c.clone()).collect();
    let linhas_cedidas: Vec<String> = cedidos.iter().map(|(_, linha)| linha.clone()).collect();
    let mut stage_dirs_with_children = HashSet::new();
    for entry in &entries {
        let mut parent = Path::new(&entry.relative).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            stage_dirs_with_children.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
    }
    for entry in &entries {
        let rel = &entry.relative;
        let virt = stage_paths
            .get(rel)
            .ok_or_else(|| anyhow::anyhow!("STAGE indexado sem caminho canônico"))?
            .clone();
        // Já cedido: o dono legítimo é o sucessor, e é ele quem o preflight
        // encontraria aqui. Sem esta linha o refresh de um provisional cedido
        // morreria em "doublethink detectado" no primeiro arquivo cedido —
        // acusando de conflito exatamente a cessão que o registro descreve.
        if cedidos_set.contains(virt.as_str()) {
            continue;
        }
        if let Some((owner, version, directory)) =
            indexed_claim_at_or_above(&external_directory_index, &virt, true)
        {
            return fail(
                4,
                format!(
                    "doublethink detectado: {virt} sobrepõe diretório {directory} de {owner} {version}"
                ),
            );
        }
        if let Some((owner, version, directory)) =
            indexed_claim_at_or_above(&external_shared_directory_index, &virt, true)
        {
            if virt == directory && entry.is_dir() && path_is_shared(&virt, &shared_roots) {
                return fail(
                    4,
                    format!(
                        "doublethink detectado: {} tentaria emitir segunda claim D: para {virt}, já fornecida por {owner} {version}",
                        r.name
                    ),
                );
            }
            if !r.deps.iter().any(|dependency| dependency == owner) {
                return fail(
                    4,
                    format!(
                        "doublethink detectado: {virt} está sob diretório compartilhado {directory} de {owner} {version}, mas {owner} não é DEPS direta de {}",
                        r.name
                    ),
                );
            }
            if virt == directory && !entry.is_dir() {
                return fail(
                    4,
                    format!(
                        "doublethink detectado: {virt} tentaria substituir diretório compartilhado de {owner} {version} por outra espécie"
                    ),
                );
            }
        } else if !entry.is_dir() || !stage_dirs_with_children.contains(rel) {
            if let Some((owner, version, directory)) =
                indexed_descendant(&external_shared_directory_index, &virt)
            {
                return fail(
                    4,
                    format!(
                        "doublethink detectado: {virt} sobrepõe diretório compartilhado {directory} de {owner} {version}"
                    ),
                );
            }
        }
        let overlap = if entry.is_dir() {
            indexed_claim_at_or_above(&external_claim_index, &virt, true).or_else(|| {
                (!stage_dirs_with_children.contains(rel)
                    && !path_is_shared(&virt, &reused_shared_roots))
                .then(|| indexed_descendant(&external_claim_index, &virt))
                .flatten()
            })
        } else {
            indexed_claim_at_or_above(&external_claim_index, &virt, false)
                .or_else(|| indexed_descendant(&external_claim_index, &virt))
        };
        // Diretório de um cedente provisional declarado não bloqueia: ele é
        // cedido junto com o conteúdo, do mesmo modo que arquivo e link já
        // eram pelo eligible_takeover logo abaixo. Sem esta exceção a
        // sucessão fica pela metade — o sucessor toma os arquivos mas esbarra
        // no diretório que os contém.
        // Claim de um cedente provisional declarado não bloqueia, seja ela o
        // próprio diretório ou a árvore ACIMA de um arquivo que vai dentro
        // dele. Vale para entrada de qualquer tipo: um diretório do cedente
        // cobre tudo o que está sob ele, e é justamente isso que o sucessor
        // precisa ocupar. As duas condições de sempre continuam valendo, e
        // colisão em caminho exato ainda passa pelo eligible_takeover abaixo.
        let overlap = match overlap {
            Some((owner, _, _)) if ceded_directory_owners.contains(owner) => None,
            outro => outro,
        };
        if let Some((owner, version, path)) = overlap {
            return fail(
                4,
                format!("doublethink detectado: {virt} sobrepõe {path} de {owner} {version}"),
            );
        }
        if entry.is_dir() {
            continue;
        }
        let owners: Vec<&str> = all_claim_index
            .get(&virt)
            .into_iter()
            .flatten()
            .map(|(owner, _)| *owner)
            .collect();
        let external: Vec<&str> = owners
            .iter()
            .copied()
            .filter(|owner| *owner != r.name)
            .collect();
        let eligible_takeover = external.len() == 1
            && is_provisional(ctx, external[0])
            && r.supersedes.iter().any(|name| name == external[0]);
        if !external.is_empty() && !eligible_takeover {
            return fail(
                4,
                format!(
                    "doublethink detectado: {virt} tem donos incompatíveis: {}",
                    external.join(", ")
                ),
            );
        }
        let replace_is_owned = owners.iter().any(|owner| *owner == r.name) || eligible_takeover;
        if !replace_is_owned && confined_exists(&ctx.root, &virt)? {
            return fail(
                4,
                format!("doublethink detectado: {virt} já existe sem dono compatível"),
            );
        }
    }

    let mut journal = Journal::begin(ctx, &r.name)?;
    let (mut manifest, pulados_por_cessao) = match apply_stage(
        ctx,
        sealed_artifact,
        &entries,
        r,
        SharedStagePolicy {
            declared: &shared_roots,
            reused: &reused_shared_roots,
        },
        &cedidos_set,
        &mut journal,
    ) {
        Ok(resultado) => resultado,
        Err(error) => {
            if let Err(rollback) = journal.rollback() {
                return Err(anyhow::anyhow!(
                    "aplicação falhou: {error}; rollback também falhou: {rollback}"
                ));
            }
            return Err(error);
        }
    };
    // A GUARDA CONTINUA, COM UMA EXCEÇÃO ESTREITA E PROVADA. Ela existe para
    // pegar build que não produziu nada, e isso continua sendo erro. Mas há um
    // caso em que manifesto vazio é a resposta CERTA: um provisional que já
    // cedeu tudo. O binutils da semente é exatamente esse — cedeu os 199
    // caminhos do baseline ao binutils-glibc, e o que ele ainda possui é o
    // conjunto vazio. Ele existe apenas como registro.
    //
    // Sem a exceção, a primeira reconstrução da árvore parou aqui: o refresh
    // fez o que devia — pulou tudo o que já era do sucessor — e a guarda leu o
    // resultado como build quebrado.
    //
    // A exceção é estreita porque `pulados_por_cessao > 0` só é verdade quando
    // o STAGE de fato produziu entradas e TODAS foram puladas por já terem
    // dono. Uma entrada não cedida produziria claim, e o manifesto não estaria
    // vazio; então este par de condições não pode encobrir um build vazio de
    // verdade.
    if manifest.is_empty() && pulados_por_cessao > 0 {
        println!(
            "{} {}: cedeu todos os {} caminhos aos sucessores; \
             registro atualizado sem payload",
            r.name, r.version, pulados_por_cessao
        );
    } else if manifest.is_empty() {
        if let Err(rollback) = journal.rollback() {
            return Err(anyhow::anyhow!(
                "STAGE sem payload e rollback também falhou: {rollback}"
            ));
        }
        return fail(
            1,
            format!("{}: STAGE não produziu nenhuma claim instalável", r.name),
        );
    }
    if let Err(error) = write_record(
        ctx,
        &rec_dir,
        r,
        "B",
        &mut manifest,
        RecordWrite {
            artifact_hash: Some(reprocorr),
            fingerprint,
            manifest_typed: true,
            source_origin: origin,
            journal: Some(&mut journal),
            // Mesmo motivo do mundo A: o ativo encolhe, o baseline não. Ver a
            // documentação do campo.
            baseline_extra: (!linhas_cedidas.is_empty()).then_some(&linhas_cedidas),
        },
    ) {
        if let Err(rollback) = journal.rollback() {
            return Err(anyhow::anyhow!(
                "registro falhou: {error}; rollback também falhou: {rollback}"
            ));
        }
        return Err(error);
    }
    journal.commit()?;
    if explicit {
        world_add(ctx, &r.name)?;
    }
    match origin {
        SourceRecordOrigin::Local => println!(
            "{} {} — compilado e retificado. doubleplusgood.",
            r.name, r.version
        ),
        SourceRecordOrigin::Channel(selection) => println!(
            "{} {} — canal {} retificado. doubleplusgood.",
            r.name, r.version, selection.channel
        ),
    }
    Ok(())
}

/// Aplica o STAGE em `/` PELO Journal (transacional). Devolve o manifesto. Todo
/// arquivo/symlink passa por `jrnl.place_*` (guarda o anterior); as remoções de
/// upgrade por `jrnl.drop_path`. Um erro aqui é revertido pelo chamador.
fn owned_directory_claim_is_intact(ctx: &Ctx, old_manifest: &[String], virt: &str) -> Result<bool> {
    let Some(line) = old_manifest.iter().find(|line| {
        canonical_virtual_path(&ctx.root, manifest_path(line)).is_ok_and(|path| path == virt)
            && manifest_integrity(line)
                .is_some_and(|tag| tag.starts_with("d:") || tag.starts_with("D:"))
    }) else {
        return Ok(false);
    };
    if confined_claim_matches(line, &ctx.root, virt)? != Some(true) {
        bail!("{virt}: claim de diretório anterior foi modificada; conversão recusada");
    }
    Ok(true)
}

#[derive(Clone, Copy)]
struct SharedStagePolicy<'a> {
    declared: &'a [String],
    reused: &'a [String],
}

#[cfg(test)]
const NO_SHARED_STAGE_POLICY: SharedStagePolicy<'static> = SharedStagePolicy {
    declared: &[],
    reused: &[],
};

fn apply_stage(
    ctx: &Ctx,
    image: &fs::File,
    entries: &[SealedStageEntry],
    r: &Recipe,
    shared: SharedStagePolicy<'_>,
    cedidos_set: &HashSet<String>,
    jrnl: &mut Journal,
) -> Result<(Vec<String>, usize)> {
    let rec_dir = ctx.records_dir().join(&r.name);
    // Mesmo conjunto que o preflight consultou. Aqui ele impede a mutação em
    // si: sem isto o journal escreveria por cima do arquivo do sucessor e o
    // manifesto novo reivindicaria de volta o que já não é deste pacote.
    // Quantas entradas do STAGE foram puladas por já pertencerem a um sucessor.
    // O chamador precisa deste número para distinguir "o build não produziu
    // nada" de "tudo o que ele produziu já é de outro dono".
    let mut pulados_por_cessao = 0usize;
    let old_manifest = if rec_dir.join("meta").is_file() {
        read_manifest_strict(&rec_dir)?
    } else {
        Vec::new()
    };
    // Valida o registro antigo antes da primeira mutação. Uma tag futura ou
    // malformada jamais pode virar autorização para substituir/remover o path;
    // divergência de uma prova conhecida continua sendo tratada pela política
    // específica de upgrade/preservação abaixo.
    for line in &old_manifest {
        let path = manifest_path(line);
        rooted_path(&ctx.root, path)?;
        let _ = confined_claim_matches(line, &ctx.root, path)?;
    }

    let mut manifest: Vec<String> = Vec::new();
    let mut dirs_with_children: HashSet<String> = HashSet::new();
    let mut present_dirs: HashSet<String> = HashSet::new();
    let empty_tree_hash = crate::pack::empty_deterministic_hash()?;
    for entry in entries {
        let rel = &entry.relative;
        let mut parent = Path::new(rel).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            dirs_with_children.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
        if entry.is_dir() {
            if let Some(sub) = rel.strip_prefix("etc/") {
                present_dirs.insert(canonical_virtual_path(
                    &ctx.root,
                    &format!("/usr/share/factory/etc/{sub}"),
                )?);
            } else if rel != "etc" {
                present_dirs.insert(canonical_virtual_path(&ctx.root, &virt_path(rel))?);
            }
        }
    }
    for entry in entries {
        let rel = &entry.relative;
        if let Some(sub) = rel.strip_prefix("etc/") {
            // Nenhum pacote é dono de /etc: o default vai para a fábrica…
            let factory = ctx.root.join("usr/share/factory/etc").join(sub);
            let factory_virt =
                canonical_virtual_path(&ctx.root, &format!("/usr/share/factory/etc/{sub}"))?;
            if !entry.is_dir() {
                if let Some(prov) =
                    adopt_provisional_path(ctx, &factory_virt, &r.name, &r.supersedes, Some(jrnl))?
                {
                    eprintln!("  {factory_virt}: assume o controle de {prov} (provisório)");
                }
            }
            if entry.is_dir() {
                let empty = !dirs_with_children.contains(rel);
                let virt = factory_virt.clone();
                let owned = owned_directory_claim_is_intact(ctx, &old_manifest, &virt)?;
                if path_is_shared(&virt, shared.declared) {
                    let claimable = jrnl.ensure_shared_dir(
                        &factory,
                        fs::Permissions::from_mode(entry.mode()),
                        owned,
                    )?;
                    if claimable {
                        manifest.push(format!("{}  {virt}", entry.shared_directory_integrity()?));
                    }
                } else if path_is_shared(&virt, shared.reused) {
                    jrnl.ensure_dir(
                        &factory,
                        fs::Permissions::from_mode(entry.mode()),
                        false,
                        false,
                    )?;
                } else {
                    let claimable = jrnl.ensure_dir(
                        &factory,
                        fs::Permissions::from_mode(entry.mode()),
                        empty,
                        owned,
                    )?;
                    if empty && claimable {
                        manifest.push(format!("{}  {virt}", entry.integrity(&empty_tree_hash)));
                    }
                }
            } else {
                match &entry.kind {
                    SealedStageKind::Symlink { target } => {
                        jrnl.place_symlink(&factory, target)?;
                    }
                    SealedStageKind::Regular {
                        mode,
                        offset,
                        size,
                        xattrs,
                        ..
                    } => {
                        jrnl.place_sealed_file(&factory, image, *offset, *size, *mode, xattrs)?;
                    }
                    SealedStageKind::Directory { .. } => unreachable!(),
                }
            }
            if !entry.is_dir() {
                let virt = factory_virt;
                manifest.push(format!("{}  {virt}", entry.integrity(&empty_tree_hash)));
                // …e é materializado em /etc só se o administrador ainda não decidiu.
                // O TERCEIRO PONTO DA COMPARAÇÃO. O old_manifest guarda o
                // hash da fábrica ANTERIOR — os arquivos de
                // /usr/share/factory/etc estão no manifesto, ao contrário do
                // /etc vivo. Sem ele, materialize_etc só podia comparar o /etc
                // com a fábrica NOVA, e qualquer mudança de receita virava
                // "modificado pelo administrador".
                let fabrica_anterior = old_manifest.iter().find_map(|line| {
                    let alvo = format!("/usr/share/factory/etc/{sub}");
                    if manifest_path(line) == alvo {
                        manifest_integrity(line)
                            .and_then(|tag| tag.strip_prefix("f:"))
                            .map(|h| h.to_string())
                    } else {
                        None
                    }
                });
                materialize_etc(jrnl, ctx, &factory, sub, fabrica_anterior.as_deref())?;
            }
        } else {
            let dst = ctx.root.join(rel);
            if cedidos_set.contains(&canonical_virtual_path(&ctx.root, &virt_path(rel))?) {
                pulados_por_cessao += 1;
                continue;
            }
            if entry.is_dir() {
                let empty = !dirs_with_children.contains(rel);
                let virt = canonical_virtual_path(&ctx.root, &virt_path(rel))?;
                // Cessão de DIRETÓRIO. O adopt_provisional_path casa por
                // caminho, então serve para claim de qualquer espécie — só
                // não era chamado aqui, e por isso o cedente entregava os
                // arquivos mas continuava reivindicando a árvore que os
                // contém. O registro dele ficava "provisional incoerente" na
                // operação seguinte: soltava o conteúdo e segurava o
                // continente. As duas condições de sempre valem dentro da
                // função — PROVISIONAL e declarado em SUPERSEDES.
                if let Some(prov) =
                    adopt_provisional_path(ctx, &virt, &r.name, &r.supersedes, Some(jrnl))?
                {
                    eprintln!("  {virt}: assume o diretório de {prov} (provisório)");
                }
                let owned = owned_directory_claim_is_intact(ctx, &old_manifest, &virt)?;
                if path_is_shared(&virt, shared.declared) {
                    let claimable = jrnl.ensure_shared_dir(
                        &dst,
                        fs::Permissions::from_mode(entry.mode()),
                        owned,
                    )?;
                    if claimable {
                        manifest.push(format!("{}  {virt}", entry.shared_directory_integrity()?));
                    }
                } else if path_is_shared(&virt, shared.reused) {
                    jrnl.ensure_dir(&dst, fs::Permissions::from_mode(entry.mode()), false, false)?;
                } else {
                    let claimable = jrnl.ensure_dir(
                        &dst,
                        fs::Permissions::from_mode(entry.mode()),
                        empty,
                        owned,
                    )?;
                    // `/etc` vivo nunca tem dono. Outros diretórios vazios são
                    // payload real e entram no manifesto tipado (`d:`).
                    if rel != "etc" && empty && claimable {
                        manifest.push(format!("{}  {virt}", entry.integrity(&empty_tree_hash)));
                    }
                }
            } else {
                let virt = canonical_virtual_path(&ctx.root, &virt_path(rel))?;
                if let Some(prov) =
                    adopt_provisional_path(ctx, &virt, &r.name, &r.supersedes, Some(jrnl))?
                {
                    eprintln!("  {virt}: assume o controle de {prov} (provisório)");
                }
                match &entry.kind {
                    SealedStageKind::Symlink { target } => {
                        jrnl.place_symlink(&dst, target)?;
                    }
                    SealedStageKind::Regular {
                        mode,
                        offset,
                        size,
                        xattrs,
                        ..
                    } => {
                        jrnl.place_sealed_file(&dst, image, *offset, *size, *mode, xattrs)?;
                    }
                    SealedStageKind::Directory { .. } => unreachable!(),
                }
                manifest.push(format!("{}  {virt}", entry.integrity(&empty_tree_hash)));
            }
        }
    }

    // Upgrade: recolhe caminhos do manifesto antigo que sumiram do novo.
    let new_set: HashSet<&str> = manifest.iter().map(|line| manifest_path(line)).collect();
    for old in old_manifest {
        let path = manifest_path(&old);
        let canonical_path = canonical_virtual_path(&ctx.root, path)?;
        if !new_set.contains(canonical_path.as_str()) && !present_dirs.contains(&canonical_path) {
            let p = rooted_path(&ctx.root, path)?;
            let current = match confined_path_integrity(&ctx.root, path) {
                Ok(current) => current,
                Err(error) if error_is_not_found(&error) => continue,
                Err(error) => return Err(error),
            };
            if manifest_integrity(&old).is_some_and(|expected| expected.starts_with("D:")) {
                if confined_claim_matches(&old, &ctx.root, path)? != Some(true) {
                    eprintln!("  {path}: diretório compartilhado mudou de tipo/modo — preservado");
                    continue;
                }
                // Claim D: nunca autoriza mover/apagar uma árvore. O rmdir
                // confinado só vence quando nenhum produtor/admin deixou filho.
                if !jrnl.drop_empty_dir(&p)? {
                    eprintln!("  {path}: diretório compartilhado não está vazio — preservado");
                }
            } else if current.starts_with("d:") {
                let unchanged_owned_directory = manifest_integrity(&old)
                    .is_some_and(|expected| expected.starts_with("d:") && expected == current);
                if !unchanged_owned_directory {
                    eprintln!(
                        "  {path}: diretório ganhou conteúdo/metadados ou não tem prova d: — preservado"
                    );
                    continue;
                }
                jrnl.drop_path(&p, true)?;
            } else {
                jrnl.drop_path(&p, false)?;
            }
        }
    }
    Ok((manifest, pulados_por_cessao))
}

/// Materializa um default de fábrica em /etc conforme a política do admin
/// (Clear Linux + `.new` do Slackware): copia se ausente; se o admin já mexeu,
/// grava `<arquivo>.new` ao lado e avisa. O /etc vivo não entra no manifesto.
/// Trata symlinks (ex.: openssl instala /etc/ssl/misc/tsget -> tsget.pl):
/// materializa-os COMO symlink, nunca por `fs::copy` — que seguiria o link.
fn materialize_etc(
    jrnl: &mut Journal,
    ctx: &Ctx,
    factory: &Path,
    sub: &str,
    fabrica_anterior: Option<&str>,
) -> Result<()> {
    let live = ctx.root.join("etc").join(sub);

    // Default que É symlink: materializa como symlink. `fs::copy` seguiria o
    // link e (a) daria ENOENT quando o alvo ainda não foi copiado à fábrica — a
    // walk processa em ordem alfabética, e `tsget` vem antes de `tsget.pl` — e
    // (b) copiaria o conteúdo do alvo, perdendo a natureza de link.
    if fs::symlink_metadata(factory)?.file_type().is_symlink() {
        let tgt = fs::read_link(factory)?;
        match fs::symlink_metadata(&live) {
            // ausente: cria o link
            Err(_) => {
                jrnl.place_symlink(&live, &tgt)?;
            }
            // já é exatamente o mesmo link: nada a fazer
            Ok(m)
                if m.file_type().is_symlink()
                    && fs::read_link(&live).ok().as_deref() == Some(tgt.as_path()) => {}
            // admin trocou: grava o novo default como `<nome>.new` ao lado
            Ok(_) => {
                let new = live.with_file_name(format!(
                    "{}.new",
                    live.file_name().unwrap().to_string_lossy()
                ));
                jrnl.place_symlink(&new, &tgt)?;
                eprintln!(
                    "  aviso: /etc/{sub} foi modificado pelo administrador; novo default (link) em {}",
                    new.display()
                );
            }
        }
        return Ok(());
    }

    // Default regular: copia se ausente; se o admin já mexeu, grava `<nome>.new`.
    match fs::symlink_metadata(&live) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            jrnl.place_file(&live, factory)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let live_virt = format!("/etc/{sub}");
    rooted_path(&ctx.root, &live_virt)?;
    let factory_hash = sha256_bytes(&read_regular_nofollow(factory)?);
    let vivo = confined_regular_content_hash(&ctx.root, &live_virt)?;
    let same = vivo.as_deref() == Some(factory_hash.as_str());

    // COMPARAÇÃO DE TRÊS PONTOS, e o terceiro é o que faltava.
    //
    // Antes desta mudança havia só dois: o /etc vivo e a fábrica NOVA. Com
    // isso, toda alteração de receita fazia os dois diferirem, e o minitrue
    // lia essa diferença como edição do administrador — escrevia `.new` e
    // preservava o arquivo. O efeito não era "catraca depois da primeira
    // divergência": era SEMPRE, já na primeira mudança de receita, para
    // qualquer arquivo de /etc. Um arquivo materializado uma vez nunca mais
    // recebia atualização.
    //
    // Medido duas vezes nesta árvore. No root de build, 14 arquivos parados na
    // era 0.1 — /etc/hostname dizia `airstrip1` e /etc/os-release dizia
    // "Distrópica 0.1 (Airstrip One)" enquanto as receitas estavam na 0.10. E
    // depois, no bump para 0.11, o /etc/os-release recusou o número novo mesmo
    // tendo sido igualado à fábrica 0.10 na mão.
    //
    // O terceiro ponto é o hash da fábrica ANTERIOR, que o manifesto do
    // registro já guardava — os arquivos de /usr/share/factory/etc entram no
    // manifesto, e é só o /etc vivo que não entra. Se o arquivo vivo é
    // IDÊNTICO à fábrica anterior, ninguém o editou: o default muda e o vivo
    // acompanha. Se difere das duas, aí sim houve edição, e o `.new` é a
    // resposta certa.
    //
    // Sem fábrica anterior — instalação nova, ou registro v1 sem a entrada —
    // cai no comportamento antigo, que é o conservador: preserva e avisa.
    if !same {
        // SELO CONTRA SELO, e não hash de conteúdo contra selo. O `f:` do
        // manifesto não é o sha256 do arquivo: é
        // sha256("minitrue-regular-integrity-v2\0" + modo + hash + xattrs).
        // A primeira versão desta comparação confrontava o selo do manifesto
        // com o hash de conteúdo do arquivo vivo — duas grandezas diferentes,
        // que nunca coincidem. O sintoma era a correção não fazer efeito
        // nenhum, que é pior que não ter escrito: parece implementado.
        //
        // Os xattrs entram vazios porque um arquivo de /etc materializado da
        // fábrica não os carrega; se um dia carregar, o selo diverge e a
        // decisão cai no lado conservador — preserva e avisa.
        if let (Some(anterior), Some(conteudo)) = (fabrica_anterior, vivo.as_deref()) {
            let modo_vivo = fs::symlink_metadata(&live)?.permissions().mode() & 0o7777;
            let selo_vivo = regular_integrity(modo_vivo, conteudo);
            if anterior == selo_vivo {
                jrnl.place_file(&live, factory)?;
                return Ok(());
            }
        }
        let new = live.with_file_name(format!(
            "{}.new",
            live.file_name().unwrap().to_string_lossy()
        ));
        jrnl.place_file(&new, factory)?;
        eprintln!(
            "  aviso: /etc/{sub} foi modificado pelo administrador; novo default em {}",
            new.display()
        );
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

fn room101(ctx: &Ctx, r: &Recipe, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    let room = ctx.room101();
    ensure_real_directory_or_absent(&ctx.root, &room, "diretório Room 101")?;
    fs::create_dir_all(&room)?;
    ensure_real_directory_or_absent(&ctx.root, &room, "diretório Room 101")?;
    let log = ctx.room101().join(format!("{}-{}.log", r.name, r.version));
    let mut body = stdout.to_vec();
    body.extend_from_slice(stderr);
    write_atomic(&log, &body)?;
    Ok(())
}

struct NeverFailReader<R> {
    inner: R,
    error: Option<std::io::Error>,
}

impl<R: Read> Read for NeverFailReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.error.is_some() {
            return Ok(0);
        }
        match self.inner.read(buffer) {
            Ok(read) => Ok(read),
            Err(error) => {
                self.error = Some(error);
                Ok(0)
            }
        }
    }
}

struct NeverFailWriter<W> {
    inner: W,
    error: Option<std::io::Error>,
}

impl<W: Write> Write for NeverFailWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.error.is_some() {
            return Ok(buffer.len());
        }
        if let Err(error) = self.inner.write_all(buffer) {
            self.error = Some(error);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.error.is_none() {
            if let Err(error) = self.inner.flush() {
                self.error = Some(error);
            }
        }
        Ok(())
    }
}

fn compress_zstd_deterministic(source: fs::File, destination: fs::File) -> Result<()> {
    let mut reader = NeverFailReader {
        inner: source,
        error: None,
    };
    let mut writer = NeverFailWriter {
        inner: destination,
        error: None,
    };
    let compressed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ruzstd::encoding::compress(
            &mut reader,
            &mut writer,
            ruzstd::encoding::CompressionLevel::Fastest,
        );
    }));
    if compressed.is_err() {
        bail!("encoder zstd abortou ao emitir canal");
    }
    writer.flush()?;
    if let Some(error) = reader.error {
        return Err(error.into());
    }
    if let Some(error) = writer.error {
        return Err(error.into());
    }
    Ok(())
}

fn emit_relative_path(virtual_path: &str) -> Result<PathBuf> {
    let relative = virtual_path
        .strip_prefix("/usr/share/factory/etc/")
        .map(|suffix| Path::new("etc").join(suffix))
        .or_else(|| (virtual_path == "/usr/share/factory/etc").then(|| PathBuf::from("etc")))
        .unwrap_or_else(|| PathBuf::from(virtual_path.trim_start_matches('/')));
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("claim não pode voltar a STAGE: {virtual_path}");
    }
    Ok(relative)
}

fn emitted_virtual_path(relative: &Path) -> Result<String> {
    let relative = relative
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("STAGE reconstruído ganhou path não UTF-8"))?;
    if relative == "etc" {
        // O STAGE `etc/` é instalado como default imutável na fábrica. `/etc`
        // vivo é deliberadamente administrável (inclusive pelo overlay da
        // mídia) e pode ter outro modo sem invalidar as claims do pacote.
        Ok("/usr/share/factory/etc".to_string())
    } else if let Some(suffix) = relative.strip_prefix("etc/") {
        Ok(format!("/usr/share/factory/etc/{suffix}"))
    } else {
        Ok(format!("/{relative}"))
    }
}

/// Diretórios não-vazios não viram claims individuais, mas seus modos
/// entram no tar canônico. Para reemitir sem inventar metadata, copia-se o modo
/// da hierarquia instalada e o hash ARTIFACT_HASH continua sendo o juiz final:
/// se um pai preexistia ou foi alterado, a emissão simplesmente é recusada.
fn reconstruct_stage_parents(ctx: &Ctx, stage: &Path, relative: &Path) -> Result<()> {
    let mut hierarchy = Vec::new();
    let mut current = PathBuf::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("pai não canônico durante emissão: {}", relative.display());
        };
        current.push(component);
        hierarchy.push(current.clone());
    }
    for parent in hierarchy {
        let destination = stage.join(&parent);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!(
                "hierarquia reconstruída não é diretório: {}",
                destination.display()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => fs::create_dir(&destination)?,
            Err(error) => return Err(error.into()),
        }
        let virtual_path = emitted_virtual_path(&parent)?;
        let descriptor = open_confined(
            &ctx.root,
            &virtual_path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
        let metadata = fs::File::from(descriptor).metadata()?;
        if !metadata.file_type().is_dir() {
            bail!("pai instalado deixou de ser diretório: {virtual_path}");
        }
        fs::set_permissions(
            &destination,
            fs::Permissions::from_mode(metadata.permissions().mode() & 0o7777),
        )?;
    }
    Ok(())
}

fn reconstruct_stage_from_record(
    ctx: &Ctx,
    package: &str,
    stage: &Path,
) -> Result<HashMap<String, String>> {
    let meta = attestable_meta(ctx, package)?;
    if meta.get("PROVISIONAL").map(String::as_str) == Some("1") {
        bail!("{package}: registro provisional não pode ser emitido após ceder claims");
    }
    fs::create_dir(stage)?;
    let record = ctx.records_dir().join(package);
    let manifest = read_manifest_strict(&record)?;
    for line in manifest {
        let virtual_path = manifest_path(&line);
        if manifest_integrity(&line).is_none()
            || confined_claim_matches(&line, &ctx.root, virtual_path)? != Some(true)
        {
            bail!("{package}: claim não está íntegra para emissão: {virtual_path}");
        }
        let relative = emit_relative_path(virtual_path)?;
        let destination = stage.join(&relative);
        if let Some(parent) = destination.parent() {
            let relative_parent = parent
                .strip_prefix(stage)
                .map_err(|_| anyhow::anyhow!("destino de emissão escapou do STAGE"))?;
            reconstruct_stage_parents(ctx, stage, relative_parent)?;
        }
        let descriptor = open_confined(&ctx.root, virtual_path, libc::O_PATH | libc::O_NOFOLLOW)?;
        let metadata = fs::File::from(descriptor).metadata()?;
        if metadata.file_type().is_file() {
            let descriptor = open_confined(
                &ctx.root,
                virtual_path,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )?;
            let mut input = fs::File::from(descriptor);
            let input_metadata = input.metadata()?;
            if !input_metadata.file_type().is_file() {
                bail!("{virtual_path}: deixou de ser arquivo regular durante emissão");
            }
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination)?;
            std::io::copy(&mut input, &mut output)?;
            output.set_permissions(fs::Permissions::from_mode(
                input_metadata.permissions().mode() & 0o7777,
            ))?;
            output.flush()?;
        } else if metadata.file_type().is_symlink() {
            let target = readlink_confined(&ctx.root, virtual_path)?;
            symlink(Path::new(OsStr::from_bytes(&target)), &destination)?;
        } else if metadata.file_type().is_dir() {
            let descriptor = open_confined(
                &ctx.root,
                virtual_path,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )?;
            let directory_metadata = fs::File::from(descriptor).metadata()?;
            if !directory_metadata.file_type().is_dir() {
                bail!("{virtual_path}: deixou de ser diretório durante emissão");
            }
            fs::create_dir(&destination)?;
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(directory_metadata.permissions().mode() & 0o7777),
            )?;
        } else {
            bail!("{virtual_path}: tipo especial não pode ser emitido");
        }
    }
    Ok(meta)
}

/// Reutiliza o tar selado de uma instalação por canal quando o objeto ainda
/// está no cache content-addressed. Isso preserva a topologia lexical original
/// (`lib/` versus `usr/lib/`) que o manifesto registra apenas em sua forma
/// canônica. A proveniência/claims já foram validadas por `attestable_meta`; aqui
/// ainda prendemos separadamente os hashes de transporte e do tar interno.
fn cached_channel_image(
    ctx: &Ctx,
    package: &str,
    meta: &HashMap<String, String>,
) -> Result<Option<(fs::File, String)>> {
    if !meta
        .get("ORIGIN")
        .is_some_and(|origin| origin.starts_with("canal:"))
    {
        return Ok(None);
    }
    let transport_hash = meta
        .get("CHANNEL_SHA256")
        .ok_or_else(|| anyhow::anyhow!("{package}: registro de canal sem CHANNEL_SHA256"))?;
    let artifact_hash = meta
        .get("ARTIFACT_HASH")
        .ok_or_else(|| anyhow::anyhow!("{package}: registro de canal sem ARTIFACT_HASH"))?;
    let cache = ctx.cache_dir();
    ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    let path = cache.join(transport_hash);
    let transport = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let (transport, obtained_transport) =
        sealed_transport_snapshot(transport, &path, MAX_CHANNEL_TRANSPORT_BYTES)?;
    if obtained_transport != *transport_hash {
        bail!(
            "{package}: objeto original do canal tem hash {obtained_transport}, registro prende {transport_hash}"
        );
    }
    let (mut image, obtained_artifact) =
        decompress_channel_artifact(transport, &path, MAX_CHANNEL_TAR_BYTES)?;
    if obtained_artifact != *artifact_hash {
        bail!(
            "{package}: tar original do canal tem {obtained_artifact}, registro atesta {artifact_hash}"
        );
    }
    // Revalida o formato instalável/canônico antes de republicar os bytes.
    let _ = preflight_sealed_stage(&ctx.root, &image)?;
    image.seek(SeekFrom::Start(0))?;
    Ok(Some((image, obtained_artifact)))
}

fn recorded_epoch(record: &Path) -> Result<u64> {
    let bytes = read_regular_nofollow(&record.join("recipe"))?;
    if let Some(value) = recipe::literal_assignment_bytes(&bytes, "EPOCH") {
        return value
            .parse()
            .map_err(|_| anyhow::anyhow!("EPOCH histórico não é timestamp Unix"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("receita histórica não é UTF-8"))?;
    if text.lines().any(|line| line.starts_with("EPOCH=")) {
        bail!("EPOCH histórico não é atribuição literal; emissão recusada");
    }
    Ok(1_704_067_200)
}

pub fn channel_emit(
    ctx: &Ctx,
    output: &Path,
    packages: &[String],
    release_root: bool,
) -> Result<()> {
    let _lock = acquire_lock(ctx)?;
    Journal::recover_all(ctx)?;
    for package in packages {
        recipe::validate_name(package)?;
        let _ = attestable_meta(ctx, package)?;
    }
    // Gate de fechamento (SPEC-0013 §10.2): publicar é afirmar que o conjunto
    // se fecha. Um artefato cujo payload exige provedor não declarado só
    // funciona no computador onde por acaso já existe o que falta — publicá-lo
    // propaga a dependência acidental para todo mundo que o instalar. Isto
    // **recusa**, e é essa recusa que separa "auditoria informativa" de gate.
    crate::audit::gate(ctx, packages)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let leaf = output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("--output não tem nome final"))?;
    let destination = parent.join(leaf);
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Ok(_) => bail!(
            "channel emit não sobrescreve {}: destino já existe",
            destination.display()
        ),
        Err(error) => return Err(error.into()),
    }

    let finalized = crate::plan::finalize_applied(
        ctx,
        packages,
        crate::plan::PlanPurpose::ChannelEmit,
        BinaryPolicy::PreferBinary,
        if release_root {
            crate::plan::AbiPolicy::Strict
        } else {
            crate::plan::AbiPolicy::Development
        },
        &BTreeSet::new(),
        // Emissão de canal já usava raízes explícitas e nunca emitiu receipt —
        // o `Complete` aqui é o comportamento de sempre, escrito por extenso.
        crate::plan::AppliedClosure::Complete,
    )?;
    if finalized.identities.is_empty() {
        bail!("channel emit exige ao menos um payload material fechado");
    }
    let producer_plan = crate::plan::persisted_lock_bytes(ctx, &finalized.lock_sha256)?;
    let mut emission_packages: Vec<String> = finalized
        .identities
        .iter()
        .filter(|identity| identity.role == "runtime" && identity.kind == "source")
        .map(|identity| identity.name.clone())
        .collect();
    emission_packages.sort();
    emission_packages.dedup();
    if emission_packages.is_empty() {
        bail!("channel emit não encontrou payload source runtime na closure finalizada");
    }
    for package in &emission_packages {
        let _ = attestable_meta(ctx, package)?;
    }
    crate::audit::gate(ctx, &emission_packages)?;
    eprintln!(
        "  inventário de canal: PLAN_LOCK_SHA256={} materiais={}",
        finalized.lock_sha256,
        finalized.identities.len()
    );

    let mut staging = None;
    for _ in 0..128 {
        let serial = ATOMIC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.minitrue-channel-{}-{serial}",
            leaf.to_string_lossy(),
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&candidate) {
            Ok(()) => {
                staging = Some(candidate);
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let staging = staging.ok_or_else(|| {
        anyhow::anyhow!(
            "não consegui reservar diretório temporário irmão de {}",
            destination.display()
        )
    })?;

    let result = (|| -> Result<()> {
        let pool = staging.join("pool");
        fs::create_dir(&pool)?;
        fs::set_permissions(&pool, fs::Permissions::from_mode(0o755))?;
        let plans = staging.join("plans");
        fs::create_dir(&plans)?;
        fs::set_permissions(&plans, fs::Permissions::from_mode(0o755))?;
        let producer_plan_path = plans.join(format!("{}.lock", finalized.lock_sha256));
        let mut producer = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&producer_plan_path)?;
        producer.write_all(&producer_plan)?;
        producer.sync_all()?;
        producer.set_permissions(fs::Permissions::from_mode(0o644))?;
        let workspace = staging.join(".work");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;

        let mut index_lines = Vec::new();
        let mut producer_expected = Vec::new();
        for package in &emission_packages {
            let meta = attestable_meta(ctx, package)?;
            let version = meta
                .get("VERSION")
                .ok_or_else(|| anyhow::anyhow!("{package}: registro sem VERSION"))?;
            let expected = meta
                .get("ARTIFACT_HASH")
                .ok_or_else(|| anyhow::anyhow!("{package}: registro sem ARTIFACT_HASH"))?;
            let fingerprint = meta
                .get("FINGERPRINT")
                .ok_or_else(|| anyhow::anyhow!("{package}: registro sem FINGERPRINT"))?;
            let stage = workspace.join(format!("{package}.stage"));
            let tar_path = workspace.join(format!("{package}.tar"));
            let (source, reprocorr, reconstructed) = if let Some(image) =
                retained_stage_image(ctx, expected)?
            {
                (image, expected.clone(), false)
            } else if release_root {
                bail!(
                    "{package}: channel emit --release exige o tar selado retido do build local \
                     em {}; reconstrução posterior e objeto de outro canal não são raiz de release",
                    retained_stage_path(ctx, expected)?.display()
                );
            } else if let Some((image, hash)) = cached_channel_image(ctx, package, &meta)? {
                (image, hash, false)
            } else {
                let _ = reconstruct_stage_from_record(ctx, package, &stage)?;
                let epoch = recorded_epoch(&ctx.records_dir().join(package))?;
                let tar_file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&tar_path)?;
                let hash = crate::pack::pack_deterministic(&stage, epoch, tar_file)?;
                if &hash != expected {
                    bail!(
                        "{package}: STAGE reconstruído tem {hash}, registro atesta {expected}; emissão recusada"
                    );
                }
                let mut image = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&tar_path)?;
                let _ = preflight_sealed_stage(&ctx.root, &image)?;
                image.seek(SeekFrom::Start(0))?;
                (image, hash, true)
            };
            let artifact_name = format!("{package}-{version}-x86_64.tar.zst");
            let artifact_rel = format!("pool/{artifact_name}");
            let artifact = pool.join(&artifact_name);
            let artifact_output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&artifact)?;
            compress_zstd_deterministic(source, artifact_output)?;
            fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644))?;
            let transport_hash = fetch::sha256_file(&artifact)?;
            index_lines.push(channel::index_line(
                package,
                version,
                fingerprint,
                &artifact_rel,
                &transport_hash,
                &reprocorr,
                &finalized.lock_sha256,
            )?);
            producer_expected.push((
                package.clone(),
                version.clone(),
                fingerprint.clone(),
                reprocorr.clone(),
            ));
            if reconstructed {
                fs::remove_dir_all(&stage)?;
                fs::remove_file(&tar_path)?;
            }
        }
        producer_expected.sort();
        crate::plan::verify_channel_producer_plan(
            &producer_plan,
            &finalized.lock_sha256,
            release_root,
            &producer_expected,
        )?;
        fs::remove_dir(&workspace)?;
        index_lines.sort();
        let index_path = staging.join("index");
        let mut index = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&index_path)?;
        index.write_all(channel::index_header_for(release_root).as_bytes())?;
        for line in index_lines {
            index.write_all(line.as_bytes())?;
        }
        index.flush()?;
        index.set_permissions(fs::Permissions::from_mode(0o644))?;
        let index_hash = fetch::sha256_file(&index_path)?;
        let mut emit_meta = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(staging.join("emit.meta"))?;
        emit_meta.write_all(
            format!(
                "CHANNEL_EMIT_FORMAT=4\nARCH=x86_64\nCOMPRESSION=ruzstd-0.8.3-fastest\nINDEX_SIGNED=no\nINDEX_SHA256={index_hash}\nPRODUCER_PLAN_LOCK_SHA256={}\nRELEASE_ROOT={}\n",
                finalized.lock_sha256,
                if release_root { "yes" } else { "no" }
            )
            .as_bytes(),
        )?;
        emit_meta.flush()?;
        emit_meta.set_permissions(fs::Permissions::from_mode(0o644))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;

        let source = path_cstring(staging.as_os_str())?;
        let target = path_cstring(destination.as_os_str())?;
        // SAFETY: ambos são CStrings válidos; renameat2 não retém ponteiros.
        let published = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if published != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    println!(
        "canal emitido em {}; assine index externamente como index.minisig antes de publicar",
        destination.display()
    );
    Ok(())
}

// ---------- memoryhole ----------

pub fn memoryhole(ctx: &Ctx, names: &[String]) -> Result<()> {
    let _lock = acquire_lock(ctx)?; // segurado até o fim da operação
    Journal::recover_all(ctx)?;
    ensure_real_directory_or_absent(
        &ctx.root,
        &ctx.root.join("etc/minitrue"),
        "configuração do minitrue",
    )?;
    ensure_no_internal_claims(ctx)?;
    for name in names {
        recipe::validate_name(name)?;
    }
    let removing: HashSet<&str> = names.iter().map(String::as_str).collect();
    for name in names {
        let rec_dir = ctx.records_dir().join(name);
        ensure_real_directory_or_absent(&ctx.root, &rec_dir, "registro do pacote")?;
        // Nunca remova um pacote sobre estado intermediário: resolve primeiro
        // a transação órfã desse mesmo pacote, com a mesma regra do rectify.
        Journal::recover(ctx, name)?;
        if !rec_dir.is_dir() {
            return fail(
                2,
                format!("{name}: não há registro — talvez nunca tenha existido"),
            );
        }
        for (other, _, _) in all_manifests(ctx)? {
            if removing.contains(other.as_str()) {
                continue;
            }
            let deps = read_meta_strict(&ctx.records_dir().join(&other))?
                .and_then(|m| m.get("DEPS").cloned())
                .unwrap_or_default();
            if deps.split_whitespace().any(|d| d == name) {
                return fail(
                    1,
                    format!("{name} ainda sustenta {other} — memoryhole recusado"),
                );
            }
        }

        let record_meta = read_meta_strict(&rec_dir)?.ok_or_else(|| crate::Fail {
            code: 1,
            msg: format!("{name}: registro sem meta — memoryhole recusado"),
        })?;
        ensure_supported_record_format(&record_meta, name)?;
        let world = record_meta
            .get("WORLD")
            .cloned()
            .unwrap_or_else(|| "A".into());
        // Resolve e valida o manifesto inteiro ANTES da primeira remoção. Um
        // registro truncado/adulterado nunca pode causar travessia nem deixar
        // um memoryhole pela metade até descobrirmos uma linha inválida.
        let manifest = read_manifest_strict(&rec_dir).map_err(|error| crate::Fail {
            code: 1,
            msg: format!("{name}: manifesto ilegível — memoryhole recusado: {error}"),
        })?;
        let empty_meta = record_meta.get("KIND").map(String::as_str) == Some("meta")
            && record_meta.get("WORLD").map(String::as_str) == Some("M")
            && record_meta.get("ORIGIN").map(String::as_str) == Some("meta");
        if empty_meta {
            match read_regular_nofollow(&rec_dir.join("manifest")) {
                Ok(bytes) if bytes == b"\n" => {}
                Ok(_) => {
                    return fail(
                        1,
                        format!("{name}: manifesto meta não canônico — memoryhole recusado"),
                    )
                }
                Err(_) => {
                    return fail(
                        1,
                        format!("{name}: manifesto meta ilegível — memoryhole recusado"),
                    )
                }
            }
        }
        if manifest.is_empty()
            && record_meta.get("PROVISIONAL").map(String::as_str) != Some("1")
            && !empty_meta
        {
            return fail(
                1,
                format!("{name}: manifesto ausente/vazio — memoryhole recusado"),
            );
        }
        let mut claims = manifest
            .into_iter()
            .map(|line| {
                let virt = manifest_path(&line).to_string();
                // `openat2(RESOLVE_IN_ROOT)` prende inclusive symlinks
                // intermediários ao rootfs; a validação lexical sozinha não
                // basta para uma operação destrutiva.
                let matches = confined_claim_matches(&line, &ctx.root, &virt)?;
                Ok((line, virt, matches))
            })
            .collect::<Result<Vec<_>>>()?;
        claims.sort_by(|a, b| a.1.cmp(&b.1));
        if world == "A" {
            let opt_prefix = format!("/opt/{name}/");
            for (line, path, matches) in claims.iter().rev() {
                if matches == &Some(false) && confined_exists(&ctx.root, path)? {
                    println!("  {path}: modificado desde a instalação — preservado");
                    continue;
                }
                if manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:")) {
                    if !remove_empty_confined_dir(&ctx.root, path)? {
                        println!("  {path}: diretório compartilhado não está vazio — preservado");
                    }
                    continue;
                }
                if path.starts_with("/usr/") {
                    // Defesa adicional para registros v0/v1: link mundo A só é
                    // gerido se ainda aponta para o /opt deste pacote.
                    let target = match readlink_confined(&ctx.root, path) {
                        Ok(target) => target,
                        Err(error) if error_is_not_found(&error) => continue,
                        Err(error) => return Err(error),
                    };
                    if String::from_utf8_lossy(&target).contains(&format!("/opt/{name}/")) {
                        remove_confined(&ctx.root, path, false)?;
                    }
                } else if path.starts_with(&opt_prefix) {
                    let recursive = manifest_integrity(line)
                        .is_some_and(|tag| tag.starts_with("d:"))
                        || (manifest_integrity(line).is_none()
                            && confined_path_integrity(&ctx.root, path)
                                .is_ok_and(|tag| tag.starts_with("d:")));
                    remove_confined(&ctx.root, path, recursive)?;
                }
            }
            let _ = remove_empty_confined_dir(&ctx.root, &format!("/opt/{name}"))?;
        } else {
            for (line, path, matches) in claims.iter().rev() {
                // v2 prende conteúdo+tipo+alvo/árvore; v1 prende regulares.
                // Legado sem prova conserva a política histórica de presença.
                if matches == &Some(false) && confined_exists(&ctx.root, path)? {
                    println!("  {path}: modificado desde a instalação — preservado");
                    continue;
                }
                if manifest_integrity(line)
                    .is_some_and(|tag| tag.starts_with("d:") || tag.starts_with("D:"))
                {
                    // Mundo B só registra diretórios vazios. Nunca remove sua
                    // árvore recursivamente: se outro pacote/admin acrescentou
                    // filhos, `rmdir` falha e o conteúdo é preservado.
                    if !remove_empty_confined_dir(&ctx.root, path)? {
                        println!("  {path}: diretório não está vazio — preservado");
                    }
                } else {
                    remove_confined(&ctx.root, path, false)?;
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
    ensure_real_directory_or_absent(&ctx.root, &dir, "diretório de registros")?;
    let mut rows: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries {
            let e = entry?;
            if !e.file_type()?.is_dir() {
                bail!(
                    "entrada de registro não é diretório real: {}",
                    e.path().display()
                );
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let meta = read_meta(&e.path()).unwrap_or_default();
            let n_paths = read_manifest(&e.path()).len();
            let origin = meta.get("ORIGIN").map(String::as_str).unwrap_or("?");
            let trust = meta.get("TRUST").map(String::as_str).unwrap_or("-");
            rows.push(format!(
                "{name} {} [mundo {}; origem {origin}; confiança {trust}] {} caminhos",
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

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Valida a parte autocontida da proveniência de canal. Ela não depende da
/// receita corrente nem do índice mutável: o registro aponta para um lock
/// content-addressed, e os três hashes precisam continuar canônicos e íntegros.
fn verify_channel_provenance(ctx: &Ctx, meta: &HashMap<String, String>) -> Result<()> {
    let channel_fields = [
        "TRUST",
        "CHANNEL_PATH",
        "CHANNEL_SHA256",
        "CHANNEL_INDEX_SHA256",
        "CHANNEL_INDEX_FORMAT",
        "CHANNEL_RELEASE_ROOT",
        "CHANNEL_PRODUCER_PLAN_LOCK_SHA256",
        "CHANNEL_LOCK_SHA256",
    ];
    let origin = meta.get("ORIGIN").map(String::as_str);
    let Some(channel_name) = origin.and_then(|value| value.strip_prefix("canal:")) else {
        if channel_fields.iter().any(|field| meta.contains_key(*field)) {
            bail!("campos CHANNEL_ sem ORIGIN=canal:<nome>");
        }
        return Ok(());
    };
    recipe::validate_name(channel_name)?;
    if meta.get("WORLD").map(String::as_str) != Some("B")
        || meta.get("KIND").map(String::as_str) != Some("source")
    {
        bail!("ORIGIN de canal só é válido para pacote source do mundo B");
    }
    if !matches!(
        meta.get("TRUST").map(String::as_str),
        Some("oficial" | "corroborado" | "builder")
    ) {
        bail!("TRUST de canal ausente ou inválido");
    }
    let required = |field: &str| {
        meta.get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow::anyhow!("{field} ausente na proveniência de canal"))
    };
    for field in [
        "CHANNEL_SHA256",
        "CHANNEL_INDEX_SHA256",
        "CHANNEL_LOCK_SHA256",
    ] {
        if !meta.get(field).is_some_and(|hash| canonical_sha256(hash)) {
            bail!("{field} ausente ou não canônico");
        }
    }
    let index_format = required("CHANNEL_INDEX_FORMAT")?
        .parse::<u8>()
        .map_err(|_| anyhow::anyhow!("CHANNEL_INDEX_FORMAT inválido"))?;
    let producer_plan = required("CHANNEL_PRODUCER_PLAN_LOCK_SHA256")?;
    let release_root = match required("CHANNEL_RELEASE_ROOT")? {
        "yes" => true,
        "no" => false,
        _ => bail!("CHANNEL_RELEASE_ROOT não é yes/no canônico"),
    };
    match (
        index_format,
        required("TRUST")?,
        producer_plan,
        release_root,
    ) {
        (4, _, hash, _) if canonical_sha256(hash) => {}
        (2 | 3, "builder", _, false) => {}
        _ => bail!("proveniência de canal não fecha formato/plano produtor"),
    }
    let package = required("NAME")?;
    let version = required("VERSION")?;
    let recipe_fingerprint = required("FINGERPRINT")?;
    let artifact_reprocorr = required("ARTIFACT_HASH")?;
    recipe::validate_name(package)?;
    recipe::validate_version(package, version)?;
    if !canonical_sha256(recipe_fingerprint) || !canonical_sha256(artifact_reprocorr) {
        bail!("fingerprint ou ARTIFACT_HASH inválido na proveniência de canal");
    }
    let recipe_reprocorr = meta.get("REPROCORR").map(String::as_str);
    if recipe_reprocorr.is_some_and(|hash| !canonical_sha256(hash)) {
        bail!("REPROCORR inválido na proveniência de canal");
    }
    let channel_path = required("CHANNEL_PATH")?;
    channel::validate_artifact_path(channel_name, channel_path)?;
    let lock_hash = meta
        .get("CHANNEL_LOCK_SHA256")
        .expect("validado imediatamente acima");
    let bytes = channel::read_persisted_lock(ctx, lock_hash)?;
    channel::verify_lock_provenance(
        &bytes,
        &channel::RecordedProvenance {
            package,
            version,
            recipe_fingerprint,
            channel: channel_name,
            path: channel_path,
            trust: required("TRUST")?,
            artifact_sha256: required("CHANNEL_SHA256")?,
            index_sha256: required("CHANNEL_INDEX_SHA256")?,
            artifact_reprocorr,
            recipe_reprocorr,
            index_format,
            release_root,
            producer_plan_lock_sha256: (producer_plan != "-").then_some(producer_plan),
        },
    )
}

pub fn verify(ctx: &Ctx) -> Result<()> {
    let mut problems = 0usize;
    let mut claimed: HashMap<String, String> = HashMap::new();
    if let Err(error) = crate::plan::verify_applied_receipt(ctx) {
        println!("wrongthink: autoridade global de plano aplicado é inválida: {error}");
        problems += 1;
    }
    ensure_real_directory_or_absent(&ctx.root, &ctx.records_dir(), "diretório de registros")?;
    let shared_directory_claims = match all_shared_directory_claims(ctx) {
        Ok(claims) => claims,
        Err(error) => {
            println!("wrongthink: claims de diretório compartilhado são inválidas: {error}");
            problems += 1;
            Vec::new()
        }
    };
    let shared_directory_index =
        index_directory_claims(&shared_directory_claims, "", &HashSet::new());
    let journal_dir = ctx.root.join("var/lib/minitrue/journal");
    if let Ok(entries) = fs::read_dir(&journal_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') && entry.path().is_dir() {
                println!(
                    "wrongthink: transação pendente de {name}; rode `rectify {name}` antes de confiar no estado"
                );
                problems += 1;
            }
        }
    }
    if let Ok(entries) = fs::read_dir(ctx.records_dir()) {
        for entry in entries {
            let e = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    println!("wrongthink: não pude ler uma entrada de registro: {error}");
                    problems += 1;
                    continue;
                }
            };
            let name = e.file_name().to_string_lossy().into_owned();
            if !e.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                println!("wrongthink: registro de {name} não é diretório real");
                problems += 1;
                continue;
            }
            let meta = match read_meta_strict(&e.path()) {
                Ok(Some(meta)) => meta,
                Ok(None) => {
                    println!("wrongthink: registro de {name} não tem meta legível");
                    problems += 1;
                    continue;
                }
                Err(error) => {
                    println!("wrongthink: meta de {name} é inválido: {error}");
                    problems += 1;
                    continue;
                }
            };
            if let Err(error) = ensure_supported_record_format(&meta, &name) {
                println!("wrongthink: {error}");
                problems += 1;
                continue;
            }
            if meta.get("RECORD_FORMAT").map(String::as_str) != Some(FINAL_RECORD_FORMAT) {
                println!(
                    "wrongthink: registro de {name} ainda não possui fechamento factual RECORD_FORMAT=4"
                );
                problems += 1;
            }
            let shared_roots = match recorded_shared_roots(ctx, &meta, &name) {
                Ok(roots) => roots,
                Err(error) => {
                    println!("wrongthink: SHARED_DIRS de {name} é inválido: {error}");
                    problems += 1;
                    continue;
                }
            };
            if let Err(error) = verify_channel_provenance(ctx, &meta) {
                println!("wrongthink: proveniência de canal de {name} é inválida: {error}");
                problems += 1;
            }
            if let Err(error) = crate::plan::verify_record_binding(ctx, &e.path(), &meta) {
                println!("wrongthink: vínculo de PLAN_LOCK de {name} é inválido: {error}");
                problems += 1;
            }
            if typed_record_format(&meta) {
                let Some(dependencies) = meta.get("DEPS") else {
                    println!("wrongthink: registro v2 de {name} não declara DEPS");
                    problems += 1;
                    continue;
                };
                for dependency in dependencies.split_whitespace() {
                    if recipe::validate_name(dependency).is_err() {
                        println!("wrongthink: {name} declara dependência inválida {dependency:?}");
                        problems += 1;
                        continue;
                    }
                    let dependency_record = ctx.records_dir().join(dependency);
                    let dependency_is_real = fs::symlink_metadata(&dependency_record)
                        .is_ok_and(|metadata| metadata.file_type().is_dir());
                    let dependency_meta = dependency_is_real
                        && read_meta_strict(&dependency_record).is_ok_and(|dependency_meta| {
                            dependency_meta.is_some_and(|dependency_meta| {
                                dependency_meta.get("NAME").map(String::as_str) == Some(dependency)
                            })
                        });
                    if !dependency_meta {
                        println!(
                            "wrongthink: dependência {dependency} de {name} não tem registro factual"
                        );
                        problems += 1;
                    }
                }
            }
            let mut versioned_manifest = None;
            if typed_record_format(&meta) {
                let version = meta.get("VERSION").map(String::as_str);
                let baseline = version.and_then(|version| {
                    recipe::validate_version(&name, version).ok().and_then(|_| {
                        read_regular_nofollow(&e.path().join(format!("manifest@{version}"))).ok()
                    })
                });
                match baseline {
                    Some(bytes) => {
                        let baseline_hash = sha256_bytes(&bytes);
                        if meta.get("MANIFEST_BASELINE_SHA256") != Some(&baseline_hash) {
                            println!(
                                "wrongthink: baseline versionado de {name} não confere com o meta"
                            );
                            problems += 1;
                        }
                        versioned_manifest = Some(bytes);
                    }
                    None => {
                        println!("wrongthink: baseline versionado de {name} está ausente/inválido");
                        problems += 1;
                    }
                }
            }
            let manifest = match read_manifest_strict(&e.path()) {
                Ok(manifest) => manifest,
                Err(error) => {
                    println!("wrongthink: manifesto de {name} é ilegível: {error}");
                    problems += 1;
                    continue;
                }
            };
            let is_meta = meta.get("KIND").map(String::as_str) == Some("meta")
                && meta.get("WORLD").map(String::as_str) == Some("M")
                && meta.get("ORIGIN").map(String::as_str) == Some("meta");
            let meta_marker_present = meta.get("KIND").map(String::as_str) == Some("meta")
                || meta.get("WORLD").map(String::as_str) == Some("M")
                || meta.get("ORIGIN").map(String::as_str) == Some("meta");
            if meta_marker_present && !is_meta {
                println!("wrongthink: registro meta de {name} tem KIND/WORLD/ORIGIN incoerentes");
                problems += 1;
            }
            if typed_record_format(&meta) && !is_meta && license_of(&e.path(), &meta).is_none() {
                println!("wrongthink: registro v2 de {name} não declara LICENSE válida");
                problems += 1;
            }
            if is_meta {
                let forbidden = [
                    "ARTIFACT_HASH",
                    "TRANSACTION_ID",
                    "PROVISIONAL",
                    "REPROCORR",
                    "LICENSE",
                ];
                if meta.get("SHA256").is_none_or(|value| !value.is_empty())
                    || meta.get("NAME").map(String::as_str) != Some(name.as_str())
                    || meta.get("SUPERSEDES").is_none_or(|value| !value.is_empty())
                    || (matches!(
                        meta.get("RECORD_FORMAT").map(String::as_str),
                        Some(RECORD_FORMAT | FINAL_RECORD_FORMAT)
                    ) && meta
                        .get("SHARED_DIRS")
                        .is_none_or(|value| !value.is_empty()))
                    || meta.get("DEPS").is_none_or(|value| value.is_empty())
                    || meta.get("DEPS").is_some_and(|value| {
                        value
                            .split_whitespace()
                            .any(|dep| recipe::validate_name(dep).is_err())
                    })
                    || !meta
                        .get("FINGERPRINT")
                        .is_some_and(|value| canonical_sha256(value))
                    || forbidden.iter().any(|field| meta.contains_key(*field))
                {
                    println!("wrongthink: metapacote {name} contém campos de payload/build");
                    problems += 1;
                }
                let recipe_current = read_regular_nofollow(&e.path().join("recipe"));
                let recipe_versioned = meta.get("VERSION").map(|version| {
                    read_regular_nofollow(&e.path().join(format!("recipe@{version}")))
                });
                let recipe_coherent = recipe_current.as_ref().is_ok_and(|current| {
                    !current.is_empty()
                        && recipe_versioned.as_ref().is_some_and(|versioned| {
                            versioned
                                .as_ref()
                                .is_ok_and(|versioned| versioned == current)
                        })
                        && recipe::literal_assignment_bytes(current, "NAME").as_deref()
                            == Some(name.as_str())
                        && recipe::literal_assignment_bytes(current, "VERSION").as_ref()
                            == meta.get("VERSION")
                        && recipe::literal_assignment_bytes(current, "KIND").as_deref()
                            == Some("meta")
                        && recipe::literal_assignment_bytes(current, "DEPS").as_ref()
                            == meta.get("DEPS")
                });
                if !recipe_coherent {
                    println!("wrongthink: snapshots da receita meta de {name} são incoerentes");
                    problems += 1;
                }
                let current = read_regular_nofollow(&e.path().join("manifest"));
                let versioned = meta.get("VERSION").map(|version| {
                    read_regular_nofollow(&e.path().join(format!("manifest@{version}")))
                });
                if !current.is_ok_and(|bytes| bytes == b"\n")
                    || !versioned.is_some_and(|bytes| bytes.is_ok_and(|bytes| bytes == b"\n"))
                {
                    println!("wrongthink: manifesto vazio de {name} não é canônico");
                    problems += 1;
                }
            }
            if manifest.is_empty() && !is_provisional(ctx, &name) && !is_meta {
                println!("wrongthink: manifesto de {name} está ausente/vazio");
                problems += 1;
            }
            if is_meta && !manifest.is_empty() {
                println!("wrongthink: metapacote {name} reivindica payload");
                problems += 1;
            }
            if typed_record_format(&meta)
                && meta.get("PROVISIONAL").map(String::as_str) == Some("1")
            {
                if let Some(versioned_manifest) = versioned_manifest.as_deref() {
                    let coherence = std::str::from_utf8(versioned_manifest)
                        .map_err(|_| anyhow::anyhow!("baseline não UTF-8"))
                        .and_then(|baseline| {
                            let active: Vec<&str> = manifest.iter().map(String::as_str).collect();
                            let baseline: Vec<&str> =
                                baseline.lines().filter(|line| !line.is_empty()).collect();
                            provisional_manifest_coherent(ctx, &name, &active, &baseline, false)
                        });
                    match coherence {
                        Ok(true) => {}
                        Ok(false) => {
                            println!(
                                "wrongthink: manifesto provisional de {name} não é coerente com o baseline ou tem cessão sem sucessor válido"
                            );
                            problems += 1;
                        }
                        Err(error) => {
                            println!(
                                "wrongthink: coerência do manifesto provisional de {name} não pôde ser validada: {error}"
                            );
                            problems += 1;
                        }
                    }
                }
            }
            for line in manifest {
                if let Err(error) = validate_manifest_line_for_record(&meta, &name, &line) {
                    println!("wrongthink: manifesto de {name} é inválido: {error}");
                    problems += 1;
                    continue;
                }
                let path = manifest_path(&line);
                match rooted_path(&ctx.root, path) {
                    Ok(_) => {}
                    Err(err) => {
                        println!("wrongthink: manifesto de {name} tem caminho inválido: {err}");
                        problems += 1;
                        continue;
                    }
                };
                let canonical = match canonical_virtual_path(&ctx.root, path) {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        println!(
                            "wrongthink: claim {path} de {name} não pôde ser canonicalizada: {error}"
                        );
                        problems += 1;
                        continue;
                    }
                };
                if manifest_integrity(&line).is_some_and(|tag| tag.starts_with("D:"))
                    && !path_is_shared(&canonical, &shared_roots)
                {
                    println!("wrongthink: claim D: {canonical} de {name} fica fora de SHARED_DIRS");
                    problems += 1;
                    continue;
                }
                if let Some((owner, _, directory)) =
                    indexed_claim_at_or_above(&shared_directory_index, &canonical, true)
                {
                    if owner != name
                        && !meta
                            .get("DEPS")
                            .is_some_and(|deps| deps.split_whitespace().any(|dep| dep == owner))
                    {
                        println!(
                            "wrongthink: {canonical} (de {name}) usa diretório compartilhado {directory} de {owner} sem DEPS direta"
                        );
                        problems += 1;
                    }
                }
                if let Some(previous) = claimed.insert(canonical.clone(), name.clone()) {
                    println!("wrongthink: ownership duplicado de {canonical}: {previous} e {name}");
                    problems += 1;
                }
                match confined_exists(&ctx.root, path) {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("wrongthink: {path} (de {name}) sumiu do filesystem");
                        problems += 1;
                        continue;
                    }
                    Err(err) => {
                        println!("wrongthink: {path} (de {name}) não pôde ser inspecionado: {err}");
                        problems += 1;
                        continue;
                    }
                }
                match confined_claim_matches(&line, &ctx.root, path) {
                    Ok(Some(false)) => {
                        println!("wrongthink: {path} (de {name}) foi modificado — conteúdo/tipo/alvo difere do registro");
                        problems += 1;
                    }
                    Ok(Some(true) | None) => {}
                    Err(err) => {
                        println!("wrongthink: manifesto de {name} é inválido em {path}: {err}");
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
            let canonical = canonical_virtual_path(&ctx.root, &virt).unwrap_or(virt.clone());
            if !claimed.contains_key(&canonical) {
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

struct RecordWrite<'a> {
    artifact_hash: Option<&'a str>,
    fingerprint: &'a str,
    manifest_typed: bool,
    source_origin: SourceRecordOrigin<'a>,
    journal: Option<&'a mut Journal>,
    /// Linhas que entram SÓ no baseline (`manifest@<versão>`), além do
    /// manifesto ativo. Apenas o refresh de provisional cedido usa isto.
    ///
    /// Normalmente os dois arquivos recebem o mesmo corpo: numa instalação
    /// limpa o pacote possui tudo o que produziu, e a cessão depois encolhe
    /// apenas o `manifest`, deixando o baseline como memória do que era dele.
    /// Ao reconstruir um provisional que JÁ CEDEU, o ativo tem de sair menor —
    /// senão retomaríamos os caminhos dos sucessores — mas o baseline tem de
    /// continuar cheio. Se ele encolhesse junto, `provisional_cession_state`
    /// passaria a responder `NotCeded`, e a PRÓXIMA correção de receita cairia
    /// no caminho de reconstrução normal, que tentaria reivindicar `ar`, `awk`
    /// e `strings` de volta e morreria em doublethink.
    ///
    /// São as linhas do baseline ANTIGO, copiadas verbatim, e não linhas
    /// recalculadas: recalcular a integridade de `/usr/bin/ar` hoje leria o
    /// arquivo do binutils e gravaria o hash DELE dentro do registro do
    /// busybox. O que o baseline afirma é "quando era meu, era assim".
    baseline_extra: Option<&'a [String]>,
}

fn record_kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Binary => "binary",
        Kind::Source => "source",
        Kind::Meta => "meta",
    }
}

fn record_world(kind: Kind) -> &'static str {
    match kind {
        Kind::Binary => "A",
        Kind::Source => "B",
        Kind::Meta => "M",
    }
}

fn write_record(
    ctx: &Ctx,
    rec_dir: &Path,
    r: &Recipe,
    world: &str,
    manifest: &mut Vec<String>,
    mut write: RecordWrite<'_>,
) -> Result<()> {
    ensure_real_directory_or_absent(&ctx.root, rec_dir, "registro do pacote")?;
    if let Some(journal) = write.journal.as_deref_mut() {
        journal.ensure_dir(rec_dir, fs::Permissions::from_mode(0o755), false, false)?;
    } else {
        fs::create_dir_all(rec_dir)?;
    }
    manifest.sort();
    manifest.dedup();
    // ORIGIN: quando os canais (SPEC-0009) chegarem, a instalação de canal grava
    // `canal:<nome>` (+ TRUST, CHANNEL_SHA256); por ora deriva do mundo.
    let origin = match (world, write.source_origin) {
        ("A", _) => "vendor".to_string(),
        ("B", SourceRecordOrigin::Local) => "fonte".to_string(),
        ("B", SourceRecordOrigin::Channel(selection)) => {
            format!("canal:{}", selection.channel)
        }
        ("M", _) => "meta".to_string(),
        _ => bail!("mundo de registro inválido: {world}"),
    };
    let transaction = write
        .journal
        .as_ref()
        .map(|j| format!("TRANSACTION_ID={}\n", j.txid))
        .unwrap_or_default();
    let mut meta = format!(
        "RECORD_FORMAT={RECORD_FORMAT}\nNAME={}\nVERSION={}\nKIND={}\nWORLD={}\nORIGIN={}\nSHA256={}\nDEPS={}\nSHARED_DIRS={}\nFINGERPRINT={}\nINSTALLED_AT={}\n",
        r.name,
        r.version,
        record_kind(r.kind),
        world,
        origin,
        r.sha256.join(" "),
        r.deps.join(" "),
        r.shared_dirs.join(" "),
        write.fingerprint,
        iso_now(),
    );
    if let Some(hash) = write.artifact_hash {
        meta.push_str(&format!("ARTIFACT_HASH={hash}\n"));
    }
    if let SourceRecordOrigin::Channel(selection) = write.source_origin {
        meta.push_str(&format!(
            "TRUST={}\nCHANNEL_PATH={}\nCHANNEL_SHA256={}\nCHANNEL_INDEX_SHA256={}\nCHANNEL_INDEX_FORMAT={}\nCHANNEL_RELEASE_ROOT={}\nCHANNEL_PRODUCER_PLAN_LOCK_SHA256={}\nCHANNEL_LOCK_SHA256={}\n",
            selection.trust.as_str(),
            selection.path,
            selection.artifact_sha256,
            selection.index_sha256,
            selection.index_format,
            if selection.release_root { "yes" } else { "no" },
            selection
                .producer_plan_lock_sha256
                .as_deref()
                .unwrap_or("-"),
            selection.lock_sha256,
        ));
    }
    // LICENSE descreve o payload. Metapacotes não carregam payload próprio e
    // portanto omitem o campo; registros A/B novos sempre o congelam aqui.
    if let Some(license) = &r.license {
        meta.push_str(&format!("LICENSE={license}\n"));
    }
    if r.provisional {
        meta.push_str("PROVISIONAL=1\n");
    }
    // A licença de tomar claims de uma semente faz parte do registro histórico.
    // Ela também prova cadeias provisional→provisional após um restart.
    meta.push_str(&format!("SUPERSEDES={}\n", r.supersedes.join(" ")));
    if !r.about.is_empty() {
        meta.push_str(&format!("ABOUT={}\n", r.about));
    }
    if let Some(pinned) = &r.reprocorr {
        meta.push_str(&format!("REPROCORR={pinned}\n"));
    }
    // Manifesto v2: cada linha prende tipo+conteúdo (`f:`), alvo de link (`l:`)
    // ou árvore de diretório (`d:`). Além do `verify`/`memoryhole`, isso impede
    // que o fast path aceite um link retargetado ou payload mundo-A adulterado.
    let decorated: Vec<String> = if write.manifest_typed {
        let shared_roots = canonical_shared_roots(ctx, r)?;
        manifest
            .iter()
            .map(|line| -> Result<String> {
                let path = manifest_path(line);
                rooted_path(&ctx.root, path)?;
                let canonical_path = canonical_virtual_path(&ctx.root, path)?;
                let Some(integrity) = manifest_integrity(line) else {
                    bail!("manifesto pré-calculado contém claim inválida: {line:?}");
                };
                if integrity.starts_with("D:")
                    && (world != "B" || !path_is_shared(&canonical_path, &shared_roots))
                {
                    bail!("{}: claim D: fora de SHARED_DIRS declarada: {path}", r.name);
                }
                Ok(line.clone())
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        manifest
            .iter()
            .map(|p| -> Result<String> {
                rooted_path(&ctx.root, p)?;
                Ok(format!("{}  {p}", confined_path_integrity(&ctx.root, p)?))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let body = decorated.join("\n") + "\n";
    // O baseline é o ativo mais as linhas cedidas, quando há. O
    // MANIFEST_BASELINE_SHA256 acompanha o ARQUIVO manifest@<versão> e não o
    // manifest ativo — é assim que `provisional_cession_state` o confere, e
    // divergir aqui deixaria todo registro refrescado "incoerente".
    let baseline_body = match write.baseline_extra {
        None => body.clone(),
        Some(extra) => {
            let mut linhas: Vec<String> = decorated.clone();
            for linha in extra {
                validate_manifest_line_syntax(linha)?;
                rooted_path(&ctx.root, manifest_path(linha))?;
                linhas.push(linha.clone());
            }
            linhas.sort();
            linhas.dedup();
            linhas.join("\n") + "\n"
        }
    };
    meta.push_str(&format!(
        "MANIFEST_BASELINE_SHA256={}\n",
        sha256_bytes(baseline_body.as_bytes())
    ));
    // Sempre por último: é a única marca que autoriza recovery a concluir uma
    // transação journalizada em vez de revertê-la.
    meta.push_str(&transaction);
    // Todas as partes são preparadas antes da primeira mutação. Quando o
    // chamador fornece Journal (instalações B e migrações legadas A), cada
    // troca entra nele; o `meta` com txid é a última e única marca de commit.
    // Sem Journal (instalações A normais e mundo M), cada arquivo ainda troca
    // atomicamente.
    let files = [
        (rec_dir.join("manifest"), body.as_bytes()),
        (
            rec_dir.join(format!("manifest@{}", r.version)),
            baseline_body.as_bytes(),
        ),
        (rec_dir.join("recipe"), r.recipe_bytes.as_slice()),
        (
            rec_dir.join(format!("recipe@{}", r.version)),
            r.recipe_bytes.as_slice(),
        ),
        (rec_dir.join("meta"), meta.as_bytes()),
    ];
    for (path, bytes) in files {
        if let Some(jrnl) = write.journal.as_deref_mut() {
            jrnl.place_bytes(&path, bytes)?;
        } else {
            write_atomic(&path, bytes)?;
        }
    }
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
    mut journal: Option<&mut Journal>,
) -> Result<Option<String>> {
    ensure_real_directory_or_absent(&ctx.root, &ctx.records_dir(), "diretório de registros")?;
    let entries = match fs::read_dir(ctx.records_dir()) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let e = entry?;
        if !e.file_type()?.is_dir() {
            bail!(
                "entrada de registro não é diretório real: {}",
                e.path().display()
            );
        }
        let owner = e.file_name().to_string_lossy().into_owned();
        // Só cede de provisional que ESTA receita declarou superseder
        // (SPEC-0003 §7). Provisional não-declarado não é cedido — vira
        // doublethink no check de colisão.
        if owner == myself || !is_provisional(ctx, &owner) || !supersedes.contains(&owner) {
            continue;
        }
        let mut m = read_manifest_strict(&e.path())?;
        if let Some(pos) = m.iter().position(|line| {
            canonical_virtual_path(&ctx.root, manifest_path(line)).is_ok_and(|path| path == virt)
        }) {
            m.remove(pos);
            let body = m.join("\n") + "\n";
            let path = e.path().join("manifest");
            if let Some(jrnl) = journal.as_deref_mut() {
                jrnl.place_bytes(&path, body.as_bytes())?;
            } else {
                write_atomic(&path, body.as_bytes())?;
            }
            return Ok(Some(owner));
        }
    }
    Ok(None)
}

pub(crate) fn read_meta_strict(rec_dir: &Path) -> Result<Option<HashMap<String, String>>> {
    let path = rec_dir.join("meta");
    let bytes = match read_regular_nofollow(&path) {
        Ok(bytes) => bytes,
        Err(error) if error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(parse_meta_bytes(&bytes)?))
}

fn parse_meta_bytes(bytes: &[u8]) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(bytes).context("meta não é UTF-8")?;
    let mut meta = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("meta linha {} malformada", index + 1))?;
        let valid_key = !key.is_empty()
            && key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && key.as_bytes()[0].is_ascii_uppercase();
        if !valid_key || value.chars().any(char::is_control) {
            bail!("meta linha {} não é canônica", index + 1);
        }
        if meta.insert(key.to_string(), value.to_string()).is_some() {
            bail!("meta contém campo duplicado: {key}");
        }
    }
    if meta.is_empty() {
        bail!("meta está vazio");
    }
    Ok(meta)
}

/// Identidade factual de payload/origem para um nó que o resolvedor já provou
/// como `keep`. Mundo B possui ARTIFACT_HASH; mundo A prende exatamente o
/// manifesto tipado da árvore instalada, cujo hash vira a identidade material
/// do plano. Metapacote não possui payload.
pub(crate) fn installed_plan_material(
    ctx: &Ctx,
    recipe: &Recipe,
) -> Result<Option<(String, String)>> {
    let record = ctx.records_dir().join(&recipe.name);
    let Some(meta) = read_meta_strict(&record)? else {
        return Ok(None);
    };
    let origin = meta
        .get("ORIGIN")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{}: registro sem ORIGIN", recipe.name))?;
    let payload = match recipe.kind {
        Kind::Source => meta
            .get("ARTIFACT_HASH")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{}: registro B sem ARTIFACT_HASH", recipe.name))?,
        Kind::Binary => crate::plan::record_payload_sha256(
            &record,
            &recipe.name,
            crate::plan::record_is_provisional(&meta),
        )?,
        Kind::Meta => "-".to_string(),
    };
    Ok(Some((origin, payload)))
}

pub(crate) struct VendorProducerRecordFact {
    pub record_fact_sha256: String,
    pub payload_sha256: String,
}

/// Snapshot produtor usado por um PLAN de mídia para um pacote A. Ele não
/// promove um Keep para a ação portátil: apenas observa, por dirfd e com a
/// segunda passagem histórica, o payload/ABI que a ação Vendor deverá
/// reproduzir no consumidor. V3 nunca é autoridade para esse fechamento.
pub(crate) fn vendor_producer_record_fact(
    ctx: &Ctx,
    recipe: &Recipe,
    expected_fingerprint: &str,
) -> Result<VendorProducerRecordFact> {
    if recipe.kind != Kind::Binary {
        bail!("snapshot vendor produtor exige KIND=binary");
    }
    let record = ctx.records_dir().join(&recipe.name);
    let (record_fact_sha256, meta, payload_sha256) =
        verify_historical_record_snapshot(ctx, &record, &recipe.name)?;
    if meta.get("RECORD_FORMAT").map(String::as_str) != Some(FINAL_RECORD_FORMAT)
        || meta.get("NAME") != Some(&recipe.name)
        || meta.get("VERSION") != Some(&recipe.version)
        || meta.get("KIND").map(String::as_str) != Some("binary")
        || meta.get("WORLD").map(String::as_str) != Some("A")
        || meta.get("ORIGIN").map(String::as_str) != Some("vendor")
        || meta.get("FINGERPRINT").map(String::as_str) != Some(expected_fingerprint)
        || meta.get("LICENSE") != recipe.license.as_ref()
        || meta.get("INSTALL_PLAN_ACTION").map(String::as_str) != Some("keep")
    {
        bail!(
            "{}: record produtor não é o v4 vendor factual da recipe/fingerprint exatos",
            recipe.name
        );
    }
    if meta.get("INSTALL_PLAN_PAYLOAD_SHA256") != Some(&payload_sha256) {
        bail!(
            "{}: payload do record produtor diverge do vínculo v4",
            recipe.name
        );
    }
    Ok(VendorProducerRecordFact {
        record_fact_sha256,
        payload_sha256,
    })
}

pub(crate) fn read_meta(rec_dir: &Path) -> Option<HashMap<String, String>> {
    read_meta_strict(rec_dir).ok().flatten()
}

/// Valida a identidade instalada antes de ela virar uma declaração assinada.
/// Não basta o `ARTIFACT_HASH` ser hex: o registro v2, baseline, snapshots e
/// todas as claims ativas precisam formar um estado íntegro de mundo B.
pub(crate) fn attestable_meta(ctx: &Ctx, pkg: &str) -> Result<HashMap<String, String>> {
    recipe::validate_name(pkg)?;
    let rec_dir = ctx.records_dir().join(pkg);
    ensure_real_directory_or_absent(&ctx.root, &rec_dir, "registro atestável")?;
    let (_, meta, _) = verify_historical_record_snapshot(ctx, &rec_dir, pkg).map_err(|error| {
        anyhow::anyhow!("{pkg}: record não é um snapshot histórico atestável: {error}")
    })?;
    if meta.get("RECORD_FORMAT").map(String::as_str) != Some(FINAL_RECORD_FORMAT)
        || meta.get("NAME").map(String::as_str) != Some(pkg)
        || meta.get("KIND").map(String::as_str) != Some("source")
        || meta.get("WORLD").map(String::as_str) != Some("B")
        || meta
            .get("TRANSACTION_ID")
            .is_none_or(|value| value.is_empty())
    {
        bail!("{pkg}: somente RECORD_FORMAT=4 factual íntegro de mundo B pode ser atestado");
    }
    if let Some(pinned) = meta.get("REPROCORR") {
        if meta.get("ARTIFACT_HASH") != Some(pinned) {
            bail!("{pkg}: ARTIFACT_HASH diverge do REPROCORR pinado");
        }
    }
    Ok(meta)
}

pub(crate) fn read_manifest(rec_dir: &Path) -> Vec<String> {
    read_regular_text_nofollow(&rec_dir.join("manifest"))
        // Um provisional pode ceder todas as claims e ficar com o corpo
        // canônico "\n". Linha vazia não é caminho; o status PROVISIONAL no
        // meta decide se um manifesto sem claims é legítimo.
        .map(|t| {
            t.lines()
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Leitura factual de um manifesto persistido. Diferentemente de
/// `read_manifest`, distingue o corpo canônico sem claims (`"\n"`) de arquivo
/// ausente, vazio, ilegível ou não UTF-8. Operações que decidem integridade,
/// colisão ou remoção nunca podem tratar corrupção como "zero caminhos".
fn read_manifest_strict(rec_dir: &Path) -> Result<Vec<String>> {
    let bytes = read_regular_nofollow(&rec_dir.join("manifest"))?;
    if bytes.is_empty() {
        bail!("arquivo vazio");
    }
    let text = String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("conteúdo não UTF-8"))?;
    Ok(text
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn read_versioned_manifest_strict(rec_dir: &Path, version: &str) -> Result<Vec<String>> {
    let bytes = read_regular_nofollow(&rec_dir.join(format!("manifest@{version}")))?;
    if bytes.is_empty() {
        bail!("manifest@{version} vazio");
    }
    let text =
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("manifest@{version} não é UTF-8"))?;
    Ok(text
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Formatos futuros são estado desconhecido, não "legado". Regravá-los como
/// v2 seria um downgrade silencioso e poderia descartar invariantes que esta
/// versão do minitrue não entende.
fn ensure_supported_record_format(meta: &HashMap<String, String>, name: &str) -> Result<()> {
    match meta.get("RECORD_FORMAT").map(String::as_str) {
        None
        | Some(
            "0" | "1" | PREVIOUS_TYPED_RECORD_FORMAT | RECORD_FORMAT | FINAL_RECORD_FORMAT,
        ) => Ok(()),
        Some(format) => bail!(
            "{name}: RECORD_FORMAT={format} não é suportado por este minitrue (máximo {FINAL_RECORD_FORMAT})"
        ),
    }
}

fn typed_record_format(meta: &HashMap<String, String>) -> bool {
    matches!(
        meta.get("RECORD_FORMAT").map(String::as_str),
        Some(PREVIOUS_TYPED_RECORD_FORMAT | RECORD_FORMAT | FINAL_RECORD_FORMAT)
    )
}

fn validate_manifest_line_for_record(
    meta: &HashMap<String, String>,
    name: &str,
    line: &str,
) -> Result<()> {
    validate_manifest_line_syntax(line)?;
    if !typed_record_format(meta) {
        return Ok(());
    }
    let Some(tag) = manifest_integrity(line) else {
        bail!("{name}: registro tipado contém claim não tipada");
    };
    if meta.get("RECORD_FORMAT").map(String::as_str) == Some(PREVIOUS_TYPED_RECORD_FORMAT)
        && tag.starts_with("D:")
    {
        bail!("{name}: RECORD_FORMAT=2 não pode conter claim D:");
    }
    Ok(())
}

fn recorded_shared_roots(
    ctx: &Ctx,
    meta: &HashMap<String, String>,
    name: &str,
) -> Result<Vec<String>> {
    if !matches!(
        meta.get("RECORD_FORMAT").map(String::as_str),
        Some(RECORD_FORMAT | FINAL_RECORD_FORMAT)
    ) {
        return Ok(Vec::new());
    }
    let value = meta
        .get("SHARED_DIRS")
        .ok_or_else(|| anyhow::anyhow!("{name}: registro v3 não declara SHARED_DIRS"))?;
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for path in value.split_whitespace() {
        rooted_path(&ctx.root, path)?;
        let canonical = canonical_virtual_path(&ctx.root, path)?;
        if !seen.insert(canonical.clone()) {
            bail!("{name}: SHARED_DIRS gravado repete {canonical}");
        }
        roots.push(canonical);
    }
    Ok(roots)
}

/// Coerência comum a provisionals v2 e legados congelados. Cessão normal só
/// remove linhas: as restantes precisam ser byte-idênticas ao baseline, e
/// toda linha ausente precisa aparecer no manifesto ativo de um sucessor. Um
/// sucessor ainda provisional só prova a cessão quando seu snapshot histórico
/// declara `SUPERSEDES=<cedente>`; sem isso, subconjunto também poderia ser
/// truncamento.
fn successor_authorizes_cession(ctx: &Ctx, successor: &str, cedent: &str) -> Result<bool> {
    let rec_dir = ctx.records_dir().join(successor);
    let Some(meta) = read_meta_strict(&rec_dir)? else {
        return Ok(false);
    };
    ensure_supported_record_format(&meta, successor)?;
    if meta.get("NAME").map(String::as_str) != Some(successor) {
        return Ok(false);
    }
    if meta.get("PROVISIONAL").map(String::as_str) != Some("1") {
        return Ok(true);
    }

    let declaration = if let Some(value) = meta.get("SUPERSEDES") {
        Some(value.clone())
    } else {
        // Compatibilidade com registros anteriores ao campo congelado. A
        // receita é aberta sem seguir link e apenas atribuições literais são
        // aceitas; nenhum shell histórico é executado.
        read_regular_nofollow(&rec_dir.join("recipe"))
            .ok()
            .and_then(|bytes| recipe::literal_assignment_bytes(&bytes, "SUPERSEDES"))
    };
    let Some(declaration) = declaration else {
        return Ok(false);
    };
    for package in declaration.split_whitespace() {
        recipe::validate_name(package)?;
    }
    Ok(declaration
        .split_whitespace()
        .any(|package| package == cedent))
}

fn provisional_manifest_coherent(
    ctx: &Ctx,
    name: &str,
    active: &[&str],
    baseline: &[&str],
    require_cession: bool,
) -> Result<bool> {
    Ok(
        provisional_unproved_cessions(ctx, name, active, baseline, require_cession)?
            .is_some_and(|unproved| unproved.is_empty()),
    )
}

/// Distingue corrupção estrutural de uma cessão cuja prova de ownership
/// desapareceu. `None` significa que ativo e baseline nem sequer formam a
/// relação de subconjunto íntegro exigida; `Some(paths)` traz, em ordem
/// canônica, apenas as claims removidas que nenhum sucessor atual prova.
///
/// `verify` continua exigindo `Some(vazio)`. A distinção existe somente para
/// que um upgrade de identidade possa consultar o STAGE selado antes de
/// decidir se uma claim foi aposentada pelos dois produtores.
fn provisional_unproved_cessions(
    ctx: &Ctx,
    name: &str,
    active: &[&str],
    baseline: &[&str],
    require_cession: bool,
) -> Result<Option<Vec<String>>> {
    let active_by_path: HashMap<&str, &str> = active
        .iter()
        .map(|line| (manifest_path(line), *line))
        .collect();
    let baseline_by_path: HashMap<&str, &str> = baseline
        .iter()
        .map(|line| (manifest_path(line), *line))
        .collect();
    if active_by_path.len() != active.len()
        || baseline_by_path.len() != baseline.len()
        || active_by_path.len() > baseline_by_path.len()
        || (require_cession && active_by_path.len() == baseline_by_path.len())
        || active_by_path
            .iter()
            .any(|(path, line)| baseline_by_path.get(path) != Some(line))
    {
        return Ok(None);
    }
    for line in baseline {
        validate_manifest_line_syntax(line)?;
        rooted_path(&ctx.root, manifest_path(line))?;
    }
    if active_by_path.len() == baseline_by_path.len() {
        return Ok(Some(Vec::new()));
    }
    let owners = all_manifests(ctx)?;
    let mut unproved = Vec::new();
    for removed in baseline_by_path
        .keys()
        .filter(|path| !active_by_path.contains_key(*path))
    {
        let canonical_removed = canonical_virtual_path(&ctx.root, removed)?;
        // Claim de DIRETÓRIO se prova de outro jeito. Exigir que o sucessor
        // reivindique o mesmo caminho é impossível para diretório: ele é
        // cedido exatamente porque o sucessor o ENCHE de arquivos, e um
        // diretório com conteúdo não gera claim `d:`. Então, para diretório,
        // a prova é alguém reivindicar algo DENTRO dele. Para arquivo e link
        // a regra continua sendo o caminho exato.
        let removed_is_directory = baseline_by_path
            .get(*removed)
            .and_then(|line| manifest_integrity(line))
            .is_some_and(|tag| tag.starts_with("d:") || tag.starts_with("D:"));
        let prefix = format!("{canonical_removed}/");
        let mut proved = false;
        for (owner, _, claims) in &owners {
            if owner == name || !successor_authorizes_cession(ctx, owner, name)? {
                continue;
            }
            let claims_it = claims.contains(&canonical_removed)
                || (removed_is_directory && claims.iter().any(|c| c.starts_with(&prefix)));
            if claims_it {
                proved = true;
                break;
            }
        }
        if !proved {
            unproved.push(canonical_removed);
        }
    }
    unproved.sort();
    Ok(Some(unproved))
}

/// Reconhece uma semente provisional que já cedeu claims. `manifest@VERSION`
/// é o baseline imutável; `manifest` é o conjunto ainda ativo. Uma inclusão
/// própria e estrita prova que houve cessão, mesmo se a receita/fingerprint
/// corrente mudou desde o bootstrap. Só as claims ativas são inspecionadas —
/// as ausentes pertencem justamente aos sucessores e não podem ser re-hashadas
/// como se ainda fossem da semente.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisionalCession {
    NotCeded,
    Intact,
    /// Ativo e baseline são estruturalmente íntegros, mas pelo menos uma
    /// claim removida já não tem sucessor atual que prove a cessão.
    Unproved,
    Incoherent,
}

/// O que o registro deste pacote diz ter cedido, ou vazio quando não há
/// registro, quando ele não é provisional, ou quando nada foi cedido.
///
/// Existe para que preflight, materialização e escrita do registro no mundo B
/// consultem A MESMA fonte. Três leituras independentes do par
/// baseline/ativo divergiriam no primeiro caso de borda, e o sintoma seria um
/// pacote que passa no preflight e depois apaga o arquivo do sucessor.
fn cedidos_do_registro(ctx: &Ctx, rec_dir: &Path) -> Result<Vec<(String, String)>> {
    let Some(meta) = read_meta(rec_dir) else {
        return Ok(Vec::new());
    };
    if meta.get("PROVISIONAL").map(String::as_str) != Some("1") {
        return Ok(Vec::new());
    }
    let Some(versao) = meta.get("VERSION") else {
        return Ok(Vec::new());
    };
    if !rec_dir.join(format!("manifest@{versao}")).is_file() {
        return Ok(Vec::new());
    }
    caminhos_cedidos(ctx, rec_dir, versao)
}

/// Claims de `baseline - ativo` que já não têm prova em sucessor atual. Esta
/// lista não autoriza reparo sozinha: o chamador ainda precisa provar mudança
/// de identidade, ausência no root e omissão no STAGE selado.
fn cessoes_sem_sucessor_do_registro(ctx: &Ctx, rec_dir: &Path, name: &str) -> Result<Vec<String>> {
    let Some(meta) = read_meta_strict(rec_dir)? else {
        return Ok(Vec::new());
    };
    ensure_supported_record_format(&meta, name)?;
    if meta.get("PROVISIONAL").map(String::as_str) != Some("1") {
        return Ok(Vec::new());
    }
    if meta.get("NAME").map(String::as_str) != Some(name) {
        bail!("{name}: registro provisional tem NAME incoerente");
    }
    let version = meta
        .get("VERSION")
        .ok_or_else(|| anyhow::anyhow!("{name}: registro provisional sem VERSION"))?;
    recipe::validate_version(name, version)?;
    let active = read_manifest_strict(rec_dir)?;
    let baseline = read_versioned_manifest_strict(rec_dir, version)?;
    if typed_record_format(&meta) {
        let baseline_bytes = read_regular_nofollow(&rec_dir.join(format!("manifest@{version}")))?;
        if meta.get("MANIFEST_BASELINE_SHA256") != Some(&sha256_bytes(&baseline_bytes)) {
            bail!("{name}: hash do baseline provisional não confere");
        }
    }
    let active_lines: Vec<&str> = active.iter().map(String::as_str).collect();
    let baseline_lines: Vec<&str> = baseline.iter().map(String::as_str).collect();
    let unproved = provisional_unproved_cessions(ctx, name, &active_lines, &baseline_lines, false)?
        .ok_or_else(|| anyhow::anyhow!("{name}: ativo não é subconjunto íntegro do baseline"))?;
    Ok(unproved)
}

fn cessoes_sem_sucessor_ausentes(ctx: &Ctx, rec_dir: &Path, name: &str) -> Result<Vec<String>> {
    let unproved = cessoes_sem_sucessor_do_registro(ctx, rec_dir, name)?;
    for path in &unproved {
        if confined_exists(&ctx.root, path)? {
            bail!(
                "{name}: cessão sem sucessor ainda existe no root em {path}; aposentadoria automática recusada"
            );
        }
    }
    Ok(unproved)
}

/// O que este provisional já cedeu: `baseline - ativo`, como pares
/// (caminho canônico, linha original do baseline).
///
/// Só faz sentido depois de `provisional_cession_state` responder `Intact`, ou
/// dentro do fluxo `Unproved` que filtra as claims aposentáveis antes de usar o
/// resultado. Fora dessas duas fronteiras, um manifesto truncado pareceria uma
/// "cessão", que é exatamente o contrário do que o registro deve fazer.
fn caminhos_cedidos(ctx: &Ctx, rec_dir: &Path, versao: &str) -> Result<Vec<(String, String)>> {
    let ativo = read_manifest_strict(rec_dir)?;
    let baseline = read_versioned_manifest_strict(rec_dir, versao)?;
    let ativos: HashSet<&str> = ativo.iter().map(|l| manifest_path(l)).collect();
    let mut saida = Vec::new();
    for linha in &baseline {
        let caminho = manifest_path(linha);
        if !ativos.contains(caminho) {
            saida.push((canonical_virtual_path(&ctx.root, caminho)?, linha.clone()));
        }
    }
    saida.sort();
    Ok(saida)
}

fn provisional_cession_state(
    ctx: &Ctx,
    rec_dir: &Path,
    recipe: &Recipe,
) -> Result<ProvisionalCession> {
    let Some(meta) = read_meta_strict(rec_dir)? else {
        return Ok(ProvisionalCession::NotCeded);
    };
    ensure_supported_record_format(&meta, &recipe.name)?;
    if meta.get("NAME") != Some(&recipe.name)
        || meta.get("PROVISIONAL").map(String::as_str) != Some("1")
    {
        return Ok(ProvisionalCession::NotCeded);
    }
    let expected_kind = record_kind(recipe.kind);
    let expected_world = record_world(recipe.kind);
    // A receita corrente pode legitimamente ter outra VERSION: esse e
    // justamente o upgrade que precisa reconhecer a cessao antes de
    // reconstruir. A autoridade sobre o estado instalado e VERSION do meta,
    // abaixo validada e usada para abrir manifest@VERSION/recipe@VERSION; usar
    // `recipe.version` aqui confundiria "upgrade pendente" com corrupcao.
    if !recipe.provisional
        || meta.get("KIND").map(String::as_str) != Some(expected_kind)
        || meta.get("WORLD").map(String::as_str) != Some(expected_world)
    {
        return Ok(ProvisionalCession::Incoherent);
    }
    let Some(version) = meta.get("VERSION") else {
        return Ok(ProvisionalCession::Incoherent);
    };
    recipe::validate_version(&recipe.name, version)?;

    let active = read_manifest_strict(rec_dir)?;
    let baseline = read_versioned_manifest_strict(rec_dir, version)?;
    if typed_record_format(&meta) {
        let baseline_bytes = read_regular_nofollow(&rec_dir.join(format!("manifest@{version}")))?;
        let baseline_hash = sha256_bytes(&baseline_bytes);
        if meta.get("MANIFEST_BASELINE_SHA256") != Some(&baseline_hash) {
            return Ok(ProvisionalCession::Incoherent);
        }
    }
    let active_lines: Vec<&str> = active.iter().map(String::as_str).collect();
    let baseline_lines: Vec<&str> = baseline.iter().map(String::as_str).collect();
    if active.len() > baseline.len() {
        return Ok(ProvisionalCession::Incoherent);
    }
    if active.len() == baseline.len() {
        return Ok(
            if provisional_manifest_coherent(
                ctx,
                &recipe.name,
                &active_lines,
                &baseline_lines,
                false,
            )? {
                ProvisionalCession::NotCeded
            } else {
                ProvisionalCession::Incoherent
            },
        );
    }
    let unproved = match provisional_unproved_cessions(
        ctx,
        &recipe.name,
        &active_lines,
        &baseline_lines,
        true,
    )? {
        Some(unproved) => unproved,
        None => return Ok(ProvisionalCession::Incoherent),
    };
    for line in &active {
        let path = manifest_path(line);
        match confined_claim_matches(line, &ctx.root, path)? {
            Some(true) => {}
            Some(false) => return Ok(ProvisionalCession::Incoherent),
            None if confined_exists(&ctx.root, path)? => {}
            None => return Ok(ProvisionalCession::Incoherent),
        }
    }

    let historical = [
        rec_dir.join("recipe"),
        rec_dir.join(format!("recipe@{version}")),
    ];
    if historical.iter().any(|path| {
        !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
    }) {
        return Ok(ProvisionalCession::Incoherent);
    }
    let Ok(current_recipe) = read_regular_nofollow(&historical[0]) else {
        return Ok(ProvisionalCession::Incoherent);
    };
    let Ok(versioned_recipe) = read_regular_nofollow(&historical[1]) else {
        return Ok(ProvisionalCession::Incoherent);
    };
    if current_recipe != versioned_recipe {
        return Ok(ProvisionalCession::Incoherent);
    }

    Ok(if unproved.is_empty() {
        ProvisionalCession::Intact
    } else {
        ProvisionalCession::Unproved
    })
}

/// Valor de integridade do manifesto tipado:
///
/// - `f:<sha256>`: modo + conteúdo de arquivo regular;
/// - `l:<sha256>`: bytes crus do alvo de symlink;
/// - `d:<sha256>`: modo do diretório-raiz + tar canônico do conteúdo.
/// - `D:<sha256>`: somente tipo diretório + modo; o conteúdo é um ponto de
///   depósito compartilhado e continua pertencendo às claims dos produtores.
///
/// O prefixo prende também o tipo. Assim trocar link por arquivo, retargetar um
/// link ou adulterar o payload sob `/opt/<pkg>/<versão>` invalida o fast path.
#[cfg(test)]
fn path_integrity(path: &Path) -> Result<String> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_file() {
        let hash = file_hash(path);
        if hash == "-" {
            bail!("não consegui hashear arquivo regular {}", path.display());
        }
        Ok(format!(
            "f:{}",
            regular_integrity(md.permissions().mode() & 0o7777, &hash)
        ))
    } else if md.file_type().is_symlink() {
        let mut h = Sha256::new();
        h.update(fs::read_link(path)?.as_os_str().as_bytes());
        Ok(format!("l:{}", hex::encode(h.finalize())))
    } else if md.file_type().is_dir() {
        let tree_hash = crate::pack::pack_deterministic(path, 0, std::io::sink())?;
        Ok(format!("d:{}", directory_integrity(&md, &tree_hash)))
    } else {
        bail!("tipo especial não registrável: {}", path.display())
    }
}

fn directory_integrity(metadata: &fs::Metadata, tree_hash: &str) -> String {
    directory_integrity_mode(metadata.permissions().mode() & 0o7777, tree_hash)
}

pub(crate) fn regular_integrity(mode: u32, content_hash: &str) -> String {
    regular_integrity_xattr(mode, content_hash, &[])
}

/// Integridade de um regular incluindo seus xattrs (`pack` v2).
///
/// Sem xattr o hash é **idêntico** ao de antes: nenhum registro já gravado
/// migra, e só o arquivo que de fato carrega capability ganha claim nova. É o
/// que faz o `verify` acusar quem arrancar o `security.capability` de um
/// `dumpcap` — antes isso passava batido, porque a claim prendia só modo e
/// conteúdo.
pub(crate) fn regular_integrity_xattr(
    mode: u32,
    content_hash: &str,
    xattrs: &[(String, Vec<u8>)],
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"minitrue-regular-integrity-v2\0");
    hash.update((mode & 0o7777).to_be_bytes());
    hash.update(content_hash.as_bytes());
    if !xattrs.is_empty() {
        hash.update(b"minitrue-xattr-v1\0");
        for (name, value) in xattrs {
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name.as_bytes());
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }
    hex::encode(hash.finalize())
}

fn directory_integrity_mode(mode: u32, tree_hash: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"minitrue-directory-integrity-v1\0");
    hash.update((mode & 0o7777).to_be_bytes());
    hash.update(tree_hash.as_bytes());
    hex::encode(hash.finalize())
}

fn shared_directory_integrity_mode(mode: u32) -> String {
    let mut hash = Sha256::new();
    hash.update(b"minitrue-shared-directory-integrity-v1\0");
    hash.update((mode & 0o7777).to_be_bytes());
    hex::encode(hash.finalize())
}

fn canonical_integrity(value: &str) -> bool {
    value.len() == 66
        && matches!(value.as_bytes().first(), Some(b'f' | b'l' | b'd' | b'D'))
        && value.as_bytes().get(1) == Some(&b':')
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn manifest_integrity(line: &str) -> Option<&str> {
    line.split_once("  ")
        .map(|(value, _)| value)
        .filter(|value| canonical_integrity(value))
}

fn validate_manifest_line_syntax(line: &str) -> Result<()> {
    if manifest_integrity(line).is_some() || manifest_hash(line).is_some() {
        return Ok(());
    }
    match line.split_once("  ") {
        None | Some(("-", _)) => Ok(()),
        Some((tag, _)) => bail!("tag de integridade inválida no manifesto: {tag:?}"),
    }
}

fn record_meta_matches(rec_dir: &Path, meta: &HashMap<String, String>, recipe: &Recipe) -> bool {
    let expected_kind = record_kind(recipe.kind);
    let expected_world = record_world(recipe.kind);
    let field = |name: &str| meta.get(name).map(String::as_str);
    let channel_origin = field("ORIGIN").and_then(|origin| origin.strip_prefix("canal:"));
    let origin_matches = match recipe.kind {
        Kind::Binary => field("ORIGIN") == Some("vendor") && channel_origin.is_none(),
        Kind::Source if field("ORIGIN") == Some("fonte") => [
            "TRUST",
            "CHANNEL_PATH",
            "CHANNEL_SHA256",
            "CHANNEL_INDEX_SHA256",
            "CHANNEL_INDEX_FORMAT",
            "CHANNEL_RELEASE_ROOT",
            "CHANNEL_PRODUCER_PLAN_LOCK_SHA256",
            "CHANNEL_LOCK_SHA256",
        ]
        .iter()
        .all(|name| field(name).is_none()),
        Kind::Source => channel_origin.is_some_and(|channel| {
            recipe::validate_name(channel).is_ok()
                && matches!(field("TRUST"), Some("oficial" | "corroborado" | "builder"))
                && field("CHANNEL_PATH")
                    .is_some_and(|path| channel::validate_artifact_path(channel, path).is_ok())
                && [
                    "CHANNEL_SHA256",
                    "CHANNEL_INDEX_SHA256",
                    "CHANNEL_LOCK_SHA256",
                ]
                .iter()
                .all(|name| {
                    field(name).is_some_and(|hash| {
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                })
                && match (
                    field("CHANNEL_INDEX_FORMAT"),
                    field("CHANNEL_RELEASE_ROOT"),
                    field("CHANNEL_PRODUCER_PLAN_LOCK_SHA256"),
                ) {
                    (Some("4"), Some("yes" | "no"), Some(hash)) => canonical_sha256(hash),
                    (Some("3"), Some("no"), Some(hash)) => {
                        field("TRUST") == Some("builder") && canonical_sha256(hash)
                    }
                    (Some("2"), Some("no"), Some("-")) => field("TRUST") == Some("builder"),
                    _ => false,
                }
        }),
        Kind::Meta => {
            field("ORIGIN") == Some("meta")
                && channel_origin.is_none()
                && [
                    "TRUST",
                    "CHANNEL_PATH",
                    "CHANNEL_SHA256",
                    "CHANNEL_INDEX_SHA256",
                    "CHANNEL_INDEX_FORMAT",
                    "CHANNEL_RELEASE_ROOT",
                    "CHANNEL_PRODUCER_PLAN_LOCK_SHA256",
                    "CHANNEL_LOCK_SHA256",
                ]
                .iter()
                .all(|name| field(name).is_none())
        }
    };
    if !matches!(
        field("RECORD_FORMAT"),
        Some(RECORD_FORMAT | FINAL_RECORD_FORMAT)
    ) || field("NAME") != Some(recipe.name.as_str())
        || field("VERSION") != Some(recipe.version.as_str())
        || field("KIND") != Some(expected_kind)
        || field("WORLD") != Some(expected_world)
        || !origin_matches
        || field("SHA256") != Some(recipe.sha256.join(" ").as_str())
        || field("DEPS") != Some(recipe.deps.join(" ").as_str())
        || field("SHARED_DIRS") != Some(recipe.shared_dirs.join(" ").as_str())
        || field("SUPERSEDES") != Some(recipe.supersedes.join(" ").as_str())
        || match recipe.kind {
            Kind::Binary | Kind::Source => {
                license_of(rec_dir, meta).as_deref() != recipe.license.as_deref()
            }
            Kind::Meta => field("LICENSE").is_some() || recipe.license.is_some(),
        }
        || field("INSTALLED_AT").is_none_or(str::is_empty)
        || !field("MANIFEST_BASELINE_SHA256").is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || (if recipe.about.is_empty() {
            field("ABOUT").is_some()
        } else {
            field("ABOUT") != Some(recipe.about.as_str())
        })
        || field("REPROCORR") != recipe.reprocorr.as_deref()
        || (if recipe.provisional {
            field("PROVISIONAL") != Some("1")
        } else {
            field("PROVISIONAL").is_some()
        })
        || match recipe.kind {
            Kind::Source => field("TRANSACTION_ID").is_none_or(str::is_empty),
            // Migrações legadas do mundo A podem carregar um txid factual;
            // um valor vazio nunca é válido. Mundo M não usa Journal.
            Kind::Binary => field("TRANSACTION_ID").is_some_and(str::is_empty),
            Kind::Meta => field("TRANSACTION_ID").is_some(),
        }
    {
        return false;
    }
    match recipe.kind {
        Kind::Source => field("ARTIFACT_HASH").is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && recipe
                    .reprocorr
                    .as_deref()
                    .is_none_or(|pinned| pinned == hash)
        }),
        Kind::Binary | Kind::Meta => field("ARTIFACT_HASH").is_none(),
    }
}

/// A idempotência só é verdadeira para um registro corrente completo: receita
/// histórica e cópias versionadas precisam ser os snapshots atuais, e cada
/// claim precisa conservar conteúdo, tipo e (para links) alvo. Num provisional,
/// `manifest@` é o baseline instalado e o manifesto ativo pode ser um subconjunto
/// após cessões declaradas; nos demais eles precisam ser idênticos.
fn record_is_intact_with_intermediate(
    ctx: &Ctx,
    rec_dir: &Path,
    recipe: &Recipe,
    allow_intermediate: bool,
) -> bool {
    let meta = match read_meta_strict(rec_dir) {
        Ok(Some(meta)) => meta,
        _ => return false,
    };
    if meta.get("RECORD_FORMAT").map(String::as_str) == Some(RECORD_FORMAT) && !allow_intermediate {
        return false;
    }
    let matches_identity = if meta.get("RECORD_FORMAT").map(String::as_str)
        == Some(PREVIOUS_TYPED_RECORD_FORMAT)
        && recipe.shared_dirs.is_empty()
    {
        let mut normalized = meta.clone();
        normalized.insert("RECORD_FORMAT".into(), RECORD_FORMAT.into());
        normalized.insert("SHARED_DIRS".into(), String::new());
        record_meta_matches(rec_dir, &normalized, recipe)
    } else if meta.get("RECORD_FORMAT").map(String::as_str) == Some(FINAL_RECORD_FORMAT) {
        let mut normalized = meta.clone();
        normalized.insert("RECORD_FORMAT".into(), RECORD_FORMAT.into());
        record_meta_matches(rec_dir, &normalized, recipe)
    } else {
        record_meta_matches(rec_dir, &meta, recipe)
    };
    if !matches_identity {
        return false;
    }
    let shared_roots = match recorded_shared_roots(ctx, &meta, &recipe.name) {
        Ok(roots) => roots,
        Err(_) => return false,
    };
    if verify_channel_provenance(ctx, &meta).is_err() {
        return false;
    }
    if crate::plan::verify_record_binding(ctx, rec_dir, &meta).is_err() {
        return false;
    }
    let version = match meta.get("VERSION") {
        Some(version) => version,
        None => return false,
    };
    let recipe_paths = [
        rec_dir.join("recipe"),
        rec_dir.join(format!("recipe@{version}")),
    ];
    if recipe_paths.iter().any(|path| {
        !fs::symlink_metadata(path).is_ok_and(|md| md.file_type().is_file())
            || read_regular_nofollow(path).ok().as_deref() != Some(recipe.recipe_bytes.as_slice())
    }) {
        return false;
    }

    let manifest_path_versioned = rec_dir.join(format!("manifest@{version}"));
    let manifest_bytes = match read_regular_nofollow(&rec_dir.join("manifest")) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return false,
    };
    let manifest = match String::from_utf8(manifest_bytes) {
        Ok(manifest) => manifest,
        Err(_) => return false,
    };
    let versioned = match read_regular_text_nofollow(&manifest_path_versioned) {
        Ok(versioned) => versioned,
        Err(_) => return false,
    };
    if recipe.kind == Kind::Meta && (manifest != "\n" || versioned != "\n") {
        return false;
    }
    let baseline_hash = sha256_bytes(versioned.as_bytes());
    if meta.get("MANIFEST_BASELINE_SHA256") != Some(&baseline_hash) {
        return false;
    }
    let lines: Vec<&str> = manifest.lines().filter(|line| !line.is_empty()).collect();
    let versioned_lines: Vec<&str> = versioned.lines().filter(|line| !line.is_empty()).collect();
    let manifests_coherent = if recipe.provisional {
        provisional_manifest_coherent(ctx, &recipe.name, &lines, &versioned_lines, false)
            .unwrap_or(false)
    } else {
        manifest.as_bytes() == versioned.as_bytes()
            && lines.iter().copied().collect::<HashSet<_>>().len() == lines.len()
    };
    manifests_coherent
        && versioned_lines.iter().all(|line| {
            validate_manifest_line_for_record(&meta, &recipe.name, line).is_ok()
                && (!manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:"))
                    || canonical_virtual_path(&ctx.root, manifest_path(line))
                        .is_ok_and(|path| path_is_shared(&path, &shared_roots)))
        })
        && (recipe.kind == Kind::Meta || recipe.provisional || !lines.is_empty())
        && (recipe.kind != Kind::Meta || lines.is_empty())
        && lines.iter().all(|line| {
            if validate_manifest_line_for_record(&meta, &recipe.name, line).is_err() {
                return false;
            }
            let path = manifest_path(line);
            if manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:"))
                && canonical_virtual_path(&ctx.root, path)
                    .is_ok_and(|path| !path_is_shared(&path, &shared_roots))
            {
                return false;
            }
            rooted_path(&ctx.root, path)
                .and_then(|_| confined_claim_matches(line, &ctx.root, path))
                .is_ok_and(|matches| matches == Some(true))
        })
}

/// Fast paths e consumidores de uma nova operação só aceitam v4. O plano pode
/// reabrir um v3 para auditá-lo/promovê-lo, mas isso é uma fronteira explícita.
pub(crate) fn record_is_intact(ctx: &Ctx, rec_dir: &Path, recipe: &Recipe) -> bool {
    record_is_intact_with_intermediate(ctx, rec_dir, recipe, false)
}

fn record_is_intact_for_plan(
    ctx: &Ctx,
    rec_dir: &Path,
    recipe: &Recipe,
    allow_intermediate: bool,
) -> bool {
    record_is_intact_with_intermediate(ctx, rec_dir, recipe, allow_intermediate)
}

/// Prova um record pela sua própria identidade histórica. É a fronteira do
/// `plan --sync`: uma recipe removida da árvore atual continua podendo ser
/// classificada como `unreachable`, mas corrupção nunca vira omissão silenciosa.
pub(crate) fn verify_historical_record(
    ctx: &Ctx,
    rec_dir: &Path,
    expected_name: &str,
) -> Result<String> {
    Ok(verify_historical_record_snapshot(ctx, rec_dir, expected_name)?.0)
}

fn verify_historical_record_snapshot(
    ctx: &Ctx,
    rec_dir: &Path,
    expected_name: &str,
) -> Result<(String, HashMap<String, String>, String)> {
    recipe::validate_name(expected_name)?;
    let snapshot = HistoricalRecordSnapshot::capture(rec_dir, expected_name)?;
    let meta = snapshot.meta.clone();
    ensure_supported_record_format(&meta, expected_name)?;
    let field = |name: &str| meta.get(name).map(String::as_str);
    if field("NAME") != Some(expected_name) {
        bail!("record histórico diverge do nome do diretório");
    }
    let version = field("VERSION").ok_or_else(|| anyhow::anyhow!("record sem VERSION"))?;
    recipe::validate_version(expected_name, version)?;
    let canonical_hash = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !field("FINGERPRINT").is_some_and(canonical_hash)
        || !field("MANIFEST_BASELINE_SHA256").is_some_and(canonical_hash)
        || field("INSTALLED_AT").is_none_or(str::is_empty)
        || field("DEPS").is_none()
        || (matches!(
            field("RECORD_FORMAT"),
            Some(RECORD_FORMAT | FINAL_RECORD_FORMAT)
        ) && field("SHARED_DIRS").is_none())
    {
        bail!("record histórico não possui identidade tipada completa");
    }
    for dependency in field("DEPS").unwrap_or_default().split_whitespace() {
        recipe::validate_name(dependency)?;
    }
    for hash in field("SHA256").unwrap_or_default().split_whitespace() {
        if !canonical_hash(hash) {
            bail!("record histórico contém SHA256 não canônico");
        }
    }
    let channel_origin = field("ORIGIN").and_then(|origin| origin.strip_prefix("canal:"));
    let kind = field("KIND").ok_or_else(|| anyhow::anyhow!("record sem KIND"))?;
    let coherent_identity = match kind {
        "binary" => {
            field("WORLD") == Some("A")
                && field("ORIGIN") == Some("vendor")
                && field("LICENSE").is_some_and(|value| !value.is_empty())
                && field("ARTIFACT_HASH").is_none()
        }
        "source" => {
            field("WORLD") == Some("B")
                && (field("ORIGIN") == Some("fonte") || channel_origin.is_some())
                && field("LICENSE").is_some_and(|value| !value.is_empty())
                && field("ARTIFACT_HASH").is_some_and(canonical_hash)
                && field("TRANSACTION_ID").is_some_and(|value| !value.is_empty())
        }
        "meta" => {
            field("WORLD") == Some("M")
                && field("ORIGIN") == Some("meta")
                && field("LICENSE").is_none()
                && field("ARTIFACT_HASH").is_none()
                && field("TRANSACTION_ID").is_none()
        }
        _ => false,
    };
    if !coherent_identity {
        bail!("record histórico tem KIND/WORLD/ORIGIN incoerente");
    }
    let shared_roots = recorded_shared_roots(ctx, &meta, expected_name)?;
    verify_channel_provenance(ctx, &meta)?;
    crate::plan::verify_record_binding(ctx, rec_dir, &meta)?;

    let current_recipe = &snapshot.current_recipe.bytes;
    let versioned_recipe = &snapshot.versioned_recipe.bytes;
    if current_recipe.is_empty() || current_recipe != versioned_recipe {
        bail!("snapshots históricos da recipe divergem");
    }
    let manifest_bytes = &snapshot.manifest.bytes;
    let baseline_bytes = &snapshot.baseline.bytes;
    if meta.get("MANIFEST_BASELINE_SHA256") != Some(&sha256_bytes(baseline_bytes)) {
        bail!("baseline histórico diverge do hash do meta");
    }
    let manifest = std::str::from_utf8(manifest_bytes).context("manifest não é UTF-8")?;
    let baseline = std::str::from_utf8(baseline_bytes).context("baseline não é UTF-8")?;
    let active: Vec<&str> = manifest.lines().filter(|line| !line.is_empty()).collect();
    let historical: Vec<&str> = baseline.lines().filter(|line| !line.is_empty()).collect();
    let provisional = field("PROVISIONAL") == Some("1");
    if field("PROVISIONAL").is_some_and(|value| value != "1") {
        bail!("PROVISIONAL histórico não canônico");
    }
    let coherent_manifests = if kind == "meta" {
        manifest_bytes == b"\n" && baseline_bytes == b"\n"
    } else if provisional {
        provisional_manifest_coherent(ctx, expected_name, &active, &historical, false)?
    } else {
        !active.is_empty()
            && manifest_bytes == baseline_bytes
            && active.iter().copied().collect::<HashSet<_>>().len() == active.len()
    };
    if !coherent_manifests {
        bail!("manifestos históricos não são coerentes");
    }
    for line in &historical {
        validate_manifest_line_for_record(&meta, expected_name, line)?;
        if manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:")) {
            let path = canonical_virtual_path(&ctx.root, manifest_path(line))?;
            if !path_is_shared(&path, &shared_roots) {
                bail!("claim D: histórica está fora de SHARED_DIRS");
            }
        }
    }
    for line in &active {
        validate_manifest_line_for_record(&meta, expected_name, line)?;
        let path = manifest_path(line);
        let canonical = canonical_virtual_path(&ctx.root, path)?;
        if manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:"))
            && !path_is_shared(&canonical, &shared_roots)
        {
            bail!("claim D: ativa está fora de SHARED_DIRS");
        }
        rooted_path(&ctx.root, path)?;
        if confined_claim_matches(line, &ctx.root, path)? != Some(true) {
            bail!("claim ativa do record histórico não confere");
        }
    }
    snapshot.revalidate()?;
    let meta_bytes = &snapshot.meta_file.bytes;
    let mut digest = Sha256::new();
    digest.update(b"MINITRUE_RECORD_FACT_FORMAT=1\0");
    for component in [
        expected_name.as_bytes(),
        meta_bytes.as_slice(),
        current_recipe.as_slice(),
        versioned_recipe.as_slice(),
        manifest_bytes.as_slice(),
        baseline_bytes.as_slice(),
    ] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component);
    }
    Ok((
        hex::encode(digest.finalize()),
        meta,
        sha256_bytes(manifest_bytes),
    ))
}

/// Promove um registro tipado v2 para v3 sem reconstruir payload nem alterar
/// manifesto. O v2 não conhece `D:`; portanto validar integralmente as claims
/// antigas e trocar apenas a marca de formato é uma migração sem perda. Meta
/// de canal é preservado byte a byte (salvo FORMAT/TXID), inclusive as provas
/// de proveniência que `write_record` não poderia reconstruir sem a Selection.
fn migrate_v2_record(
    ctx: &Ctx,
    rec_dir: &Path,
    recipe: &Recipe,
    fingerprint: &str,
    meta: &HashMap<String, String>,
) -> Result<bool> {
    if !recipe.shared_dirs.is_empty() {
        // Um registro v2 nunca emitiu D:. Ativar uma declaração que já
        // estivesse textual na receita antiga exige reaplicar o STAGE.
        return Ok(false);
    }
    let mut normalized = meta.clone();
    normalized.insert("RECORD_FORMAT".into(), RECORD_FORMAT.into());
    normalized.insert("SHARED_DIRS".into(), String::new());
    if meta.get("VERSION") != Some(&recipe.version)
        || meta.get("FINGERPRINT").map(String::as_str) != Some(fingerprint)
        || !record_meta_matches(rec_dir, &normalized, recipe)
        || verify_channel_provenance(ctx, meta).is_err()
    {
        return Ok(false);
    }
    let version = &recipe.version;
    let active_bytes = read_regular_nofollow(&rec_dir.join("manifest"))?;
    let baseline_bytes = read_regular_nofollow(&rec_dir.join(format!("manifest@{version}")))?;
    if active_bytes.is_empty()
        || baseline_bytes.is_empty()
        || meta.get("MANIFEST_BASELINE_SHA256") != Some(&sha256_bytes(&baseline_bytes))
    {
        return Ok(false);
    }
    let active_text = match std::str::from_utf8(&active_bytes) {
        Ok(text) => text,
        Err(_) => return Ok(false),
    };
    let baseline_text = match std::str::from_utf8(&baseline_bytes) {
        Ok(text) => text,
        Err(_) => return Ok(false),
    };
    let active: Vec<&str> = active_text
        .lines()
        .filter(|line| !line.is_empty())
        .collect();
    let baseline: Vec<&str> = baseline_text
        .lines()
        .filter(|line| !line.is_empty())
        .collect();
    if active
        .iter()
        .chain(&baseline)
        .any(|line| validate_manifest_line_for_record(meta, &recipe.name, line).is_err())
    {
        return Ok(false);
    }
    let is_meta = recipe.kind == Kind::Meta;
    let coherent = if is_meta {
        active_bytes == b"\n" && baseline_bytes == b"\n"
    } else if recipe.provisional {
        provisional_manifest_coherent(ctx, &recipe.name, &active, &baseline, false)?
    } else {
        !active.is_empty() && active_bytes == baseline_bytes
    };
    if !coherent {
        return Ok(false);
    }
    for line in &active {
        let path = manifest_path(line);
        if rooted_path(&ctx.root, path).is_err()
            || confined_claim_matches(line, &ctx.root, path)? != Some(true)
        {
            return Ok(false);
        }
    }

    let raw_meta = read_regular_text_nofollow(&rec_dir.join("meta"))?;
    let rewrite = |txid: Option<&str>| -> Result<Vec<u8>> {
        let mut lines = Vec::new();
        let mut saw_format = false;
        let mut saw_txid = false;
        let mut saw_shared_dirs = false;
        for line in raw_meta.lines() {
            if line == "RECORD_FORMAT=2" {
                lines.push(format!("RECORD_FORMAT={RECORD_FORMAT}"));
                saw_format = true;
            } else if line.starts_with("TRANSACTION_ID=") {
                saw_txid = true;
                if let Some(txid) = txid {
                    lines.push(format!("TRANSACTION_ID={txid}"));
                } else {
                    lines.push(line.to_string());
                }
            } else if line.starts_with("SHARED_DIRS=") {
                saw_shared_dirs = true;
                lines.push("SHARED_DIRS=".to_string());
            } else {
                lines.push(line.to_string());
            }
        }
        if !saw_format {
            bail!("{}: meta v2 não contém marcador canônico", recipe.name);
        }
        if !saw_shared_dirs {
            lines.push("SHARED_DIRS=".to_string());
        }
        if let Some(txid) = txid.filter(|_| !saw_txid) {
            lines.push(format!("TRANSACTION_ID={txid}"));
        }
        Ok((lines.join("\n") + "\n").into_bytes())
    };

    if is_meta {
        write_atomic(&rec_dir.join("meta"), &rewrite(None)?)?;
    } else {
        let mut journal = Journal::begin(ctx, &recipe.name)?;
        let bytes = rewrite(Some(&journal.txid))?;
        if let Err(error) = journal.place_bytes(&rec_dir.join("meta"), &bytes) {
            if let Err(rollback) = journal.rollback() {
                return Err(anyhow::anyhow!(
                    "migração v2 falhou: {error}; rollback também falhou: {rollback}"
                ));
            }
            return Err(error);
        }
        journal.commit()?;
    }
    eprintln!(
        "  registro tipado de {} migrado de RECORD_FORMAT=2 para {RECORD_FORMAT}",
        recipe.name
    );
    Ok(true)
}

/// Migração in-place do registro v0/v1 para o formato corrente, sem reinstalar o payload. É
/// essencial para provisionals que já cederam claims: reconstruí-los tentaria
/// tomar de volta arquivos hoje pertencentes aos sucessores e produziria
/// doublethink. A migração só ocorre quando identidade e snapshot da receita já
/// coincidem; provas v1 existentes precisam conferir. Claims legadas sem prova
/// viram baseline v2 do estado atual — não piora a confiança que o esquema
/// antigo oferecia e passa a detectar mudanças futuras.
fn migrate_legacy_record(
    ctx: &Ctx,
    rec_dir: &Path,
    recipe: &Recipe,
    fingerprint: &str,
) -> Result<bool> {
    let meta = match read_meta_strict(rec_dir)? {
        Some(meta) => meta,
        None => return Ok(false),
    };
    ensure_supported_record_format(&meta, &recipe.name)?;
    match meta.get("RECORD_FORMAT").map(String::as_str) {
        Some(RECORD_FORMAT | FINAL_RECORD_FORMAT) => return Ok(false),
        Some(PREVIOUS_TYPED_RECORD_FORMAT) => {
            return migrate_v2_record(ctx, rec_dir, recipe, fingerprint, &meta)
        }
        None | Some("0" | "1") => {}
        Some(_) => unreachable!("ensure_supported_record_format filtrou o valor"),
    }
    if !recipe.shared_dirs.is_empty() {
        return Ok(false);
    }
    if meta.get("VERSION") != Some(&recipe.version)
        || meta.get("FINGERPRINT").map(String::as_str) != Some(fingerprint)
        || !fs::symlink_metadata(rec_dir.join("recipe"))
            .is_ok_and(|metadata| metadata.file_type().is_file())
        || read_regular_nofollow(&rec_dir.join("recipe"))
            .ok()
            .as_deref()
            != Some(recipe.recipe_bytes.as_slice())
        || !fs::symlink_metadata(rec_dir.join(format!("recipe@{}", recipe.version)))
            .is_ok_and(|metadata| metadata.file_type().is_file())
        || read_regular_nofollow(&rec_dir.join(format!("recipe@{}", recipe.version)))
            .ok()
            .as_deref()
            != Some(recipe.recipe_bytes.as_slice())
    {
        return Ok(false);
    }

    let old_manifest = read_manifest_strict(rec_dir)?;
    if old_manifest.is_empty() && meta.get("PROVISIONAL").map(String::as_str) != Some("1") {
        return Ok(false);
    }
    let baseline = match read_versioned_manifest_strict(rec_dir, &recipe.version) {
        Ok(baseline) => baseline,
        Err(_) => return Ok(false),
    };
    if meta.get("PROVISIONAL").map(String::as_str) == Some("1") {
        let active_lines: Vec<&str> = old_manifest.iter().map(String::as_str).collect();
        let baseline_lines: Vec<&str> = baseline.iter().map(String::as_str).collect();
        if !provisional_manifest_coherent(ctx, &recipe.name, &active_lines, &baseline_lines, false)?
            || active_lines.len() != baseline_lines.len()
        {
            // Não achata a história de uma cessão (nem truncamento). O fast
            // path congelado preserva uma cessão provada; o resto reconstrói.
            return Ok(false);
        }
    } else if old_manifest != baseline {
        return Ok(false);
    }
    let mut paths = Vec::with_capacity(old_manifest.len());
    for line in &old_manifest {
        let virt = manifest_path(line);
        rooted_path(&ctx.root, virt)?;
        match confined_claim_matches(line, &ctx.root, virt)? {
            Some(true) => {}
            Some(false) => return Ok(false),
            None if confined_exists(&ctx.root, virt)? => {}
            None => return Ok(false),
        }
        paths.push(virt.to_string());
    }

    let world = match meta.get("WORLD").map(String::as_str) {
        Some("A") => "A",
        Some("B") => "B",
        _ => return Ok(false),
    };
    let artifact_hash = meta.get("ARTIFACT_HASH").map(String::as_str);
    let mut journal = Journal::begin(ctx, &recipe.name)?;
    if let Err(error) = write_record(
        ctx,
        rec_dir,
        recipe,
        world,
        &mut paths,
        RecordWrite {
            artifact_hash,
            fingerprint,
            manifest_typed: false,
            source_origin: SourceRecordOrigin::Local,
            journal: Some(&mut journal),
            baseline_extra: None,
        },
    ) {
        if let Err(rollback) = journal.rollback() {
            return Err(anyhow::anyhow!(
                "migração do registro falhou: {error}; rollback também falhou: {rollback}"
            ));
        }
        return Err(error);
    }
    journal.commit()?;
    eprintln!(
        "  registro legado de {} migrado para RECORD_FORMAT={RECORD_FORMAT}",
        recipe.name
    );
    Ok(true)
}

/// O caminho de uma linha de manifesto. Registro **v1**: `<sha256>␠␠<caminho>`;
/// legado v0 (linha sem os dois espaços): a própria linha. Retrocompatível.
pub(crate) fn manifest_path(line: &str) -> &str {
    line.split_once("  ").map(|(_, p)| p).unwrap_or(line)
}

/// Resolve um caminho virtual de manifesto sem permitir `..`, caminho relativo
/// ou controles. Registros são estado persistente e podem estar truncados ou
/// adulterados; nenhuma rotina de upgrade/memoryhole deve transformar isso em
/// acesso fora do rootfs.
fn rooted_path(root: &Path, virt: &str) -> Result<PathBuf> {
    if virt.chars().any(char::is_control) {
        bail!("caminho de manifesto contém controle: {virt:?}");
    }
    let rel_text = virt
        .strip_prefix("/")
        .ok_or_else(|| anyhow::anyhow!("caminho de manifesto não é absoluto: {virt:?}"))?;
    let rel = Path::new(rel_text);
    if rel_text
        .split('/')
        .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || rel.as_os_str().is_empty()
        || rel
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("caminho de manifesto não é canônico: {virt:?}");
    }
    Ok(root.join(rel))
}

/// Identidade canônica de ownership para uma folha, resolvendo apenas seus
/// ancestrais. Assim `/lib/x` e `/usr/lib/x` são a mesma claim num rootfs com
/// `/lib -> usr/lib`, enquanto o próprio symlink `/lib` continua sendo uma
/// folha distinta e nunca é seguido. Componentes ainda inexistentes são
/// anexados ao ancestral existente mais próximo.
fn canonical_virtual_path(root: &Path, virt: &str) -> Result<String> {
    let path = rooted_path(root, virt)?;
    ensure_mutation_confined(root, &path)?;
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("caminho virtual sem folha: {virt:?}"))?
        .to_os_string();
    let mut ancestor = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("caminho virtual sem pai: {virt:?}"))?
        .to_path_buf();
    let mut missing = Vec::new();
    let mut resolved = loop {
        match fs::symlink_metadata(&ancestor) {
            Ok(_) => break fs::canonicalize(&ancestor)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    anyhow::anyhow!("não encontrei ancestral existente para {virt:?}")
                })?;
                missing.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("caminho escapou do root"))?
                    .to_path_buf();
            }
            Err(error) => return Err(error.into()),
        }
    };
    let root_real = fs::canonicalize(root)?;
    if !resolved.starts_with(&root_real) {
        bail!("{virt:?} resolve para fora do rootfs");
    }
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    resolved.push(leaf);
    let relative = resolved
        .strip_prefix(&root_real)
        .map_err(|_| anyhow::anyhow!("caminho canônico fora do rootfs"))?;
    let text = relative
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("caminho canônico não UTF-8"))?;
    Ok(format!("/{text}"))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

fn path_cstring(path: &OsStr) -> Result<CString> {
    CString::new(path.as_bytes())
        .map_err(|_| anyhow::anyhow!("caminho contém NUL e não pode ser aberto"))
}

fn open_root_fd(root: &Path) -> Result<OwnedFd> {
    let root = path_cstring(root.as_os_str())?;
    // SAFETY: `root` é NUL-terminated; flags não exigem argumento mode.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd >= 0 acabou de ser transferido por `open` e tem dono único.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn openat2_confined(root_fd: &OwnedFd, relative: &Path, flags: i32) -> Result<OwnedFd> {
    let relative = path_cstring(relative.as_os_str())?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: ponteiros apontam para `CString`/`OpenHow` válidos durante a
    // syscall; o tamanho casa exatamente com a estrutura do ABI openat2.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            relative.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd >= 0 acabou de ser transferido por `openat2`.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn confined_relative(virt: &str) -> Result<PathBuf> {
    // Reutiliza toda a validação lexical; o root fictício não é usado depois.
    let checked = rooted_path(Path::new("/"), virt)?;
    checked
        .strip_prefix("/")
        .map(Path::to_path_buf)
        .map_err(|_| anyhow::anyhow!("caminho virtual inválido: {virt:?}"))
}

fn open_confined(root: &Path, virt: &str, flags: i32) -> Result<OwnedFd> {
    let root_fd = open_root_fd(root)?;
    let relative = confined_relative(virt)?;
    openat2_confined(&root_fd, &relative, flags)
}

fn confined_parent(root: &Path, virt: &str) -> Result<(OwnedFd, CString)> {
    let relative = confined_relative(virt)?;
    let name = relative
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("caminho sem nome final: {virt:?}"))?;
    let name = path_cstring(name)?;
    let root_fd = open_root_fd(root)?;
    let parent = match relative.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => openat2_confined(&root_fd, parent, libc::O_PATH | libc::O_DIRECTORY)?,
        None => root_fd,
    };
    Ok((parent, name))
}

fn readlink_confined(root: &Path, virt: &str) -> Result<Vec<u8>> {
    let (parent, name) = confined_parent(root, virt)?;
    let mut capacity = 256usize;
    loop {
        let mut bytes = vec![0u8; capacity];
        // SAFETY: parent/name são descritores/CString válidos e o buffer possui
        // `capacity` bytes graváveis. readlinkat não acrescenta NUL.
        let len = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if len < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let len = len as usize;
        if len < bytes.len() {
            bytes.truncate(len);
            return Ok(bytes);
        }
        capacity = capacity
            .checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("alvo de symlink grande demais"))?;
    }
}

fn hash_reader(mut reader: impl Read) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex::encode(hash.finalize())
}

/// Hash de conteúdo apenas quando a folha confinada continua sendo regular.
/// O primeiro `O_PATH` classifica sem bloquear; a segunda abertura usa
/// `O_NONBLOCK` e revalida o tipo para fechar a corrida entre classificação e
/// leitura. Symlink/FIFO/socket significam “não é o regular esperado”.
fn confined_regular_content_hash(root: &Path, virt: &str) -> Result<Option<String>> {
    let path_fd = match open_confined(root, virt, libc::O_PATH | libc::O_NOFOLLOW) {
        Ok(fd) => fd,
        Err(error) if error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !fs::File::from(path_fd).metadata()?.file_type().is_file() {
        return Ok(None);
    }
    let file_fd = open_confined(
        root,
        virt,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
    let file = fs::File::from(file_fd);
    if !file.metadata()?.file_type().is_file() {
        return Ok(None);
    }
    Ok(Some(hash_reader(file)?))
}

/// Versão confinada de `path_integrity`: todos os symlinks intermediários são
/// resolvidos pelo kernel dentro do fd de `root`. Um link absoluto passa a ser
/// relativo ao rootfs; magic-links de `/proc` são recusados.
fn confined_path_integrity(root: &Path, virt: &str) -> Result<String> {
    let path_fd = open_confined(root, virt, libc::O_PATH | libc::O_NOFOLLOW)?;
    let path_file = fs::File::from(path_fd);
    let metadata = path_file.metadata()?;
    if metadata.file_type().is_file() {
        let file_fd = open_confined(
            root,
            virt,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )?;
        let mut file = fs::File::from(file_fd);
        let before = file.metadata()?;
        if !before.file_type().is_file() || !same_build_snapshot(&metadata, &before) {
            bail!("tipo/identidade de {virt} mudou durante a inspeção");
        }
        let xattrs_before = read_build_xattrs(&file, Path::new(virt))?;
        let content_hash = hash_reader(&mut file)?;
        let after = file.metadata()?;
        let xattrs_after = read_build_xattrs(&file, Path::new(virt))?;
        if !same_build_snapshot(&before, &after) || xattrs_before != xattrs_after {
            bail!("{virt} mudou durante a inspeção de integridade");
        }
        Ok(format!(
            "f:{}",
            regular_integrity_xattr(
                before.permissions().mode() & 0o7777,
                &content_hash,
                &xattrs_before,
            )
        ))
    } else if metadata.file_type().is_symlink() {
        let mut hash = Sha256::new();
        hash.update(readlink_confined(root, virt)?);
        Ok(format!("l:{}", hex::encode(hash.finalize())))
    } else if metadata.file_type().is_dir() {
        let dir_fd = open_confined(
            root,
            virt,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", dir_fd.as_raw_fd()));
        let tree_hash = crate::pack::pack_deterministic(&proc_path, 0, std::io::sink())?;
        Ok(format!("d:{}", directory_integrity(&metadata, &tree_hash)))
    } else {
        bail!("tipo especial não registrável: {virt}")
    }
}

/// Prova uma claim `D:` sem enumerar a árvore. A folha é aberta com
/// `O_NOFOLLOW` e o modo vem do próprio descritor; portanto trocar o caminho
/// por symlink (inclusive durante a inspeção) nunca satisfaz a claim.
fn confined_shared_directory_integrity(root: &Path, virt: &str) -> Result<String> {
    let descriptor = open_confined(
        root,
        virt,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    let metadata = fs::File::from(descriptor).metadata()?;
    if !metadata.file_type().is_dir() {
        bail!("{virt}: deixou de ser diretório durante a inspeção");
    }
    Ok(format!(
        "D:{}",
        shared_directory_integrity_mode(metadata.permissions().mode() & 0o7777)
    ))
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == ErrorKind::NotFound)
}

fn error_is_not_directory(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)))
}

fn confined_claim_matches(line: &str, root: &Path, virt: &str) -> Result<Option<bool>> {
    if let Some(expected) = manifest_integrity(line) {
        if expected.starts_with("D:") {
            return match confined_shared_directory_integrity(root, virt) {
                Ok(actual) => Ok(Some(actual == expected)),
                Err(error) if error_is_not_found(&error) || error_is_not_directory(&error) => {
                    Ok(Some(false))
                }
                Err(error) => Err(error),
            };
        }
        return match confined_path_integrity(root, virt) {
            Ok(actual) => Ok(Some(actual == expected)),
            Err(error) if error_is_not_found(&error) => Ok(Some(false)),
            Err(error) => Err(error),
        };
    }
    if let Some(expected) = manifest_hash(line) {
        return Ok(Some(
            confined_regular_content_hash(root, virt)?.as_deref() == Some(expected),
        ));
    }
    match line.split_once("  ") {
        None | Some(("-", _)) => Ok(None),
        Some((tag, _)) => bail!("tag de integridade inválida no manifesto: {tag:?}"),
    }
}

fn confined_exists(root: &Path, virt: &str) -> Result<bool> {
    match open_confined(root, virt, libc::O_PATH | libc::O_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(error) if error_is_not_found(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Lê todos os regulares de um diretório virtual sem seguir symlinks nem no
/// diretório nem nas entradas. Usado para raízes de confiança e attestations.
pub(crate) fn confined_regular_files(
    root: &Path,
    directory: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let dir_fd = open_confined(
        root,
        directory,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", dir_fd.as_raw_fd()));
    let mut files = Vec::new();
    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("entrada não UTF-8 em {directory}"))?
            .to_string();
        if name.is_empty() || name.contains('/') || name.chars().any(char::is_control) {
            bail!("entrada inválida em {directory}: {name:?}");
        }
        let virt = format!("{directory}/{name}");
        let fd = open_confined(
            root,
            &virt,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )?;
        let mut file = fs::File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            bail!("{virt} não é arquivo regular");
        }
        if metadata.len() > 1024 * 1024 {
            bail!("{virt} excede 1 MiB");
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        files.push((name, bytes));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn unlinkat_checked(parent: &OwnedFd, name: &CString, flags: i32) -> Result<()> {
    // SAFETY: descritor e CString são válidos; unlinkat não retém ponteiros.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error.into())
        }
    }
}

fn remove_dir_contents(dir: &OwnedFd) -> Result<()> {
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    let entries = fs::read_dir(&proc_path)?.collect::<std::io::Result<Vec<_>>>()?;
    for entry in entries {
        let name = path_cstring(&entry.file_name())?;
        // Diretório real: abre sem seguir link, esvazia e remove pelo parent fd.
        // SAFETY: fd/CString válidos; flags não exigem mode.
        let child = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if child >= 0 {
            // SAFETY: fd recém-transferido por openat, com dono único.
            let child = unsafe { OwnedFd::from_raw_fd(child) };
            remove_dir_contents(&child)?;
            unlinkat_checked(dir, &name, libc::AT_REMOVEDIR)?;
        } else {
            // Arquivo ou symlink: unlinkat no diretório já ancorado nunca segue
            // o alvo. Se houve um erro real (ex.: submount), falha fechado.
            unlinkat_checked(dir, &name, 0)?;
        }
    }
    Ok(())
}

fn remove_confined(root: &Path, virt: &str, recursive_directory: bool) -> Result<()> {
    let (parent, name) = match confined_parent(root, virt) {
        Ok(parts) => parts,
        Err(error) if error_is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    if recursive_directory {
        // SAFETY: fd/CString válidos; O_NOFOLLOW impede aceitar symlink final.
        let dir = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error.into());
        }
        // SAFETY: fd recém-transferido por openat, com dono único.
        let dir = unsafe { OwnedFd::from_raw_fd(dir) };
        remove_dir_contents(&dir)?;
        unlinkat_checked(&parent, &name, libc::AT_REMOVEDIR)
    } else {
        unlinkat_checked(&parent, &name, 0)
    }
}

fn remove_empty_confined_dir(root: &Path, virt: &str) -> Result<bool> {
    let (parent, name) = match confined_parent(root, virt) {
        Ok(parts) => parts,
        Err(error) if error_is_not_found(&error) => return Ok(true),
        Err(error) => return Err(error),
    };
    // SAFETY: descritor/CString válidos; AT_REMOVEDIR não segue symlink.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == ErrorKind::NotFound {
        Ok(true)
    } else if matches!(
        error.raw_os_error(),
        Some(libc::ENOTEMPTY) | Some(libc::EEXIST) | Some(libc::ENOTDIR) | Some(libc::ELOOP)
    ) {
        Ok(false)
    } else {
        Err(error.into())
    }
}

/// Hash regular gravado, para mensagens/compatibilidade. Aceita v2 (`f:`) e o
/// v1 histórico de 64 hex; links/diretórios não são hashes de arquivo.
fn manifest_hash(line: &str) -> Option<&str> {
    line.split_once("  ").map(|(h, _)| h).and_then(|h| {
        if let Some(hash) = h.strip_prefix("f:") {
            canonical_integrity(h).then_some(hash)
        } else {
            (h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .then_some(h)
        }
    })
}

/// Confere uma claim persistida. `None` é formato legado sem prova de
/// conteúdo; `Some` é uma prova v1/v2. Tags desconhecidas falham fechado.
#[cfg(test)]
fn manifest_claim_matches(line: &str, path: &Path) -> Result<Option<bool>> {
    if let Some(expected) = manifest_integrity(line) {
        if expected.starts_with("D:") {
            return Ok(Some(
                shared_directory_integrity(path).is_ok_and(|actual| actual == expected),
            ));
        }
        return Ok(Some(
            path_integrity(path).is_ok_and(|actual| actual == expected),
        ));
    }
    if let Some(expected) = manifest_hash(line) {
        return Ok(Some(file_hash(path) == expected));
    }
    match line.split_once("  ") {
        None | Some(("-", _)) => Ok(None),
        Some((tag, _)) => bail!("tag de integridade inválida no manifesto: {tag:?}"),
    }
}

#[cfg(test)]
fn shared_directory_integrity(path: &Path) -> Result<String> {
    let descriptor = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = descriptor.metadata()?;
    Ok(format!(
        "D:{}",
        shared_directory_integrity_mode(metadata.permissions().mode() & 0o7777)
    ))
}

/// sha256 (hex) de um arquivo regular, em streaming; `-` para symlink, diretório
/// ou ausente. É o hash por arquivo do manifesto v1 (SPEC-0003 §6).
#[cfg(test)]
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

type IndexedClaims<'a> = BTreeMap<String, Vec<(&'a str, &'a str)>>;

/// Índice ordenado de ownership. Exato/ancestral custam O(profundidade × log n)
/// e o primeiro descendente custa O(log n), evitando comparar cada entrada de
/// um STAGE grande com todas as claims do sistema.
fn index_manifest_claims<'a>(
    claims: &'a [(String, String, HashSet<String>)],
    exclude_owner: Option<&str>,
) -> IndexedClaims<'a> {
    let mut index = BTreeMap::new();
    for (owner, version, paths) in claims {
        if exclude_owner == Some(owner.as_str()) {
            continue;
        }
        for path in paths {
            index
                .entry(path.clone())
                .or_insert_with(Vec::new)
                .push((owner.as_str(), version.as_str()));
        }
    }
    index
}

/// Índice de claims de diretório para o check de colisão.
///
/// `ceded` são os donos cujos diretórios NÃO bloqueiam: um predecessor
/// PROVISIONAL que esta receita declarou superseder. Sem isso a sucessão fica
/// assimétrica — o `adopt_provisional_path` cede arquivo e link, mas um
/// diretório do cedente barra o sucessor para sempre. Foi o que aconteceu com
/// o python semente, que reivindica `lib-dynload` como árvore justamente por
/// estar VAZIO (não tem módulo de extensão nenhum) e assim impedia o
/// python-glibc, cuja razão de existir é encher esse diretório.
fn index_directory_claims<'a>(
    claims: &'a [(String, String, String)],
    exclude_owner: &str,
    ceded: &std::collections::HashSet<String>,
) -> IndexedClaims<'a> {
    let mut index = BTreeMap::new();
    for (owner, version, path) in claims {
        if owner == exclude_owner || ceded.contains(owner) {
            continue;
        }
        index
            .entry(path.clone())
            .or_insert_with(Vec::new)
            .push((owner.as_str(), version.as_str()));
    }
    index
}

fn indexed_claim_at_or_above<'a, 'b>(
    index: &'b IndexedClaims<'a>,
    path: &str,
    include_exact: bool,
) -> Option<(&'a str, &'a str, &'b str)> {
    let mut candidate = path;
    let mut exact = true;
    loop {
        if !exact || include_exact {
            if let Some((claim, owners)) = index.get_key_value(candidate) {
                if let Some((owner, version)) = owners.first() {
                    return Some((*owner, *version, claim.as_str()));
                }
            }
        }
        let slash = candidate.rfind('/')?;
        if slash == 0 {
            return None;
        }
        candidate = &candidate[..slash];
        exact = false;
    }
}

fn indexed_descendant<'a, 'b>(
    index: &'b IndexedClaims<'a>,
    path: &str,
) -> Option<(&'a str, &'a str, &'b str)> {
    let prefix = format!("{path}/");
    let (claim, owners) = index.range(prefix.clone()..).next()?;
    if !claim.starts_with(&prefix) {
        return None;
    }
    let (owner, version) = owners.first()?;
    Some((*owner, *version, claim.as_str()))
}

fn all_manifests(ctx: &Ctx) -> Result<Vec<(String, String, HashSet<String>)>> {
    all_manifests_for_recovery(ctx, &HashSet::new(), &HashSet::new())
}

/// Claims que possuem conteúdo/namespace exclusivo. `D:` fica deliberadamente
/// fora: ela autoriza descendentes de dependentes e não pode aparecer como se
/// fosse uma claim `d:` da árvore inteira.
fn all_exclusive_manifests(ctx: &Ctx) -> Result<Vec<(String, String, HashSet<String>)>> {
    let mut claims = all_manifests(ctx)?;
    for (owner, _, path) in all_shared_directory_claims(ctx)? {
        if let Some((_, _, paths)) = claims.iter_mut().find(|(name, _, _)| name == &owner) {
            paths.remove(&path);
        }
    }
    Ok(claims)
}

fn record_manifest_claims(
    ctx: &Ctx,
    rec_dir: &Path,
    name: &str,
) -> Result<Option<(String, String, HashSet<String>)>> {
    // Registro sem `meta` = instalação não-commitada (crash entre o manifest e
    // o meta): ignora, para não reivindicar caminhos de pacote meio-instalado.
    let Some(meta) = read_meta_strict(rec_dir)? else {
        return Ok(None);
    };
    ensure_supported_record_format(&meta, name)?;
    let ver = meta.get("VERSION").cloned().unwrap_or_else(|| "?".into());
    let lines = read_manifest_strict(rec_dir)
        .map_err(|error| anyhow::anyhow!("{name}: manifesto instalado ilegível: {error}"))?;
    let shared_roots = recorded_shared_roots(ctx, &meta, name)?;
    for line in &lines {
        validate_manifest_line_for_record(&meta, name, line)?;
        if manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:")) {
            let canonical = canonical_virtual_path(&ctx.root, manifest_path(line))?;
            if !path_is_shared(&canonical, &shared_roots) {
                bail!(
                    "{name}: claim D: fora de SHARED_DIRS gravada: {}",
                    manifest_path(line)
                );
            }
        }
    }
    let set: HashSet<String> = lines
        .iter()
        .map(|line| canonical_virtual_path(&ctx.root, manifest_path(line)))
        .collect::<Result<HashSet<_>>>()?;
    if set.len() != lines.len() {
        bail!("{name}: manifesto contém claims duplicadas");
    }
    Ok(Some((name.to_string(), ver, set)))
}

/// Visão de ownership usada também durante recovery. `excluded` contém o
/// próprio pacote transacional. Para registros que o journal está alterando,
/// um estado intermediário ilegível é tolerado; se já estiver novamente válido
/// (por exemplo, um commit posterior), suas claims continuam sendo consideradas.
fn all_manifests_for_recovery(
    ctx: &Ctx,
    excluded: &HashSet<String>,
    tolerate_intermediate: &HashSet<String>,
) -> Result<Vec<(String, String, HashSet<String>)>> {
    let mut v = Vec::new();
    ensure_real_directory_or_absent(&ctx.root, &ctx.records_dir(), "diretório de registros")?;
    match fs::read_dir(ctx.records_dir()) {
        Ok(entries) => {
            for entry in entries {
                let e = entry?;
                if !e.file_type()?.is_dir() {
                    bail!(
                        "entrada de registro não é diretório real: {}",
                        e.path().display()
                    );
                }
                let name = e
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("registro com nome não UTF-8"))?;
                if excluded.contains(&name) {
                    continue;
                }
                match record_manifest_claims(ctx, &e.path(), &name) {
                    Ok(Some(claims)) => v.push(claims),
                    Ok(None) => {}
                    Err(_) if tolerate_intermediate.contains(&name) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(v)
}

/// Registros antigos também não podem reivindicar nomes que uma execução
/// futura tratará como estado/temporário descartável. Falhar antes do fetch ou
/// do build evita apagar payload legado sem consultar ownership.
fn ensure_no_internal_claims(ctx: &Ctx) -> Result<()> {
    let claims = all_manifests(ctx)?;
    let control_roots = ["/var/lib/minitrue", "/var/cache/minitrue", "/etc/minitrue"]
        .into_iter()
        .map(|path| canonical_virtual_path(&ctx.root, path))
        .collect::<Result<Vec<_>>>()?;
    let tmp_sentinel = canonical_virtual_path(&ctx.root, "/tmp/minitrue-namespace-sentinel")?;
    let tmp_root = Path::new(&tmp_sentinel)
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| anyhow::anyhow!("namespace temporário não canônico"))?;
    let tmp_prefix = format!("{tmp_root}/");

    for (owner, version, paths) in &claims {
        for path in paths {
            let control_overlap = control_roots.iter().any(|control| {
                virtual_at_or_below(path, control) || virtual_at_or_below(control, path)
            });
            let temporary_overlap = path
                .strip_prefix(&tmp_prefix)
                .and_then(|suffix| suffix.split('/').next())
                .is_some_and(|component| {
                    component.starts_with("minitrue-build-")
                        || component.starts_with("minitrue-work-")
                })
                || path == tmp_root;
            if control_overlap || temporary_overlap {
                bail!(
                    "registro {owner} {version} reivindica namespace interno do minitrue: {path}"
                );
            }
        }
    }
    Ok(())
}

fn ensure_paths_unclaimed(ctx: &Ctx, current_owner: &str, paths: &[(&Path, &str)]) -> Result<()> {
    let claims = all_manifests(ctx)?;
    let external = index_manifest_claims(&claims, Some(current_owner));
    for (path, description) in paths {
        journal_path_text(&ctx.root, path)?;
        let relative = path
            .strip_prefix(&ctx.root)
            .map_err(|_| anyhow::anyhow!("workspace fora do rootfs"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("workspace não UTF-8"))?;
        let virt = canonical_virtual_path(&ctx.root, &format!("/{relative}"))?;
        if let Some((owner, version, claim)) = indexed_claim_at_or_above(&external, &virt, true)
            .or_else(|| indexed_descendant(&external, &virt))
        {
            bail!(
                "{description} {virt} sobrepõe claim {claim} de {owner} {version}; limpeza recusada"
            );
        }
    }
    Ok(())
}

fn all_tagged_directory_claims(
    ctx: &Ctx,
    expected_prefix: &str,
) -> Result<Vec<(String, String, String)>> {
    let mut claims = Vec::new();
    ensure_real_directory_or_absent(&ctx.root, &ctx.records_dir(), "diretório de registros")?;
    match fs::read_dir(ctx.records_dir()) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    bail!(
                        "entrada de registro não é diretório real: {}",
                        entry.path().display()
                    );
                }
                let Some(meta) = read_meta_strict(&entry.path())? else {
                    continue;
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                ensure_supported_record_format(&meta, &name)?;
                let version = meta.get("VERSION").cloned().unwrap_or_else(|| "?".into());
                let shared_roots = recorded_shared_roots(ctx, &meta, &name)?;
                for line in read_manifest_strict(&entry.path()).map_err(|error| {
                    anyhow::anyhow!("{name}: manifesto instalado ilegível: {error}")
                })? {
                    validate_manifest_line_for_record(&meta, &name, &line)?;
                    if manifest_integrity(&line).is_some_and(|tag| tag.starts_with(expected_prefix))
                    {
                        let path = manifest_path(&line);
                        let canonical = canonical_virtual_path(&ctx.root, path)?;
                        if expected_prefix == "D:" && !path_is_shared(&canonical, &shared_roots) {
                            bail!("{name}: claim D: fora de SHARED_DIRS gravada: {path}");
                        }
                        claims.push((name.clone(), version.clone(), canonical));
                    }
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(claims)
}

fn all_directory_claims(ctx: &Ctx) -> Result<Vec<(String, String, String)>> {
    all_tagged_directory_claims(ctx, "d:")
}

fn all_shared_directory_claims(ctx: &Ctx) -> Result<Vec<(String, String, String)>> {
    all_tagged_directory_claims(ctx, "D:")
}

fn world_add(ctx: &Ctx, name: &str) -> Result<()> {
    let p = ctx.world_path();
    ensure_mutation_confined(&ctx.root, &p)?;
    let directory = p
        .parent()
        .ok_or_else(|| anyhow::anyhow!("world sem diretório pai"))?;
    ensure_real_directory_or_absent(&ctx.root, directory, "configuração do minitrue")?;
    fs::create_dir_all(directory)?;
    ensure_real_directory_or_absent(&ctx.root, directory, "configuração do minitrue")?;
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
    ensure_mutation_confined(&ctx.root, &p)?;
    let directory = p
        .parent()
        .ok_or_else(|| anyhow::anyhow!("world sem diretório pai"))?;
    ensure_real_directory_or_absent(&ctx.root, directory, "configuração do minitrue")?;
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
        Some("M") => "M — conjunto declarativo sem payload",
        _ => "?",
    }
}

/// De onde veio o artefato (campo `ORIGIN`; canais em SPEC-0009 gravam
/// `canal:<nome>`). Sem `ORIGIN` (registro legado), deriva de `WORLD`.
fn origin_label(meta: &HashMap<String, String>) -> String {
    match meta.get("ORIGIN").map(String::as_str) {
        Some("vendor") => "binário de vendor (upstream)".into(),
        Some("fonte") => "compilado localmente da fonte".into(),
        Some("meta") => "conjunto declarativo local".into(),
        Some(o) if o.starts_with("canal:") => format!("canal binário «{}» (SPEC-0009)", &o[6..]),
        Some(o) => o.to_string(),
        None => match meta.get("WORLD").map(String::as_str) {
            Some("A") => "binário de vendor (upstream)".into(),
            Some("B") => "compilado localmente da fonte".into(),
            Some("M") => "conjunto declarativo local".into(),
            _ => "desconhecida".into(),
        },
    }
}

/// Lê um metadado congelado no registro. Para registros anteriores à adição do
/// campo, aceita apenas uma atribuição comprovadamente literal na cópia da
/// receita — jamais executa shell durante `explain`.
fn recorded_recipe_field(
    rec_dir: &Path,
    meta: &HashMap<String, String>,
    key: &str,
) -> Option<String> {
    meta.get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| recipe::literal_assignment(&rec_dir.join("recipe"), key))
        .filter(|value| !value.is_empty())
}

/// Extrai o `REPROCORR` pinado, preferindo o snapshot do `meta` e mantendo
/// compatibilidade segura com registros antigos.
fn reprocorr_of(rec_dir: &Path, meta: &HashMap<String, String>) -> Option<String> {
    recorded_recipe_field(rec_dir, meta, "REPROCORR")
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
}

/// `explain <caminho>` — quem é o dono de um arquivo e toda a sua proveniência.
pub fn explain(ctx: &Ctx, target: &str) -> Result<()> {
    let virt = resolve_virt(target);
    let real = rooted_path(&ctx.root, &virt)?;
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
            let short = |s: &str| s[..s.len().min(16)].to_string();
            match (meta.get("ARTIFACT_HASH"), reprocorr_of(&rec, &meta)) {
                (Some(b), Some(p)) if b == &p => println!(
                    "  reprocorr:   {} — build reproduziu o hash PINADO (SPEC-0009 §6)",
                    short(b)
                ),
                (Some(b), Some(p)) => println!(
                    "  reprocorr:   DIVERGE — build {} vs pinado {} (crimestop)",
                    short(b),
                    short(&p)
                ),
                (Some(b), None) => println!(
                    "  artefato:    {} — hash reprodutível; pinável como REPROCORR na receita",
                    short(b)
                ),
                (None, Some(p)) => {
                    println!("  reprocorr:   {} (pinado; registro legado)", short(&p))
                }
                (None, None) => {
                    println!("  reprocorr:   (a receita não pina hash reprodutível ainda)")
                }
            }
            if let Some(line) = crate::attest::corroboration_line(ctx, &name) {
                println!("  corroboração: {line}");
            }
            if field("PROVISIONAL") == "1" {
                println!("  provisório:  sim — cede o caminho a um sucessor (SPEC-0003 §3)");
            }
            if let Some(fp) = meta.get("FINGERPRINT") {
                println!("  fingerprint: {}", &fp[..fp.len().min(16)]);
            }
            // Hash do próprio regular no manifesto v1/v2.
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
            if let Some(license) = license_of(&rec, &meta) {
                println!("  licença:     {license}");
            }
            if let Some(about) = about_of(&rec, &meta) {
                println!("  é:           {about}");
            }
            if virt.starts_with("/etc/") {
                println!("  nota:        default de /etc (a fábrica é a fonte; a sua cópia pode divergir — SPEC-0002 §6)");
            }
            if let Ok(t) = fs::read_link(&real) {
                println!("  link →       {}", t.display());
            }
            Ok(())
        }
        None => {
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
    recipe::validate_name(name)?;
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

/// Extrai o `ABOUT` congelado, sem sourcear código histórico.
fn about_of(rec_dir: &Path, meta: &HashMap<String, String>) -> Option<String> {
    recorded_recipe_field(rec_dir, meta, "ABOUT")
        .filter(|value| !value.chars().any(char::is_control))
}

/// Extrai a licença congelada. Registros v2 anteriores ao campo continuam
/// legíveis pela atribuição literal no snapshot histórico, aberto sem seguir
/// symlink e jamais executado. Se o campo existe no `meta`, inclusive vazio ou
/// inválido, ele é factual e não pode ser mascarado pelo fallback.
fn license_of(rec_dir: &Path, meta: &HashMap<String, String>) -> Option<String> {
    let value = match meta.get("LICENSE") {
        Some(value) => Some(value.clone()),
        None => read_regular_nofollow(&rec_dir.join("recipe"))
            .ok()
            .and_then(|bytes| recipe::literal_assignment_bytes(&bytes, "LICENSE")),
    }?;
    recipe::license_value_is_valid(&value).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use blake2::Blake2b512;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::FileTypeExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    fn historical_snapshot_fixture(label: &str) -> (PathBuf, PathBuf) {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "minitrue-historical-snapshot-{label}-{}-{n}",
            std::process::id()
        ));
        let record = root.join("records/pkg");
        fs::create_dir_all(&record).unwrap();
        fs::write(record.join("meta"), b"NAME=pkg\nVERSION=1\n").unwrap();
        fs::write(record.join("recipe"), b"recipe-v1\n").unwrap();
        fs::write(record.join("recipe@1"), b"recipe-v1\n").unwrap();
        fs::write(record.join("manifest"), b"manifest-v1\n").unwrap();
        fs::write(record.join("manifest@1"), b"manifest-v1\n").unwrap();
        (root, record)
    }

    #[test]
    fn snapshot_historico_reabre_todas_as_folhas_e_recusa_coexistencia() {
        let (root, record) = historical_snapshot_fixture("replace");
        let snapshot = HistoricalRecordSnapshot::capture(&record, "pkg").unwrap();
        let replacement = record.join(".manifest.new");
        fs::write(&replacement, b"manifest-v2\n").unwrap();
        fs::rename(&replacement, record.join("manifest")).unwrap();
        assert!(snapshot.revalidate().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_historico_recusa_hardlink_e_ancestral_symlink() {
        let (root, record) = historical_snapshot_fixture("links");
        fs::hard_link(record.join("recipe"), record.join("recipe.alias")).unwrap();
        assert!(HistoricalRecordSnapshot::capture(&record, "pkg").is_err());
        fs::remove_file(record.join("recipe.alias")).unwrap();

        let alias = root.join("record-alias");
        symlink("records/pkg", &alias).unwrap();
        assert!(HistoricalRecordSnapshot::capture(&alias, "pkg").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn test_runner(ctx: &Ctx) -> Recipe {
        let directory = ctx.newspeak_paths()[0].join(recipe::BUILD_RUNNER_PACKAGE);
        if !directory.join("recipe").is_file() {
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("recipe"),
                format!(
                    "NAME={}\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://e/runner\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                    recipe::BUILD_RUNNER_PACKAGE,
                    "b".repeat(64)
                ),
            )
            .unwrap();
        }
        recipe::load(ctx, recipe::BUILD_RUNNER_PACKAGE).unwrap()
    }

    fn build_fingerprints_for_test(
        ctx: &Ctx,
        recipes: impl IntoIterator<Item = Recipe>,
    ) -> Result<HashMap<String, String>> {
        let mut recipes: Vec<Recipe> = recipes.into_iter().collect();
        if recipes.iter().any(|recipe| recipe.kind == Kind::Source)
            && !recipes
                .iter()
                .any(|recipe| recipe.name == recipe::BUILD_RUNNER_PACKAGE)
        {
            recipes.push(test_runner(ctx));
        }
        recipe::build_fingerprints(&recipes)
    }

    fn write_view_recipe(ctx: &Ctx, name: &str, fields: &str, build: &str) -> Recipe {
        let directory = ctx.newspeak_paths()[0].join(name);
        fs::create_dir_all(&directory).unwrap();
        let default_toolchain = if fields.lines().any(|line| line.starts_with("TOOLCHAIN=")) {
            ""
        } else {
            "TOOLCHAIN=none\n"
        };
        fs::write(
            directory.join("recipe"),
            format!(
                "NAME={name}\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\n{default_toolchain}{fields}build() {{\n{build}\n}}\n"
            ),
        )
        .unwrap();
        recipe::load(ctx, name).unwrap()
    }

    fn write_view_binary_recipe(ctx: &Ctx, name: &str) -> Recipe {
        let directory = ctx.newspeak_paths()[0].join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("recipe"),
            format!(
                "NAME={name}\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://e/{name}\nSHA256={}\ninstall_pkg() {{ :; }}\n",
                sha256_bytes(name.as_bytes())
            ),
        )
        .unwrap();
        recipe::load(ctx, name).unwrap()
    }

    fn copy_test_busybox(destination: &Path) {
        mkparent(destination).unwrap();
        let source = [
            Path::new("/usr/bin/busybox"),
            Path::new("/bin/busybox"),
            Path::new("../rootfs/opt/busybox/current/bin/busybox"),
        ]
        .into_iter()
        .find(|path| {
            matches!(
                elf::inspect(path),
                Ok(Object::Elf(object)) if object.detailed
                    && object.machine == elf::EM_X86_64
                    && object.is_static()
            )
        })
        .expect("os testes do runner exigem um BusyBox estático");
        fs::copy(source, destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn install_view_record(ctx: &Ctx, recipe: &Recipe, fingerprint: &str, paths: &[&str]) {
        let prefix = format!("/opt/{}/{}", recipe.name, recipe.version);
        let current = format!("/opt/{}/current", recipe.name);
        fs::create_dir_all(rooted_path(&ctx.root, &prefix).unwrap()).unwrap();
        let current_host = rooted_path(&ctx.root, &current).unwrap();
        if fs::symlink_metadata(&current_host).is_err() {
            symlink(&recipe.version, &current_host).unwrap();
        }
        let mut manifest: Vec<String> = paths.iter().map(|path| (*path).to_string()).collect();
        for path in [prefix, current] {
            if !manifest.contains(&path) {
                manifest.push(path);
            }
        }
        write_record(
            ctx,
            &ctx.records_dir().join(&recipe.name),
            recipe,
            "A",
            &mut manifest,
            RecordWrite {
                artifact_hash: None,
                fingerprint,
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: None,
                baseline_extra: None,
            },
        )
        .unwrap();
    }

    fn install_view_runner(ctx: &Ctx, runner: &Recipe, fingerprint: &str) {
        let busybox = ctx.root.join("bin/busybox");
        copy_test_busybox(&busybox);
        symlink("busybox", ctx.root.join("bin/sh")).unwrap();
        install_view_record(ctx, runner, fingerprint, &["/bin/busybox", "/bin/sh"]);
    }

    fn install_factual_test_runner(ctx: &Ctx) -> Recipe {
        let input = ctx.root.join("var/tmp/minitrue-test-runner");
        copy_test_busybox(&input);
        let hash = fetch::sha256_file(&input).unwrap();
        let directory = ctx.newspeak_paths()[0].join(recipe::BUILD_RUNNER_PACKAGE);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("recipe"),
            format!(
                "NAME={}\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://e/runner\nSHA256={hash}\ninstall_pkg() {{ :; }}\n",
                recipe::BUILD_RUNNER_PACKAGE
            ),
        )
        .unwrap();
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(&input, ctx.cache_dir().join(&hash)).unwrap();
        let runner = recipe::load(ctx, recipe::BUILD_RUNNER_PACKAGE).unwrap();
        let fingerprint = recipe::build_fingerprints(std::slice::from_ref(&runner))
            .unwrap()
            .remove(recipe::BUILD_RUNNER_PACKAGE)
            .unwrap();
        install_view_runner(ctx, &runner, &fingerprint);
        crate::plan::finalize_applied(
            ctx,
            &[recipe::BUILD_RUNNER_PACKAGE.to_string()],
            crate::plan::PlanPurpose::ChannelEmit,
            BinaryPolicy::PreferBinary,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from([recipe::BUILD_RUNNER_PACKAGE.to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        runner
    }

    fn run_view_build(ctx: &Ctx, recipe: &Recipe) -> Result<std::process::Output> {
        for directory in [
            ctx.root.join("proc"),
            ctx.root.join("dev"),
            ctx.root.join("usr/bin"),
            ctx.root.join("var/cache/minitrue/zig"),
        ] {
            fs::create_dir_all(directory)?;
        }
        let work = ctx.root.join("var/tmp/view-test");
        for directory in [work.join("src"), work.join("stage"), work.join("tmp")] {
            fs::create_dir_all(directory)?;
        }
        fs::write(work.join("recipe"), &recipe.recipe_bytes)?;
        let plan = crate::plan::resolve(
            ctx,
            std::slice::from_ref(&recipe.name),
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Development,
            channel::LoadMode::ReadOnly,
        )?;
        let frozen = FrozenBuildGraph::new(&plan);
        let written: Vec<String> = plan
            .nodes
            .keys()
            .filter(|name| {
                read_meta_strict(&ctx.records_dir().join(name))
                    .ok()
                    .flatten()
                    .is_some_and(|meta| {
                        meta.get("RECORD_FORMAT").map(String::as_str) == Some(RECORD_FORMAT)
                    })
            })
            .cloned()
            .collect();
        for name in written {
            frozen.observe_written_record(ctx, &name)?;
        }
        let build_env = setup_toolchain(ctx, &work, recipe, 0)?;
        let view = create_build_view(ctx, &work, recipe, &frozen, &[], 0)?;
        build_command(ctx, &build_env, &view, 0, &work, "0", &[])
            .output()
            .context("executando fixture da view com bwrap")
    }

    fn view_test_context(label: &str) -> (PathBuf, Ctx) {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-build-view-{label}-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        for (alias, target) in recipe::BUILD_SYSROOT_ALIASES {
            symlink(target, root.join(alias.trim_start_matches('/'))).unwrap();
        }
        (root, ctx)
    }

    #[test]
    fn symlink_pendurado_nao_e_executavel_e_o_erro_diz_o_caminho() {
        let (root, ctx) = view_test_context("pendurado");
        // O caso real: o fontconfig guarda 23 gabaritos de /etc em
        // /usr/share/factory/etc/fonts/conf.d/, e o caminho relativo deles foi
        // calculado para o destino — de /etc/fonts/conf.d resolve, de onde
        // ficam guardados pendura. Isso parou dois rebuilds inteiros no cairo
        // com "No such file or directory (os error 2)", sem caminho nem pacote.
        let factory = root.join("usr/share/factory/etc/fonts/conf.d");
        fs::create_dir_all(&factory).unwrap();
        symlink(
            "../../../usr/share/fontconfig/conf.avail/45-latin.conf",
            factory.join("45-latin.conf"),
        )
        .unwrap();
        assert_eq!(
            executable_mode(&ctx, "/usr/share/factory/etc/fonts/conf.d/45-latin.conf").unwrap(),
            None,
            "link que não aponta para lugar nenhum não é executável"
        );

        // Quem PRECISA do caminho de verdade continua recusando — e agora diz
        // qual travessia falhou, em vez de devolver o erro cru do io.
        let erro = resolve_build_virtual(&ctx, "/usr/share/factory/etc/fonts/conf.d/45-latin.conf")
            .unwrap_err()
            .to_string();
        assert!(
            erro.contains("/usr/share/factory/etc/fonts/conf.d/45-latin.conf"),
            "o erro precisa nomear o caminho, e trouxe {erro:?}"
        );

        // O link que resolve segue resolvendo, e o modo continua sendo lido no
        // ALVO — é isso que a tolerância acima não podia afrouxar.
        fs::write(root.join("usr/bin/ferramenta"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(
            root.join("usr/bin/ferramenta"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("ferramenta", root.join("usr/bin/alias")).unwrap();
        assert_eq!(
            executable_mode(&ctx, "/usr/bin/alias").unwrap(),
            Some(0o100755)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn view_recusa_ferramenta_acidental_inclusive_por_caminho_absoluto() {
        let (root, ctx) = view_test_context("acidental");
        let runner = test_runner(&ctx);
        let accidental = write_view_binary_recipe(&ctx, "accidental-tools");
        let target = write_view_recipe(&ctx, "view-target", "", "    /usr/bin/whoami");
        copy_test_busybox(&root.join("usr/bin/whoami"));

        let recipes = vec![runner.clone(), accidental.clone(), target.clone()];
        let fingerprints = recipe::build_fingerprints(&recipes).unwrap();
        install_view_runner(&ctx, &runner, &fingerprints[&runner.name]);
        install_view_record(
            &ctx,
            &accidental,
            &fingerprints[&accidental.name],
            &["/usr/bin/whoami"],
        );

        let output = run_view_build(&ctx, &target).unwrap();
        assert!(
            !output.status.success(),
            "ferramenta fora da closure atravessou a máscara absoluta"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not found"),
            "falha deveria explicar ausência na view: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn view_inclui_executavel_de_build_dep_declarada() {
        let (root, ctx) = view_test_context("declarada");
        let runner = test_runner(&ctx);
        let tools = write_view_binary_recipe(&ctx, "declared-tools");
        let target = write_view_recipe(
            &ctx,
            "declared-target",
            "BUILD_DEPS=declared-tools\n",
            "    /usr/bin/uname >/dev/null",
        );
        copy_test_busybox(&root.join("usr/bin/uname"));

        let recipes = vec![runner.clone(), tools.clone(), target.clone()];
        let fingerprints = recipe::build_fingerprints(&recipes).unwrap();
        install_view_runner(&ctx, &runner, &fingerprints[&runner.name]);
        install_view_record(
            &ctx,
            &tools,
            &fingerprints[&tools.name],
            &["/usr/bin/uname"],
        );

        let output = run_view_build(&ctx, &target).unwrap();
        assert!(
            output.status.success(),
            "dependência declarada ficou fora da view: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sysroot_esconde_headers_e_bibliotecas_fora_da_closure() {
        let (root, ctx) = view_test_context("sysroot-data");
        let runner = test_runner(&ctx);
        let sdk = write_view_binary_recipe(&ctx, "declared-sdk");
        let missing = write_view_recipe(
            &ctx,
            "sdk-missing-target",
            "",
            "    [ ! -e /usr/include/secret.h ]\n    [ ! -e /usr/lib/libsecret.a ]",
        );
        let allowed = write_view_recipe(
            &ctx,
            "sdk-allowed-target",
            "BUILD_DEPS=declared-sdk\n",
            "    [ -r /usr/include/secret.h ]\n    [ -r /usr/lib/libsecret.a ]",
        );
        let header = root.join("usr/include/secret.h");
        let library = root.join("usr/lib/libsecret.a");
        mkparent(&header).unwrap();
        mkparent(&library).unwrap();
        fs::write(&header, "#define SECRET 1\n").unwrap();
        fs::write(&library, "!<arch>\n").unwrap();

        let recipes = vec![
            runner.clone(),
            sdk.clone(),
            missing.clone(),
            allowed.clone(),
        ];
        let fingerprints = recipe::build_fingerprints(&recipes).unwrap();
        install_view_runner(&ctx, &runner, &fingerprints[&runner.name]);
        install_view_record(
            &ctx,
            &sdk,
            &fingerprints[&sdk.name],
            &["/usr/include/secret.h", "/usr/lib/libsecret.a"],
        );

        let output = run_view_build(&ctx, &missing).unwrap();
        assert!(
            output.status.success(),
            "sysroot vazou dado não declarado: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root.join("var/tmp/view-test"));
        let output = run_view_build(&ctx, &allowed).unwrap();
        assert!(
            output.status.success(),
            "sysroot omitiu dado declarado: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn view_congela_claim_em_inode_novo_antes_do_build() {
        let (root, ctx) = view_test_context("snapshot-copy");
        let runner = test_runner(&ctx);
        let sdk = write_view_binary_recipe(&ctx, "snapshot-sdk");
        let target = write_view_recipe(
            &ctx,
            "snapshot-target",
            "BUILD_DEPS=snapshot-sdk\n",
            "    IFS= read -r value </usr/include/snapshot-value\n    [ \"$value\" = before ]",
        );
        let source = root.join("usr/include/snapshot-value");
        mkparent(&source).unwrap();
        fs::write(&source, "before\n").unwrap();

        let recipes = vec![runner.clone(), sdk.clone(), target.clone()];
        let fingerprints = recipe::build_fingerprints(&recipes).unwrap();
        install_view_runner(&ctx, &runner, &fingerprints[&runner.name]);
        install_view_record(
            &ctx,
            &sdk,
            &fingerprints[&sdk.name],
            &["/usr/include/snapshot-value"],
        );

        let work = root.join("var/tmp/view-test");
        for directory in [work.join("src"), work.join("stage"), work.join("tmp")] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(work.join("recipe"), &target.recipe_bytes).unwrap();
        fs::create_dir_all(root.join("var/cache/minitrue/zig")).unwrap();
        let plan = crate::plan::resolve(
            &ctx,
            std::slice::from_ref(&target.name),
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Development,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        let graph = FrozenBuildGraph::new(&plan);
        graph.observe_written_record(&ctx, &runner.name).unwrap();
        graph.observe_written_record(&ctx, &sdk.name).unwrap();
        let build_env = setup_toolchain(&ctx, &work, &target, 123).unwrap();
        let view = create_build_view(&ctx, &work, &target, &graph, &[], 123).unwrap();
        let frozen = view.host_path("/usr/include/snapshot-value");
        let live_metadata = fs::metadata(&source).unwrap();
        let frozen_metadata = fs::metadata(&frozen).unwrap();
        assert_ne!(
            (live_metadata.dev(), live_metadata.ino()),
            (frozen_metadata.dev(), frozen_metadata.ino()),
            "a view não pode manter hardlink mutável para o rootfs"
        );
        fs::write(&source, "after\n").unwrap();
        assert_eq!(fs::read_to_string(&frozen).unwrap(), "before\n");

        let output = build_command(&ctx, &build_env, &view, 0, &work, "123", &[])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "o build não observou o snapshot congelado: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn view_recusa_symlink_ancestral_fora_dos_aliases_versionados() {
        let (root, _) = view_test_context("ancestor-symlink");
        let view = root.join("view");
        let outside = root.join("outside");
        fs::create_dir(&view).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, view.join("escape")).unwrap();
        let destination = view.join("escape/created/payload");
        let error = ensure_build_view_parent(&view, &destination)
            .expect_err("symlink absoluto ancestral deveria ser recusado");
        assert!(error.to_string().contains("aliases usr-merge"));
        assert!(!outside.join("created").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn view_normaliza_timestamps_em_workdirs_distintos() {
        let base = std::env::temp_dir().join(format!(
            "mt-build-view-timestamps-{}-{}",
            std::process::id(),
            CNT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut views = Vec::new();
        for (name, source_epoch) in [("one", 11), ("two", 22)] {
            let source_root = base.join(format!("source-{name}"));
            let view = base.join(format!("view-{name}"));
            fs::create_dir_all(source_root.join("nested")).unwrap();
            fs::create_dir_all(view.join("nested")).unwrap();
            let source_file = source_root.join("payload");
            let source_link = source_root.join("link");
            fs::write(&source_file, "same bytes\n").unwrap();
            symlink("payload", &source_link).unwrap();
            set_build_timestamp(&source_file, source_epoch).unwrap();
            set_build_timestamp(&source_link, source_epoch).unwrap();
            copy_regular_or_link_into_view(&source_file, &view.join("nested/payload")).unwrap();
            copy_regular_or_link_into_view(&source_link, &view.join("nested/link")).unwrap();
            normalize_build_timestamps(&view, 1_704_067_200).unwrap();
            views.push(view);
        }

        for relative in ["", "nested", "nested/payload", "nested/link"] {
            let left = fs::symlink_metadata(views[0].join(relative)).unwrap();
            let right = fs::symlink_metadata(views[1].join(relative)).unwrap();
            assert_eq!(left.file_type(), right.file_type());
            assert_eq!(left.permissions().mode(), right.permissions().mode());
            assert_eq!(
                (left.atime(), left.atime_nsec()),
                (right.atime(), right.atime_nsec())
            );
            assert_eq!(
                (left.mtime(), left.mtime_nsec()),
                (right.mtime(), right.mtime_nsec())
            );
            assert_eq!(left.mtime(), 1_704_067_200);
        }
        assert_ne!(
            fs::metadata(base.join("source-one/payload"))
                .unwrap()
                .mtime(),
            fs::metadata(base.join("source-two/payload"))
                .unwrap()
                .mtime()
        );
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn view_exige_provedor_do_interpretador_de_script() {
        let (root, ctx) = view_test_context("interpreter");
        let runner = test_runner(&ctx);
        let scripts = write_view_binary_recipe(&ctx, "script-tools");
        let interpreter = write_view_binary_recipe(&ctx, "script-interpreter");
        let missing = write_view_recipe(
            &ctx,
            "script-missing-target",
            "BUILD_DEPS=script-tools\n",
            "    script-tool",
        );
        let allowed = write_view_recipe(
            &ctx,
            "script-allowed-target",
            "BUILD_DEPS=\"script-tools script-interpreter\"\n",
            "    script-tool",
        );
        let script = root.join("usr/bin/script-tool");
        mkparent(&script).unwrap();
        fs::write(&script, "#!/usr/bin/busybox sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        copy_test_busybox(&root.join("usr/bin/busybox"));

        let recipes = vec![
            runner.clone(),
            scripts.clone(),
            interpreter.clone(),
            missing.clone(),
            allowed.clone(),
        ];
        let fingerprints = recipe::build_fingerprints(&recipes).unwrap();
        install_view_runner(&ctx, &runner, &fingerprints[&runner.name]);
        install_view_record(
            &ctx,
            &scripts,
            &fingerprints[&scripts.name],
            &["/usr/bin/script-tool"],
        );
        install_view_record(
            &ctx,
            &interpreter,
            &fingerprints[&interpreter.name],
            &["/usr/bin/busybox"],
        );

        let error = run_view_build(&ctx, &missing)
            .expect_err("interpretador instalado porém não declarado deve ser recusado");
        assert!(
            error.to_string().contains("interpretador")
                || error.to_string().contains("/usr/bin/busybox"),
            "erro inesperado: {error:#}"
        );

        // A primeira tentativa reservou a view no workspace. Um build real
        // elimina o workspace ao falhar; a fixture reproduz essa fronteira.
        let _ = fs::remove_dir_all(root.join("var/tmp/view-test"));
        let output = run_view_build(&ctx, &allowed).unwrap();
        assert!(
            output.status.success(),
            "script com interpretador declarado falhou: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn view_materializa_toolchain_implicita_e_seus_shims() {
        let (root, ctx) = view_test_context("toolchain");
        let runner = test_runner(&ctx);
        let zig = write_view_binary_recipe(&ctx, "zig");
        let target = write_view_recipe(
            &ctx,
            "toolchain-target",
            "TOOLCHAIN=seed\n",
            "    cc fixture.c",
        );
        let zig_binary = root.join("opt/zig/1/zig");
        mkparent(&zig_binary).unwrap();
        fs::write(&zig_binary, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&zig_binary, fs::Permissions::from_mode(0o755)).unwrap();
        symlink("1", root.join("opt/zig/current")).unwrap();

        let recipes = vec![runner.clone(), zig.clone(), target.clone()];
        let fingerprints = recipe::build_fingerprints(&recipes).unwrap();
        install_view_runner(&ctx, &runner, &fingerprints[&runner.name]);
        install_view_record(
            &ctx,
            &zig,
            &fingerprints[&zig.name],
            &["/opt/zig/1", "/opt/zig/current"],
        );

        let output = run_view_build(&ctx, &target).unwrap();
        assert!(
            output.status.success(),
            "shim/toolchain implícita ficou fora da view: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lint_shell_nao_confunde_redirecionamento_for_ou_subshell_com_comando() {
        let (root, ctx) = view_test_context("lint-shell");
        let recipe = write_view_recipe(
            &ctx,
            "lint-shell-target",
            "",
            "    n=$(find . -type f | wc -l)\n    i=$((n + 1))\n    j=$(($i * 2))\n    suffix=${name#*:}\n    find . -exec printf x {} +\n    ./make install\n    for pc in a b; do\n        [ \"$pc\" = a ] || echo nope >&2\n    done\n    case \"$n\" in\n        0|1) sed -n 1p file ;;\n        *) cp a b ;;\n    esac\n    command -v patch >/dev/null\n    ! grep -q x file 2>/dev/null",
        );
        assert_eq!(
            static_build_commands(&recipe),
            ["cp", "find", "grep", "patch", "sed", "wc"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lint_sucessor_permitido_fica_desconhecido_ate_claim_e_fp_exatos() {
        let (root, ctx) = view_test_context("lint-successor");
        let directory = ctx.newspeak_paths()[0].join("successor");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("recipe"),
            format!(
                "NAME=successor\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSUPERSEDES=legacy\nSRC=https://e/successor\nSHA256={}\ninstall_pkg() {{ :; }}\n",
                sha256_bytes(b"successor")
            ),
        )
        .unwrap();
        let successor = recipe::load(&ctx, "successor").unwrap();
        let catalog = vec![successor.clone()];
        let fingerprints = recipe::build_fingerprints(&catalog).unwrap();
        let recipes: HashMap<&str, &Recipe> = catalog
            .iter()
            .map(|recipe| (recipe.name.as_str(), recipe))
            .collect();
        let current = ["legacy".to_string()].into_iter().collect();
        let allowed = ["successor".to_string()].into_iter().collect();
        let successor_current = ["successor".to_string()].into_iter().collect();

        let stale =
            allowed_provider_proof(&ctx, &successor_current, &allowed, &recipes, &fingerprints)
                .unwrap();
        assert!(!stale.exact);
        assert_eq!(stale.pending, ["successor"]);

        assert_eq!(
            pending_allowed_superseders(&ctx, &current, &allowed, &recipes, &fingerprints).unwrap(),
            vec!["successor"]
        );

        install_view_record(&ctx, &successor, &fingerprints[&successor.name], &[]);
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            ctx.cache_dir().join(sha256_bytes(b"successor")),
            b"successor",
        )
        .unwrap();
        crate::plan::finalize_applied(
            &ctx,
            &["successor".to_string()],
            crate::plan::PlanPurpose::ChannelEmit,
            BinaryPolicy::PreferBinary,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from(["successor".to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        let exact =
            allowed_provider_proof(&ctx, &successor_current, &allowed, &recipes, &fingerprints)
                .unwrap();
        assert!(exact.exact);
        assert!(exact.pending.is_empty());
        assert!(
            pending_allowed_superseders(&ctx, &current, &allowed, &recipes, &fingerprints)
                .unwrap()
                .is_empty(),
            "record íntegro na versão/fingerprint congelados encerra a incerteza"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lint_sem_claim_exige_candidato_permitido_explicito() {
        let allowed: BTreeSet<String> = ["gettext", "meson", "pkgconf", "python-glibc"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(
            unproved_allowed_provider_candidates("meson", &allowed),
            ["meson"]
        );
        assert_eq!(
            unproved_allowed_provider_candidates("pkg-config", &allowed),
            ["pkgconf"]
        );
        assert_eq!(
            unproved_allowed_provider_candidates("msgfmt", &allowed),
            ["gettext"]
        );
        assert_eq!(
            unproved_allowed_provider_candidates("python3", &allowed),
            ["python-glibc"]
        );
        assert!(unproved_allowed_provider_candidates("file", &allowed).is_empty());
    }

    /// Sucessão provisional cobre DIRETÓRIO, não só arquivo e link.
    ///
    /// O `adopt_provisional_path` sempre cedeu arquivos, mas a checagem de
    /// colisão de diretório não consultava `SUPERSEDES` — então um diretório
    /// do cedente barrava o sucessor para sempre. O caso real: o python
    /// semente reivindica `lib-dynload` como árvore PORQUE está vazio (não
    /// tem módulo de extensão nenhum), e isso impedia o python-glibc, cuja
    /// razão de existir é justamente encher esse diretório.
    ///
    /// As duas condições do adopt continuam valendo: só cede quem é
    /// PROVISIONAL **e** foi declarado em SUPERSEDES.
    #[test]
    fn diretorio_de_provisional_declarado_e_cedido_e_o_resto_nao() {
        let claims = vec![
            (
                "semente".to_string(),
                "1".to_string(),
                "/usr/lib/coisa".to_string(),
            ),
            (
                "alheio".to_string(),
                "1".to_string(),
                "/usr/lib/outra".to_string(),
            ),
        ];

        // Sem cessão declarada, os dois diretórios bloqueiam.
        let nenhum = std::collections::HashSet::new();
        let index = index_directory_claims(&claims, "sucessor", &nenhum);
        assert!(index.contains_key("/usr/lib/coisa"));
        assert!(index.contains_key("/usr/lib/outra"));

        // Com a semente cedida, só ela sai do índice: o diretório de um
        // pacote não declarado continua sendo doublethink.
        let mut cedidos = std::collections::HashSet::new();
        cedidos.insert("semente".to_string());
        let index = index_directory_claims(&claims, "sucessor", &cedidos);
        assert!(
            !index.contains_key("/usr/lib/coisa"),
            "diretório de provisional declarado deveria ter sido cedido"
        );
        assert!(
            index.contains_key("/usr/lib/outra"),
            "diretório de pacote NÃO declarado não pode ser cedido"
        );
    }

    /// Ida e volta do `pack` v2: o xattr posto no STAGE atravessa o tar
    /// selado, chega ao indexador e passa a prender a claim. Sem isso o
    /// `setcap` de `dumpcap`/`nmap`/`mtr-packet` sumia sem ninguém notar.
    #[test]
    fn xattr_atravessa_o_tar_selado_e_prende_a_claim() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-xattr-{}-{n}", std::process::id()));
        let stage = root.join("stage");
        fs::create_dir_all(stage.join("usr/bin")).unwrap();
        let alvo = stage.join("usr/bin/dumpcap");
        fs::write(&alvo, b"captura").unwrap();

        let pack_para = |destino: &Path| {
            let arquivo = fs::File::create(destino).unwrap();
            crate::pack::pack_deterministic(&stage, 1_704_067_200, arquivo).unwrap()
        };

        // Sem xattr: continua v1, e a claim é a de sempre.
        let sem = root.join("sem.tar");
        pack_para(&sem);
        let entradas = index_sealed_stage(&fs::File::open(&sem).unwrap()).unwrap();
        let claim_sem = entradas
            .iter()
            .find(|e| e.relative == "usr/bin/dumpcap")
            .unwrap()
            .integrity("vazio");

        let c_path = std::ffi::CString::new(alvo.as_os_str().as_bytes()).unwrap();
        let c_name = std::ffi::CString::new("user.distropica.cap").unwrap();
        let posto = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                b"cap_net_raw".as_ptr().cast(),
                11,
                0,
            )
        } == 0;
        if !posto {
            let _ = fs::remove_dir_all(&root);
            eprintln!("sistema de arquivos sem xattr; teste sem o que provar");
            return;
        }

        let com = root.join("com.tar");
        pack_para(&com);
        let entradas = index_sealed_stage(&fs::File::open(&com).unwrap()).unwrap();
        let entrada = entradas
            .iter()
            .find(|e| e.relative == "usr/bin/dumpcap")
            .unwrap();
        match &entrada.kind {
            SealedStageKind::Regular { xattrs, .. } => {
                assert_eq!(xattrs.len(), 1);
                assert_eq!(xattrs[0].0, "user.distropica.cap");
                assert_eq!(xattrs[0].1, b"cap_net_raw");
            }
            outro => panic!("esperava regular com xattr, veio {outro:?}"),
        }
        assert_ne!(
            claim_sem,
            entrada.integrity("vazio"),
            "a claim precisa prender o xattr; senão o verify não acusa quem o arrancar"
        );

        // Um artefato que se diz v1 e traz xattr está mentindo sobre o que
        // exige do leitor: recusa, não aplica assim mesmo.
        let mut bytes = fs::read(&com).unwrap();
        let at = bytes
            .windows(18)
            .position(|w| w == b"DISTROPICA.pack=2\n")
            .unwrap();
        bytes[at + 16] = b'1';
        let mentiroso = root.join("mentiroso.tar");
        fs::write(&mentiroso, &bytes).unwrap();
        let erro = index_sealed_stage(&fs::File::open(&mentiroso).unwrap()).unwrap_err();
        assert!(
            erro.to_string().contains("xattr"),
            "erro inesperado: {erro}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn meta_only_binary_registra_intencao_sem_payload() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-meta-e2e-{}-{n}", std::process::id()));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let cache = root.join("var/cache/minitrue");
        fs::create_dir_all(recipes.join("compiler")).unwrap();
        fs::create_dir_all(recipes.join("miniplenty-buildbase")).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();

        // O objeto não é executado pela fixture. Mantê-lo sem shebang evita
        // declarar falsamente uma dependência ABI em /bin/sh.
        let payload = b"compiler fixture\n";
        let hash = sha256_bytes(payload);
        fs::write(cache.join(&hash), payload).unwrap();
        fs::write(
            recipes.join("compiler/recipe"),
            format!(
                "NAME=compiler\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://invalid.example/compiler\nSHA256={hash}\nLINKS=compiler=bin/compiler\ninstall_pkg() {{\n mkdir -p \"$PREFIX/bin\"\n cp \"$DL\" \"$PREFIX/bin/compiler\"\n chmod 755 \"$PREFIX/bin/compiler\"\n}}\n"
            ),
        )
        .unwrap();
        fs::write(
            recipes.join("miniplenty-buildbase/recipe"),
            "NAME=miniplenty-buildbase\nVERSION=1\nKIND=meta\nDEPS=compiler\nABOUT='conjunto de produção'\n",
        )
        .unwrap();
        let context = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let requested = vec!["miniplenty-buildbase".to_string()];

        // O próprio meta não precisa de canal nem de exceção a
        // --only-binary; a política continua valendo para suas dependências.
        rectify(&context, &requested, BinaryPolicy::BinaryOnly).unwrap();
        assert_eq!(
            fs::read_to_string(context.world_path()).unwrap(),
            "miniplenty-buildbase\n"
        );
        assert!(root.join("usr/bin/compiler").is_symlink());
        assert_eq!(dependents_of(&context, "compiler"), requested);

        let record = context.records_dir().join("miniplenty-buildbase");
        let meta = read_meta_strict(&record).unwrap().unwrap();
        assert_eq!(meta.get("KIND").map(String::as_str), Some("meta"));
        assert_eq!(meta.get("WORLD").map(String::as_str), Some("M"));
        assert_eq!(meta.get("ORIGIN").map(String::as_str), Some("meta"));
        assert!(!meta.contains_key("LICENSE"));
        assert!(!meta.contains_key("ARTIFACT_HASH"));
        assert!(!meta.contains_key("TRANSACTION_ID"));
        assert_eq!(fs::read(record.join("manifest")).unwrap(), b"\n");
        assert_eq!(fs::read(record.join("manifest@1")).unwrap(), b"\n");
        verify(&context).unwrap();

        let meta_path = record.join("meta");
        let canonical_meta = fs::read_to_string(&meta_path).unwrap();
        fs::write(
            &meta_path,
            canonical_meta.replacen("NAME=miniplenty-buildbase\n", "NAME=outro-conjunto\n", 1),
        )
        .unwrap();
        assert!(
            verify(&context).is_err(),
            "NAME factual divergente do diretório deve falhar"
        );
        fs::write(&meta_path, &canonical_meta).unwrap();

        fs::write(
            &meta_path,
            format!("{canonical_meta}TRANSACTION_ID=nao-pertence-a-meta\n"),
        )
        .unwrap();
        assert!(
            verify(&context).is_err(),
            "meta não pode carregar marcador transacional"
        );
        rectify(&context, &requested, BinaryPolicy::BinaryOnly).unwrap();
        assert!(!read_meta_strict(&record)
            .unwrap()
            .unwrap()
            .contains_key("TRANSACTION_ID"));
        verify(&context).unwrap();

        fs::write(&meta_path, format!("{canonical_meta}LICENSE=NOASSERTION\n")).unwrap();
        assert!(
            verify(&context).is_err(),
            "meta sem payload não pode declarar LICENSE"
        );
        rectify(&context, &requested, BinaryPolicy::BinaryOnly).unwrap();
        assert!(!read_meta_strict(&record)
            .unwrap()
            .unwrap()
            .contains_key("LICENSE"));
        verify(&context).unwrap();

        // Fast path e operações de mantenedor preservam a distinção:
        // conjunto não vira tar/attestation, e sustenta seus componentes.
        rectify(&context, &requested, BinaryPolicy::BinaryOnly).unwrap();
        assert!(channel_emit(&context, &root.join("canal-meta"), &requested, false).is_err());
        assert!(memoryhole(&context, &["compiler".to_string()]).is_err());

        let compiler_meta = context.records_dir().join("compiler/meta");
        let compiler_meta_hidden = context.records_dir().join("compiler/meta.hidden");
        fs::rename(&compiler_meta, &compiler_meta_hidden).unwrap();
        assert!(verify(&context).is_err(), "DEPS sem registro deve falhar");
        fs::rename(&compiler_meta_hidden, &compiler_meta).unwrap();

        fs::write(record.join("manifest"), b"").unwrap();
        assert!(verify(&context).is_err(), "vazio não canônico deve falhar");
        assert!(
            memoryhole(&context, &requested).is_err(),
            "memoryhole não deve normalizar registro meta corrompido"
        );
        fs::write(record.join("manifest"), b"\n").unwrap();
        verify(&context).unwrap();

        memoryhole(&context, &requested).unwrap();
        assert!(!record.exists());
        assert!(context.records_dir().join("compiler").is_dir());
        assert!(root.join("usr/bin/compiler").is_symlink());
        assert!(read_world(&context).is_empty());
        assert!(
            verify(&context).is_err(),
            "memoryhole posterior invalida o receipt global até um novo commit completo"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn objeto_extra_da_midia_fica_disponivel_para_rectify_offline_posterior() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-media-extra-{}-{n}", std::process::id()));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let cache = root.join("var/cache/minitrue");
        fs::create_dir_all(&recipes).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();

        // O Minipax materializa o cache completo antes do primeiro rectify.
        // Os dois objetos estão na mídia, mas apenas `base` pertence ao
        // target.world inicial; `extra` não aparece em índice de canal algum.
        let seed_binary = |name: &str, payload: &[u8]| {
            let hash = sha256_bytes(payload);
            fs::write(cache.join(&hash), payload).unwrap();
            let recipe_dir = recipes.join(name);
            fs::create_dir(&recipe_dir).unwrap();
            fs::write(
                recipe_dir.join("recipe"),
                format!(
                    "NAME={name}\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://media.invalid/{name}\nSHA256={hash}\nLINKS=\"{name}=bin/{name}\"\ninstall_pkg() {{\n  mkdir -p \"$PREFIX/bin\"\n  cp \"$DL\" \"$PREFIX/bin/{name}\"\n  chmod 755 \"$PREFIX/bin/{name}\"\n}}\n"
                ),
            )
            .unwrap();
            hash
        };
        // O artefato da fixture é dado opaco: este teste exercita apenas a
        // disponibilidade do cache. Um shebang sem DEPS=busybox introduziria
        // corretamente uma exigência ABI que pertence a outro contrato.
        let base_payload = b"base\n";
        let extra_payload = b"extra\n";
        seed_binary("base", base_payload);
        let extra_hash = seed_binary("extra", extra_payload);

        let context = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let target_world = vec!["base".to_string()];
        rectify(&context, &target_world, BinaryPolicy::PreferBinary).unwrap();

        assert_eq!(fs::read_to_string(context.world_path()).unwrap(), "base\n");
        assert!(!context.records_dir().join("extra").exists());
        assert!(!root.join("usr/bin/extra").exists());
        assert_eq!(fs::read(cache.join(&extra_hash)).unwrap(), extra_payload);
        assert!(!cache.join("channel-config").exists());
        assert!(!cache.join("channels").exists());

        rectify(&context, &["extra".to_string()], BinaryPolicy::PreferBinary).unwrap();

        assert_eq!(
            fs::read(root.join("opt/extra/1/bin/extra")).unwrap(),
            extra_payload
        );
        assert_eq!(
            fs::read_to_string(context.world_path()).unwrap(),
            "base\nextra\n"
        );
        let meta = read_meta_strict(&context.records_dir().join("extra"))
            .unwrap()
            .unwrap();
        assert_eq!(meta.get("WORLD").map(String::as_str), Some("A"));
        assert_eq!(meta.get("ORIGIN").map(String::as_str), Some("vendor"));
        assert_eq!(meta.get("SHA256"), Some(&extra_hash));
        assert_eq!(meta.get("LICENSE").map(String::as_str), Some("NOASSERTION"));
        assert!(!meta.contains_key("CHANNEL_SHA256"));
        assert!(!cache.join("channel-config").exists());
        assert!(!cache.join("channels").exists());
        verify(&context).unwrap();

        let _ = fs::remove_dir_all(&root);
    }

    /// Assinatura minisign pré-hasheada determinística para fixtures de
    /// canal. Exercita o mesmo decoder/verificador usado em produção.
    fn signed_channel_index(message: &[u8]) -> (String, Vec<u8>) {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let key_id = [8u8, 7, 6, 5, 4, 3, 2, 1];
        let mut public = Vec::from(*b"ED");
        public.extend_from_slice(&key_id);
        public.extend_from_slice(&signing.verifying_key().to_bytes());
        let public = base64::engine::general_purpose::STANDARD.encode(public);

        let digest = <Blake2b512 as blake2::Digest>::digest(message);
        let signature = signing.sign(&digest);
        let trusted = "timestamp:0\tfile:index";
        let mut global_body = Vec::from(signature.to_bytes());
        global_body.extend_from_slice(trusted.as_bytes());
        let global = signing.sign(&global_body);
        let mut first = Vec::from(*b"ED");
        first.extend_from_slice(&key_id);
        first.extend_from_slice(&signature.to_bytes());
        let text = format!(
            "untrusted comment: fixture\n{}\ntrusted comment: {}\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(first),
            trusted,
            base64::engine::general_purpose::STANDARD.encode(global.to_bytes())
        );
        (public, text.into_bytes())
    }

    fn zstd_fixture(bytes: &[u8]) -> Vec<u8> {
        let mut input = std::io::Cursor::new(bytes);
        let mut output = Vec::new();
        ruzstd::encoding::compress(
            &mut input,
            &mut output,
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        output
    }

    fn append_test_pack_header<W: std::io::Write>(builder: &mut tar::Builder<W>) {
        let body_tail = format!(" DISTROPICA.pack={}\n", crate::pack::PACK_FORMAT);
        let mut size = body_tail.len() + 1;
        let global_body = loop {
            let candidate = format!("{size}{body_tail}");
            if candidate.len() == size {
                break candidate.into_bytes();
            }
            size = candidate.len();
        };
        let mut global = tar::Header::new_gnu();
        global.set_entry_type(tar::EntryType::new(b'g'));
        global.set_mode(0);
        global.set_uid(0);
        global.set_gid(0);
        global.set_mtime(0);
        global.set_size(global_body.len() as u64);
        builder
            .append_data(&mut global, "pax_global_header", global_body.as_slice())
            .unwrap();
    }

    fn finish_test_stage(mut builder: tar::Builder<fs::File>, path: &Path) -> fs::File {
        builder.finish().unwrap();
        let mut image = builder.into_inner().unwrap();
        image.flush().unwrap();
        image.seek(SeekFrom::Start(0)).unwrap();
        fs::remove_file(path).unwrap();
        image
    }

    /// Escreve nomes diretamente no cabeçalho para conseguir representar
    /// duplicata/travessia que a API segura do `tar::Builder` recusa.
    fn stage_image_with_raw_entries(entries: &[(&[u8], tar::EntryType, &[u8])]) -> fs::File {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mt-stage-hostile-{}-{n}.tar", std::process::id()));
        let output = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut builder = tar::Builder::new(output);
        append_test_pack_header(&mut builder);
        for (name, kind, body) in entries {
            assert!(name.len() <= 100, "fixture crua só cobre nome GNU curto");
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(body.len() as u64);
            header.as_mut_bytes()[..name.len()].copy_from_slice(name);
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        finish_test_stage(builder, &path)
    }

    fn stage_image_with_long_path(path_name: &str) -> fs::File {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mt-stage-long-path-{}-{n}.tar", std::process::id()));
        let output = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut builder = tar::Builder::new(output);
        append_test_pack_header(&mut builder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(1);
        builder
            .append_data(&mut header, path_name, &b"X"[..])
            .unwrap();
        finish_test_stage(builder, &path)
    }

    fn canonical_path_with_len(len: usize) -> String {
        let mut remaining = len;
        let mut components = Vec::new();
        while remaining > 255 {
            components.push("a".repeat(254));
            remaining -= 255; // 254 bytes do componente + a barra
        }
        assert!(remaining > 0);
        components.push("a".repeat(remaining));
        let path = components.join("/");
        assert_eq!(path.len(), len);
        path
    }

    fn stage_image_with_explicit_ancestor(kind: tar::EntryType) -> fs::File {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mt-stage-explicit-ancestor-{}-{n}.tar",
            std::process::id()
        ));
        let output = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut builder = tar::Builder::new(output);

        append_test_pack_header(&mut builder);

        let mut parent = tar::Header::new_gnu();
        parent.set_entry_type(kind);
        parent.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
        parent.set_uid(0);
        parent.set_gid(0);
        parent.set_mtime(0);
        if kind.is_symlink() {
            parent.set_size(0);
            builder
                .append_link(&mut parent, "x", "var/lib/minitrue")
                .unwrap();
        } else if kind.is_dir() {
            parent.set_size(0);
            builder
                .append_data(&mut parent, "x", std::io::empty())
                .unwrap();
        } else {
            parent.set_size(6);
            builder
                .append_data(&mut parent, "x", &b"parent"[..])
                .unwrap();
        }

        let mut child = tar::Header::new_gnu();
        child.set_entry_type(tar::EntryType::Regular);
        child.set_mode(0o644);
        child.set_uid(0);
        child.set_gid(0);
        child.set_mtime(0);
        child.set_size(4);
        builder
            .append_data(&mut child, "x/lock", &b"LOCK"[..])
            .unwrap();
        finish_test_stage(builder, &path)
    }

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

        // Uma colisão adversarial no primeiro nome temporário é ignorada, não
        // seguida. Isso protege inclusive contra symlink que apontaria para
        // fora do diretório do registro.
        let victim = root.join("vitima");
        fs::write(&victim, b"INTEGRA").unwrap();
        let serial = ATOMIC_COUNTER.load(Ordering::Relaxed);
        let planted = root.join(format!(
            ".meta.minitrue-atomic-{}-{serial}",
            std::process::id()
        ));
        symlink(&victim, &planted).unwrap();
        write_atomic(&p, b"apos-colisao\n").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"INTEGRA");
        assert_eq!(fs::read_to_string(&p).unwrap(), "apos-colisao\n");
        fs::remove_file(&planted).unwrap();
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
        let g2 = acquire_lock(&ctx).expect("após soltar, relockeia");
        drop(g2);

        let lock = root.join("var/lib/minitrue/lock");
        fs::remove_file(&lock).unwrap();
        let lock_victim = root.join("lock-victim");
        fs::write(&lock_victim, b"INTEGRA").unwrap();
        symlink(&lock_victim, &lock).unwrap();
        assert!(acquire_lock(&ctx).is_err(), "lock não segue symlink");
        assert_eq!(fs::read(&lock_victim).unwrap(), b"INTEGRA");
        fs::remove_file(&lock).unwrap();
        let fifo = CString::new(lock.as_os_str().as_bytes()).unwrap();
        // SAFETY: caminho NUL-terminated e modo válido.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(acquire_lock(&ctx).is_err(), "FIFO não pode bloquear o lock");
        assert!(read_regular_nofollow(&lock).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn copia_fallback_so_publica_depois_de_completa() {
        struct PartialThenError(bool);
        impl Read for PartialThenError {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Err(std::io::Error::other("falha injetada após parcial"));
                }
                self.0 = true;
                let bytes = b"PARCIAL";
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
        }

        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-copy-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let dst = root.join("backup");
        let permissions = fs::Permissions::from_mode(0o640);
        assert!(copy_regular_atomically(&mut PartialThenError(false), &dst, permissions).is_err());
        assert!(
            fs::symlink_metadata(&dst).is_err_and(|e| e.kind() == ErrorKind::NotFound),
            "bytes parciais não podem aparecer sob o nome final"
        );
        assert!(
            fs::read_dir(&root).unwrap().next().is_none(),
            "temporário parcial deve ser limpo numa falha observável"
        );

        let mut complete = std::io::Cursor::new(b"COMPLETO".as_slice());
        copy_regular_atomically(&mut complete, &dst, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"COMPLETO");
        assert_eq!(
            fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o640
        );
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

    #[test]
    fn manifesto_v2_prende_tipo_alvo_e_arvore() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-manifest-v2-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();

        let file = root.join("file");
        fs::write(&file, b"A").unwrap();
        let file_claim = format!("{}  /file", path_integrity(&file).unwrap());
        assert_eq!(
            manifest_claim_matches(&file_claim, &file).unwrap(),
            Some(true)
        );
        fs::write(&file, b"B").unwrap();
        assert_eq!(
            manifest_claim_matches(&file_claim, &file).unwrap(),
            Some(false)
        );

        let link = root.join("link");
        symlink("alvo-a", &link).unwrap();
        let link_claim = format!("{}  /link", path_integrity(&link).unwrap());
        fs::remove_file(&link).unwrap();
        symlink("alvo-b", &link).unwrap();
        assert_eq!(
            manifest_claim_matches(&link_claim, &link).unwrap(),
            Some(false)
        );

        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("payload"), b"original").unwrap();
        let tree_claim = format!("{}  /tree", path_integrity(&tree).unwrap());
        fs::write(tree.join("payload"), b"adulterado").unwrap();
        assert_eq!(
            manifest_claim_matches(&tree_claim, &tree).unwrap(),
            Some(false)
        );
        fs::remove_file(tree.join("payload")).unwrap();
        let empty_claim = format!("{}  /tree", path_integrity(&tree).unwrap());
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            manifest_claim_matches(&empty_claim, &tree).unwrap(),
            Some(false),
            "a prova d: também prende o modo do diretório-raiz"
        );

        assert!(rooted_path(&root, "/usr/../etc/passwd").is_err());
        assert!(rooted_path(&root, "../../fora").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_recusa_nome_nao_utf8_em_vez_de_manglear() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-stage-name-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let name = std::ffi::OsString::from_vec(vec![b'n', b'o', b'm', b'e', 0xff]);
        fs::write(root.join(name), b"X").unwrap();
        let (image, _) = sealed_stage_snapshot(&root, 0).unwrap();
        assert!(index_sealed_stage(&image).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_recusa_hardlink_que_a_instalacao_nao_preservaria() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-stage-hardlink-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a"), b"mesmo inode").unwrap();
        fs::hard_link(root.join("a"), root.join("b")).unwrap();
        let (image, _) = sealed_stage_snapshot(&root, 0).unwrap();
        assert!(index_sealed_stage(&image).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_selado_aplica_orcamentos_antes_de_indexar() {
        let image = stage_image_with_raw_entries(&[
            (b"usr/bin/a", tar::EntryType::Regular, b"A"),
            (b"usr/bin/b", tar::EntryType::Regular, b"B"),
        ]);

        let error = index_sealed_stage_with_limits(
            &image,
            SealedStageLimits {
                entries: 1,
                ..SEALED_STAGE_LIMITS
            },
        )
        .expect_err("segunda entrada deveria exceder o orçamento");
        assert!(error.to_string().contains("1 entradas"), "{error}");

        let error = index_sealed_stage_with_limits(
            &image,
            SealedStageLimits {
                regular_bytes: 1,
                ..SEALED_STAGE_LIMITS
            },
        )
        .expect_err("dois bytes regulares deveriam exceder o orçamento");
        assert!(error.to_string().contains("conteúdo regular"), "{error}");

        let error = index_sealed_stage_with_limits(
            &image,
            SealedStageLimits {
                tar_bytes: image.metadata().unwrap().len() - 1,
                ..SEALED_STAGE_LIMITS
            },
        )
        .expect_err("descritor maior que o teto deveria falhar antes do parse");
        assert!(error.to_string().contains("limite"), "{error}");

        let error = index_sealed_stage_with_limits(
            &image,
            SealedStageLimits {
                path_bytes: 8,
                ..SEALED_STAGE_LIMITS
            },
        )
        .expect_err("nome acima do teto deveria falhar");
        assert!(error.to_string().contains("caminho"), "{error}");

        let pax = stage_image_with_raw_entries(&[
            (b"pax_extended_header", tar::EntryType::new(b'x'), b"XX"),
            (b"usr/bin/a", tar::EntryType::Regular, b"A"),
        ]);
        let error = index_sealed_stage_with_limits(
            &pax,
            SealedStageLimits {
                pax_bytes: 1,
                ..SEALED_STAGE_LIMITS
            },
        )
        .expect_err("PAX deveria ser limitado antes de a biblioteca alocá-lo");
        assert!(error.to_string().contains("PAX por entrada"), "{error}");
    }

    #[test]
    fn stage_preserva_gnu_longname_no_limite_e_recusa_um_byte_a_mais() {
        let at_limit = canonical_path_with_len(MAX_SEALED_STAGE_PATH_BYTES);
        let image = stage_image_with_long_path(&at_limit);
        let entries = index_sealed_stage(&image).expect("limite inclusivo precisa ser compatível");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative, at_limit);

        let over_limit = canonical_path_with_len(MAX_SEALED_STAGE_PATH_BYTES + 1);
        let image = stage_image_with_long_path(&over_limit);
        let error = index_sealed_stage(&image).expect_err("4097 bytes deveriam ser recusados");
        assert!(error.to_string().contains("caminho"), "{error}");
    }

    #[test]
    fn stage_hostil_recusa_duplicata_travessia_e_tipo_especial() {
        let duplicate = stage_image_with_raw_entries(&[
            (b"usr/bin/a", tar::EntryType::Regular, b"A"),
            (b"usr/bin/a", tar::EntryType::Regular, b"B"),
        ]);
        let error = index_sealed_stage(&duplicate).expect_err("duplicata deveria falhar");
        assert!(
            error.to_string().contains("repete caminho"),
            "erro inesperado: {error}"
        );

        let traversal = stage_image_with_raw_entries(&[(
            b"usr/../etc/passwd",
            tar::EntryType::Regular,
            b"NAO",
        )]);
        let error = index_sealed_stage(&traversal).expect_err("travessia deveria falhar");
        assert!(
            error.to_string().contains("não canônico"),
            "erro inesperado: {error}"
        );

        let fifo = stage_image_with_raw_entries(&[(b"usr/run/fifo", tar::EntryType::Fifo, b"")]);
        let error = index_sealed_stage(&fifo).expect_err("FIFO deveria falhar no preflight");
        assert!(
            error
                .to_string()
                .contains("tipo de entrada TAR não instalável"),
            "erro inesperado: {error}"
        );
    }

    #[test]
    fn stage_recusa_descendente_de_ancestral_explicito_nao_diretorio() {
        for kind in [tar::EntryType::Symlink, tar::EntryType::Regular] {
            let image = stage_image_with_explicit_ancestor(kind);
            let error = index_sealed_stage(&image)
                .expect_err("ancestral symlink/regular deveria falhar no preflight");
            assert!(error.to_string().contains("ancestral não-diretório"));
        }

        let image = stage_image_with_explicit_ancestor(tar::EntryType::Directory);
        assert_eq!(index_sealed_stage(&image).unwrap().len(), 2);
    }

    #[test]
    fn snapshot_selado_e_a_fonte_unica_do_hash_e_da_instalacao() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-sealed-stage-{}-{n}", std::process::id()));
        let stage = root.join("stage");
        fs::create_dir_all(stage.join("usr/bin")).unwrap();
        fs::create_dir_all(stage.join("usr/share/sticky")).unwrap();
        fs::write(stage.join("usr/bin/tool"), b"VERSAO-A").unwrap();
        fs::set_permissions(
            stage.join("usr/bin/tool"),
            fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        fs::set_permissions(
            stage.join("usr/share/sticky"),
            fs::Permissions::from_mode(0o1777),
        )
        .unwrap();

        let recipe_dir = root.join("var/lib/minitrue/newspeak/pkg");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "pkg").unwrap();

        let (mut image, hash) = sealed_stage_snapshot(&stage, 1_704_067_200).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(
            image.write_all(b"adulteracao").is_err(),
            "o memfd precisa estar selado contra escrita"
        );
        let entries = index_sealed_stage(&image).unwrap();
        fs::write(stage.join("usr/bin/tool"), b"VERSAO-B").unwrap();
        let mut journal = Journal::begin(&ctx, "pkg").unwrap();
        let (manifest, pulados) = apply_stage(
            &ctx,
            &image,
            &entries,
            &recipe,
            NO_SHARED_STAGE_POLICY,
            &HashSet::new(),
            &mut journal,
        )
        .unwrap();
        assert_eq!(pulados, 0, "pacote comum não pula caminho por cessão");

        assert_eq!(fs::read(root.join("usr/bin/tool")).unwrap(), b"VERSAO-A");
        assert_eq!(
            fs::metadata(root.join("usr/bin/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o4755
        );
        assert_eq!(
            fs::metadata(root.join("usr/share/sticky"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o1777
        );
        for line in &manifest {
            assert_eq!(
                confined_claim_matches(line, &root, manifest_path(line)).unwrap(),
                Some(true)
            );
        }
        journal.rollback().unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_recusa_colisoes_canonicas_de_usr_merge_e_factory() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-stage-alias-{}-{n}", std::process::id()));
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();

        let exact = root.join("stage-exact");
        fs::create_dir_all(exact.join("lib")).unwrap();
        fs::create_dir_all(exact.join("usr/lib")).unwrap();
        fs::write(exact.join("lib/x"), b"A").unwrap();
        fs::write(exact.join("usr/lib/x"), b"B").unwrap();
        let (image, _) = sealed_stage_snapshot(&exact, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        assert!(canonical_stage_topology(&root, &entries).is_err());

        let ancestor = root.join("stage-ancestor");
        fs::create_dir_all(ancestor.join("lib/foo")).unwrap();
        fs::create_dir_all(ancestor.join("usr/lib/foo")).unwrap();
        fs::write(ancestor.join("usr/lib/foo/bar"), b"B").unwrap();
        let (image, _) = sealed_stage_snapshot(&ancestor, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        assert!(canonical_stage_topology(&root, &entries).is_err());

        let factory = root.join("stage-factory");
        fs::create_dir_all(factory.join("etc/app")).unwrap();
        fs::create_dir_all(factory.join("usr/share/factory/etc/app")).unwrap();
        fs::write(factory.join("usr/share/factory/etc/app/x"), b"X").unwrap();
        let (image, _) = sealed_stage_snapshot(&factory, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        assert!(canonical_stage_topology(&root, &entries).is_err());

        let factory_ancestor = root.join("stage-factory-ancestor");
        fs::create_dir_all(factory_ancestor.join("etc/app")).unwrap();
        fs::create_dir_all(factory_ancestor.join("usr/share/factory")).unwrap();
        fs::write(factory_ancestor.join("etc/app/config"), b"CONFIG").unwrap();
        let (image, _) = sealed_stage_snapshot(&factory_ancestor, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        assert!(canonical_stage_topology(&root, &entries).is_err());

        let empty_share = root.join("stage-empty-share");
        fs::create_dir_all(empty_share.join("etc/app")).unwrap();
        fs::create_dir_all(empty_share.join("usr/share")).unwrap();
        fs::write(empty_share.join("etc/app/config"), b"CONFIG").unwrap();
        let (image, _) = sealed_stage_snapshot(&empty_share, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        assert!(canonical_stage_topology(&root, &entries).is_err());

        for (index, internal) in [
            "var/lib/minitrue/journal/pkg/log",
            "var/lib/minitrue/records/victim/meta",
            "var/cache/minitrue/download",
            "etc/minitrue/world",
            "tmp/minitrue-build-pkg/installed",
            "tmp/minitrue-work-pkg/installed",
        ]
        .into_iter()
        .enumerate()
        {
            let stage = root.join(format!("stage-control-{index}"));
            let payload = stage.join(internal);
            mkparent(&payload).unwrap();
            fs::write(&payload, b"NAO-PUBLICAR").unwrap();
            let (image, _) = sealed_stage_snapshot(&stage, 0).unwrap();
            let entries = index_sealed_stage(&image).unwrap();
            let paths = canonical_stage_topology(&root, &entries).unwrap();
            assert!(
                ensure_stage_avoids_control_plane(&root, &entries, &paths).is_err(),
                "namespace interno aceito: {internal}"
            );
        }
        assert!(!root.join("var/lib/minitrue/journal/pkg/log").exists());

        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("var/lib/minitrue/journal/pkg")).unwrap();
        symlink("../var/lib/minitrue/journal/pkg", root.join("etc/app")).unwrap();
        let aliased = root.join("stage-etc-alias/etc/app/log");
        mkparent(&aliased).unwrap();
        fs::write(&aliased, b"NAO-TOCAR-JOURNAL").unwrap();
        let (image, _) = sealed_stage_snapshot(&root.join("stage-etc-alias"), 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        let paths = canonical_stage_topology(&root, &entries).unwrap();
        assert!(ensure_stage_avoids_control_plane(&root, &entries, &paths).is_err());

        let claimed_temp = root.join("opt/foo/.1.tmp/payload");
        mkparent(&claimed_temp).unwrap();
        fs::write(&claimed_temp, b"B").unwrap();
        let outsider = root.join("var/lib/minitrue/records/outsider");
        fs::create_dir_all(&outsider).unwrap();
        fs::write(outsider.join("meta"), "NAME=outsider\nVERSION=1\n").unwrap();
        fs::write(outsider.join("manifest"), "/opt/foo/.1.tmp/payload\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        assert!(
            ensure_paths_unclaimed(&ctx, "foo", &[(&root.join("opt/foo"), "prefixo mundo A")])
                .is_err()
        );
        assert_eq!(fs::read(&claimed_temp).unwrap(), b"B");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_permite_etc_e_usr_share_no_mesmo_pacote() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-stage-factory-share-{}-{n}", std::process::id()));
        fs::create_dir_all(root.join("usr/share")).unwrap();

        let stage = root.join("stage");
        fs::create_dir_all(stage.join("etc/app")).unwrap();
        fs::create_dir_all(stage.join("usr/share/licenses/app")).unwrap();
        fs::write(stage.join("etc/app/config"), b"CONFIG").unwrap();
        fs::write(stage.join("usr/share/licenses/app/COPYING"), b"LICENSE").unwrap();

        let (image, _) = sealed_stage_snapshot(&stage, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        let paths = canonical_stage_topology(&root, &entries).unwrap();
        assert_eq!(
            paths.get("etc/app/config").map(String::as_str),
            Some("/usr/share/factory/etc/app/config")
        );
        assert_eq!(
            paths
                .get("usr/share/licenses/app/COPYING")
                .map(String::as_str),
            Some("/usr/share/licenses/app/COPYING")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn memoryhole_recusa_manifesto_vazio_ou_com_travessia() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-memory-safe-{}-{n}", std::process::id()));
        let rec = root.join("var/lib/minitrue/records/pkg");
        fs::create_dir_all(&rec).unwrap();
        fs::write(rec.join("meta"), "NAME=pkg\nWORLD=B\nDEPS=\n").unwrap();
        fs::write(
            rec.join("manifest"),
            "f:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /usr/../../fora\n",
        )
        .unwrap();
        let victim = root.with_extension("fora");
        fs::write(&victim, b"INTEGRO").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        assert!(memoryhole(&ctx, &["pkg".into()]).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"INTEGRO");
        assert!(rec.is_dir());

        fs::write(rec.join("manifest"), "").unwrap();
        assert!(memoryhole(&ctx, &["pkg".into()]).is_err());
        assert!(rec.is_dir());

        fs::write(
            rec.join("meta"),
            "RECORD_FORMAT=99\nNAME=pkg\nWORLD=B\nDEPS=\nPROVISIONAL=1\n",
        )
        .unwrap();
        fs::write(rec.join("manifest"), "/guardado\n").unwrap();
        fs::write(root.join("guardado"), b"PRESERVAR").unwrap();
        assert!(memoryhole(&ctx, &["pkg".into()]).is_err());
        assert_eq!(fs::read(root.join("guardado")).unwrap(), b"PRESERVAR");
        assert!(verify(&ctx).is_err(), "verify reporta formato futuro");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&victim);
    }

    #[test]
    fn memoryhole_nao_remove_plano_de_controle_reivindicado() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-memory-control-{}-{n}", std::process::id()));
        let rec = root.join("var/lib/minitrue/records/adversarial");
        fs::create_dir_all(&rec).unwrap();
        fs::write(
            rec.join("meta"),
            "NAME=adversarial\nVERSION=1\nWORLD=B\nDEPS=\n",
        )
        .unwrap();
        fs::write(rec.join("manifest"), "/var/lib/minitrue/lock\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        assert!(memoryhole(&ctx, &["adversarial".into()]).is_err());
        assert!(root.join("var/lib/minitrue/lock").is_file());
        assert!(rec.is_dir());

        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("opt/cfg")).unwrap();
        fs::write(root.join("opt/cfg/world"), b"OUTRO-DONO\n").unwrap();
        symlink("../opt/cfg", root.join("etc/minitrue")).unwrap();
        assert!(world_add(&ctx, "pkg").is_err());
        assert_eq!(
            fs::read(root.join("opt/cfg/world")).unwrap(),
            b"OUTRO-DONO\n"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn meta_corrompido_nao_apaga_o_pacote_da_visao_de_ownership() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-meta-strict-{}-{n}", std::process::id()));
        let rec = root.join("var/lib/minitrue/records/pkg");
        let outside = root.with_extension("outside-meta");
        fs::create_dir_all(&rec).unwrap();
        fs::write(&outside, "NAME=pkg\nVERSION=1\nWORLD=B\n").unwrap();
        symlink(&outside, rec.join("meta")).unwrap();
        fs::write(rec.join("manifest"), "/usr/bin/owned\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        assert!(all_manifests(&ctx).is_err());
        fs::remove_file(rec.join("meta")).unwrap();
        fs::write(
            rec.join("meta"),
            "NAME=pkg\nVERSION=1\nWORLD=B\nTRANSACTION_ID=a\nTRANSACTION_ID=b\n",
        )
        .unwrap();
        assert!(all_manifests(&ctx).is_err());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }

    #[test]
    fn memoryhole_nao_segue_symlink_intermediario_para_fora_do_root() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-memory-link-{}-{n}", std::process::id()));
        let outside = root.with_extension("outside");
        let rec = root.join("var/lib/minitrue/records/pkg");
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim");
        fs::write(&victim, b"NAO-APAGAR").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        fs::write(rec.join("meta"), "NAME=pkg\nWORLD=B\nDEPS=\n").unwrap();
        fs::write(rec.join("manifest"), "/escape/victim\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        assert!(memoryhole(&ctx, &["pkg".into()]).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"NAO-APAGAR");
        assert!(rec.exists(), "a recusa preserva o registro para inspeção");
        fs::remove_dir_all(&rec).unwrap();

        // Symlink relativo que permanece dentro do rootfs continua suportado
        // (usr-merge real: /lib -> usr/lib, /sbin -> usr/bin).
        let rec = root.join("var/lib/minitrue/records/internal");
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        fs::write(root.join("usr/lib/owned"), b"X").unwrap();
        fs::write(rec.join("meta"), "NAME=internal\nWORLD=B\nDEPS=\n").unwrap();
        fs::write(rec.join("manifest"), "/lib/owned\n").unwrap();
        memoryhole(&ctx, &["internal".into()]).unwrap();
        assert!(!root.join("usr/lib/owned").exists());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn leitura_de_claim_para_reemissao_reinterpreta_symlink_absoluto_no_rootfs() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-emit-confined-root-{}-{n}", std::process::id()));
        let relative_outside = PathBuf::from(format!(
            "tmp/mt-emit-confined-outside-{}-{n}",
            std::process::id()
        ));
        let outside = Path::new("/").join(&relative_outside);
        let inside = root.join(&relative_outside);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir_all(&inside).unwrap();
        fs::write(outside.join("secret"), b"FORA").unwrap();
        fs::write(inside.join("secret"), b"DENTRO").unwrap();
        symlink(Path::new("/").join(&relative_outside), root.join("alias")).unwrap();

        let descriptor = open_confined(
            &root,
            "/alias/secret",
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
        .unwrap();
        let mut bytes = Vec::new();
        fs::File::from(descriptor).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"DENTRO", "nunca deve ler o homônimo fora do rootfs");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn journal_recusa_symlink_externo_e_aceita_usr_merge_interno() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-journal-link-{}-{n}", std::process::id()));
        let outside = root.with_extension("outside");
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim"), b"FORA").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        let source = root.join("source");
        fs::write(&source, b"NOVO").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let mut journal = Journal::begin(&ctx, "pkg").unwrap();

        assert!(journal
            .place_file(&root.join("escape/victim"), &source)
            .is_err());
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"FORA");
        journal
            .place_file(&root.join("lib/owned"), &source)
            .unwrap();
        assert_eq!(fs::read(root.join("usr/lib/owned")).unwrap(), b"NOVO");
        journal.rollback().unwrap();
        assert!(!root.join("usr/lib/owned").exists());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn memoryhole_nao_remove_diretorio_mundo_b_que_ganhou_filhos() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-memory-dir-{}-{n}", std::process::id()));
        let rec = root.join("var/lib/minitrue/records/pkg");
        let owned = root.join("usr/share/pkg-empty");
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(&owned).unwrap();
        let claim = format!(
            "{}  /usr/share/pkg-empty\n",
            path_integrity(&owned).unwrap()
        );
        fs::write(
            rec.join("meta"),
            "RECORD_FORMAT=2\nNAME=pkg\nVERSION=1\nWORLD=B\nDEPS=\n",
        )
        .unwrap();
        fs::write(rec.join("manifest"), claim).unwrap();
        fs::write(owned.join("foreign"), b"PRESERVAR").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        memoryhole(&ctx, &["pkg".into()]).unwrap();
        assert_eq!(fs::read(owned.join("foreign")).unwrap(), b"PRESERVAR");
        assert!(!rec.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn falha_no_meio_fecha_o_que_ja_construiu_e_nao_emite_receipt() {
        // A cadeia de rebuild da árvore vinha custando ~2h30 por falha porque
        // tudo o que ela construía ficava em RECORD_FORMAT=3, e v3 não é
        // elegível para `keep`: a execução seguinte reconstruía os mesmos
        // pacotes — inclusive um superseder como o gawk, que não reconstrói
        // depois de ter tomado o /usr/bin/awk do busybox. Medido numa raiz
        // interrompida de 12 pacotes: o plano de retomada propunha refazer 10.
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-parcial-{}-{n}", std::process::id()));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let escreve = |name: &str, deps: &str, corpo: &str| {
            let directory = recipes.join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("recipe"),
                format!(
                    "NAME={name}\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nDEPS={deps:?}\nbuild() {{ {corpo} }}\n"
                ),
            )
            .unwrap();
        };
        // O quebrado DEPENDE do feito, então a ordem é determinística: o
        // primeiro termina, o segundo morre, e o fechamento parcial tem
        // exatamente um pacote para preservar.
        // O `feito` precisa PRODUZIR algo: um STAGE vazio não gera claim e o
        // rectify recusa antes de o teste chegar ao ponto que interessa.
        escreve(
            "feito",
            "",
            "mkdir -p \"$STAGE/usr/share/feito\"; echo pronto > \"$STAGE/usr/share/feito/marca\";",
        );
        escreve("quebrado", "feito", "exit 1;");

        // Os aliases do sysroot e o runner factual são fronteira da view de
        // build: sem eles o rectify falha antes de chegar a qualquer receita, e
        // o teste mediria outra coisa.
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        for (alias, target) in recipe::BUILD_SYSROOT_ALIASES {
            symlink(target, root.join(alias.trim_start_matches('/'))).unwrap();
        }
        install_factual_test_runner(&ctx);

        let erro = rectify(&ctx, &["quebrado".to_string()], BinaryPolicy::PreferBinary)
            .expect_err("o build do 'quebrado' sai com 1 e a operação precisa falhar");
        // O erro que sobe é o do BUILD, e não o de um fechamento que não deu
        // certo: esconder a causa real seria pior que não fechar nada.
        assert!(
            format!("{erro:#}").contains("quebrado"),
            "o erro devia nomear o pacote que falhou, e veio: {erro:#}"
        );

        // O que terminou está fechado e é retomável.
        let meta = read_meta_strict(&ctx.records_dir().join("feito"))
            .unwrap()
            .expect("o record do pacote que terminou tem de existir");
        assert_eq!(
            meta.get("RECORD_FORMAT").map(String::as_str),
            Some(FINAL_RECORD_FORMAT),
            "o pacote que terminou precisa ficar em v4, senão a retomada o reconstrói"
        );
        assert!(
            meta.contains_key("INSTALL_PLAN_LOCK_SHA256"),
            "v4 sem vínculo de plano não é fechamento"
        );

        // O que falhou não deixa record.
        assert!(!ctx.records_dir().join("quebrado").exists());

        // E o RECEIPT não pode existir: ele afirma que este plano É o mundo
        // instalado, e metade de um plano não é mundo nenhum.
        let receipts = root.join("var/lib/minitrue/applied-plans");
        let tem_current = receipts.join("current").exists();
        assert!(
            !tem_current,
            "fechamento parcial não pode publicar autoridade de plano aplicado"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fechamento_parcial_tolera_provedor_sem_abi_observada_e_nao_o_promove() {
        // A v42 morreu no libepoxy com 74 pacotes construídos, o fechamento
        // parcial disparou como projetado e FALHOU — "ABI_REQUIRE não
        // corresponde a exatamente um ABI_PROVIDE factual" —, e os 74 se
        // perderam do mesmo jeito. O teste acima não pegava isso porque no
        // cenário dele nenhum pacote fica sem ABI observada.
        //
        // O gatilho real foi o `icu`: 47 erros de auditoria, três deles por
        // instalar SCRIPTS que exigem /bin/sh sem declarar quem o fornece. Um
        // pacote assim vai para ABI_PENDING e não emite ABI_PROVIDE nenhum —
        // e quem o nomeia como provedor não acha correspondência.
        //
        // Aqui a pendência é fabricada pelo mesmo mecanismo e sem ELF nenhum:
        // shebang apontando para arquivo de outro pacote.
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-parcial-abi-{}-{n}", std::process::id()));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let escreve = |name: &str, deps: &str, corpo: &str| {
            let directory = recipes.join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("recipe"),
                format!(
                    "NAME={name}\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nDEPS={deps:?}\nbuild() {{ {corpo} }}\n"
                ),
            )
            .unwrap();
        };

        // `provedor` instala um interpretador que ele próprio invoca por
        // shebang sem declarar o dono do /bin/sh: a auditoria acusa erro, o
        // snapshot volta incompleto, e ele cai em ABI_PENDING.
        escreve(
            "provedor",
            "",
            "mkdir -p \"$STAGE/usr/bin\"; \
             printf '#!/bin/sh\\nexit 0\\n' > \"$STAGE/usr/bin/interp\"; \
             chmod 755 \"$STAGE/usr/bin/interp\";",
        );
        // `consumidor` aponta o shebang para o arquivo do `provedor`. É isso que
        // gera o ABI_REQUIRE nomeando um provedor que não tem ABI_PROVIDE.
        escreve(
            "consumidor",
            "provedor",
            "mkdir -p \"$STAGE/usr/bin\"; \
             printf '#!/usr/bin/interp\\n' > \"$STAGE/usr/bin/usa\"; \
             chmod 755 \"$STAGE/usr/bin/usa\";",
        );
        escreve("quebrado", "consumidor", "exit 1;");

        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        for (alias, target) in recipe::BUILD_SYSROOT_ALIASES {
            symlink(target, root.join(alias.trim_start_matches('/'))).unwrap();
        }
        install_factual_test_runner(&ctx);

        let erro = rectify(&ctx, &["quebrado".to_string()], BinaryPolicy::PreferBinary)
            .expect_err("o build do 'quebrado' sai com 1 e a operação precisa falhar");
        assert!(
            format!("{erro:#}").contains("quebrado"),
            "o erro devia nomear o pacote que falhou, e veio: {erro:#}"
        );

        // O CONSUMIDOR fecha. Antes da correção o fechamento inteiro abortava
        // por causa dele: seu ABI_REQUIRE nomeia um provedor pendente.
        let meta = read_meta_strict(&ctx.records_dir().join("consumidor"))
            .unwrap()
            .expect("o record do consumidor tem de existir");
        assert_eq!(
            meta.get("RECORD_FORMAT").map(String::as_str),
            Some(FINAL_RECORD_FORMAT),
            "quem depende de um pendente não pode ser punido: o payload dele foi observado"
        );

        // O PENDENTE não é promovido. É a metade que a correção NÃO afrouxa:
        // v4 afirma "record factual", e ABI não observada não sustenta isso.
        let pendente = read_meta_strict(&ctx.records_dir().join("provedor"))
            .unwrap()
            .expect("o record do provedor tem de existir");
        assert_ne!(
            pendente.get("RECORD_FORMAT").map(String::as_str),
            Some(FINAL_RECORD_FORMAT),
            "pacote sem ABI observada não pode virar v4; a retomada tem de reconstruí-lo"
        );

        assert!(!ctx.records_dir().join("quebrado").exists());
        assert!(
            !root.join("var/lib/minitrue/applied-plans/current").exists(),
            "fechamento parcial não pode publicar autoridade de plano aplicado"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn diretorio_compartilhado_autoriza_so_dep_direta_e_nao_copia_filhos_ao_emitir() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-shared-dir-{}-{n}", std::process::id()));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let write_recipe = |name: &str, deps: &str, shared: &str| {
            let directory = recipes.join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("recipe"),
                format!(
                    "NAME={name}\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nDEPS={deps:?}\n{shared}build() {{ :; }}\n"
                ),
            )
            .unwrap();
        };
        write_recipe("depot", "", "SHARED_DIRS=/usr/share/depot\n");
        write_recipe("middle", "depot", "");
        write_recipe("direct", "depot", "");
        write_recipe("empty", "depot", "");
        write_recipe("indirect", "middle", "");
        write_recipe("replace", "depot", "");

        // A fixture passa pela mesma fronteira de uma aplicação: o runner e
        // todos os fingerprints existem antes de qualquer record v3 nascer.
        let runner_payload = root.join("fixtures/runner-busybox");
        copy_test_busybox(&runner_payload);
        let runner_hash = fetch::sha256_file(&runner_payload).unwrap();
        let runner_directory = recipes.join(recipe::BUILD_RUNNER_PACKAGE);
        fs::create_dir_all(&runner_directory).unwrap();
        fs::write(
            runner_directory.join("recipe"),
            format!(
                "NAME={}\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://e/runner\nSHA256={runner_hash}\ninstall_pkg() {{ :; }}\n",
                recipe::BUILD_RUNNER_PACKAGE
            ),
        )
        .unwrap();
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(&runner_payload, ctx.cache_dir().join(&runner_hash)).unwrap();
        let mut resolved_recipes = Vec::new();
        for name in [
            recipe::BUILD_RUNNER_PACKAGE,
            "depot",
            "middle",
            "direct",
            "empty",
            "indirect",
            "replace",
        ] {
            resolved_recipes.push(recipe::load(&ctx, name).unwrap());
        }
        let fingerprints = recipe::build_fingerprints(&resolved_recipes).unwrap();
        let runner = resolved_recipes
            .iter()
            .find(|item| item.name == recipe::BUILD_RUNNER_PACKAGE)
            .unwrap();
        install_view_runner(&ctx, runner, &fingerprints[&runner.name]);

        let install_stage = |recipe: &Recipe, stage: &Path| -> Result<String> {
            let (image, hash) = sealed_stage_snapshot(stage, 0)?;
            install_sealed_source(
                &ctx,
                recipe,
                false,
                &fingerprints[&recipe.name],
                &image,
                &hash,
                SourceRecordOrigin::Local,
            )?;
            Ok(hash)
        };

        let depot_stage = root.join("fixtures/depot");
        fs::create_dir_all(depot_stage.join("usr/share/depot/bucket")).unwrap();
        fs::write(
            depot_stage.join("usr/share/depot/index.theme"),
            b"[depot]\n",
        )
        .unwrap();
        let depot = recipe::load(&ctx, "depot").unwrap();
        let depot_hash = install_stage(&depot, &depot_stage).unwrap();
        let depot_manifest = read_manifest_strict(&ctx.records_dir().join("depot")).unwrap();
        assert!(depot_manifest.iter().any(|line| {
            manifest_path(line) == "/usr/share/depot"
                && manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:"))
        }));
        assert!(depot_manifest.iter().any(|line| {
            manifest_path(line) == "/usr/share/depot/bucket"
                && manifest_integrity(line).is_some_and(|tag| tag.starts_with("D:"))
        }));
        assert!(depot_manifest.iter().all(|line| {
            !manifest_path(line).starts_with("/usr/share/depot")
                || !manifest_integrity(line).is_some_and(|tag| tag.starts_with("d:"))
        }));

        let middle_stage = root.join("fixtures/middle");
        fs::create_dir_all(middle_stage.join("usr/share/middle")).unwrap();
        fs::write(middle_stage.join("usr/share/middle/marker"), b"middle").unwrap();
        let middle = recipe::load(&ctx, "middle").unwrap();
        install_stage(&middle, &middle_stage).unwrap();

        let direct_stage = root.join("fixtures/direct");
        fs::create_dir_all(direct_stage.join("usr/share/depot/bucket")).unwrap();
        fs::write(
            direct_stage.join("usr/share/depot/bucket/icon.png"),
            b"icone",
        )
        .unwrap();
        let direct = recipe::load(&ctx, "direct").unwrap();
        install_stage(&direct, &direct_stage).unwrap();
        let empty_stage = root.join("fixtures/empty");
        fs::create_dir_all(empty_stage.join("usr/share/depot/bucket")).unwrap();
        fs::create_dir_all(empty_stage.join("usr/share/empty")).unwrap();
        fs::write(empty_stage.join("usr/share/empty/marker"), b"payload").unwrap();
        let empty = recipe::load(&ctx, "empty").unwrap();
        install_stage(&empty, &empty_stage)
            .expect("diretório leaf do consumidor reutiliza D: sem exigir vazio");
        fs::create_dir_all(ctx.world_path().parent().unwrap()).unwrap();
        fs::write(ctx.world_path(), b"direct\nempty\nmiddle\n").unwrap();
        crate::plan::finalize_applied(
            &ctx,
            &[],
            crate::plan::PlanPurpose::Rectify,
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from([
                recipe::BUILD_RUNNER_PACKAGE.to_string(),
                "depot".to_string(),
                "middle".to_string(),
                "direct".to_string(),
                "empty".to_string(),
            ]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        verify(&ctx).expect("filho de DEPS direta não altera a prova D:");
        let bucket = root.join("usr/share/depot/bucket");
        let bucket_mode = fs::metadata(&bucket).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&bucket, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            verify(&ctx).is_err(),
            "D: precisa prender o modo do diretório"
        );
        fs::set_permissions(&bucket, fs::Permissions::from_mode(bucket_mode)).unwrap();
        let saved_bucket = root.join("usr/share/depot/bucket.real");
        let outside = root.with_extension("shared-outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("marker"), b"fora").unwrap();
        fs::rename(&bucket, &saved_bucket).unwrap();
        symlink(&outside, &bucket).unwrap();
        assert!(verify(&ctx).is_err(), "D: não pode seguir symlink na folha");
        assert_eq!(fs::read(outside.join("marker")).unwrap(), b"fora");
        fs::remove_file(&bucket).unwrap();
        fs::rename(&saved_bucket, &bucket).unwrap();
        verify(&ctx).unwrap();

        let reconstructed = root.join("reconstructed-depot");
        reconstruct_stage_from_record(&ctx, "depot", &reconstructed).unwrap();
        assert!(reconstructed.join("usr/share/depot/bucket").is_dir());
        assert!(reconstructed.join("usr/share/depot/index.theme").is_file());
        assert!(
            !reconstructed
                .join("usr/share/depot/bucket/icon.png")
                .exists(),
            "emissão deve recriar D: vazio, sem copiar payload vivo do dependente"
        );
        let reconstructed_tar = root.join("reconstructed.tar");
        let rebuilt_hash = crate::pack::pack_deterministic(
            &reconstructed,
            0,
            fs::File::create(&reconstructed_tar).unwrap(),
        )
        .unwrap();
        assert_eq!(rebuilt_hash, depot_hash);

        let indirect_stage = root.join("fixtures/indirect");
        fs::create_dir_all(indirect_stage.join("usr/share/depot/bucket")).unwrap();
        fs::write(
            indirect_stage.join("usr/share/depot/bucket/forbidden.png"),
            b"nao instalar",
        )
        .unwrap();
        let indirect = recipe::load(&ctx, "indirect").unwrap();
        let (indirect_image, indirect_hash) = sealed_stage_snapshot(&indirect_stage, 0).unwrap();
        let error = install_sealed_source(
            &ctx,
            &indirect,
            false,
            &fingerprints[&indirect.name],
            &indirect_image,
            &indirect_hash,
            SourceRecordOrigin::Local,
        )
        .expect_err("dependência apenas transitiva não autoriza escrita");
        assert!(error.to_string().contains("não é DEPS direta"));
        assert!(!root.join("usr/share/depot/bucket/forbidden.png").exists());
        assert!(!ctx.records_dir().join("indirect").exists());

        let replace_stage = root.join("fixtures/replace");
        fs::create_dir_all(replace_stage.join("usr/share/depot")).unwrap();
        fs::write(replace_stage.join("usr/share/depot/bucket"), b"arquivo").unwrap();
        let replace = recipe::load(&ctx, "replace").unwrap();
        let (replace_image, replace_hash) = sealed_stage_snapshot(&replace_stage, 0).unwrap();
        assert!(install_sealed_source(
            &ctx,
            &replace,
            false,
            &fingerprints[&replace.name],
            &replace_image,
            &replace_hash,
            SourceRecordOrigin::Local,
        )
        .is_err());
        assert!(root.join("usr/share/depot/bucket").is_dir());

        memoryhole(&ctx, &["direct".into()]).unwrap();
        memoryhole(&ctx, &["empty".into()]).unwrap();
        memoryhole(&ctx, &["middle".into()]).unwrap();
        fs::write(root.join("usr/share/depot/bucket/admin"), b"preservar").unwrap();
        memoryhole(&ctx, &["depot".into()]).unwrap();
        assert_eq!(
            fs::read(root.join("usr/share/depot/bucket/admin")).unwrap(),
            b"preservar"
        );
        assert!(!ctx.records_dir().join("depot").exists());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn write_record_nao_inventa_claim_d_maiusculo_sem_declaracao() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-shared-forge-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/pkg");
        let shared = root.join("usr/share/depot");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&shared).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "pkg").unwrap();
        let mut manifest = vec![format!(
            "{}  /usr/share/depot",
            shared_directory_integrity(&shared).unwrap()
        )];
        let rec = ctx.records_dir().join("pkg");
        assert!(write_record(
            &ctx,
            &rec,
            &recipe,
            "B",
            &mut manifest,
            RecordWrite {
                artifact_hash: Some(&"a".repeat(64)),
                fingerprint: &"b".repeat(64),
                manifest_typed: true,
                source_origin: SourceRecordOrigin::Local,
                journal: None,
                baseline_extra: None,
            },
        )
        .is_err());
        assert!(
            !rec.join("manifest").exists(),
            "falha de autorização precisa ocorrer antes de publicar registro"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn memoryhole_mundo_a_preserva_payload_modificado() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-memory-a-{}-{n}", std::process::id()));
        let rec = root.join("var/lib/minitrue/records/tool");
        let version = root.join("opt/tool/1");
        let current = root.join("opt/tool/current");
        let command = root.join("usr/bin/tool");
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(&version).unwrap();
        mkparent(&command).unwrap();
        fs::write(version.join("payload"), b"ORIGINAL").unwrap();
        symlink("1", &current).unwrap();
        symlink("../../opt/tool/current/payload", &command).unwrap();
        let manifest = format!(
            "{}  /opt/tool/1\n{}  /opt/tool/current\n{}  /usr/bin/tool\n",
            path_integrity(&version).unwrap(),
            path_integrity(&current).unwrap(),
            path_integrity(&command).unwrap()
        );
        fs::write(rec.join("meta"), "NAME=tool\nWORLD=A\nDEPS=\n").unwrap();
        fs::write(rec.join("manifest"), manifest).unwrap();
        fs::write(version.join("payload"), b"MODIFICADO").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        memoryhole(&ctx, &["tool".into()]).unwrap();
        assert_eq!(fs::read(version.join("payload")).unwrap(), b"MODIFICADO");
        assert!(!current.exists());
        assert!(!command.exists());
        assert!(!rec.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn idempotencia_exige_registro_integro() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-idempotencia-{}-{n}", std::process::id()));
        let rec = root.join("var/lib/minitrue/records/pkg");
        let source = root.join("var/lib/minitrue/newspeak/pkg/recipe");
        let installed = root.join("usr/bin/tool");
        mkparent(&installed).unwrap();
        fs::create_dir_all(&rec).unwrap();
        mkparent(&source).unwrap();
        fs::write(
            &source,
            "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nbuild(){ :; }\n",
        )
        .unwrap();
        fs::write(&installed, b"original\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "pkg").unwrap();
        let manifest = format!("{}  /usr/bin/tool\n", path_integrity(&installed).unwrap());
        let baseline_hash = sha256_bytes(manifest.as_bytes());
        fs::write(
            rec.join("meta"),
            format!(
                "RECORD_FORMAT=2\nNAME=pkg\nVERSION=1\nKIND=source\nWORLD=B\nORIGIN=fonte\nSHA256=\nDEPS=\nSUPERSEDES=\nFINGERPRINT=x\nINSTALLED_AT=2026-07-21T00:00:00Z\nARTIFACT_HASH={}\nMANIFEST_BASELINE_SHA256={baseline_hash}\nTRANSACTION_ID=teste\n",
                "a".repeat(64),
            ),
        )
        .unwrap();
        fs::write(rec.join("manifest"), &manifest).unwrap();
        fs::write(rec.join("manifest@1"), &manifest).unwrap();
        fs::write(rec.join("recipe"), &recipe.recipe_bytes).unwrap();
        fs::write(rec.join("recipe@1"), &recipe.recipe_bytes).unwrap();

        assert!(
            record_is_intact(&ctx, &rec, &recipe),
            "registro v2 anterior a LICENSE deve usar o snapshot literal"
        );
        let legacy_meta = fs::read_to_string(rec.join("meta")).unwrap();
        fs::write(
            rec.join("meta"),
            legacy_meta.replace("DEPS=\n", "DEPS=\nLICENSE=MIT\n"),
        )
        .unwrap();
        assert!(
            !record_is_intact(&ctx, &rec, &recipe),
            "LICENSE factual divergente deve invalidar o fast path"
        );
        fs::write(
            rec.join("meta"),
            legacy_meta.replace("DEPS=\n", "DEPS=\nLICENSE=\n"),
        )
        .unwrap();
        assert!(
            !record_is_intact(&ctx, &rec, &recipe),
            "LICENSE factual vazia não pode cair no fallback"
        );
        fs::write(rec.join("meta"), &legacy_meta).unwrap();
        fs::write(&installed, b"adulterado\n").unwrap();
        assert!(!record_is_intact(&ctx, &rec, &recipe));
        fs::write(&installed, b"original\n").unwrap();
        fs::write(rec.join("recipe"), b"# adulterada\n").unwrap();
        assert!(!record_is_intact(&ctx, &rec, &recipe));
        fs::write(rec.join("recipe"), &recipe.recipe_bytes).unwrap();
        fs::remove_file(&installed).unwrap();
        assert!(!record_is_intact(&ctx, &rec, &recipe));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn migracao_v1_promove_provisional_legitimamente_vazio() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-migrate-v1-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/seed");
        let rec = root.join("var/lib/minitrue/records/seed");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&rec).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=seed\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nPROVISIONAL=1\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        install_factual_test_runner(&ctx);
        let recipe = recipe::load(&ctx, "seed").unwrap();
        let fingerprint = build_fingerprints_for_test(&ctx, [recipe.clone()])
            .unwrap()
            .remove("seed")
            .unwrap();
        fs::write(
            rec.join("meta"),
            format!(
                "RECORD_FORMAT=1\nNAME=seed\nVERSION=1\nKIND=source\nWORLD=B\nFINGERPRINT={fingerprint}\nPROVISIONAL=1\nARTIFACT_HASH={}\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        fs::write(rec.join("recipe"), &recipe.recipe_bytes).unwrap();
        fs::write(rec.join("recipe@1"), &recipe.recipe_bytes).unwrap();
        fs::write(rec.join("manifest"), "\n").unwrap();
        fs::write(rec.join("manifest@1"), "\n").unwrap();

        assert!(migrate_legacy_record(&ctx, &rec, &recipe, &fingerprint).unwrap());
        assert_eq!(
            read_meta(&rec)
                .unwrap()
                .get("RECORD_FORMAT")
                .map(String::as_str),
            Some(RECORD_FORMAT)
        );
        assert_eq!(fs::read(rec.join("manifest")).unwrap(), b"\n");
        assert_eq!(
            fs::read(rec.join("manifest")).unwrap(),
            fs::read(rec.join("manifest@1")).unwrap()
        );
        assert!(
            !record_is_intact(&ctx, &rec, &recipe),
            "v3 migrado é histórico e não pode virar fast path de nova operação"
        );
        let reapplied_stage = root.join("fixtures/reapply-seed");
        fs::create_dir_all(reapplied_stage.join("usr/bin")).unwrap();
        fs::write(reapplied_stage.join("usr/bin/seed"), b"seed reaplicada\n").unwrap();
        let (reapplied, artifact_hash) = sealed_stage_snapshot(&reapplied_stage, 0).unwrap();
        install_sealed_source(
            &ctx,
            &recipe,
            true,
            &fingerprint,
            &reapplied,
            &artifact_hash,
            SourceRecordOrigin::Local,
        )
        .unwrap();
        crate::plan::finalize_applied(
            &ctx,
            &[],
            crate::plan::PlanPurpose::Rectify,
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from(["seed".to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        assert_eq!(
            read_meta_strict(&rec)
                .unwrap()
                .unwrap()
                .get("RECORD_FORMAT")
                .map(String::as_str),
            Some("4")
        );
        assert!(record_is_intact(&ctx, &rec, &recipe));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn v2_integro_migra_no_fast_path_sem_canal_ou_build_em_only_binary() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-migrate-v2-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/pkg");
        let rec = root.join("var/lib/minitrue/records/pkg");
        let payload = root.join("usr/bin/pkg");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&rec).unwrap();
        mkparent(&payload).unwrap();
        fs::write(&payload, b"payload-v2\n").unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        install_factual_test_runner(&ctx);
        let recipe = recipe::load(&ctx, "pkg").unwrap();
        let fingerprint = build_fingerprints_for_test(&ctx, [recipe.clone()])
            .unwrap()
            .remove("pkg")
            .unwrap();
        let manifest = format!("{}  /usr/bin/pkg\n", path_integrity(&payload).unwrap());
        let baseline_hash = sha256_bytes(manifest.as_bytes());
        fs::write(
            rec.join("meta"),
            format!(
                "RECORD_FORMAT=2\nNAME=pkg\nVERSION=1\nKIND=source\nWORLD=B\nORIGIN=fonte\nSHA256=\nDEPS=\nFINGERPRINT={fingerprint}\nINSTALLED_AT=2026-08-11T00:00:00Z\nARTIFACT_HASH={}\nLICENSE=NOASSERTION\nSUPERSEDES=\nMANIFEST_BASELINE_SHA256={baseline_hash}\nTRANSACTION_ID=v2\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        fs::write(rec.join("manifest"), &manifest).unwrap();
        fs::write(rec.join("manifest@1"), &manifest).unwrap();
        fs::write(rec.join("recipe"), &recipe.recipe_bytes).unwrap();
        fs::write(rec.join("recipe@1"), &recipe.recipe_bytes).unwrap();

        assert!(record_is_intact(&ctx, &rec, &recipe));
        assert!(
            !source_needs_install(&ctx, &recipe, &fingerprint, BinaryPolicy::BinaryOnly).unwrap(),
            "mudança apenas de schema não pode procurar canal nem expandir BUILD_DEPS"
        );
        let active_plan = crate::plan::resolve(
            &ctx,
            &["pkg".to_string()],
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Development,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        let frozen = FrozenBuildGraph::new(&active_plan);
        let legacy_error = install_one(
            &ctx,
            &recipe,
            false,
            &fingerprint,
            BinaryPolicy::BinaryOnly,
            None,
            &frozen,
        )
        .expect_err("v2 migrado para v3 não pode atravessar novo fast path --only-binary");
        assert!(legacy_error.to_string().contains("sem seleção congelada"));
        let migrated = read_meta_strict(&rec).unwrap().unwrap();
        assert_eq!(migrated.get("RECORD_FORMAT").map(String::as_str), Some("3"));
        assert_eq!(migrated.get("SHARED_DIRS").map(String::as_str), Some(""));
        assert_eq!(fs::read(&payload).unwrap(), b"payload-v2\n");
        assert!(!record_is_intact(&ctx, &rec, &recipe));
        assert!(
            source_needs_install(&ctx, &recipe, &fingerprint, BinaryPolicy::BinaryOnly).unwrap()
        );

        let stage = root.join("fixtures/reapply-pkg/usr/bin");
        fs::create_dir_all(&stage).unwrap();
        fs::write(stage.join("pkg"), b"payload-v2\n").unwrap();
        let stage_root = root.join("fixtures/reapply-pkg");
        let (sealed, artifact_hash) = sealed_stage_snapshot(&stage_root, 0).unwrap();
        install_sealed_source(
            &ctx,
            &recipe,
            true,
            &fingerprint,
            &sealed,
            &artifact_hash,
            SourceRecordOrigin::Local,
        )
        .unwrap();
        crate::plan::finalize_applied(
            &ctx,
            &[],
            crate::plan::PlanPurpose::Rectify,
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from(["pkg".to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        assert!(record_is_intact(&ctx, &rec, &recipe));
        assert_eq!(
            read_meta_strict(&rec)
                .unwrap()
                .unwrap()
                .get("RECORD_FORMAT")
                .map(String::as_str),
            Some("4")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migracao_v1_binaria_preserva_txid_factual_no_fast_path() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-migrate-v1-a-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/tool");
        let rec = root.join("var/lib/minitrue/records/tool");
        let payload = root.join("opt/tool/1/bin/tool");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&rec).unwrap();
        mkparent(&payload).unwrap();
        fs::write(&payload, b"payload\n").unwrap();
        symlink("1", root.join("opt/tool/current")).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            format!(
                "NAME=tool\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://invalid.example/tool\nSHA256={}\ninstall_pkg() {{ mkdir -p \"$PREFIX/bin\"; cp \"$DL\" \"$PREFIX/bin/tool\"; }}\n",
                sha256_bytes(b"payload\n")
            ),
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "tool").unwrap();
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            ctx.cache_dir().join(sha256_bytes(b"payload\n")),
            b"payload\n",
        )
        .unwrap();
        let fingerprint = recipe::build_fingerprints(std::slice::from_ref(&recipe))
            .unwrap()
            .remove("tool")
            .unwrap();
        fs::write(
            rec.join("meta"),
            format!(
                "RECORD_FORMAT=1\nNAME=tool\nVERSION=1\nKIND=binary\nWORLD=A\nFINGERPRINT={fingerprint}\n"
            ),
        )
        .unwrap();
        fs::write(rec.join("recipe"), &recipe.recipe_bytes).unwrap();
        fs::write(rec.join("recipe@1"), &recipe.recipe_bytes).unwrap();
        let legacy_manifest = "/opt/tool/1\n/opt/tool/current\n/opt/tool/1/bin/tool\n";
        fs::write(rec.join("manifest"), legacy_manifest).unwrap();
        fs::write(rec.join("manifest@1"), legacy_manifest).unwrap();

        assert!(migrate_legacy_record(&ctx, &rec, &recipe, &fingerprint).unwrap());
        let migrated = read_meta_strict(&rec).unwrap().unwrap();
        assert!(migrated
            .get("TRANSACTION_ID")
            .is_some_and(|value| !value.is_empty()));
        assert!(
            !record_is_intact(&ctx, &rec, &recipe),
            "v3 histórico migrado não é fast path de uma nova operação"
        );
        assert!(binary_needs_install(&ctx, &recipe, &fingerprint).unwrap());

        let canonical = fs::read_to_string(rec.join("meta")).unwrap();
        let txid = migrated.get("TRANSACTION_ID").unwrap();
        fs::write(
            rec.join("meta"),
            canonical.replace(&format!("TRANSACTION_ID={txid}\n"), "TRANSACTION_ID=\n"),
        )
        .unwrap();
        assert!(!record_is_intact(&ctx, &rec, &recipe));
        assert!(binary_needs_install(&ctx, &recipe, &fingerprint).unwrap());
        fs::write(rec.join("meta"), canonical).unwrap();

        install_binary(&ctx, &recipe, true, &fingerprint).unwrap();
        assert_eq!(
            read_meta_strict(&rec)
                .unwrap()
                .unwrap()
                .get("RECORD_FORMAT")
                .map(String::as_str),
            Some("3")
        );
        crate::plan::finalize_applied(
            &ctx,
            &[],
            crate::plan::PlanPurpose::Rectify,
            BinaryPolicy::PreferBinary,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from(["tool".to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        assert!(record_is_intact(&ctx, &rec, &recipe));
        assert_eq!(
            read_meta_strict(&rec)
                .unwrap()
                .unwrap()
                .get("RECORD_FORMAT")
                .map(String::as_str),
            Some("4")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_exige_sucessor_para_claim_removida_do_provisional_v2() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-verify-cession-{}-{n}", std::process::id()));
        let records = root.join("var/lib/minitrue/records");
        let installed = root.join("usr/bin/cedido");
        fs::create_dir_all(&records).unwrap();
        mkparent(&installed).unwrap();
        fs::write(&installed, b"payload do sucessor\n").unwrap();
        let claim = format!("{}  /usr/bin/cedido\n", path_integrity(&installed).unwrap());

        let write_v2_record = |name: &str,
                               provisional: bool,
                               supersedes: &str,
                               active: &str,
                               baseline: &str| {
            let rec = records.join(name);
            fs::create_dir_all(&rec).unwrap();
            let provisional_meta = if provisional { "PROVISIONAL=1\n" } else { "" };
            let recipe = format!(
                    "NAME={name}\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\n{provisional_meta}SUPERSEDES={supersedes}\nbuild() {{ :; }}\n"
                );
            fs::write(
                    rec.join("meta"),
                    format!(
                        "RECORD_FORMAT=2\nNAME={name}\nVERSION=1\nKIND=source\nWORLD=B\nORIGIN=fonte\nSHA256=\nDEPS=\nFINGERPRINT={}\nINSTALLED_AT=2026-08-11T00:00:00Z\nARTIFACT_HASH={}\nLICENSE=NOASSERTION\n{provisional_meta}SUPERSEDES={supersedes}\nMANIFEST_BASELINE_SHA256={}\nTRANSACTION_ID=fixture\n",
                        "a".repeat(64),
                        "b".repeat(64),
                        sha256_bytes(baseline.as_bytes()),
                    ),
                )
                .unwrap();
            fs::write(rec.join("manifest"), active).unwrap();
            fs::write(rec.join("manifest@1"), baseline).unwrap();
            fs::write(rec.join("recipe"), &recipe).unwrap();
            fs::write(rec.join("recipe@1"), recipe).unwrap();
        };

        write_v2_record("semente", true, "", "\n", &claim);
        let context = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        assert!(
            verify(&context).is_err(),
            "baseline menos ativo sem dono não pode receber thinkpol"
        );

        write_v2_record("sucessor", false, "semente", &claim, &claim);
        assert!(
            verify_historical_record(&context, &records.join("semente"), "semente").is_ok(),
            "o sucessor fecha a prova histórica da cessão para migração"
        );
        assert!(
            verify(&context).is_err(),
            "records v2, ainda que coerentes, não são estado global atestável sem v4+receipt"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cessao_provisional_distingue_cessao_legitima_de_truncamento() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-frozen-v1-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/seed");
        let rec = root.join("var/lib/minitrue/records/seed");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&rec).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=seed\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nPROVISIONAL=1\nABOUT=novo\nbuild(){ :; }\n",
        )
        .unwrap();
        let historical = b"NAME=seed\nVERSION=1\nKIND=source\nPROVISIONAL=1\nbuild(){ :; }\n";
        fs::write(rec.join("recipe"), historical).unwrap();
        fs::write(rec.join("recipe@1"), historical).unwrap();
        fs::write(
            rec.join("meta"),
            "RECORD_FORMAT=1\nNAME=seed\nVERSION=1\nKIND=source\nWORLD=B\nFINGERPRINT=antigo\nPROVISIONAL=1\n",
        )
        .unwrap();
        fs::write(rec.join("manifest"), "\n").unwrap();
        fs::write(rec.join("manifest@1"), "/usr/bin/cedido\n").unwrap();
        let successor = root.join("var/lib/minitrue/records/real");
        fs::create_dir_all(&successor).unwrap();
        fs::write(
            successor.join("meta"),
            "RECORD_FORMAT=1\nNAME=real\nVERSION=1\nWORLD=B\n",
        )
        .unwrap();
        fs::write(successor.join("manifest"), "/usr/bin/cedido\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "seed").unwrap();

        assert_eq!(
            provisional_cession_state(&ctx, &rec, &recipe).unwrap(),
            ProvisionalCession::Intact
        );
        fs::remove_dir_all(&successor).unwrap();
        assert_eq!(
            provisional_cession_state(&ctx, &rec, &recipe).unwrap(),
            ProvisionalCession::Unproved,
            "linha removida sem sucessor é estruturalmente íntegra, mas não está provada"
        );
        fs::create_dir_all(&successor).unwrap();
        fs::write(
            successor.join("meta"),
            "RECORD_FORMAT=1\nNAME=real\nVERSION=1\nWORLD=B\nPROVISIONAL=1\nSUPERSEDES=seed\n",
        )
        .unwrap();
        fs::write(successor.join("manifest"), "/usr/bin/cedido\n").unwrap();
        assert_eq!(
            provisional_cession_state(&ctx, &rec, &recipe).unwrap(),
            ProvisionalCession::Intact,
            "sucessor provisional declarado preserva a prova transitiva"
        );
        fs::write(
            successor.join("meta"),
            "RECORD_FORMAT=1\nNAME=real\nVERSION=1\nWORLD=B\nPROVISIONAL=1\nSUPERSEDES=outra-semente\n",
        )
        .unwrap();
        assert_eq!(
            provisional_cession_state(&ctx, &rec, &recipe).unwrap(),
            ProvisionalCession::Unproved,
            "provisional arbitrário não pode legitimar truncamento"
        );
        fs::write(
            successor.join("meta"),
            "RECORD_FORMAT=1\nNAME=real\nVERSION=1\nWORLD=B\n",
        )
        .unwrap();
        fs::write(successor.join("manifest"), "/usr/bin/cedido\n").unwrap();
        // ESTE BLOCO JA AFIRMOU O CONTRARIO. Ele chamava install_source com um
        // fingerprint novo e exigia que NADA mudasse — que o registro ficasse
        // congelado com "antigo". Era a especificacao do defeito: toda correcao
        // de receita num provisional cedido morria em silencio, e o teste
        // guardava esse silencio.
        //
        // O que se exige agora e que o conjunto cedido seja IDENTIFICADO com
        // precisao, porque e dele que o refresh depende para nao retomar o que
        // ja nao e seu. A reconstrucao em si nao cabe num teste de unidade: ela
        // roda o build() de verdade, com plano de toolchain e artefato selado.
        let cedidos = cedidos_do_registro(&ctx, &rec).unwrap();
        assert_eq!(
            cedidos.iter().map(|(c, _)| c.as_str()).collect::<Vec<_>>(),
            vec!["/usr/bin/cedido"],
            "o cedido e exatamente baseline menos ativo"
        );
        assert_eq!(
            cedidos[0].1, "/usr/bin/cedido",
            "a linha volta VERBATIM do baseline; recalcula-la leria o arquivo \
             do sucessor e gravaria a integridade DELE no registro do cedente"
        );

        // Um pacote que nao e provisional nunca tem cedidos, ainda que os
        // manifestos difiram — a diferenca ali seria corrupcao, nao cessao.
        let comum = root.join("var/lib/minitrue/records/comum");
        fs::create_dir_all(&comum).unwrap();
        fs::write(
            comum.join("meta"),
            "RECORD_FORMAT=1\nNAME=comum\nVERSION=1\nWORLD=B\n",
        )
        .unwrap();
        fs::write(comum.join("manifest"), "\n").unwrap();
        fs::write(comum.join("manifest@1"), "/usr/bin/x\n").unwrap();
        assert!(
            cedidos_do_registro(&ctx, &comum).unwrap().is_empty(),
            "so provisional cede; para o resto a diferenca e defeito"
        );

        // Sem registro nenhum tambem nao ha cedidos — o caminho de instalacao
        // limpa passa por aqui e nao pode pular nada.
        assert!(
            cedidos_do_registro(&ctx, &root.join("var/lib/minitrue/records/inexistente"))
                .unwrap()
                .is_empty()
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// O baseline nao encolhe junto com o ativo no refresh de um provisional
    /// cedido, e isso NAO e detalhe de contabilidade: se ele encolhesse,
    /// `provisional_cession_state` passaria a responder `NotCeded` e a proxima
    /// correcao de receita cairia no caminho de reconstrucao comum, que tentaria
    /// reivindicar de volta os caminhos dos sucessores e morreria em
    /// doublethink. O bug seria uma operacao depois do refresh, longe daqui.
    #[test]
    fn refresh_encolhe_o_ativo_e_preserva_o_baseline() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-refresh-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/seed");
        let rec = root.join("var/lib/minitrue/records/seed");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&rec).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/meu"), b"conteudo").unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=seed\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nPROVISIONAL=1\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "seed").unwrap();

        let cedida = "/usr/bin/cedido".to_string();
        let mut manifest = vec!["/usr/bin/meu".to_string()];
        write_record(
            &ctx,
            &rec,
            &recipe,
            "B",
            &mut manifest,
            RecordWrite {
                artifact_hash: None,
                fingerprint: "novo",
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: None,
                baseline_extra: Some(std::slice::from_ref(&cedida)),
            },
        )
        .unwrap();

        let ativo = fs::read_to_string(rec.join("manifest")).unwrap();
        let baseline = fs::read_to_string(rec.join("manifest@1")).unwrap();
        assert!(ativo.contains("/usr/bin/meu"), "o ativo tem o que e dele");
        assert!(
            !ativo.contains("/usr/bin/cedido"),
            "o ativo NAO pode reivindicar o que foi cedido"
        );
        assert!(
            baseline.contains("/usr/bin/meu") && baseline.contains("/usr/bin/cedido"),
            "o baseline guarda os dois: e a memoria do que ja foi deste pacote"
        );

        // O MANIFEST_BASELINE_SHA256 acompanha o ARQUIVO manifest@<versao>, e e
        // assim que provisional_cession_state o confere. Apontar para o ativo
        // deixaria todo registro refrescado "incoerente" na operacao seguinte.
        let meta = read_meta_strict(&rec).unwrap().unwrap();
        assert_eq!(
            meta.get("MANIFEST_BASELINE_SHA256").map(String::as_str),
            Some(sha256_bytes(baseline.as_bytes()).as_str()),
            "o hash do baseline e do baseline, nao do ativo"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// VERSION da arvore descreve o upgrade desejado; VERSION do registro
    /// escolhe os snapshots que provam a cessao ja consumada. Confundir as
    /// duas fazia um provisional 1.0 cedido virar `Incoherent` assim que a
    /// receita passava a 2.0, antes de o refresh ter chance de preservar o
    /// baseline.
    #[test]
    fn upgrade_provisional_cedido_usa_snapshot_instalado_e_preserva_baseline() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-upgrade-provisional-{}-{n}", std::process::id()));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let recipe_dir = recipes.join("seed");
        let rec = root.join("var/lib/minitrue/records/seed");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(recipes.join("real")).unwrap();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        let cedido_regular = root.join("usr/lib/cedido-regular");
        let cedido_link = root.join("usr/lib/cedido-link");
        fs::write(&cedido_regular, b"bytes glibc do sucessor").unwrap();
        fs::write(root.join("usr/lib/alvo-glibc"), b"alvo glibc").unwrap();
        symlink("alvo-glibc", &cedido_link).unwrap();

        let recipe_v1 = "NAME=seed\nVERSION=1.0\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nPROVISIONAL=1\nbuild(){ :; }\n";
        fs::write(recipe_dir.join("recipe"), recipe_v1).unwrap();
        fs::write(
            recipes.join("real/recipe"),
            "NAME=real\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        install_factual_test_runner(&ctx);
        let v1 = recipe::load(&ctx, "seed").unwrap();
        let fingerprint_v1 = build_fingerprints_for_test(&ctx, [v1.clone()])
            .unwrap()
            .remove("seed")
            .unwrap();
        let artifact_v1 = "1".repeat(64);
        let mut manifest_v1 = vec![
            "/usr/lib/cedido-regular".to_string(),
            "/usr/lib/cedido-link".to_string(),
        ];
        write_record(
            &ctx,
            &rec,
            &v1,
            "B",
            &mut manifest_v1,
            RecordWrite {
                artifact_hash: Some(&artifact_v1),
                fingerprint: &fingerprint_v1,
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: None,
                baseline_extra: None,
            },
        )
        .unwrap();

        // A cessao encolhe apenas o ativo. O baseline e o snapshot v1 ficam
        // imutaveis, e um sucessor real passa a provar ownership do ausente.
        fs::write(rec.join("manifest"), "\n").unwrap();
        let successor = root.join("var/lib/minitrue/records/real");
        let real = recipe::load(&ctx, "real").unwrap();
        let fingerprint_real = build_fingerprints_for_test(&ctx, [real.clone()])
            .unwrap()
            .remove("real")
            .unwrap();
        let artifact_real = "2".repeat(64);
        let mut manifest_real = vec![
            "/usr/lib/cedido-regular".to_string(),
            "/usr/lib/cedido-link".to_string(),
        ];
        let mut real_journal = Journal::begin(&ctx, "real").unwrap();
        write_record(
            &ctx,
            &successor,
            &real,
            "B",
            &mut manifest_real,
            RecordWrite {
                artifact_hash: Some(&artifact_real),
                fingerprint: &fingerprint_real,
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: Some(&mut real_journal),
                baseline_extra: None,
            },
        )
        .unwrap();
        real_journal.commit().unwrap();

        let recipe_v2 = recipe_v1.replace("VERSION=1.0", "VERSION=2.0");
        fs::write(recipe_dir.join("recipe"), recipe_v2).unwrap();
        let v2 = recipe::load(&ctx, "seed").unwrap();
        let fingerprint_v2 = build_fingerprints_for_test(&ctx, [v2.clone()])
            .unwrap()
            .remove("seed")
            .unwrap();
        assert_eq!(
            provisional_cession_state(&ctx, &rec, &v2).unwrap(),
            ProvisionalCession::Intact,
            "o estado instalado 1.0, nao a VERSION desejada 2.0, prova a cessao"
        );
        assert!(
            source_needs_install(&ctx, &v2, &fingerprint_v2, BinaryPolicy::PreferBinary).unwrap(),
            "cessao integra nao pode esconder um upgrade de identidade"
        );

        let cedidos = cedidos_do_registro(&ctx, &rec).unwrap();
        assert_eq!(cedidos.len(), 2);
        assert_eq!(
            cedidos
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["/usr/lib/cedido-link", "/usr/lib/cedido-regular"]
        );

        // O STAGE novo tenta substituir justamente as duas claims já cedidas,
        // uma regular e um symlink, além de trazer uma folha realmente nova.
        // O aplicador precisa instalar só a nova; bytes e alvo vivos pertencem
        // ao sucessor e são intocáveis.
        let stage = root.join("stage-v2");
        fs::create_dir_all(stage.join("usr/lib")).unwrap();
        fs::write(
            stage.join("usr/lib/cedido-regular"),
            b"bytes musl da semente",
        )
        .unwrap();
        symlink("alvo-musl", stage.join("usr/lib/cedido-link")).unwrap();
        fs::write(stage.join("usr/lib/novo-da-semente"), b"novo").unwrap();
        let (sealed, reprocorr) = sealed_stage_snapshot(&stage, 1_704_067_200).unwrap();
        install_sealed_source(
            &ctx,
            &v2,
            false,
            &fingerprint_v2,
            &sealed,
            &reprocorr,
            SourceRecordOrigin::Local,
        )
        .unwrap();

        assert_eq!(
            fs::read(&cedido_regular).unwrap(),
            b"bytes glibc do sucessor"
        );
        assert_eq!(
            fs::read_link(&cedido_link).unwrap(),
            PathBuf::from("alvo-glibc")
        );
        assert_eq!(
            fs::read(root.join("usr/lib/novo-da-semente")).unwrap(),
            b"novo"
        );

        let active_v2 = read_manifest_strict(&rec).unwrap();
        let baseline_v2 = read_versioned_manifest_strict(&rec, "2.0").unwrap();
        assert_eq!(
            active_v2
                .iter()
                .map(|line| manifest_path(line))
                .collect::<Vec<_>>(),
            vec!["/usr/lib/novo-da-semente"],
            "o ativo leva só o caminho novo, nunca os dois cedidos"
        );
        let mut baseline_v2_paths: Vec<&str> =
            baseline_v2.iter().map(|line| manifest_path(line)).collect();
        baseline_v2_paths.sort_unstable();
        assert_eq!(
            baseline_v2_paths,
            vec![
                "/usr/lib/cedido-link",
                "/usr/lib/cedido-regular",
                "/usr/lib/novo-da-semente",
            ],
            "o baseline 2.0 carrega adiante a memoria das claims cedidas em 1.0"
        );
        assert_eq!(
            provisional_cession_state(&ctx, &rec, &v2).unwrap(),
            ProvisionalCession::Intact
        );
        assert!(
            source_needs_install(&ctx, &v2, &fingerprint_v2, BinaryPolicy::PreferBinary).unwrap(),
            "o refresh produz v3 desta operação, nunca fast path histórico"
        );
        fs::create_dir_all(ctx.world_path().parent().unwrap()).unwrap();
        fs::write(ctx.world_path(), b"real\nseed\n").unwrap();
        assert!(
            !source_needs_install_for_plan(
                &ctx,
                &real,
                &fingerprint_real,
                BinaryPolicy::SourceOnly,
                true,
            )
            .unwrap(),
            "o record corrente do sucessor precisa pertencer à operação factual"
        );
        assert!(
            !source_needs_install_for_plan(
                &ctx,
                &v2,
                &fingerprint_v2,
                BinaryPolicy::SourceOnly,
                true,
            )
            .unwrap(),
            "o refresh da semente precisa pertencer à operação factual"
        );
        crate::plan::finalize_applied(
            &ctx,
            &[],
            crate::plan::PlanPurpose::Rectify,
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from(["real".to_string(), "seed".to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        assert!(
            !source_needs_install(&ctx, &v2, &fingerprint_v2, BinaryPolicy::PreferBinary).unwrap(),
            "somente o v4 factual fechado volta a ser idempotente"
        );
        verify(&ctx).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    /// Um sucessor também pode deixar de produzir uma claim entre versões. O
    /// registro antigo da semente então perde a prova viva da cessão, mas isso
    /// não autoriza nem retomar o caminho nem aceitar truncamento como fast
    /// path: somente outra identidade, com STAGE selado que também omite a
    /// claim já ausente do root, pode aposentá-la do baseline novo.
    #[test]
    fn upgrade_provisional_aposenta_claim_omitida_por_ambos_sem_retomada() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-upgrade-provisional-retire-{}-{n}",
            std::process::id()
        ));
        let recipes = root.join("var/lib/minitrue/newspeak");
        let seed_recipe_dir = recipes.join("seed");
        let successor_recipe_dir = recipes.join("real");
        let seed_record = root.join("var/lib/minitrue/records/seed");
        let successor_record = root.join("var/lib/minitrue/records/real");
        let kept = root.join("usr/bin/mantido");
        let retired = root.join("usr/bin/aposentado");
        fs::create_dir_all(&seed_recipe_dir).unwrap();
        fs::create_dir_all(&successor_recipe_dir).unwrap();
        mkparent(&kept).unwrap();
        fs::write(&kept, b"sucessor v1: mantido\n").unwrap();
        fs::write(&retired, b"sucessor v1: aposentado\n").unwrap();

        let seed_v1_text = "NAME=seed\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nPROVISIONAL=1\nbuild(){ :; }\n";
        let successor_v1_text = "NAME=real\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nSUPERSEDES=seed\nbuild(){ :; }\n";
        fs::write(seed_recipe_dir.join("recipe"), seed_v1_text).unwrap();
        fs::write(successor_recipe_dir.join("recipe"), successor_v1_text).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        install_factual_test_runner(&ctx);

        let seed_v1 = recipe::load(&ctx, "seed").unwrap();
        let seed_v1_fingerprint = build_fingerprints_for_test(&ctx, [seed_v1.clone()])
            .unwrap()
            .remove("seed")
            .unwrap();
        let mut seed_v1_manifest = vec![
            "/usr/bin/mantido".to_string(),
            "/usr/bin/aposentado".to_string(),
        ];
        write_record(
            &ctx,
            &seed_record,
            &seed_v1,
            "B",
            &mut seed_v1_manifest,
            RecordWrite {
                artifact_hash: Some(&"1".repeat(64)),
                fingerprint: &seed_v1_fingerprint,
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: None,
                baseline_extra: None,
            },
        )
        .unwrap();
        fs::write(seed_record.join("manifest"), "\n").unwrap();

        let successor_v1 = recipe::load(&ctx, "real").unwrap();
        let successor_v1_fingerprint = build_fingerprints_for_test(&ctx, [successor_v1.clone()])
            .unwrap()
            .remove("real")
            .unwrap();
        let mut successor_v1_manifest = vec![
            "/usr/bin/mantido".to_string(),
            "/usr/bin/aposentado".to_string(),
        ];
        write_record(
            &ctx,
            &successor_record,
            &successor_v1,
            "B",
            &mut successor_v1_manifest,
            RecordWrite {
                artifact_hash: Some(&"2".repeat(64)),
                fingerprint: &successor_v1_fingerprint,
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: None,
                baseline_extra: None,
            },
        )
        .unwrap();
        assert_eq!(
            provisional_cession_state(&ctx, &seed_record, &seed_v1).unwrap(),
            ProvisionalCession::Intact
        );

        // O sucessor v2 conserva uma claim e aposenta a outra, inclusive do
        // filesystem. Seu manifesto corrente já não prova a segunda cessão.
        fs::write(&kept, b"sucessor v2: mantido\n").unwrap();
        fs::remove_file(&retired).unwrap();
        fs::write(
            successor_recipe_dir.join("recipe"),
            successor_v1_text.replace("VERSION=1", "VERSION=2"),
        )
        .unwrap();
        let successor_v2 = recipe::load(&ctx, "real").unwrap();
        let successor_v2_fingerprint = build_fingerprints_for_test(&ctx, [successor_v2.clone()])
            .unwrap()
            .remove("real")
            .unwrap();
        let mut successor_v2_manifest = vec!["/usr/bin/mantido".to_string()];
        let mut successor_v2_journal = Journal::begin(&ctx, "real").unwrap();
        write_record(
            &ctx,
            &successor_record,
            &successor_v2,
            "B",
            &mut successor_v2_manifest,
            RecordWrite {
                artifact_hash: Some(&"3".repeat(64)),
                fingerprint: &successor_v2_fingerprint,
                manifest_typed: false,
                source_origin: SourceRecordOrigin::Local,
                journal: Some(&mut successor_v2_journal),
                baseline_extra: None,
            },
        )
        .unwrap();
        successor_v2_journal.commit().unwrap();

        assert_eq!(
            provisional_cession_state(&ctx, &seed_record, &seed_v1).unwrap(),
            ProvisionalCession::Unproved
        );
        assert!(verify(&ctx).is_err(), "verify continua estrito");
        assert!(
            source_needs_install(
                &ctx,
                &seed_v1,
                &seed_v1_fingerprint,
                BinaryPolicy::PreferBinary
            )
            .is_err(),
            "manifesto truncado sem upgrade não pode atravessar o preflight"
        );

        fs::write(
            seed_recipe_dir.join("recipe"),
            seed_v1_text.replace("VERSION=1", "VERSION=2"),
        )
        .unwrap();
        let seed_v2 = recipe::load(&ctx, "seed").unwrap();
        let seed_v2_fingerprint = build_fingerprints_for_test(&ctx, [seed_v2.clone()])
            .unwrap()
            .remove("seed")
            .unwrap();
        fs::write(&retired, b"arquivo orfao ainda presente\n").unwrap();
        assert!(
            source_needs_install(
                &ctx,
                &seed_v2,
                &seed_v2_fingerprint,
                BinaryPolicy::PreferBinary
            )
            .is_err(),
            "identidade nova não basta enquanto a claim órfã ainda existe no root"
        );
        assert_eq!(
            fs::read(&retired).unwrap(),
            b"arquivo orfao ainda presente\n"
        );
        fs::remove_file(&retired).unwrap();
        assert!(source_needs_install(
            &ctx,
            &seed_v2,
            &seed_v2_fingerprint,
            BinaryPolicy::PreferBinary
        )
        .unwrap());

        // Se a semente nova ainda produz a claim órfã, não há decisão segura
        // de ownership. A recusa ocorre antes do Journal: não instala a cópia
        // da semente, não remove nada e não regrava o registro v1.
        let bad_stage = root.join("stage-seed-v2-reapresenta");
        fs::create_dir_all(bad_stage.join("usr/bin")).unwrap();
        fs::write(bad_stage.join("usr/bin/mantido"), b"semente v2\n").unwrap();
        fs::write(
            bad_stage.join("usr/bin/aposentado"),
            b"semente v2 reapresentou\n",
        )
        .unwrap();
        let (bad_sealed, bad_hash) = sealed_stage_snapshot(&bad_stage, 1_704_067_200).unwrap();
        let error = install_sealed_source(
            &ctx,
            &seed_v2,
            false,
            &seed_v2_fingerprint,
            &bad_sealed,
            &bad_hash,
            SourceRecordOrigin::Local,
        )
        .expect_err("reapresentação não pode retomar claim órfã");
        assert!(error.to_string().contains("retomada automática recusada"));
        assert_eq!(fs::read(&kept).unwrap(), b"sucessor v2: mantido\n");
        assert!(!retired.exists());
        assert_eq!(
            read_meta_strict(&seed_record)
                .unwrap()
                .unwrap()
                .get("VERSION")
                .map(String::as_str),
            Some("1")
        );

        // Quando os dois produtores omitem a órfã, sua ausência no root fecha
        // a terceira prova. A claim ainda possuída pelo sucessor continua no
        // baseline; apenas a aposentada desaparece.
        let good_stage = root.join("stage-seed-v2-omite");
        fs::create_dir_all(good_stage.join("usr/bin")).unwrap();
        fs::write(good_stage.join("usr/bin/mantido"), b"semente v2\n").unwrap();
        let (good_sealed, good_hash) = sealed_stage_snapshot(&good_stage, 1_704_067_200).unwrap();
        install_sealed_source(
            &ctx,
            &seed_v2,
            false,
            &seed_v2_fingerprint,
            &good_sealed,
            &good_hash,
            SourceRecordOrigin::Local,
        )
        .unwrap();

        assert_eq!(fs::read(&kept).unwrap(), b"sucessor v2: mantido\n");
        assert!(!retired.exists());
        assert!(read_manifest_strict(&seed_record).unwrap().is_empty());
        let seed_v2_baseline = read_versioned_manifest_strict(&seed_record, "2").unwrap();
        assert_eq!(
            seed_v2_baseline
                .iter()
                .map(|line| manifest_path(line))
                .collect::<Vec<_>>(),
            vec!["/usr/bin/mantido"]
        );
        assert_eq!(
            provisional_cession_state(&ctx, &seed_record, &seed_v2).unwrap(),
            ProvisionalCession::Intact
        );
        fs::create_dir_all(ctx.world_path().parent().unwrap()).unwrap();
        fs::write(ctx.world_path(), b"real\nseed\n").unwrap();
        assert!(
            !source_needs_install_for_plan(
                &ctx,
                &successor_v2,
                &successor_v2_fingerprint,
                BinaryPolicy::SourceOnly,
                true,
            )
            .unwrap(),
            "o sucessor v2 precisa ser record factual desta operação"
        );
        assert!(
            !source_needs_install_for_plan(
                &ctx,
                &seed_v2,
                &seed_v2_fingerprint,
                BinaryPolicy::SourceOnly,
                true,
            )
            .unwrap(),
            "a semente v2 precisa ser record factual desta operação"
        );
        crate::plan::finalize_applied(
            &ctx,
            &[],
            crate::plan::PlanPurpose::Rectify,
            BinaryPolicy::SourceOnly,
            crate::plan::AbiPolicy::Strict,
            &BTreeSet::from(["real".to_string(), "seed".to_string()]),
            crate::plan::AppliedClosure::Complete,
        )
        .unwrap();
        verify(&ctx).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    /// materialize_etc trata symlink em /etc — regressão do openssl (instala
    /// A COMPARAÇÃO DE TRÊS PONTOS. Sem o terceiro — o selo da fábrica
    /// ANTERIOR — o /etc congelava na primeira mudança de receita: comparava-se
    /// o arquivo vivo com a fábrica NOVA, os dois diferiam por definição, e o
    /// minitrue lia isso como edição do administrador. Medido na árvore: 14
    /// arquivos parados na era 0.1, com /etc/hostname dizendo `airstrip1`
    /// enquanto as receitas estavam na 0.10.
    ///
    /// Os dois lados importam igualmente, e por isso estão no mesmo teste: o
    /// default tem de andar quando ninguém mexeu, e a edição do administrador
    /// tem de sobreviver quando alguém mexeu.
    #[test]
    fn materialize_etc_tres_pontos() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-3p-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let fab = root.join("usr/share/factory/etc/exemplo.conf");
        mkparent(&fab).unwrap();
        let live = root.join("etc/exemplo.conf");
        let mut jrnl = Journal::begin(&ctx, "test").unwrap();

        // v1 chega num /etc vazio: materializa direto.
        fs::write(&fab, b"versao=1\n").unwrap();
        materialize_etc(&mut jrnl, &ctx, &fab, "exemplo.conf", None).unwrap();
        assert_eq!(fs::read_to_string(&live).unwrap(), "versao=1\n");

        // O selo da fábrica v1, que é o que o manifesto guardaria.
        let modo_v1 = fs::symlink_metadata(&fab).unwrap().permissions().mode() & 0o7777;
        let selo_v1 = regular_integrity(modo_v1, &sha256_bytes(b"versao=1\n"));

        // LADO A: a receita muda para v2 e NINGUÉM editou o vivo. O default
        // anda e não há .new.
        fs::write(&fab, b"versao=2\n").unwrap();
        materialize_etc(&mut jrnl, &ctx, &fab, "exemplo.conf", Some(&selo_v1)).unwrap();
        assert_eq!(
            fs::read_to_string(&live).unwrap(),
            "versao=2\n",
            "o /etc devia acompanhar a receita quando ninguem o editou"
        );
        assert!(
            !root.join("etc/exemplo.conf.new").exists(),
            "nao se escreve .new quando nao houve edicao"
        );

        // LADO B: agora o administrador edita, e a receita vai para v3. A
        // edicao sobrevive e o default novo fica ao lado.
        fs::write(&live, b"versao=2\nlocal=sim\n").unwrap();
        let selo_v2 = regular_integrity(modo_v1, &sha256_bytes(b"versao=2\n"));
        fs::write(&fab, b"versao=3\n").unwrap();
        materialize_etc(&mut jrnl, &ctx, &fab, "exemplo.conf", Some(&selo_v2)).unwrap();
        assert_eq!(
            fs::read_to_string(&live).unwrap(),
            "versao=2\nlocal=sim\n",
            "a edicao do administrador tem de sobreviver"
        );
        assert_eq!(
            fs::read_to_string(root.join("etc/exemplo.conf.new")).unwrap(),
            "versao=3\n",
            "o default novo vai para .new"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// /etc/ssl/misc/tsget -> tsget.pl, e o alvo ainda não existe na fábrica
    /// quando o link é materializado, pela ordem alfabética da walk). O bug era
    /// `fs::copy` seguir o link e estourar ENOENT.
    #[test]
    fn materialize_etc_symlink() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-etc-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let fdir = root.join("usr/share/factory/etc/ssl/misc");
        fs::create_dir_all(&fdir).unwrap();
        let mut jrnl = Journal::begin(&ctx, "test").unwrap();

        // default que é symlink, com ALVO AUSENTE na fábrica (ordem da walk)
        let link = fdir.join("tsget");
        symlink("tsget.pl", &link).unwrap();
        materialize_etc(&mut jrnl, &ctx, &link, "ssl/misc/tsget", None)
            .expect("symlink em /etc não deve dar ENOENT");
        let live = root.join("etc/ssl/misc/tsget");
        let md = fs::symlink_metadata(&live).expect("live materializado");
        assert!(md.file_type().is_symlink(), "materializado COMO symlink");
        assert_eq!(fs::read_link(&live).unwrap(), PathBuf::from("tsget.pl"));

        // idempotente: 2ª chamada, mesmo link, sem erro e sem `.new`
        materialize_etc(&mut jrnl, &ctx, &link, "ssl/misc/tsget", None).expect("idempotente");
        assert!(
            !root.join("etc/ssl/misc/tsget.new").exists(),
            "sem .new quando o link é igual"
        );

        // default regular ainda é copiado normalmente
        let freg = root.join("usr/share/factory/etc/ssl/openssl.cnf");
        mkparent(&freg).unwrap();
        fs::write(&freg, b"# cnf\n").unwrap();
        materialize_etc(&mut jrnl, &ctx, &freg, "ssl/openssl.cnf", None).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("etc/ssl/openssl.cnf")).unwrap(),
            "# cnf\n"
        );

        // Um link administrativo pendente também conta como decisão local:
        // o default novo vai para `.new` e o link original não é seguido.
        let factory_dangling = root.join("usr/share/factory/etc/app.conf");
        fs::write(&factory_dangling, b"novo-default\n").unwrap();
        let live_dangling = root.join("etc/app.conf");
        symlink("alvo-ausente", &live_dangling).unwrap();
        materialize_etc(&mut jrnl, &ctx, &factory_dangling, "app.conf", None).unwrap();
        assert_eq!(
            fs::read_link(&live_dangling).unwrap(),
            PathBuf::from("alvo-ausente")
        );
        assert_eq!(
            fs::read(root.join("etc/app.conf.new")).unwrap(),
            b"novo-default\n"
        );

        // Tipo administrativo inesperado não pode bloquear o rectify nem ser
        // seguido. FIFO conta como modificação local e recebe apenas `.new`.
        let factory_fifo = root.join("usr/share/factory/etc/pipe.conf");
        fs::write(&factory_fifo, b"default-seguro\n").unwrap();
        let live_fifo = root.join("etc/pipe.conf");
        let fifo_name = CString::new(live_fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString válida; caminho está dentro do root temporário.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        materialize_etc(&mut jrnl, &ctx, &factory_fifo, "pipe.conf", None).unwrap();
        assert!(fs::symlink_metadata(&live_fifo)
            .unwrap()
            .file_type()
            .is_fifo());
        assert_eq!(
            fs::read(root.join("etc/pipe.conf.new")).unwrap(),
            b"default-seguro\n"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// Núcleo transacional: rollback restaura o sobrescrito e remove o novo; um
    /// journal órfão (crash no meio) é revertido no `begin` seguinte; `commit`
    /// mantém as mudanças e descarta o journal.
    #[test]
    fn journal_transacional() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-jrnl-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        let mk = |name: &str, content: &[u8]| {
            let p = stage.join(name);
            fs::write(&p, content).unwrap();
            p
        };
        let existing = root.join("usr/bin/ls");
        fs::write(&existing, b"ORIGINAL").unwrap();
        let novo = root.join("usr/bin/cat");
        let jpath = root.join("var/lib/minitrue/journal/coreutils");

        // 1) rollback restaura o sobrescrito e remove o novo
        let mut j = Journal::begin(&ctx, "coreutils").unwrap();
        j.place_file(&existing, &mk("a", b"NOVO")).unwrap();
        j.place_file(&novo, &mk("b", b"CAT")).unwrap();
        assert_eq!(fs::read(&existing).unwrap(), b"NOVO");
        assert!(novo.exists());
        j.rollback().unwrap();
        assert_eq!(
            fs::read(&existing).unwrap(),
            b"ORIGINAL",
            "sobrescrito restaurado"
        );
        assert!(!novo.exists(), "novo removido");
        assert!(!jpath.exists(), "journal sumiu no rollback");

        // 2) recovery: um journal órfão (j sai de escopo sem commit/rollback) é
        //    revertido no begin seguinte
        {
            let mut j = Journal::begin(&ctx, "coreutils").unwrap();
            j.place_file(&existing, &mk("c", b"MEIO")).unwrap();
            assert_eq!(fs::read(&existing).unwrap(), b"MEIO");
        } // ← "crash": órfão
        let j2 = Journal::begin(&ctx, "coreutils").unwrap();
        assert_eq!(
            fs::read(&existing).unwrap(),
            b"ORIGINAL",
            "recovery restaurou o órfão"
        );
        j2.rollback().unwrap();

        // Pais novos também pertencem à transação; `create_dir_all` fora do
        // log deixava estrutura órfã depois de uma falha.
        let deep = root.join("novo/a/b/tool");
        let mut j = Journal::begin(&ctx, "deep").unwrap();
        j.place_file(&deep, &mk("deep", b"X")).unwrap();
        assert!(deep.exists());
        j.rollback().unwrap();
        assert!(!root.join("novo").exists());

        // 3) commit mantém as mudanças e descarta o journal
        let mut j = Journal::begin(&ctx, "coreutils").unwrap();
        j.place_file(&existing, &mk("d", b"FINAL")).unwrap();
        let txid = j.txid.clone();
        let meta = ctx.records_dir().join("coreutils/meta");
        j.place_bytes(&meta, format!("TRANSACTION_ID={txid}\n").as_bytes())
            .unwrap();
        j.commit().unwrap();
        assert_eq!(fs::read(&existing).unwrap(), b"FINAL");
        assert!(!jpath.exists(), "journal descartado no commit");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_global_precede_transacao_de_outro_pacote() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-journal-global-{}-{n}", std::process::id()));
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        let target = root.join("usr/bin/tool");
        fs::write(&target, b"A").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        {
            let mut orphan = Journal::begin(&ctx, "provisional-a").unwrap();
            orphan.place_bytes(&target, b"PARCIAL").unwrap();
            // Simula crash: sem commit nem rollback.
        }
        assert_eq!(fs::read(&target).unwrap(), b"PARCIAL");

        // O pacote B não pode sequer abrir sua transação sobre o estado
        // parcial de A. `begin` primeiro recupera globalmente A.
        let next = Journal::begin(&ctx, "sucessor-b").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"A");
        next.rollback().unwrap();

        // Compatibilidade com um estado anterior à fronteira global: A ficou
        // pendente, mas B já publicou ownership e retirou seu journal. Reverter
        // A cegamente apagaria B, portanto o backup precisa ser preservado.
        {
            let mut orphan = Journal::begin(&ctx, "provisional-a").unwrap();
            orphan.place_bytes(&target, b"PARCIAL-2").unwrap();
        }
        fs::write(&target, b"B-COMMITADO").unwrap();
        let successor = ctx.records_dir().join("sucessor-b");
        fs::create_dir_all(&successor).unwrap();
        fs::write(successor.join("meta"), "NAME=sucessor-b\nVERSION=1\n").unwrap();
        fs::write(successor.join("manifest"), "/usr/bin/tool\n").unwrap();
        assert!(Journal::recover_all(&ctx).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"B-COMMITADO");
        assert!(Journal::active_dir(&ctx, "provisional-a").is_dir());
        fs::remove_dir_all(&successor).unwrap();
        Journal::recover_all(&ctx).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"A");

        // Estado antigo com duas transações não tem ordem de rollback provada.
        // Falha fechado sem consumir nenhum backup.
        let base = root.join("var/lib/minitrue/journal");
        for pkg in ["a", "b"] {
            let dir = base.join(pkg);
            fs::create_dir_all(dir.join("backup")).unwrap();
            fs::write(dir.join("txid"), format!("{pkg}-tx\n")).unwrap();
            fs::write(dir.join("log"), b"").unwrap();
        }
        assert!(Journal::recover_all(&ctx).is_err());
        assert!(base.join("a").is_dir());
        assert!(base.join("b").is_dir());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn diretorio_vazio_do_stage_participa_do_journal_e_manifesto() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-empty-dir-{}-{n}", std::process::id()));
        let stage = root.join("stage");
        let empty = stage.join("usr/share/pkg/empty");
        fs::create_dir_all(&empty).unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o750)).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let preexisting_parent = root.join("usr/share/pkg");
        fs::create_dir_all(&preexisting_parent).unwrap();
        fs::set_permissions(&preexisting_parent, fs::Permissions::from_mode(0o711)).unwrap();
        let recipe_dir = root.join("var/lib/minitrue/newspeak/pkg");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nbuild(){ :; }\n",
        )
        .unwrap();
        let recipe = recipe::load(&ctx, "pkg").unwrap();
        let (image, _) = sealed_stage_snapshot(&stage, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        let mut journal = Journal::begin(&ctx, "pkg").unwrap();
        let (manifest, pulados) = apply_stage(
            &ctx,
            &image,
            &entries,
            &recipe,
            NO_SHARED_STAGE_POLICY,
            &HashSet::new(),
            &mut journal,
        )
        .unwrap();
        assert_eq!(pulados, 0, "pacote comum não pula caminho por cessão");
        let installed = root.join("usr/share/pkg/empty");
        assert!(installed.is_dir());
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert!(manifest
            .iter()
            .any(|line| manifest_path(line) == "/usr/share/pkg/empty"
                && manifest_integrity(line).is_some_and(|tag| tag.starts_with("d:"))));
        journal.rollback().unwrap();
        assert!(
            !installed.exists(),
            "rollback deve remover diretório vazio novo"
        );
        assert!(preexisting_parent.is_dir());
        assert_eq!(
            fs::metadata(&preexisting_parent)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o711,
            "rollback não pode podar/recriar pai preexistente"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Um provisional que ja cedeu TUDO nao tem o que instalar, e isso e a
    /// resposta certa — nao um build quebrado. A primeira reconstrucao da
    /// arvore parou exatamente aqui: o refresh do binutils da semente pulou os
    /// 199 caminhos que ja eram do binutils-glibc, o manifesto saiu vazio, e a
    /// guarda de "nenhuma claim instalavel" leu o vazio como defeito.
    ///
    /// O teste prende as duas metades: nada e reivindicado, E o arquivo do
    /// sucessor sobrevive intacto. A segunda importa mais que a primeira — a
    /// falha silenciosa seria o cedente sobrescrever o binario do sucessor.
    #[test]
    fn provisional_que_cedeu_tudo_nao_reivindica_o_do_sucessor() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-cedeu-tudo-{}-{n}", std::process::id()));
        let stage = root.join("stage");
        fs::create_dir_all(stage.join("usr/bin")).unwrap();
        fs::write(stage.join("usr/bin/ferramenta"), b"do cedente").unwrap();
        // O arquivo VIVO e o do sucessor, e tem de sair daqui sem um byte mudado.
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/ferramenta"), b"DO SUCESSOR").unwrap();

        let recipe_dir = root.join("var/lib/minitrue/newspeak/semente");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=semente\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nPROVISIONAL=1\nbuild(){ :; }\n",
        )
        .unwrap();

        // Registro do cedente: baseline com o caminho, manifesto ativo VAZIO.
        let rec = root.join("var/lib/minitrue/records/semente");
        fs::create_dir_all(&rec).unwrap();
        fs::write(
            rec.join("meta"),
            "RECORD_FORMAT=1\nNAME=semente\nVERSION=1\nKIND=source\nWORLD=B\nPROVISIONAL=1\n",
        )
        .unwrap();
        // Manifesto vazio e "\n" e nao "": o leitor estrito recusa arquivo de
        // zero bytes com "arquivo vazio", e o registro real do binutils da
        // semente e exatamente assim — uma linha em branco.
        fs::write(rec.join("manifest"), "\n").unwrap();
        fs::write(rec.join("manifest@1"), "/usr/bin/ferramenta\n").unwrap();

        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "semente").unwrap();
        let (image, _) = sealed_stage_snapshot(&stage, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        let mut journal = Journal::begin(&ctx, "semente").unwrap();
        let cedidos: HashSet<String> =
            cedidos_do_registro(&ctx, &ctx.records_dir().join("semente"))
                .unwrap()
                .into_iter()
                .map(|(path, _)| path)
                .collect();
        let (manifest, pulados) = apply_stage(
            &ctx,
            &image,
            &entries,
            &recipe,
            NO_SHARED_STAGE_POLICY,
            &cedidos,
            &mut journal,
        )
        .unwrap();

        assert!(
            manifest.is_empty(),
            "nao reivindica nada: tudo o que produziu ja e do sucessor"
        );
        assert_eq!(
            pulados, 1,
            "e o contador explica POR QUE o manifesto saiu vazio; e ele que \
             autoriza a excecao a guarda de 'nenhuma claim instalavel'"
        );
        assert_eq!(
            fs::read(root.join("usr/bin/ferramenta")).unwrap(),
            b"DO SUCESSOR",
            "o cedente nao pode sobrescrever o arquivo de quem o sucedeu"
        );
        journal.rollback().unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn diretorio_vazio_do_stage_nao_adota_diretorio_preexistente_com_dados() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-dir-preexisting-{}-{n}", std::process::id()));
        let stage = root.join("stage");
        let staged = stage.join("usr/share/pkg/state");
        let installed = root.join("usr/share/pkg/state");
        fs::create_dir_all(&staged).unwrap();
        fs::create_dir_all(&installed).unwrap();
        fs::write(installed.join("admin"), b"PRESERVAR").unwrap();
        let recipe_dir = root.join("var/lib/minitrue/newspeak/pkg");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nbuild(){ :; }\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = recipe::load(&ctx, "pkg").unwrap();
        let (image, _) = sealed_stage_snapshot(&stage, 0).unwrap();
        let entries = index_sealed_stage(&image).unwrap();
        let mut journal = Journal::begin(&ctx, "pkg").unwrap();
        assert!(apply_stage(
            &ctx,
            &image,
            &entries,
            &recipe,
            NO_SHARED_STAGE_POLICY,
            &HashSet::new(),
            &mut journal
        )
        .is_err());
        journal.rollback().unwrap();
        assert_eq!(fs::read(installed.join("admin")).unwrap(), b"PRESERVAR");
        assert!(!ctx.records_dir().join("pkg/manifest").exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// Janela adversarial 1: a intenção B existe, mas o move ainda não ocorreu.
    /// Recovery não pode apagar/trocar o original. Também cobre backup que é um
    /// symlink pendente: `symlink_metadata`, não `exists`, precisa restaurá-lo.
    #[test]
    fn journal_intencao_precede_move_e_restaura_dangling_symlink() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-jintent-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let dst = root.join("usr/bin/tool");
        mkparent(&dst).unwrap();
        fs::write(&dst, b"ORIGINAL").unwrap();

        // Estado possível após record(B), imediatamente antes de move(dst,bak).
        {
            let mut j = Journal::begin(&ctx, "pkg").unwrap();
            j.record_backup_intent(&dst, 0).unwrap();
        }
        Journal::recover(&ctx, "pkg").unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"ORIGINAL");

        fs::remove_file(&dst).unwrap();
        symlink("alvo-ausente", &dst).unwrap();
        {
            let mut j = Journal::begin(&ctx, "pkg").unwrap();
            j.stash(&dst, false).unwrap();
            fs::write(&dst, b"SUBSTITUTO").unwrap();
        }
        Journal::recover(&ctx, "pkg").unwrap();
        let md = fs::symlink_metadata(&dst).unwrap();
        assert!(md.file_type().is_symlink());
        assert_eq!(fs::read_link(&dst).unwrap(), PathBuf::from("alvo-ausente"));
        let _ = fs::remove_dir_all(&root);
    }

    /// Janela adversarial 2: meta final já contém o txid, mas o processo morreu
    /// antes de retirar o journal. Recovery reconhece commit e NÃO restaura backup.
    #[test]
    fn journal_orfao_commitado_nao_e_revertido() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-jcommit-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let dst = root.join("usr/bin/tool");
        let src = root.join("stage/tool");
        mkparent(&dst).unwrap();
        mkparent(&src).unwrap();
        fs::write(&dst, b"ANTIGO").unwrap();
        fs::write(&src, b"NOVO").unwrap();
        let rec = ctx.records_dir().join("pkg");
        fs::create_dir_all(&rec).unwrap();
        fs::write(rec.join("meta"), "TRANSACTION_ID=anterior\n").unwrap();

        {
            let mut j = Journal::begin(&ctx, "pkg").unwrap();
            j.place_file(&dst, &src).unwrap();
            let txid = j.txid.clone();
            j.place_bytes(
                &rec.join("meta"),
                format!("NAME=pkg\nTRANSACTION_ID={txid}\n").as_bytes(),
            )
            .unwrap();
        }
        Journal::recover(&ctx, "pkg").unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"NOVO");
        assert!(!Journal::active_dir(&ctx, "pkg").exists());

        let ambiguous = ctx.records_dir().join("ambiguous");
        {
            let mut j = Journal::begin(&ctx, "ambiguous").unwrap();
            let txid = j.txid.clone();
            j.place_bytes(
                &ambiguous.join("meta"),
                format!("NAME=ambiguous\nTRANSACTION_ID={txid}\nTRANSACTION_ID=outro\n").as_bytes(),
            )
            .unwrap();
        }
        assert!(Journal::recover(&ctx, "ambiguous").is_err());
        assert!(Journal::active_dir(&ctx, "ambiguous").is_dir());
        let _ = fs::remove_dir_all(&root);
    }

    /// Recovery que não consegue remover o destino atual deve falhar fechado:
    /// mantém o journal ativo e o único backup intacto para nova tentativa.
    #[test]
    fn journal_falha_de_recovery_preserva_backup() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-jfail-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let dst = root.join("usr/bin/tool");
        mkparent(&dst).unwrap();
        fs::write(&dst, b"ORIGINAL").unwrap();
        {
            let mut j = Journal::begin(&ctx, "pkg").unwrap();
            j.stash(&dst, false).unwrap();
            fs::create_dir(&dst).unwrap();
            fs::write(dst.join("impede-remove-dir"), b"x").unwrap();
        }

        assert!(Journal::recover(&ctx, "pkg").is_err());
        let active = Journal::active_dir(&ctx, "pkg");
        assert!(active.is_dir(), "journal deve continuar ativo");
        assert!(
            fs::symlink_metadata(active.join("backup/0")).is_ok(),
            "backup não pode ser apagado após rollback falho"
        );
        assert!(dst.join("impede-remove-dir").is_file());
        let _ = fs::remove_dir_all(&root);
    }

    /// Estados/logs ambíguos falham fechados: B sem backup E sem destino não é
    /// aceito; caminhos fora do root ou com delimitadores nunca são executados.
    #[test]
    fn journal_recusa_estado_ambiguo_e_caminhos_adversariais() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-jpath-{}-{n}", std::process::id()));
        let outside = root.with_extension("outside");
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let dst = root.join("usr/bin/tool");
        mkparent(&dst).unwrap();
        fs::write(&dst, b"ORIGINAL").unwrap();
        {
            let mut j = Journal::begin(&ctx, "missing").unwrap();
            j.record_backup_intent(&dst, 0).unwrap();
            fs::remove_file(&dst).unwrap();
        }
        assert!(Journal::recover(&ctx, "missing").is_err());
        assert!(Journal::active_dir(&ctx, "missing").is_dir());
        fs::remove_dir_all(Journal::active_dir(&ctx, "missing")).unwrap();

        fs::write(&outside, b"NAO-TOCAR").unwrap();
        {
            let mut j = Journal::begin(&ctx, "escape").unwrap();
            // Simula log adulterado/legado; replay precisa validar novamente.
            j.record(&format!("N\t{}", outside.display())).unwrap();
        }
        assert!(Journal::recover(&ctx, "escape").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"NAO-TOCAR");
        fs::remove_dir_all(Journal::active_dir(&ctx, "escape")).unwrap();

        let tab = root.join("usr/bin/com\ttab");
        fs::write(&tab, b"TAB").unwrap();
        let mut j = Journal::begin(&ctx, "tab").unwrap();
        assert!(j.stash(&tab, false).is_err());
        assert_eq!(fs::read(&tab).unwrap(), b"TAB");
        j.rollback().unwrap();

        // Assinatura de um journal produzido pela versão antiga vulnerável:
        // o log original foi movido para backup e o nome público, envenenado.
        let lock = root.join("var/lib/minitrue/lock");
        fs::write(&lock, b"LOCK-INTEGRO").unwrap();
        {
            let mut j = Journal::begin(&ctx, "poison").unwrap();
            let live_log = j.dir.join("log");
            j.record_backup_intent(&live_log, 0).unwrap();
            fs::rename(&live_log, j.dir.join("backup/0")).unwrap();
            fs::write(&live_log, format!("N\t{}\n", lock.display())).unwrap();
        }
        assert!(Journal::recover(&ctx, "poison").is_err());
        assert_eq!(fs::read(&lock).unwrap(), b"LOCK-INTEGRO");
        assert!(Journal::active_dir(&ctx, "poison").is_dir());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }

    /// Arquivos do registro também pertencem à transação. Sem o meta final com
    /// txid, um crash restaura o manifesto anterior em vez de deixá-lo híbrido.
    #[test]
    fn journal_reverte_registro_parcial() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-jrecord-{}-{n}", std::process::id()));
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let rec = ctx.records_dir().join("pkg");
        fs::create_dir_all(&rec).unwrap();
        fs::write(rec.join("manifest"), "/usr/bin/a\n").unwrap();
        fs::write(rec.join("meta"), "NAME=pkg\nVERSION=1\n").unwrap();
        {
            let mut j = Journal::begin(&ctx, "pkg").unwrap();
            j.place_bytes(&rec.join("manifest"), b"/usr/bin/b\n")
                .unwrap();
        }
        Journal::recover(&ctx, "pkg").unwrap();
        assert_eq!(
            fs::read_to_string(rec.join("manifest")).unwrap(),
            "/usr/bin/a\n"
        );
        assert_eq!(
            fs::read_to_string(rec.join("meta")).unwrap(),
            "NAME=pkg\nVERSION=1\n"
        );

        let fresh = ctx.records_dir().join("fresh");
        {
            let mut j = Journal::begin(&ctx, "fresh").unwrap();
            j.place_bytes(&fresh.join("manifest"), b"claim\n").unwrap();
        }
        Journal::recover(&ctx, "fresh").unwrap();
        assert!(
            !fresh.exists(),
            "rollback precisa remover o diretório de registro que criou"
        );

        // Cessão de provisional altera o manifesto de outro pacote dentro da
        // mesma transação. Recovery precisa tolerar a janela em que essa folha
        // está no backup e ainda não foi republicada.
        let cedent = ctx.records_dir().join("cedente");
        fs::create_dir_all(&cedent).unwrap();
        fs::write(cedent.join("meta"), "NAME=cedente\nVERSION=1\n").unwrap();
        fs::write(cedent.join("manifest"), "/usr/bin/cedido\n").unwrap();
        {
            let mut j = Journal::begin(&ctx, "sucessor").unwrap();
            j.stash(&cedent.join("manifest"), false).unwrap();
        }
        assert!(!cedent.join("manifest").exists());
        Journal::recover(&ctx, "sucessor").unwrap();
        assert_eq!(
            fs::read_to_string(cedent.join("manifest")).unwrap(),
            "/usr/bin/cedido\n"
        );
        let _ = fs::remove_dir_all(&root);
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

    #[test]
    fn explain_le_metadados_sem_executar_receita_historica() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-inspecao-{}-{n}", std::process::id()));
        let rec = root.join("record");
        fs::create_dir_all(&rec).unwrap();
        let marker = root.join("nao-executou");
        fs::write(
            rec.join("recipe"),
            format!(
                "ABOUT=\"$(touch {})\"\nLICENSE=MIT\nREPROCORR={}\n",
                marker.display(),
                "b".repeat(64)
            ),
        )
        .unwrap();

        let meta = HashMap::from([
            ("ABOUT".to_string(), "snapshot confiável".to_string()),
            ("LICENSE".to_string(), "Apache-2.0".to_string()),
            ("REPROCORR".to_string(), "a".repeat(64)),
        ]);
        assert_eq!(about_of(&rec, &meta).as_deref(), Some("snapshot confiável"));
        assert_eq!(license_of(&rec, &meta).as_deref(), Some("Apache-2.0"));
        assert_eq!(
            reprocorr_of(&rec, &meta).as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert!(!marker.exists());

        // Legado literal continua legível; a expansão dinâmica é recusada.
        let legacy = HashMap::new();
        assert_eq!(about_of(&rec, &legacy), None);
        assert_eq!(license_of(&rec, &legacy).as_deref(), Some("MIT"));
        assert_eq!(
            reprocorr_of(&rec, &legacy).as_deref(),
            Some("b".repeat(64).as_str())
        );
        assert!(!marker.exists());
        let invalid = HashMap::from([("LICENSE".to_string(), String::new())]);
        assert_eq!(
            license_of(&rec, &invalid),
            None,
            "campo factual inválido não pode ser mascarado pelo fallback"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Claim de DIRETÓRIO de um cedente provisional também é solta.
    ///
    /// O adopt_provisional_path casa por caminho, então sempre soube remover
    /// uma linha `d:`; o que faltava era ser chamado no ramo de diretório do
    /// apply_stage. Sem isso o cedente entregava os arquivos e continuava
    /// reivindicando a árvore que os contém — soltava o conteúdo e segurava o
    /// continente —, e o registro dele ficava "provisional incoerente" na
    /// operação seguinte. É o caso real do python semente, que reivindica
    /// lib-dynload como árvore justamente por estar vazio.
    #[test]
    fn diretorio_do_cedente_provisional_sai_do_manifesto() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-provdir-{}-{n}", std::process::id()));
        let recs = root.join("var/lib/minitrue/records");
        fs::create_dir_all(recs.join("semente")).unwrap();
        fs::write(
            recs.join("semente/meta"),
            "NAME=semente\nVERSION=1\nPROVISIONAL=1\n",
        )
        .unwrap();
        // uma claim de arquivo e uma de DIRETÓRIO
        fs::write(
            recs.join("semente/manifest"),
            "f:aa  /usr/lib/coisa/arquivo\nd:bb  /usr/lib/coisa/vazio\n",
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let sup = vec!["semente".to_string()];

        let owner =
            adopt_provisional_path(&ctx, "/usr/lib/coisa/vazio", "sucessor", &sup, None).unwrap();
        assert_eq!(
            owner.as_deref(),
            Some("semente"),
            "a claim de diretório precisa ser cedida como a de arquivo"
        );
        let restante = read_manifest(&recs.join("semente"));
        assert!(
            !restante
                .iter()
                .any(|line| manifest_path(line) == "/usr/lib/coisa/vazio"),
            "o cedente não pode continuar reivindicando o diretório"
        );
        assert!(
            restante
                .iter()
                .any(|line| manifest_path(line) == "/usr/lib/coisa/arquivo"),
            "as demais claims do cedente ficam"
        );
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
        fs::write(
            recs.join("gmp/manifest@6.3.0"),
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
            adopt_provisional_path(&ctx, "/usr/lib/libgmp.so.10", "estranho", &[], None).unwrap(),
            None,
            "sem SUPERSEDES, não cede"
        );
        // o rebuild-glibc que DECLARA superseder gmp cede
        let sup = vec!["gmp".to_string()];
        let owner =
            adopt_provisional_path(&ctx, "/usr/lib/libgmp.so.10", "mathlibs-glibc", &sup, None)
                .unwrap();
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
        assert_ne!(
            fs::read(recs.join("gmp/manifest")).unwrap(),
            fs::read(recs.join("gmp/manifest@6.3.0")).unwrap(),
            "manifest@ mantém o baseline anterior à cessão"
        );

        // Com journal, a cessão do manifesto também volta no rollback.
        let mut j = Journal::begin(&ctx, "mathlibs-glibc").unwrap();
        let owner = adopt_provisional_path(
            &ctx,
            "/usr/lib/libgmp.so",
            "mathlibs-glibc",
            &sup,
            Some(&mut j),
        )
        .unwrap();
        assert_eq!(owner.as_deref(), Some("gmp"));
        assert!(!read_manifest(&recs.join("gmp"))
            .iter()
            .any(|line| manifest_path(line) == "/usr/lib/libgmp.so"));
        assert_ne!(
            fs::read(recs.join("gmp/manifest")).unwrap(),
            fs::read(recs.join("gmp/manifest@6.3.0")).unwrap()
        );
        j.rollback().unwrap();
        assert!(read_manifest(&recs.join("gmp"))
            .iter()
            .any(|line| manifest_path(line) == "/usr/lib/libgmp.so"));
        assert!(fs::read_to_string(recs.join("gmp/manifest@6.3.0"))
            .unwrap()
            .contains("/usr/lib/libgmp.so.10"));

        // caminho de pacote NÃO-provisional não é cedido (viraria doublethink)
        assert_eq!(
            adopt_provisional_path(
                &ctx,
                "/usr/lib/liboutro.so",
                "x",
                &["outro".to_string()],
                None,
            )
            .unwrap(),
            None
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn plano_source_local_expande_zig_da_toolchain_uma_vez() {
        for (case, toolchain, explicit) in [
            ("seed", "seed", ""),
            ("cross", "cross", ""),
            ("duplicado", "seed", "BUILD_DEPS=zig\n"),
        ] {
            let n = CNT.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("mt-plan-zig-{case}-{}-{n}", std::process::id()));
            let recipes_dir = root.join("var/lib/minitrue/newspeak");
            fs::create_dir_all(recipes_dir.join("pkg")).unwrap();
            fs::create_dir_all(recipes_dir.join("zig")).unwrap();
            fs::write(
                recipes_dir.join("pkg/recipe"),
                format!(
                    "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN={toolchain}\n{explicit}build(){{ :; }}\n"
                ),
            )
            .unwrap();
            fs::write(
                recipes_dir.join("zig/recipe"),
                format!(
                    "NAME=zig\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://e/zig.tar.xz\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                    "a".repeat(64)
                ),
            )
            .unwrap();
            let ctx = Ctx {
                root: root.clone(),
                offline: true,
                tofu: false,
                jobs: 1,
            };
            let _runner = test_runner(&ctx);
            let plan = crate::plan::resolve(
                &ctx,
                &["pkg".to_string()],
                BinaryPolicy::SourceOnly,
                crate::plan::AbiPolicy::Development,
                channel::LoadMode::ReadOnly,
            )
            .unwrap();
            assert_eq!(
                plan.order,
                [recipe::BUILD_RUNNER_PACKAGE, "zig", "pkg"],
                "caso {case}"
            );
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn cache_verify_confere_sem_instalar_ou_usar_rede() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-cache-verify-{}-{n}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/tool");
        let cache = root.join("var/cache/minitrue");
        fs::create_dir_all(&recipe_dir).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
        let payload = b"artefato pinado";
        let hash = sha256_bytes(payload);
        fs::write(
            recipe_dir.join("recipe"),
            format!(
                "NAME=tool\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://example.invalid/tool.tar\nSHA256={hash}\ninstall_pkg(){{ return 99; }}\n"
            ),
        )
        .unwrap();
        fs::write(cache.join(&hash), payload).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            // Mesmo sem --offline externo, `cache verify` jamais baixa.
            offline: false,
            tofu: true,
            jobs: 1,
        };
        let names = vec!["tool".to_string()];
        cache_verify(&ctx, &names).unwrap();
        assert!(!ctx.records_dir().exists());
        assert!(!root.join("opt/tool").exists());
        assert!(!ctx.world_path().exists());

        fs::remove_file(cache.join(&hash)).unwrap();
        let error = cache_verify(&ctx, &names).expect_err("objeto ausente deveria falhar");
        assert_eq!(
            error
                .downcast_ref::<crate::Fail>()
                .map(|failure| failure.code),
            Some(6)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn canal_only_binary_offline_nao_expande_build_deps_e_emite() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("mt-channel-e2e-{}-{n}", std::process::id()));
        let root = base.join("root");
        let stage = base.join("stage");
        fs::create_dir_all(stage.join("etc/rc.d")).unwrap();
        for directory in [stage.join("etc"), stage.join("etc/rc.d")] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let staged_payload = stage.join("etc/rc.d/rcS");
        // Sem shebang de propósito: este teste é sobre emissão de canal, não
        // sobre resolução de intérprete. Com `#!/bin/sh` a fixture passaria a
        // exigir um provedor de shell que ela não declara, e o gate de
        // fechamento a recusaria — corretamente, mas por outro assunto.
        fs::write(&staged_payload, b"# rcS de teste do canal offline\n").unwrap();
        fs::set_permissions(&staged_payload, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(stage.join("etc/hostname"), b"distropica\n").unwrap();
        let installed_payload = root.join("usr/share/factory/etc/rc.d/rcS");

        let epoch = 1_704_067_200;
        let mut tar_bytes = Vec::new();
        let reprocorr = crate::pack::pack_deterministic(&stage, epoch, &mut tar_bytes).unwrap();
        let compressed = zstd_fixture(&tar_bytes);
        let transport_hash = sha256_bytes(&compressed);
        let zig_cache_input = b"zig upstream para availability";
        let zig_cache_hash = sha256_bytes(zig_cache_input);

        let recipes = root.join("var/lib/minitrue/newspeak");
        fs::create_dir_all(recipes.join("pkg")).unwrap();
        fs::create_dir_all(recipes.join("compiler")).unwrap();
        fs::create_dir_all(recipes.join("zig")).unwrap();
        fs::write(
            recipes.join("pkg/recipe"),
            format!(
                "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=seed\nBUILD_DEPS=compiler\nREPROCORR={reprocorr}\nEPOCH={epoch}\nbuild() {{\n  printf 'BUILD NAO PODIA RODAR\\n' > \"$ROOT/build-ran\"\n  return 99\n}}\n"
            ),
        )
        .unwrap();
        fs::write(
            recipes.join("compiler/recipe"),
            "NAME=compiler\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nbuild() {\n  printf 'E2 NAO PODIA RODAR\\n' > \"$ROOT/compiler-ran\"\n  return 99\n}\n",
        )
        .unwrap();
        fs::write(
            recipes.join("zig/recipe"),
            format!(
                "NAME=zig\nVERSION=1\nKIND=binary\nLICENSE=NOASSERTION\nSRC=https://example.invalid/zig.tar.xz\nSHA256={}\ninstall_pkg() {{\n  printf 'ZIG NAO PODIA INSTALAR\\n' > \"$ROOT/zig-ran\"\n  return 99\n}}\n",
                zig_cache_hash
            ),
        )
        .unwrap();

        let context = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let _runner = test_runner(&context);
        let requested = vec!["pkg".to_string()];
        let mut identity = Vec::new();
        collect_identity(
            &context,
            "pkg",
            &mut HashSet::new(),
            &mut Vec::new(),
            &mut identity,
        )
        .unwrap();
        let fingerprints = recipe::build_fingerprints(&identity).unwrap();
        let effective_fingerprint = fingerprints.get("pkg").unwrap().clone();
        let producer_plan = crate::plan::synthetic_channel_emit_plan(
            &recipe::load(&context, "pkg").unwrap(),
            &effective_fingerprint,
            &reprocorr,
        )
        .unwrap();
        let producer_plan_hash = sha256_bytes(&producer_plan);

        let artifact_relative = "pool/pkg-1-x86_64.tar.zst";
        let index = format!(
            "CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 1 x86_64 {effective_fingerprint} {artifact_relative} {transport_hash} {reprocorr} {producer_plan_hash}\n"
        );
        let (key, signature) = signed_channel_index(index.as_bytes());
        let config_dir = root.join("var/cache/minitrue/channel-config");
        let snapshot_dir = root.join("var/cache/minitrue/channels/oficial");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&snapshot_dir).unwrap();
        fs::write(
            config_dir.join("oficial"),
            format!(
                "URL=https://example.invalid/distropica/\nKEY={key}\nPRIORITY=100\nTRUST=oficial\n"
            ),
        )
        .unwrap();
        let index_path = snapshot_dir.join("index");
        fs::write(&index_path, &index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), signature).unwrap();
        let cached_artifact = root.join("var/cache/minitrue").join(&transport_hash);
        fs::write(&cached_artifact, &compressed).unwrap();
        fs::write(
            root.join("var/cache/minitrue").join(&zig_cache_hash),
            zig_cache_input,
        )
        .unwrap();
        fs::write(
            root.join("var/cache/minitrue").join(&producer_plan_hash),
            &producer_plan,
        )
        .unwrap();
        // O caminho offline é deliberadamente somente-leitura: a fixture já
        // precisa entregar a âncora do cache com permissões confiáveis, em vez
        // de depender de um chmod implícito durante a verificação.
        fs::set_permissions(
            root.join("var/cache/minitrue"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        // O decoder é limitado mesmo quando o frame zstd é válido.
        let compressed_file = fs::File::open(&cached_artifact).unwrap();
        let limit_error = decompress_channel_artifact(compressed_file, &cached_artifact, 64)
            .expect_err("tar maior que o teto deveria ser recusado");
        assert_eq!(
            limit_error
                .downcast_ref::<crate::Fail>()
                .map(|fail| fail.code),
            Some(3)
        );

        // Índice legado assinado continua recusado para TRUST=oficial. A
        // compatibilidade v2/v3 pertence exclusivamente a builder+development.
        let legacy_index = format!(
            "pkg 1 x86_64 {effective_fingerprint} {artifact_relative} {transport_hash} {reprocorr}\n"
        );
        let (_, legacy_signature) = signed_channel_index(legacy_index.as_bytes());
        fs::write(&index_path, &legacy_index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), legacy_signature).unwrap();
        assert!(rectify(&context, &requested, BinaryPolicy::BinaryOnly).is_err());
        assert!(!installed_payload.exists());
        assert!(!context.records_dir().join("pkg").exists());
        fs::write(&index_path, &index).unwrap();
        let (_, signature) = signed_channel_index(index.as_bytes());
        fs::write(snapshot_dir.join("index.minisig"), signature).unwrap();

        // Um par índice/assinatura adulterado falha antes de publicar lock,
        // registro ou payload.
        let mut tampered_index = index.as_bytes().to_vec();
        tampered_index[0] = b'P';
        fs::write(&index_path, tampered_index).unwrap();
        let signature_error = rectify(&context, &requested, BinaryPolicy::BinaryOnly)
            .expect_err("assinatura antiga não pode autorizar índice alterado");
        assert_eq!(
            signature_error
                .downcast_ref::<crate::Fail>()
                .map(|fail| fail.code),
            Some(7)
        );
        assert!(!installed_payload.exists());
        assert!(!context.records_dir().join("pkg").exists());
        assert!(!root.join("var/lib/minitrue/channel-locks").exists());

        // Mesmo assinado pela chave aceita, um artefato de outra revisão da
        // receita não corresponde à identidade efetiva local.
        let stale_index = format!(
            "CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 1 x86_64 {} {artifact_relative} {transport_hash} {reprocorr} {producer_plan_hash}\n",
            "0".repeat(64)
        );
        let (_, stale_signature) = signed_channel_index(stale_index.as_bytes());
        fs::write(&index_path, stale_index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), stale_signature).unwrap();
        let identity_error = rectify(&context, &requested, BinaryPolicy::BinaryOnly)
            .expect_err("fingerprint assinado divergente deveria ser crimestop");
        assert_eq!(
            identity_error
                .downcast_ref::<crate::Fail>()
                .map(|fail| fail.code),
            Some(8)
        );
        assert!(!installed_payload.exists());
        assert!(!context.records_dir().join("pkg").exists());
        assert!(!root.join("var/lib/minitrue/channel-locks").exists());

        fs::write(&index_path, &index).unwrap();
        let (_, signature) = signed_channel_index(index.as_bytes());
        fs::write(snapshot_dir.join("index.minisig"), signature).unwrap();

        // O hash do tar interno é conferido separadamente do hash de
        // transporte. Nem um índice oficial pode sobrepor o REPROCORR.
        let mut wrong_recipe = recipe::load(&context, "pkg").unwrap();
        wrong_recipe.reprocorr = Some("0".repeat(64));
        let wrong_selection = channel::Selection {
            package: "pkg".to_string(),
            version: "1".to_string(),
            recipe_fingerprint: "f".repeat(64),
            channel: "oficial".to_string(),
            trust: channel::Trust::Oficial,
            index_sha256: "1".repeat(64),
            path: artifact_relative.to_string(),
            artifact_url: format!("https://example.invalid/distropica/{artifact_relative}"),
            artifact_sha256: transport_hash.clone(),
            index_reprocorr: Some(reprocorr.clone()),
            index_format: 4,
            release_root: false,
            producer_plan_lock_sha256: Some(producer_plan_hash.clone()),
            producer_plan_url: Some(format!(
                "https://example.invalid/distropica/plans/{producer_plan_hash}.lock"
            )),
            legacy_development: false,
            lock_sha256: "2".repeat(64),
        };
        let reproduction_error = sealed_channel_snapshot(&context, &wrong_recipe, &wrong_selection)
            .expect_err("REPROCORR divergente deveria ser crimestop");
        assert_eq!(
            reproduction_error
                .downcast_ref::<crate::Fail>()
                .map(|fail| fail.code),
            Some(8)
        );
        assert!(!installed_payload.exists());

        rectify(&context, &requested, BinaryPolicy::BinaryOnly).unwrap();
        assert_eq!(
            fs::read(&installed_payload).unwrap(),
            fs::read(&staged_payload).unwrap()
        );
        assert_eq!(
            fs::read(root.join("usr/share/factory/etc/hostname")).unwrap(),
            b"distropica\n"
        );
        assert_eq!(
            fs::read(root.join("etc/hostname")).unwrap(),
            b"distropica\n"
        );
        assert!(
            fs::metadata(&installed_payload)
                .unwrap()
                .permissions()
                .mode()
                & 0o111
                != 0
        );
        assert!(
            !root.join("build-ran").exists(),
            "payload selecionado não executa build()"
        );
        assert!(
            !root.join("compiler-ran").exists(),
            "BUILD_DEPS não pode ser executado para artefato selecionado"
        );
        assert!(
            !context.records_dir().join("compiler").exists(),
            "--only-binary pkg não puxa E2/BUILD_DEPS"
        );
        assert!(
            !context.records_dir().join("zig").exists() && !root.join("zig-ran").exists(),
            "--only-binary pkg não instala a toolchain implícita"
        );
        let meta = read_meta_strict(&context.records_dir().join("pkg"))
            .unwrap()
            .unwrap();
        assert_eq!(
            meta.get("ORIGIN").map(String::as_str),
            Some("canal:oficial")
        );
        assert_eq!(meta.get("TRUST").map(String::as_str), Some("oficial"));
        assert_eq!(meta.get("CHANNEL_SHA256"), Some(&transport_hash));
        assert_eq!(
            meta.get("CHANNEL_PATH").map(String::as_str),
            Some(artifact_relative)
        );
        assert_eq!(meta.get("ARTIFACT_HASH"), Some(&reprocorr));
        let lock_hash = meta.get("CHANNEL_LOCK_SHA256").unwrap();
        let lock_path = root
            .join("var/lib/minitrue/channel-locks")
            .join(format!("{lock_hash}.lock"));
        let lock_bytes = fs::read(&lock_path).unwrap();
        assert_eq!(sha256_bytes(&lock_bytes), *lock_hash);

        // O overlay da mídia é autoridade sobre /etc vivo e pode mudar seus
        // metadados sem tocar nos defaults de fábrica atestados. A reemissão
        // precisa reconstruir `etc/` pela fábrica, não pelo diretório vivo.
        fs::set_permissions(root.join("etc"), fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            fs::metadata(root.join("usr/share/factory/etc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        verify(&context).unwrap();

        // A seleção que vai para uma mídia não descreve o estado Keep deste
        // produtor: ela precisa continuar aplicável, sem rede, num consumidor
        // sem records. O ABI factual vem do PLAN_LOCK produtor autenticado
        // pelo índice v4 release, e REPROCORR (não o zstd) identifica o
        // payload que será instalado.
        let media_roots = [
            crate::plan::PlanRoot {
                name: "pkg".to_string(),
                role: crate::plan::RootRole::Install,
            },
            crate::plan::PlanRoot {
                name: "zig".to_string(),
                role: crate::plan::RootRole::Availability,
            },
        ];
        // A recusa mora na seleção, não apenas no authenticate: as rotas de
        // instalação autenticam com strict=false, e só o resolvedor barra
        // RELEASE_ROOT=no antes de existir artefato para julgar.
        let non_release_media = crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        );
        assert!(
            non_release_media.is_err(),
            "Media Strict não pode consumir RELEASE_ROOT=no"
        );
        let release_index = index.replacen("RELEASE_ROOT=no", "RELEASE_ROOT=yes", 1);
        let (_, release_signature) = signed_channel_index(release_index.as_bytes());
        fs::write(&index_path, &release_index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), release_signature).unwrap();

        let producer_cache_path = root.join("var/cache/minitrue").join(&producer_plan_hash);
        let missing_producer = base.join("producer-plan-ausente");
        fs::rename(&producer_cache_path, &missing_producer).unwrap();
        let mut missing_plan = crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(missing_plan.authenticate_objects(&context, true).is_err());
        fs::rename(&missing_producer, &producer_cache_path).unwrap();

        fs::write(&producer_cache_path, b"PLAN_LOCK adulterado\n").unwrap();
        let mut tampered_plan = crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(tampered_plan.authenticate_objects(&context, true).is_err());
        fs::write(&producer_cache_path, &producer_plan).unwrap();

        let unrelated_payload = sha256_bytes(b"payload factual de outro produtor");
        let unrelated_plan = crate::plan::synthetic_channel_emit_plan(
            &recipe::load(&context, "compiler").unwrap(),
            fingerprints.get("compiler").unwrap(),
            &unrelated_payload,
        )
        .unwrap();
        let unrelated_hash = sha256_bytes(&unrelated_plan);
        fs::write(
            root.join("var/cache/minitrue").join(&unrelated_hash),
            unrelated_plan,
        )
        .unwrap();
        let unrelated_index = release_index.replacen(&producer_plan_hash, &unrelated_hash, 1);
        let (_, unrelated_signature) = signed_channel_index(unrelated_index.as_bytes());
        fs::write(&index_path, unrelated_index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), unrelated_signature).unwrap();
        let mut unrelated_media = crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(unrelated_media
            .authenticate_objects(&context, true)
            .is_err());

        let wrong_reprocorr = "0".repeat(64);
        let wrong_reprocorr_index = release_index.replacen(
            &format!(" {reprocorr} {producer_plan_hash}\n"),
            &format!(" {wrong_reprocorr} {producer_plan_hash}\n"),
            1,
        );
        let (_, wrong_reprocorr_signature) = signed_channel_index(wrong_reprocorr_index.as_bytes());
        fs::write(&index_path, wrong_reprocorr_index).unwrap();
        fs::write(
            snapshot_dir.join("index.minisig"),
            wrong_reprocorr_signature,
        )
        .unwrap();
        assert!(crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        )
        .is_err());

        let (_, release_signature) = signed_channel_index(release_index.as_bytes());
        fs::write(&index_path, &release_index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), release_signature).unwrap();
        assert!(
            crate::plan::resolve_for(
                &context,
                &media_roots,
                crate::plan::PlanPurpose::Media,
                BinaryPolicy::SourceOnly,
                crate::plan::AbiPolicy::Strict,
                channel::LoadMode::ReadOnly,
            )
            .is_err(),
            "Media Strict não pode cair para build Source"
        );
        let mut producer_media = crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        assert_eq!(
            producer_media.nodes["pkg"].action,
            crate::plan::PlanAction::Channel,
            "um record Keep no produtor não pode vazar para a seleção portátil"
        );
        assert_eq!(producer_media.nodes["pkg"].payload_sha256, reprocorr);
        assert!(producer_media.material_identities(true).is_err());
        producer_media.authenticate_objects(&context, true).unwrap();
        producer_media.revalidate_tree(&context).unwrap();
        let producer_media_bytes = producer_media.canonical_bytes().unwrap();
        let producer_materials = producer_media.material_identities(true).unwrap();
        assert_eq!(producer_materials.len(), 2);
        let pkg_material = producer_materials
            .iter()
            .find(|identity| identity.name == "pkg")
            .unwrap();
        assert_eq!(pkg_material.provenance_kind, "channel");
        assert_eq!(pkg_material.payload_sha256, reprocorr);
        assert!(pkg_material.artifacts.iter().any(|artifact| {
            artifact.kind == "channel"
                && artifact.transport_sha256 == transport_hash
                && artifact.reprocorr == reprocorr
                && artifact.channel_release_root == "yes"
                && artifact.producer_plan_lock_sha256 == producer_plan_hash
        }));
        let zig_material = producer_materials
            .iter()
            .find(|identity| identity.name == "zig")
            .unwrap();
        assert_eq!(zig_material.role, "cache-only");
        assert_eq!(zig_material.provenance_kind, "vendor");
        assert!(canonical_sha256(&zig_material.payload_sha256));
        producer_media.nodes.get_mut("pkg").unwrap().action = crate::plan::PlanAction::Keep;
        assert!(producer_media.material_identities(true).is_err());
        producer_media.nodes.get_mut("pkg").unwrap().action = crate::plan::PlanAction::Channel;

        let saved_records = base.join("records-do-produtor");
        fs::rename(context.records_dir(), &saved_records).unwrap();
        let mut empty_consumer_media = crate::plan::resolve_for(
            &context,
            &media_roots,
            crate::plan::PlanPurpose::Media,
            BinaryPolicy::BinaryOnly,
            crate::plan::AbiPolicy::Strict,
            channel::LoadMode::ReadOnly,
        )
        .unwrap();
        empty_consumer_media
            .authenticate_objects(&context, true)
            .unwrap();
        empty_consumer_media.revalidate_tree(&context).unwrap();
        assert_eq!(
            empty_consumer_media.canonical_bytes().unwrap(),
            producer_media_bytes,
            "o plano portátil não pode depender do record Keep do produtor"
        );
        fs::rename(&saved_records, context.records_dir()).unwrap();
        fs::write(&index_path, &index).unwrap();
        let (_, signature) = signed_channel_index(index.as_bytes());
        fs::write(snapshot_dir.join("index.minisig"), signature).unwrap();

        // Um lock content-addressed mas alheio ao pacote não autentica este
        // registro; tampouco um lock novo cujo hash de artefato diverge.
        let lock_text = String::from_utf8(lock_bytes.clone()).unwrap();
        assert!(lock_text.starts_with("CHANNEL_LOCK_FORMAT=4\n"));
        let lock_directory = lock_path.parent().unwrap();
        let persist_test_lock = |body: &str| {
            let hash = sha256_bytes(body.as_bytes());
            fs::write(lock_directory.join(format!("{hash}.lock")), body).unwrap();
            hash
        };
        let alien_body = lock_text.replace("PACKAGE.0.NAME=pkg\n", "PACKAGE.0.NAME=outro\n");
        let alien_hash = persist_test_lock(&alien_body);
        let mut alien_meta = meta.clone();
        alien_meta.insert("CHANNEL_LOCK_SHA256".to_string(), alien_hash);
        assert!(verify_channel_provenance(&context, &alien_meta).is_err());

        // O formato anterior carregava um campo homônimo, porém preenchido a
        // partir da receita local, sem autenticação pelo índice. Não pode ser
        // promovido implicitamente à nova semântica.
        let legacy_body =
            lock_text.replacen("CHANNEL_LOCK_FORMAT=4\n", "CHANNEL_LOCK_FORMAT=1\n", 1);
        let legacy_hash = persist_test_lock(&legacy_body);
        let mut legacy_meta = meta.clone();
        legacy_meta.insert("CHANNEL_LOCK_SHA256".to_string(), legacy_hash);
        assert!(verify_channel_provenance(&context, &legacy_meta).is_err());

        let other_transport = "0".repeat(64);
        let mismatched_body = lock_text.replace(
            &format!("PACKAGE.0.SHA256={transport_hash}\n"),
            &format!("PACKAGE.0.SHA256={other_transport}\n"),
        );
        let mismatched_hash = persist_test_lock(&mismatched_body);
        let mut mismatched_meta = meta.clone();
        mismatched_meta.insert("CHANNEL_LOCK_SHA256".to_string(), mismatched_hash);
        assert!(verify_channel_provenance(&context, &mismatched_meta).is_err());

        let mut mismatched_path_meta = meta.clone();
        mismatched_path_meta.insert(
            "CHANNEL_PATH".to_string(),
            "pool/outro-1-x86_64.tar.zst".to_string(),
        );
        assert!(verify_channel_provenance(&context, &mismatched_path_meta).is_err());

        // O mesmo registro v2 pode gerar um canal determinístico sem
        // recompilar; a emissão ainda deixa explícito que falta a assinatura.
        let emitted = base.join("emitted");
        channel_emit(&context, &emitted, &requested, false).unwrap();
        let emitted_index = fs::read_to_string(emitted.join("index")).unwrap();
        let mut emitted_lines = emitted_index.lines();
        assert_eq!(emitted_lines.next(), Some("CHANNEL_INDEX_FORMAT=4"));
        assert_eq!(emitted_lines.next(), Some("RELEASE_ROOT=no"));
        let fields: Vec<&str> = emitted_lines.next().unwrap().split_whitespace().collect();
        assert_eq!(fields.len(), 8);
        assert!(emitted_lines.next().is_none());
        assert_eq!(&fields[..3], &["pkg", "1", "x86_64"]);
        assert_eq!(fields[3], effective_fingerprint);
        assert_eq!(fields[4], artifact_relative);
        assert_eq!(fields[6], reprocorr);
        assert!(emitted.join(format!("plans/{}.lock", fields[7])).is_file());
        let emitted_artifact = emitted.join(fields[4]);
        assert_eq!(fetch::sha256_file(&emitted_artifact).unwrap(), fields[5]);
        let (emitted_tar, emitted_hash) = decompress_channel_artifact(
            fs::File::open(&emitted_artifact).unwrap(),
            &emitted_artifact,
            tar_bytes.len() as u64 + 1,
        )
        .unwrap();
        assert_eq!(emitted_hash, reprocorr);
        assert!(!index_sealed_stage(&emitted_tar).unwrap().is_empty());
        let emit_meta = fs::read_to_string(emitted.join("emit.meta")).unwrap();
        assert!(emit_meta.starts_with("CHANNEL_EMIT_FORMAT=4\n"));
        assert!(emit_meta.contains("INDEX_SIGNED=no\n"));
        assert!(emit_meta.contains(&format!(
            "INDEX_SHA256={}\n",
            fetch::sha256_file(&emitted.join("index")).unwrap()
        )));
        assert!(emit_meta.contains("RELEASE_ROOT=no\n"));

        // Release não pode promover o fallback histórico: sem o memfd que o
        // build local reteve, nem o objeto de outro canal nem a reconstrução
        // posterior são raiz de publicação.
        let release_without_retained = base.join("release-sem-retido");
        assert!(channel_emit(&context, &release_without_retained, &requested, true).is_err());
        assert!(!release_without_retained.exists());

        retain_local_stage(&context, &emitted_tar, &reprocorr).unwrap();
        let retained_path = retained_stage_path(&context, &reprocorr).unwrap();
        assert!(retained_path.is_file());
        let release = base.join("release-retido");
        channel_emit(&context, &release, &requested, true).unwrap();
        let release_meta = fs::read_to_string(release.join("emit.meta")).unwrap();
        assert!(release_meta.contains(&format!(
            "INDEX_SHA256={}\n",
            fetch::sha256_file(&release.join("index")).unwrap()
        )));
        assert!(release_meta.contains("RELEASE_ROOT=yes\n"));

        fs::write(&retained_path, b"retido corrompido").unwrap();
        let corrupt_release = base.join("release-retido-corrompido");
        assert!(channel_emit(&context, &corrupt_release, &requested, true).is_err());
        assert!(!corrupt_release.exists());
        let corrupt_common = base.join("comum-retido-corrompido");
        assert!(channel_emit(&context, &corrupt_common, &requested, false).is_err());
        assert!(!corrupt_common.exists());
        fs::remove_file(&retained_path).unwrap();

        // Sem o objeto original, a reconstrução continua disponível para uma
        // topologia não ambígua. Mesmo com /etc vivo em 0775, deve recuperar o
        // modo 0755 da fábrica e reproduzir exatamente o tar atestado.
        fs::remove_file(&cached_artifact).unwrap();
        let reconstructed = base.join("emitted-reconstructed");
        channel_emit(&context, &reconstructed, &requested, false).unwrap();
        let reconstructed_index = fs::read_to_string(reconstructed.join("index")).unwrap();
        let reconstructed_fields: Vec<&str> = reconstructed_index
            .lines()
            .nth(2)
            .unwrap()
            .split_whitespace()
            .collect();
        let reconstructed_artifact = reconstructed.join(reconstructed_fields[4]);
        let (_, reconstructed_hash) = decompress_channel_artifact(
            fs::File::open(&reconstructed_artifact).unwrap(),
            &reconstructed_artifact,
            tar_bytes.len() as u64 + 1,
        )
        .unwrap();
        assert_eq!(reconstructed_hash, reprocorr);
        let reconstructed_meta = fs::read_to_string(reconstructed.join("emit.meta")).unwrap();
        assert!(reconstructed_meta.contains("RELEASE_ROOT=no\n"));
        fs::write(&cached_artifact, &compressed).unwrap();

        // Corromper o lock invalida verify, attest/emit e uma nova resolução;
        // a falha ocorre antes de tocar no payload instalado.
        fs::write(&lock_path, b"lock adulterado\n").unwrap();
        assert!(verify(&context).is_err());
        let before = fs::read(&installed_payload).unwrap();
        assert!(rectify(&context, &requested, BinaryPolicy::BinaryOnly).is_err());
        assert_eq!(fs::read(&installed_payload).unwrap(), before);

        // Um objeto content-addressed que virou symlink não é seguido nem
        // aceito no modo offline, ainda que o alvo tenha os bytes esperados.
        fs::remove_file(&cached_artifact).unwrap();
        let outside = base.join("fora-do-cache");
        fs::write(&outside, &compressed).unwrap();
        symlink(&outside, &cached_artifact).unwrap();
        let cache_error =
            fetch::ensure_pinned_url(&context, &wrong_selection.artifact_url, &transport_hash)
                .expect_err("cache symlink não pode ser consumido");
        assert_eq!(
            cache_error
                .downcast_ref::<crate::Fail>()
                .map(|fail| fail.code),
            Some(6)
        );
        assert_eq!(fs::read(&outside).unwrap(), compressed);

        let _ = fs::remove_dir_all(&base);
    }

    /// O fechamento pós-apply de um mundo vindo do canal não cobra a fonte
    /// upstream — e continua cobrando a de quem não veio do canal.
    ///
    /// A matriz canônica já diz que a prova de um Keep de canal é o
    /// `record-channel`: CHANNEL_SHA256 e ARTIFACT_HASH do próprio record.
    /// Mesmo assim `authenticate_objects` autenticava os SRC de TODO Keep ao
    /// fechar. A fixture vizinha não pegava isso porque a receita dela não
    /// declara SRC — sem fonte declarada não há objeto a cobrar —, e toda
    /// receita real do Mundo B declara. Na 0.13 o defeito matou a instalação no
    /// PRIMEIRO pacote da ordem topológica, depois de os 126 anteriores já
    /// terem sido gravados e o disco já ter sido apagado.
    #[test]
    fn fechamento_de_mundo_de_canal_nao_cobra_a_fonte_upstream() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("mt-keep-canal-{}-{n}", std::process::id()));
        let root = base.join("root");
        let stage = base.join("stage");
        fs::create_dir_all(stage.join("usr/share/pkg")).unwrap();
        for directory in [
            stage.join("usr"),
            stage.join("usr/share"),
            stage.join("usr/share/pkg"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(stage.join("usr/share/pkg/marker"), b"payload de canal\n").unwrap();

        let epoch = 1_704_067_200;
        let mut tar_bytes = Vec::new();
        let reprocorr = crate::pack::pack_deterministic(&stage, epoch, &mut tar_bytes).unwrap();
        let compressed = zstd_fixture(&tar_bytes);
        let transport_hash = sha256_bytes(&compressed);
        // A FONTE UPSTREAM. Ela nunca entra no cache: é exatamente o que uma
        // máquina instalada por canal binário não tem, e não deve precisar ter.
        let upstream_hash = sha256_bytes(b"tarball upstream que a midia nao carrega");

        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let recipes = root.join("var/lib/minitrue/newspeak");
        fs::create_dir_all(recipes.join("pkg")).unwrap();
        // SIG/SIGKEY não são enfeite da fixture: a evidência de assinatura
        // upstream é o segundo braço do mesmo defeito. Ela nasce com transporte
        // `pending` — só o fetch a resolve —, e o fechamento completo recusa
        // pending. Sem declarar assinatura nenhuma, o teste passaria sem tocar
        // nisso, e é assim que toda receita real do canal difere da fixture.
        fs::write(
            recipes.join("pkg/recipe"),
            format!(
                "NAME=pkg\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nTOOLCHAIN=none\nSRC=https://example.invalid/pkg-1.tar.gz\nSHA256={upstream_hash}\nSIG=https://example.invalid/pkg-1.tar.gz.minisig\nSIGKEY=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U\nREPROCORR={reprocorr}\nEPOCH={epoch}\nbuild() {{\n  printf 'BUILD NAO PODIA RODAR\\n' > \"$ROOT/build-ran\"\n  return 99\n}}\n"
            ),
        )
        .unwrap();
        // O runner é Mundo A: origem `vendor`, cujo payload É o objeto pinado.
        // Ele fica no mesmo mundo justamente para provar que a dispensa é
        // estreita — vale para canal, e só para canal.
        let runner = install_factual_test_runner(&ctx);
        let runner_artifact = ctx.cache_dir().join(&runner.sha256[0]);
        assert!(runner_artifact.is_file());

        let mut identity = Vec::new();
        collect_identity(
            &ctx,
            "pkg",
            &mut HashSet::new(),
            &mut Vec::new(),
            &mut identity,
        )
        .unwrap();
        let fingerprints = recipe::build_fingerprints(&identity).unwrap();
        let effective_fingerprint = fingerprints.get("pkg").unwrap().clone();
        let producer_plan = crate::plan::synthetic_channel_emit_plan(
            &recipe::load(&ctx, "pkg").unwrap(),
            &effective_fingerprint,
            &reprocorr,
        )
        .unwrap();
        let producer_plan_hash = sha256_bytes(&producer_plan);

        let artifact_relative = "pool/pkg-1-x86_64.tar.zst";
        let index = format!(
            "CHANNEL_INDEX_FORMAT=4\nRELEASE_ROOT=no\npkg 1 x86_64 {effective_fingerprint} {artifact_relative} {transport_hash} {reprocorr} {producer_plan_hash}\n"
        );
        let (key, signature) = signed_channel_index(index.as_bytes());
        let config_dir = root.join("var/cache/minitrue/channel-config");
        let snapshot_dir = root.join("var/cache/minitrue/channels/oficial");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&snapshot_dir).unwrap();
        fs::write(
            config_dir.join("oficial"),
            format!(
                "URL=https://example.invalid/distropica/\nKEY={key}\nPRIORITY=100\nTRUST=oficial\n"
            ),
        )
        .unwrap();
        fs::write(snapshot_dir.join("index"), &index).unwrap();
        fs::write(snapshot_dir.join("index.minisig"), signature).unwrap();
        fs::write(ctx.cache_dir().join(&transport_hash), &compressed).unwrap();
        fs::write(ctx.cache_dir().join(&producer_plan_hash), &producer_plan).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();

        // A guarda não pode passar por acidente: a fonte tem de estar mesmo
        // ausente do cache no momento em que o fechamento roda.
        assert!(
            !ctx.cache_dir().join(&upstream_hash).exists(),
            "a fixture precisa exercer a ausência real da fonte"
        );

        // ACEITA: o mundo fecha sem a fonte, e fecha DE VERDADE — record v4,
        // origem canal e verify limpo. O runner entra por pedido explícito
        // porque `pkg` não o alcança por DEPS, e um Keep fora da closure não
        // seria exercido por fechamento nenhum.
        let requested = vec!["pkg".to_string(), recipe::BUILD_RUNNER_PACKAGE.to_string()];
        rectify(&ctx, &requested, BinaryPolicy::BinaryOnly)
            .expect("mundo de canal fecha sem o tarball upstream de cada pacote");
        assert!(!root.join("build-ran").exists());
        let meta = read_meta_strict(&ctx.records_dir().join("pkg"))
            .unwrap()
            .unwrap();
        assert_eq!(
            meta.get("ORIGIN").map(String::as_str),
            Some("canal:oficial")
        );
        assert_eq!(meta.get("RECORD_FORMAT").map(String::as_str), Some("4"));
        assert!(
            !ctx.cache_dir().join(&upstream_hash).exists(),
            "o fechamento não pode ter baixado nada"
        );
        verify(&ctx).unwrap();

        // RECUSA: o mesmo fechamento, no mesmo mundo, sem o objeto do Keep de
        // origem `vendor`. Aqui o artefato upstream É a prova do payload, e
        // dispensá-lo silenciaria a única evidência que o record tem.
        let saved_runner = base.join("runner-guardado");
        fs::rename(&runner_artifact, &saved_runner).unwrap();
        let missing = rectify(&ctx, &requested, BinaryPolicy::BinaryOnly)
            .expect_err("Keep de origem vendor precisa continuar exigindo o objeto pinado");
        assert_eq!(
            missing.downcast_ref::<crate::Fail>().map(|fail| fail.code),
            Some(6)
        );
        fs::rename(&saved_runner, &runner_artifact).unwrap();
        rectify(&ctx, &requested, BinaryPolicy::BinaryOnly)
            .expect("devolvido o objeto do vendor, o mundo volta a fechar");

        let _ = fs::remove_dir_all(&base);
    }

    fn be(work: &Path) -> BuildEnv {
        BuildEnv {
            ccache: false,
            cc: "x-gcc".into(),
            cxx: "x-g++".into(),
            ar: "x-ar".into(),
            ranlib: "x-ranlib".into(),
            ld: "x-ld".into(),
            nm: "x-nm".into(),
            path_prefix: vec![work.join(".tc")],
        }
    }
    fn build_view_fixture(work: &Path) -> BuildView {
        BuildView {
            root: work.join(".minitrue-build-view"),
            path: "/usr/bin".into(),
            masked_directories: vec!["/usr/bin".into()],
            commands: BTreeMap::new(),
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
        let view = build_view_fixture(&work);
        let cmd = build_command(
            &ctx,
            &be(&work),
            &view,
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
        // O sysroot privado é a raiz somente-leitura. Só o workspace (inclui
        // STAGE/TMP) e o cache do Zig voltam como subárvores graváveis.
        assert!(has_pair(
            &a,
            "--ro-bind",
            "/root/tmp/b/.minitrue-build-view"
        ));
        let ro = a.iter().position(|x| x == "--ro-bind").unwrap();
        assert_eq!(a[ro + 2], "/");
        assert!(a
            .windows(3)
            .any(|w| { w == ["--bind", "/root/tmp/b", "/tmp/b"] }));
        assert!(a.windows(3).any(|w| {
            w == [
                "--bind",
                "/root/var/cache/minitrue/zig",
                "/var/cache/minitrue/zig",
            ]
        }));
        // hermético
        assert!(a.contains(&"--unshare-net".to_string()));
        assert!(a.contains(&"--clearenv".to_string()));
        // variáveis em forma de CHROOT, não caminho do host
        assert!(has_pair(&a, "STAGE", "/tmp/b/stage"));
        assert!(has_pair(&a, "RECIPE", "/tmp/b/recipe"));
        assert!(has_pair(&a, "ROOT", "/"));
        assert!(has_pair(&a, "TMPDIR", "/tmp/b/tmp"));
        assert!(has_pair(&a, "CC", "x-gcc"));
        assert!(has_pair(&a, "AR", "x-ar"));
        assert!(has_pair(&a, "DL", "/var/cache/minitrue/deadbeef"));
        // PATH: prefixo em chroot + a view privada, sem PATH do host.
        assert!(
            has_pair(&a, "PATH", "/tmp/b/.tc:/usr/bin"),
            "PATH errado: {a:?}"
        );
        assert!(
            !a.windows(3)
                .filter(|w| w[0] == "--setenv")
                .any(|w| w[2].contains("/root/tmp")),
            "vazou caminho do host para o ambiente: {a:?}"
        );
        // termina em /bin/sh -ec <preâmbulo>
        assert_eq!(a[a.len() - 3], "/bin/sh");
        assert_eq!(a[a.len() - 2], "-ec");
        assert_eq!(a[a.len() - 1], BUILD_PREAMBLE);
    }

    #[test]
    fn root_slash_tambem_usa_bwrap() {
        let ctx = ctx("/");
        let work = PathBuf::from("/tmp/b");
        let view = build_view_fixture(&work);
        let cmd = build_command(&ctx, &be(&work), &view, 0, &work, "1704067200", &[]);
        assert_eq!(cmd.get_program().to_string_lossy(), "bwrap");
        let args = args_of(&cmd);
        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(has_pair(&args, "PATH", "/tmp/b/.tc:/usr/bin"));
    }
}
