use crate::tree::{Entry, EntryKind};
use anyhow::{bail, Context, Result};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub const MAX_LICENSE_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_LICENSE_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LICENSE_ENTRIES: usize = 20_000;
const MAX_CONTROL_BYTES: usize = 4 * 1024 * 1024;
const INSTALL_ROOT: &str = "usr/share/licenses/distropica-release";
const MEDIA: &str = "media";
const TAR_BLOCK_BYTES: usize = 512;
const GNU_TAR_RECORD_BYTES: usize = 20 * TAR_BLOCK_BYTES;
const MANIFEST: &str = "MANIFEST.sha256";
const INDEX: &str = "INDICE";
const PACKAGES: &str = "PACOTES";
const README: &str = "LEIA-ME";

/// Bundle autoconsistente, mas ainda não vinculado aos textos próprios da
/// árvore Newspeak que será distribuída. Serve para inspeção e comparação com
/// PLAN_LOCK; deliberadamente não é aceito por `install`.
///
/// ```compile_fail
/// use minipax::licenses::{install, UnboundLicenseBundle};
/// use std::path::Path;
/// fn nao_instala(target: &Path, bundle: &UnboundLicenseBundle) {
///     install(target, bundle);
/// }
/// ```
#[derive(Debug)]
pub struct UnboundLicenseBundle {
    bytes: Vec<u8>,
    entries: Vec<Entry>,
    packages: Vec<LicensePackage>,
    sha256: String,
}

/// Bundle que já atravessou a validação canônica, semântica e o vínculo dos
/// textos próprios com uma árvore Newspeak factual.
///
/// Os campos são deliberadamente selados: código consumidor pode observar o
/// snapshot, mas não fabricar uma instância que tenha pulado `load_unbound`.
///
/// ```compile_fail
/// use minipax::licenses::LicenseBundle;
/// fn corrompe(bundle: &mut LicenseBundle) {
///     bundle.sha256.clear();
/// }
/// ```
#[derive(Debug)]
pub struct LicenseBundle {
    bytes: Vec<u8>,
    entries: Vec<Entry>,
    /// Declaração interna de PACOTES. Não é autoridade: a integração futura
    /// precisa compará-la a identidades materiais de PLAN_LOCK_FORMAT=1.
    packages: Vec<LicensePackage>,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LicensePackage {
    name: String,
    version: String,
    world: String,
    license: String,
}

impl LicenseBundle {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn packages(&self) -> &[LicensePackage] {
        &self.packages
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl UnboundLicenseBundle {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn packages(&self) -> &[LicensePackage] {
        &self.packages
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Consome o estado não vinculado somente depois de provar que os três
    /// textos próprios são exatamente os do snapshot Newspeak selecionado.
    pub fn bind_newspeak_snapshot(self, newspeak_entries: &[Entry]) -> Result<LicenseBundle> {
        validate_own_newspeak_snapshot(&self.entries, newspeak_entries)?;
        Ok(self.into_bound())
    }

    fn bind_expected(self, expected: &BTreeMap<String, Vec<u8>>) -> Result<LicenseBundle> {
        validate_own(&self.entries, expected)?;
        Ok(self.into_bound())
    }

    fn into_bound(self) -> LicenseBundle {
        LicenseBundle {
            bytes: self.bytes,
            entries: self.entries,
            packages: self.packages,
            sha256: self.sha256,
        }
    }
}

impl LicensePackage {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub fn license(&self) -> &str {
        &self.license
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_ascii_hex_field(
    value: &str,
    max_decoded_bytes: usize,
    allow_empty: bool,
) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix("hex:")?;
    if !((allow_empty || !encoded.is_empty())
        && encoded.len() <= max_decoded_bytes.saturating_mul(2)
        && encoded.len() % 2 == 0
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return None;
    }
    hex::decode(encoded).ok()
}

#[cfg(test)]
fn encode_ascii_hex_field(value: &[u8]) -> String {
    format!("hex:{}", hex::encode(value))
}

fn safe_package(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.len() <= 128
        && !value.contains("..")
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'_' | b'.' | b'-')
        })
}

fn validate_relative(path: &Path, what: &str) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > 4096
        || path.is_absolute()
        || path.to_str().is_none()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b'\\')
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || path
            .components()
            .any(|component| component.as_os_str().as_bytes().len() > 255)
    {
        bail!("{what} contém caminho não canônico: {path:?}");
    }
    Ok(())
}

fn put_octal(field: &mut [u8], value: u64, what: &str) -> Result<()> {
    let digits = format!("{value:o}");
    let field_len = field.len();
    if digits.len() + 1 > field_len {
        bail!("{what} não cabe no cabeçalho TAR GNU canônico");
    }
    field.fill(b'0');
    let start = field_len - 1 - digits.len();
    field[start..field_len - 1].copy_from_slice(digits.as_bytes());
    field[field_len - 1] = 0;
    Ok(())
}

/// Reproduz exatamente os cabeçalhos que o produtor oficial (`bootstrap/sbom`)
/// emite com GNU tar: formato GNU, dono numérico 0, nomes de dono/grupo vazios,
/// campos de device vazios e checksum na grafia de seis octais, NUL e espaço.
/// PAX fica deliberadamente fora do formato canônico. Caminhos longos usam o
/// registro GNU `././@LongLink` exato que esse produtor emite.
fn canonical_gnu_header(
    path: &[u8],
    mode: u32,
    size: u64,
    entry_type: u8,
) -> Result<[u8; TAR_BLOCK_BYTES]> {
    if path.is_empty() || path.len() > 100 {
        bail!("nome bruto não cabe no campo de 100 bytes do TAR GNU");
    }
    let mut header = [0u8; TAR_BLOCK_BYTES];
    header[..path.len()].copy_from_slice(path);
    put_octal(&mut header[100..108], mode as u64, "modo")?;
    put_octal(&mut header[108..116], 0, "uid")?;
    put_octal(&mut header[116..124], 0, "gid")?;
    put_octal(&mut header[124..136], size, "tamanho")?;
    put_octal(&mut header[136..148], 0, "mtime")?;
    header[148..156].fill(b' ');
    header[156] = entry_type;
    header[257..265].copy_from_slice(b"ustar  \0");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let digits = format!("{checksum:06o}");
    if digits.len() != 6 {
        bail!("checksum não cabe no cabeçalho TAR GNU canônico");
    }
    header[148..154].copy_from_slice(digits.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    Ok(header)
}

fn write_zeros<W: Write>(sink: &mut W, mut count: usize) -> Result<()> {
    const ZEROS: [u8; GNU_TAR_RECORD_BYTES] = [0; GNU_TAR_RECORD_BYTES];
    while count != 0 {
        let chunk = count.min(ZEROS.len());
        sink.write_all(&ZEROS[..chunk])?;
        count -= chunk;
    }
    Ok(())
}

fn write_canonical_archive<W: Write>(entries: &[Entry], sink: &mut W) -> Result<()> {
    let mut written = 0usize;
    for entry in entries {
        let raw = entry.relative.as_os_str().as_bytes();
        let (header_path, size, entry_type, content) = match &entry.kind {
            EntryKind::Directory => {
                let mut path = raw.to_vec();
                path.push(b'/');
                (path, 0u64, b'5', None)
            }
            EntryKind::Regular(content) => (
                raw.to_vec(),
                content.len() as u64,
                b'0',
                Some(content.as_slice()),
            ),
            _ => bail!(
                "tipo não representável no licenses.tar canônico: {}",
                entry.relative.display()
            ),
        };
        let expected_mode = if content.is_some() { 0o644 } else { 0o755 };
        if entry.mode != expected_mode {
            bail!(
                "modo interno não canônico em {}: {:o}",
                entry.relative.display(),
                entry.mode
            );
        }
        let raw_header_path = if header_path.len() > 100 {
            let long_size = header_path
                .len()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("caminho TAR transbordou"))?;
            let long_header =
                canonical_gnu_header(b"././@LongLink", 0o644, long_size as u64, b'L')?;
            sink.write_all(&long_header)?;
            sink.write_all(&header_path)?;
            sink.write_all(&[0])?;
            let padding = (TAR_BLOCK_BYTES - long_size % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
            write_zeros(sink, padding)?;
            written = written
                .checked_add(TAR_BLOCK_BYTES)
                .and_then(|value| value.checked_add(long_size))
                .and_then(|value| value.checked_add(padding))
                .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?;
            &header_path[..100]
        } else {
            header_path.as_slice()
        };
        let header = canonical_gnu_header(raw_header_path, expected_mode, size, entry_type)?;
        sink.write_all(&header)?;
        written = written
            .checked_add(TAR_BLOCK_BYTES)
            .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?;
        if let Some(content) = content {
            sink.write_all(content)?;
            written = written
                .checked_add(content.len())
                .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?;
            let padding = (TAR_BLOCK_BYTES - content.len() % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
            write_zeros(sink, padding)?;
            written = written
                .checked_add(padding)
                .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?;
        }
    }
    let after_end = written
        .checked_add(2 * TAR_BLOCK_BYTES)
        .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?;
    let records = after_end
        .checked_add(GNU_TAR_RECORD_BYTES - 1)
        .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?
        / GNU_TAR_RECORD_BYTES;
    let final_len = records
        .checked_mul(GNU_TAR_RECORD_BYTES)
        .ok_or_else(|| anyhow::anyhow!("tamanho de licenses.tar transbordou"))?;
    write_zeros(sink, final_len - written)?;
    Ok(())
}

struct ExactArchive<'a> {
    observed: &'a [u8],
    offset: usize,
}

impl Write for ExactArchive<'_> {
    fn write(&mut self, expected: &[u8]) -> std::io::Result<usize> {
        let end = self
            .offset
            .checked_add(expected.len())
            .ok_or_else(|| std::io::Error::other("offset TAR transbordou"))?;
        if self.observed.get(self.offset..end) != Some(expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("divergência binária no offset {}", self.offset),
            ));
        }
        self.offset = end;
        Ok(expected.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_canonical_archive(bytes: &[u8], entries: &[Entry]) -> Result<()> {
    let mut comparator = ExactArchive {
        observed: bytes,
        offset: 0,
    };
    write_canonical_archive(entries, &mut comparator)
        .context("licenses.tar não é byte-idêntico ao GNU TAR canônico do produtor oficial")?;
    if comparator.offset != bytes.len() {
        bail!(
            "licenses.tar tem tamanho não canônico: esperado {}, observado {}",
            comparator.offset,
            bytes.len()
        );
    }
    Ok(())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Abre cada componente por descritor e nunca segue symlink, inclusive nos
/// ancestrais. Depois da abertura, uma troca de nome no host não consegue
/// redirecionar a leitura ou a instalação para outra árvore.
fn open_path_anchored(path: &Path, final_flags: OFlags, what: &str) -> Result<OwnedFd> {
    let mut current = rustix::fs::open(
        if path.is_absolute() { "/" } else { "." },
        directory_flags(),
        Mode::empty(),
    )?;
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Normal(name) => Some(Ok(name)),
            Component::ParentDir | Component::Prefix(_) => Some(Err(anyhow::anyhow!(
                "{what} contém componente não canônico"
            ))),
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() {
        if final_flags.contains(OFlags::DIRECTORY) {
            return Ok(current);
        }
        bail!("{what} não identifica um arquivo");
    }
    for (index, name) in components.iter().enumerate() {
        let flags = if index + 1 == components.len() {
            final_flags
        } else {
            directory_flags()
        };
        current = rustix::fs::openat(&current, *name, flags, Mode::empty())
            .with_context(|| format!("não abri {what}: {}", path.display()))?;
    }
    Ok(current)
}

fn same_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.file_type().is_file()
        && right.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[derive(Clone, Copy, Debug)]
struct InstallTrust {
    uid: u32,
}

impl InstallTrust {
    fn current() -> Result<Self> {
        let status = std::fs::read_to_string("/proc/self/status")
            .context("não li /proc/self/status para conferir o UID efetivo")?;
        let uid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(2))
            .ok_or_else(|| anyhow::anyhow!("UID efetivo ausente em /proc/self/status"))?
            .parse()
            .context("UID efetivo inválido em /proc/self/status")?;
        Ok(Self { uid })
    }

    fn validate_directory(&self, directory: &impl AsFd, what: &str) -> Result<u32> {
        let stat = rustix::fs::fstat(directory)?;
        let mode = stat.st_mode & 0o7777;
        if !FileType::from_raw_mode(stat.st_mode).is_dir()
            || stat.st_uid != self.uid
            || stat.st_nlink == 0
            || mode & 0o022 != 0
        {
            bail!(
                "{what} precisa ser diretório real do UID efetivo, sem escrita por grupo/outros e com nlink válido (uid observado {}, uid esperado {}, modo {:04o}, nlink {})",
                stat.st_uid,
                self.uid,
                mode,
                stat.st_nlink
            );
        }
        Ok(mode)
    }

    fn validate_regular(
        &self,
        metadata: &std::fs::Metadata,
        what: &str,
        max_links: u64,
    ) -> Result<()> {
        if !metadata.file_type().is_file()
            || metadata.uid() != self.uid
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() == 0
            || metadata.nlink() > max_links
        {
            bail!(
                "{what} precisa ser regular do UID efetivo, sem escrita por grupo/outros e com até {max_links} link(s) (uid observado {}, uid esperado {}, modo {:04o}, nlink {})",
                metadata.uid(),
                self.uid,
                metadata.mode() & 0o7777,
                metadata.nlink()
            );
        }
        Ok(())
    }
}

fn read_real_file(path: &Path, what: &str, limit: u64) -> Result<Vec<u8>> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let descriptor = open_path_anchored(path, flags, what)
        .with_context(|| format!("não abri {what}: {}", path.display()))?;
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!(
            "{what} precisa ser arquivo regular real sem hardlinks: {}",
            path.display()
        );
    }
    if before.len() > limit {
        bail!("{what} excede {limit} bytes: {}", path.display());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{what} cresceu além de {limit} bytes durante a leitura");
    }
    let after = file.metadata()?;
    if !same_metadata(&before, &after) || bytes.len() as u64 != after.len() {
        bail!("{what} mudou durante a leitura: {}", path.display());
    }
    let rebound = File::from(open_path_anchored(path, flags, what)?);
    let path_after = rebound.metadata()?;
    if !same_metadata(&after, &path_after) {
        bail!(
            "{what} deixou de nomear o mesmo inode após a leitura: {}",
            path.display()
        );
    }
    Ok(bytes)
}

fn required_own_files(newspeak: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let base = newspeak.join("base/files");
    let mut expected = BTreeMap::new();
    for (archive_name, source_name) in [
        ("distropica/GPL-3.0-or-later.txt", "GPL-3.0-or-later.txt"),
        ("distropica/NOTICE", "NOTICE"),
        ("distropica/LICENSING.md", "LICENSING.md"),
    ] {
        expected.insert(
            archive_name.to_string(),
            read_real_file(
                &base.join(source_name),
                &format!("texto próprio {source_name}"),
                1024 * 1024,
            )?,
        );
    }
    Ok(expected)
}

fn regular<'a>(files: &'a BTreeMap<String, &'a [u8]>, path: &str) -> Result<&'a [u8]> {
    files
        .get(path)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("bundle de licenças não contém {path}"))
}

fn parse_manifest(files: &BTreeMap<String, &[u8]>) -> Result<()> {
    let bytes = regular(files, MANIFEST)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        bail!("{MANIFEST} excede {MAX_CONTROL_BYTES} bytes");
    }
    let text = std::str::from_utf8(bytes).context("MANIFEST.sha256 não é UTF-8")?;
    if !text.ends_with('\n') {
        bail!("MANIFEST.sha256 não termina em newline canônico");
    }
    let mut declared = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for (index, line) in text.lines().enumerate() {
        let raw = line.as_bytes();
        if raw.len() < 67 || &raw[64..66] != b"  " {
            bail!("MANIFEST.sha256 tem linha inválida em {}", index + 1);
        }
        let hash = std::str::from_utf8(&raw[..64]).context("MANIFEST.sha256 tem hash não ASCII")?;
        let path = std::str::from_utf8(&raw[66..])
            .context("MANIFEST.sha256 separa uma sequência UTF-8")?;
        if !is_hash(hash) || path == MANIFEST {
            bail!("MANIFEST.sha256 tem entrada inválida em {}", index + 1);
        }
        validate_relative(Path::new(path), "MANIFEST.sha256")?;
        if previous.is_some_and(|value| value.as_bytes() >= path.as_bytes()) {
            bail!("MANIFEST.sha256 não está estritamente ordenado");
        }
        previous = Some(path);
        if declared
            .insert(path.to_string(), hash.to_string())
            .is_some()
        {
            bail!("MANIFEST.sha256 repete {path}");
        }
    }

    let observed = files
        .iter()
        .filter(|(path, _)| path.as_str() != MANIFEST)
        .map(|(path, bytes)| (path.clone(), sha256(bytes)))
        .collect::<BTreeMap<_, _>>();
    if declared != observed {
        let missing = observed.keys().find(|path| !declared.contains_key(*path));
        let extra = declared.keys().find(|path| !observed.contains_key(*path));
        let changed = observed
            .iter()
            .find(|(path, hash)| declared.get(*path) != Some(*hash));
        bail!(
            "MANIFEST.sha256 não cobre exatamente o bundle (ausente={missing:?}, extra={extra:?}, divergente={:?})",
            changed.map(|(path, _)| path)
        );
    }
    Ok(())
}

fn parse_packages(bytes: &[u8]) -> Result<BTreeMap<String, LicensePackage>> {
    if bytes.len() > MAX_CONTROL_BYTES {
        bail!("PACOTES excede {MAX_CONTROL_BYTES} bytes");
    }
    let text = std::str::from_utf8(bytes).context("PACOTES não é UTF-8")?;
    if !text.ends_with('\n') {
        bail!("PACOTES não termina em newline canônico");
    }
    let mut lines = text.lines();
    if lines.next() != Some("# pacote\tversao\tmundo\tlicenca") {
        bail!("PACOTES não possui cabeçalho canônico");
    }
    let mut packages = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 4
            || !safe_package(fields[0])
            || fields[1..].iter().any(|value| {
                value.is_empty()
                    || value
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte == b'\\')
            })
        {
            bail!("PACOTES contém linha inválida");
        }
        if previous.is_some_and(|value| value.as_bytes() >= line.as_bytes()) {
            bail!("PACOTES não está estritamente ordenado");
        }
        previous = Some(line);
        let package = LicensePackage {
            name: fields[0].to_string(),
            version: fields[1].to_string(),
            world: fields[2].to_string(),
            license: fields[3].to_string(),
        };
        if packages.insert(package.name.clone(), package).is_some() {
            bail!("PACOTES repete o pacote {}", fields[0]);
        }
    }
    if packages.is_empty() {
        bail!("PACOTES está vazio");
    }
    Ok(packages)
}

fn validate_index(
    files: &BTreeMap<String, &[u8]>,
    packages: &BTreeMap<String, LicensePackage>,
) -> Result<()> {
    let bytes = regular(files, INDEX)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        bail!("INDICE excede {MAX_CONTROL_BYTES} bytes");
    }
    let text = std::str::from_utf8(bytes).context("INDICE não é UTF-8")?;
    if !text.is_ascii() || !text.ends_with('\n') {
        bail!("INDICE não termina em newline canônico");
    }
    let mut lines = text.lines();
    if lines.next() != Some("# pacote\tcomponente\tsha256\tprimeira-linha") {
        bail!("INDICE não possui cabeçalho canônico");
    }
    let mut indexed = BTreeMap::<(String, String), usize>::new();
    let mut covered = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        let component = fields
            .get(1)
            .and_then(|field| decode_ascii_hex_field(field, 4096, false));
        let component_is_safe = component.as_deref().is_some_and(|decoded| {
            std::str::from_utf8(decoded).is_ok()
                && !decoded
                    .iter()
                    .any(|byte| *byte <= 0x1f || *byte == 0x7f || *byte == b'\\')
        });
        if fields.len() != 4
            || !safe_package(fields[0])
            || !packages.contains_key(fields[0])
            || !component_is_safe
            || !is_hash(fields[2])
            || decode_ascii_hex_field(fields[3], 72, true).is_none()
        {
            bail!("INDICE contém linha inválida");
        }
        if previous.is_some_and(|value| value.as_bytes() >= line.as_bytes()) {
            bail!("INDICE não está estritamente ordenado");
        }
        previous = Some(line);
        *indexed
            .entry((fields[0].to_string(), fields[2].to_string()))
            .or_default() += 1;
        covered.insert(fields[0].to_string());
    }
    if covered != packages.keys().cloned().collect() {
        bail!("INDICE não cobre exatamente os pacotes de PACOTES");
    }

    let controls = [MANIFEST, INDEX, PACKAGES, README];
    let own = [
        "distropica/GPL-3.0-or-later.txt",
        "distropica/NOTICE",
        "distropica/LICENSING.md",
    ];
    let mut observed = BTreeMap::<(String, String), usize>::new();
    for (path, content) in files {
        if controls.contains(&path.as_str()) || own.contains(&path.as_str()) {
            continue;
        }
        let mut parts = Path::new(path).components();
        let package = parts
            .next()
            .and_then(|component| component.as_os_str().to_str())
            .ok_or_else(|| anyhow::anyhow!("evidência sem pacote em {path}"))?;
        if parts.next().is_none() || !packages.contains_key(package) {
            bail!("arquivo de evidência fora de PACOTES: {path}");
        }
        *observed
            .entry((package.to_string(), sha256(content)))
            .or_default() += 1;
    }
    if observed != indexed {
        bail!("INDICE não cobre exatamente os arquivos de evidência por pacote e hash");
    }
    Ok(())
}

pub fn load_unbound(bytes: Vec<u8>) -> Result<UnboundLicenseBundle> {
    if bytes.len() as u64 > MAX_LICENSE_ARCHIVE_BYTES {
        bail!(
            "licenses.tar excede {} MiB",
            MAX_LICENSE_ARCHIVE_BYTES / 1024 / 1024
        );
    }
    let mut archive = tar::Archive::new(Cursor::new(bytes.as_slice()));
    let mut entries = Vec::new();
    let mut file_paths = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut previous: Option<Vec<u8>> = None;
    let mut total = 0u64;
    for item in archive.entries().context("não li licenses.tar")? {
        let mut item = item.context("entrada inválida em licenses.tar")?;
        if entries.len() >= MAX_LICENSE_ENTRIES {
            bail!("licenses.tar excede {MAX_LICENSE_ENTRIES} entradas");
        }
        let archived_path = item
            .path()
            .context("caminho inválido em licenses.tar")?
            .into_owned();
        validate_relative(&archived_path, "licenses.tar")?;
        let path = archived_path.components().collect::<PathBuf>();
        let archived = archived_path.as_os_str().as_bytes();
        let canonical = path.as_os_str().as_bytes();
        let is_directory = item.header().entry_type() == tar::EntryType::Directory;
        let canonical_header = archived == canonical
            || (is_directory
                && archived.len() == canonical.len() + 1
                && archived.starts_with(canonical)
                && archived.last() == Some(&b'/'));
        if !canonical_header {
            bail!("licenses.tar contém grafia de caminho não canônica: {archived_path:?}");
        }
        let raw = canonical.to_vec();
        if previous.as_ref().is_some_and(|value| value >= &raw) {
            bail!("licenses.tar não está estritamente ordenado");
        }
        previous = Some(raw);
        if item.header().uid()? != 0 || item.header().gid()? != 0 || item.header().mtime()? != 0 {
            bail!(
                "licenses.tar tem uid/gid/mtime não canônico em {}",
                path.display()
            );
        }
        let kind = if is_directory {
            if item.size() != 0 || item.header().mode()? & 0o7777 != 0o755 {
                bail!("diretório não canônico em licenses.tar: {}", path.display());
            }
            let key = path.to_string_lossy().into_owned();
            if !directories.insert(key) {
                bail!("licenses.tar repete {}", path.display());
            }
            EntryKind::Directory
        } else if item.header().entry_type() == tar::EntryType::Regular {
            let size = item.size();
            if size > MAX_LICENSE_FILE_BYTES {
                bail!(
                    "arquivo em licenses.tar excede {} MiB: {}",
                    MAX_LICENSE_FILE_BYTES / 1024 / 1024,
                    path.display()
                );
            }
            total = total
                .checked_add(size)
                .filter(|value| *value <= MAX_LICENSE_ARCHIVE_BYTES)
                .ok_or_else(|| anyhow::anyhow!("conteúdo de licenses.tar excede o limite"))?;
            if item.header().mode()? & 0o7777 != 0o644 {
                bail!("arquivo não canônico em licenses.tar: {}", path.display());
            }
            let mut content = Vec::with_capacity(size as usize);
            (&mut item).take(size + 1).read_to_end(&mut content)?;
            if content.len() as u64 != size {
                bail!("arquivo truncado em licenses.tar: {}", path.display());
            }
            let key = path.to_string_lossy().into_owned();
            if !file_paths.insert(key) {
                bail!("licenses.tar repete {}", path.display());
            }
            EntryKind::Regular(content)
        } else {
            bail!(
                "licenses.tar contém link ou tipo especial em {}",
                path.display()
            );
        };
        let mode = if matches!(&kind, EntryKind::Directory) {
            0o755
        } else {
            0o644
        };
        entries.push(Entry {
            relative: path,
            mode,
            kind,
        });
    }
    let cursor = archive.into_inner();
    if bytes[cursor.position() as usize..]
        .iter()
        .any(|byte| *byte != 0)
    {
        bail!("licenses.tar contém bytes não nulos depois do fim do arquivo TAR");
    }

    // Uma só cópia de cada texto: o mapa toma fatias dos entries. Assim o
    // pico é TAR + conteúdo decodificado, não uma terceira cópia proporcional
    // ao tamanho de um input controlado externamente.
    let files = entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            EntryKind::Regular(content) => Some((
                entry.relative.to_string_lossy().into_owned(),
                content.as_slice(),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    if files.len() != file_paths.len() {
        bail!("licenses.tar repete arquivo regular");
    }

    let mut required_dirs = BTreeSet::new();
    for path in files.keys() {
        let mut ancestor = Path::new(path).parent();
        while let Some(parent) = ancestor.filter(|parent| !parent.as_os_str().is_empty()) {
            required_dirs.insert(parent.to_string_lossy().into_owned());
            ancestor = parent.parent();
        }
    }
    if directories != required_dirs {
        let missing = required_dirs
            .iter()
            .find(|path| !directories.contains(*path));
        let extra = directories
            .iter()
            .find(|path| !required_dirs.contains(*path));
        bail!(
            "licenses.tar contém diretórios ausentes ou vazios fora do inventário (ausente={missing:?}, extra={extra:?})"
        );
    }
    parse_manifest(&files)?;
    let packages = parse_packages(regular(&files, PACKAGES)?)?;
    validate_index(&files, &packages)?;
    if regular(&files, README)?.is_empty() {
        bail!("LEIA-ME está vazio");
    }
    validate_canonical_archive(&bytes, &entries)?;
    let hash = sha256(&bytes);
    Ok(UnboundLicenseBundle {
        bytes,
        entries,
        packages: packages.into_values().collect(),
        sha256: hash,
    })
}

pub fn validate_own(entries: &[Entry], expected: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let observed = entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            EntryKind::Regular(content) => Some((
                entry.relative.to_string_lossy().into_owned(),
                content.as_slice(),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for (path, bytes) in expected {
        if observed.get(path).copied() != Some(bytes.as_slice()) {
            bail!("texto próprio em licenses.tar diverge da árvore Newspeak: {path}");
        }
    }
    Ok(())
}

pub fn validate_own_newspeak_snapshot(entries: &[Entry], newspeak_entries: &[Entry]) -> Result<()> {
    let paths = [
        (
            Path::new("base/files/GPL-3.0-or-later.txt"),
            "distropica/GPL-3.0-or-later.txt",
        ),
        (Path::new("base/files/NOTICE"), "distropica/NOTICE"),
        (
            Path::new("base/files/LICENSING.md"),
            "distropica/LICENSING.md",
        ),
    ];
    let mut expected = BTreeMap::new();
    for (source, destination) in paths {
        let content = newspeak_entries
            .iter()
            .find(|entry| entry.relative == source)
            .and_then(|entry| match &entry.kind {
                EntryKind::Regular(content) => Some(content.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "snapshot Newspeak não contém texto próprio regular {}",
                    source.display()
                )
            })?;
        expected.insert(destination.to_string(), content);
    }
    validate_own(entries, &expected)
}

pub fn load_bytes(bytes: Vec<u8>, newspeak: &Path) -> Result<LicenseBundle> {
    load_unbound(bytes)?.bind_expected(&required_own_files(newspeak)?)
}

pub fn load_path(path: &Path, newspeak: &Path) -> Result<LicenseBundle> {
    let bytes = read_real_file(path, "licenses.tar", MAX_LICENSE_ARCHIVE_BYTES)?;
    load_bytes(bytes, newspeak)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallCheckpoint {
    ModeDurable,
    FileLinked,
    GenerationReady,
    GenerationPublished,
}

fn open_or_create_dir(parent: &impl AsFd, name: &OsStr, trust: &InstallTrust) -> Result<OwnedFd> {
    let directory = match rustix::fs::openat(parent, name, directory_flags(), Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            let created = match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
                Ok(()) => true,
                Err(Errno::EXIST) => false,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            let directory = rustix::fs::openat(parent, name, directory_flags(), Mode::empty())?;
            if created {
                // mkdir respeita umask. O modo e o nome só são considerados
                // publicados depois que ambos os inodes estão duráveis.
                rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o755))?;
                rustix::fs::fsync(&directory)?;
                rustix::fs::fsync(parent)?;
            }
            directory
        }
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    trust.validate_directory(&directory, "diretório de licenças")?;
    Ok(directory)
}

fn ensure_directory_mode<F: FnMut(InstallCheckpoint) -> Result<()>>(
    parent: &impl AsFd,
    directory: &impl AsFd,
    trust: &InstallTrust,
    hook: &mut F,
) -> Result<()> {
    let mode = trust.validate_directory(directory, "diretório de licenças")?;
    if mode != 0o755 {
        rustix::fs::fchmod(directory, Mode::from_raw_mode(0o755))?;
        rustix::fs::fsync(directory)?;
        rustix::fs::fsync(parent)?;
        hook(InstallCheckpoint::ModeDurable)?;
    }
    if trust.validate_directory(directory, "diretório de licenças")? != 0o755 {
        bail!("diretório de licenças não permaneceu no modo 0755");
    }
    Ok(())
}

fn open_chain(root: &impl AsFd, path: &Path, trust: &InstallTrust) -> Result<OwnedFd> {
    let mut current = rustix::fs::openat(root, ".", directory_flags(), Mode::empty())?;
    trust.validate_directory(&current, "raiz interna de licenças")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("caminho interno não canônico: {path:?}");
        };
        current = open_or_create_dir(&current, name, trust)?;
    }
    Ok(current)
}

fn open_existing_chain(root: &impl AsFd, path: &Path, trust: &InstallTrust) -> Result<OwnedFd> {
    let mut current = rustix::fs::openat(root, ".", directory_flags(), Mode::empty())?;
    trust.validate_directory(&current, "raiz interna de licenças")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("caminho interno não canônico: {path:?}");
        };
        current = rustix::fs::openat(&current, name, directory_flags(), Mode::empty())?;
        trust.validate_directory(&current, "ancestral interno de licenças")?;
    }
    Ok(current)
}

fn open_optional_dir(
    parent: &impl AsFd,
    name: &OsStr,
    what: &str,
    trust: &InstallTrust,
) -> Result<Option<OwnedFd>> {
    match rustix::fs::openat(parent, name, directory_flags(), Mode::empty()) {
        Ok(directory) => {
            trust.validate_directory(&directory, what)?;
            Ok(Some(directory))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(std::io::Error::from(error))
            .with_context(|| format!("{what} não é diretório real sem symlink")),
    }
}

fn existing_tree(
    directory: &impl AsFd,
    prefix: &Path,
    directories: &mut BTreeSet<PathBuf>,
    files: &mut BTreeSet<PathBuf>,
    trust: &InstallTrust,
) -> Result<()> {
    trust.validate_directory(directory, "diretório da árvore de licenças")?;
    let mut stream = rustix::fs::Dir::read_from(directory)?;
    while let Some(item) = stream.read() {
        let item = item?;
        let name_bytes = item.file_name().to_bytes();
        if matches!(name_bytes, b"." | b"..") {
            continue;
        }
        let name = OsStr::from_bytes(name_bytes);
        let relative = prefix.join(name);
        validate_relative(&relative, "árvore instalada de licenças")?;
        let stat = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind.is_dir() {
            directories.insert(relative.clone());
            let child = rustix::fs::openat(directory, name, directory_flags(), Mode::empty())?;
            trust.validate_directory(&child, "diretório da árvore de licenças")?;
            existing_tree(&child, &relative, directories, files, trust)?;
        } else if kind.is_file() {
            let file = File::from(rustix::fs::openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?);
            trust.validate_regular(&file.metadata()?, "arquivo da árvore de licenças", 2)?;
            files.insert(relative);
        } else {
            bail!(
                "link ou arquivo especial na árvore instalada de licenças: {}",
                relative.display()
            );
        }
    }
    Ok(())
}

fn read_existing_stable(
    parent: &impl AsFd,
    name: &OsStr,
    limit: usize,
    what: &str,
    max_links: u64,
    trust: &InstallTrust,
) -> Result<Option<(File, std::fs::Metadata, Vec<u8>)>> {
    let descriptor = match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    trust.validate_regular(&before, what, max_links)?;
    let mut observed = Vec::with_capacity(limit.min(before.len() as usize));
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut observed)?;
    let after = file.metadata()?;
    let rebound = File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    trust.validate_regular(&after, what, max_links)?;
    let rebound = rebound.metadata()?;
    trust.validate_regular(&rebound, what, max_links)?;
    if !same_metadata(&before, &after) || !same_metadata(&after, &rebound) {
        bail!("{what} mudou durante a validação");
    }
    Ok(Some((file, after, observed)))
}

fn verify_existing<F: FnMut(InstallCheckpoint) -> Result<()>>(
    parent: &impl AsFd,
    name: &OsStr,
    expected: &[u8],
    repair_mode: bool,
    trust: &InstallTrust,
    hook: &mut F,
) -> Result<bool> {
    let Some((file, after, observed)) =
        read_existing_stable(parent, name, expected.len(), "destino de licença", 1, trust)?
    else {
        return Ok(false);
    };
    if observed != expected {
        bail!("arquivo instalado de licença diverge do snapshot");
    }
    if after.mode() & 0o7777 != 0o644 {
        if !repair_mode {
            return Ok(true);
        }
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o644))?;
        file.sync_all()?;
        rustix::fs::fsync(parent)?;
        hook(InstallCheckpoint::ModeDurable)?;
    }
    Ok(true)
}

fn verify_final(
    parent: &impl AsFd,
    name: &OsStr,
    expected: &[u8],
    trust: &InstallTrust,
) -> Result<()> {
    let descriptor = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    trust.validate_regular(&before, "arquivo final de licença", 1)?;
    if before.mode() & 0o7777 != 0o644 {
        bail!("arquivo final de licença não é regular, único e modo 0644");
    }
    let mut observed = Vec::with_capacity(expected.len());
    (&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut observed)?;
    let after = file.metadata()?;
    let rebound = File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    let rebound = rebound.metadata()?;
    trust.validate_regular(&after, "arquivo final de licença", 1)?;
    trust.validate_regular(&rebound, "arquivo final de licença", 1)?;
    if observed != expected || !same_metadata(&before, &after) || !same_metadata(&after, &rebound) {
        bail!("arquivo final de licença mudou ou diverge do snapshot");
    }
    Ok(())
}

fn temporary_receipt_name(name: &OsStr, content: &[u8]) -> OsString {
    let mut digest = Sha256::new();
    digest.update(b"MINIPAX_LICENSE_TEMP_RECEIPT_FORMAT=1\0");
    digest.update(name.as_bytes());
    digest.update([0]);
    digest.update((content.len() as u64).to_be_bytes());
    digest.update(Sha256::digest(content));
    OsString::from(format!(
        ".minipax-license-{}.tmp",
        hex::encode(digest.finalize())
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationResidue {
    Empty,
    Partial,
    Final,
    LinkedPair,
}

fn inspect_publication_residue(
    parent: &impl AsFd,
    name: &OsStr,
    temporary: &OsStr,
    expected: &[u8],
    trust: &InstallTrust,
) -> Result<PublicationResidue> {
    let final_file =
        read_existing_stable(parent, name, expected.len(), "destino de licença", 2, trust)?;
    let temporary_file = read_existing_stable(
        parent,
        temporary,
        expected.len(),
        "temporário de licença com recibo",
        2,
        trust,
    )?;
    match (final_file, temporary_file) {
        (None, None) => Ok(PublicationResidue::Empty),
        (None, Some((_file, metadata, observed))) => {
            if metadata.nlink() != 1 || !expected.starts_with(&observed) {
                bail!("temporário de licença com recibo diverge do snapshot");
            }
            Ok(PublicationResidue::Partial)
        }
        (Some((_file, metadata, observed)), None) => {
            if metadata.nlink() != 1 || observed != expected {
                bail!("destino de licença existente diverge do snapshot");
            }
            Ok(PublicationResidue::Final)
        }
        (
            Some((_final_file, final_metadata, final_bytes)),
            Some((_temporary_file, temporary_metadata, temporary_bytes)),
        ) => {
            if final_metadata.dev() != temporary_metadata.dev()
                || final_metadata.ino() != temporary_metadata.ino()
                || final_metadata.nlink() != 2
                || temporary_metadata.nlink() != 2
                || final_bytes != expected
                || temporary_bytes != expected
            {
                bail!("destino e temporário de licença coexistem sem formar o par do fallback");
            }
            Ok(PublicationResidue::LinkedPair)
        }
    }
}

fn reconcile_publication_residue(
    parent: &impl AsFd,
    name: &OsStr,
    temporary: &OsStr,
    expected: &[u8],
    trust: &InstallTrust,
) -> Result<bool> {
    match inspect_publication_residue(parent, name, temporary, expected, trust)? {
        PublicationResidue::Empty => Ok(false),
        PublicationResidue::Final => Ok(true),
        PublicationResidue::Partial | PublicationResidue::LinkedPair => {
            rustix::fs::unlinkat(parent, temporary, AtFlags::empty())?;
            rustix::fs::fsync(parent)?;
            match inspect_publication_residue(parent, name, temporary, expected, trust)? {
                PublicationResidue::Empty => Ok(false),
                PublicationResidue::Final => Ok(true),
                _ => bail!("resíduo temporário de licença não convergiu após reconciliação"),
            }
        }
    }
}

fn publish_file_with<
    F: FnMut(InstallCheckpoint) -> Result<()>,
    R: FnOnce(&OsStr) -> rustix::io::Result<()>,
>(
    parent: &impl AsFd,
    name: &OsStr,
    content: &[u8],
    trust: &InstallTrust,
    hook: &mut F,
    rename_noreplace: R,
) -> Result<()> {
    let temporary = temporary_receipt_name(name, content);
    if reconcile_publication_residue(parent, name, &temporary, content, trust)? {
        if !verify_existing(parent, name, content, true, trust, hook)? {
            bail!("arquivo de licença sumiu depois da reconciliação");
        }
        return Ok(());
    }
    let descriptor = rustix::fs::openat(
        parent,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(descriptor);
    file.write_all(content)?;
    file.sync_all()?;
    rustix::fs::fchmod(&file, Mode::from_raw_mode(0o644))?;
    // O primeiro sync fecha dados; este fecha a mudança de modo. O fsync do
    // pai torna o temporário retomável inclusive após queda de energia.
    file.sync_all()?;
    rustix::fs::fsync(parent)?;
    hook(InstallCheckpoint::ModeDurable)?;
    match rename_noreplace(&temporary) {
        Ok(()) => {}
        Err(Errno::EXIST) => {
            rustix::fs::unlinkat(parent, &temporary, AtFlags::empty())?;
            rustix::fs::fsync(parent)?;
            if !verify_existing(parent, name, content, true, trust, hook)? {
                bail!("destino de licença sumiu durante colisão de rename");
            }
        }
        Err(Errno::NOSYS | Errno::INVAL) => {
            match rustix::fs::linkat(parent, &temporary, parent, name, AtFlags::empty()) {
                Ok(()) => hook(InstallCheckpoint::FileLinked)?,
                Err(Errno::EXIST) => {
                    rustix::fs::unlinkat(parent, &temporary, AtFlags::empty())?;
                    rustix::fs::fsync(parent)?;
                    if !verify_existing(parent, name, content, true, trust, hook)? {
                        bail!("destino de licença sumiu durante colisão de hardlink");
                    }
                    return Ok(());
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            rustix::fs::unlinkat(parent, &temporary, AtFlags::empty())?;
        }
        Err(error) => return Err(std::io::Error::from(error).into()),
    }
    rustix::fs::fsync(parent)?;
    if !verify_existing(parent, name, content, true, trust, hook)? {
        bail!("arquivo de licença sumiu após publicação");
    }
    Ok(())
}

fn publish_file<F: FnMut(InstallCheckpoint) -> Result<()>>(
    parent: &impl AsFd,
    name: &OsStr,
    content: &[u8],
    trust: &InstallTrust,
    hook: &mut F,
) -> Result<()> {
    publish_file_with(parent, name, content, trust, hook, |temporary| {
        rustix::fs::renameat_with(parent, temporary, parent, name, RenameFlags::NOREPLACE)
    })
}

fn expected_inventory(entries: &[Entry]) -> (BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
    let directories = entries
        .iter()
        .filter(|entry| matches!(entry.kind, EntryKind::Directory))
        .map(|entry| entry.relative.clone())
        .collect();
    let files = entries
        .iter()
        .filter(|entry| matches!(entry.kind, EntryKind::Regular(_)))
        .map(|entry| entry.relative.clone())
        .collect();
    (directories, files)
}

fn preflight_staging(
    entries: &[Entry],
    generation: &impl AsFd,
    trust: &InstallTrust,
) -> Result<()> {
    let (expected_dirs, _expected_files) = expected_inventory(entries);
    let mut current_dirs = BTreeSet::new();
    let mut current_files = BTreeSet::new();
    existing_tree(
        generation,
        Path::new(""),
        &mut current_dirs,
        &mut current_files,
        trust,
    )?;
    if !current_dirs.is_subset(&expected_dirs) {
        bail!("staging de licenças contém diretório estrangeiro");
    }

    for relative in &current_files {
        let parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
        let candidates = entries
            .iter()
            .filter_map(|entry| {
                let EntryKind::Regular(content) = &entry.kind else {
                    return None;
                };
                if entry.relative.parent().unwrap_or_else(|| Path::new("")) != parent_path {
                    return None;
                }
                let name = entry.relative.file_name()?;
                let receipt = temporary_receipt_name(name, content);
                if entry.relative == *relative || receipt.as_os_str() == relative.file_name()? {
                    Some((name, receipt, content.as_slice()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            bail!("staging de licenças contém arquivo sem recibo reconhecido");
        }
        let (name, receipt, content) = &candidates[0];
        let parent = open_existing_chain(generation, parent_path, trust)?;
        let residue = inspect_publication_residue(&parent, name, receipt, content, trust)?;
        let is_final = relative.file_name() == Some(*name);
        if (is_final
            && !matches!(
                residue,
                PublicationResidue::Final | PublicationResidue::LinkedPair
            ))
            || (!is_final
                && !matches!(
                    residue,
                    PublicationResidue::Partial | PublicationResidue::LinkedPair
                ))
        {
            bail!("inventário do staging mudou durante o preflight");
        }
    }
    Ok(())
}

fn preflight_generation(
    generation: &impl AsFd,
    entries: &[Entry],
    trust: &InstallTrust,
) -> Result<()> {
    let (expected_dirs, expected_files) = expected_inventory(entries);
    let mut current_dirs = BTreeSet::new();
    let mut current_files = BTreeSet::new();
    existing_tree(
        generation,
        Path::new(""),
        &mut current_dirs,
        &mut current_files,
        trust,
    )?;
    if current_dirs != expected_dirs || current_files != expected_files {
        bail!("geração de licenças não reproduz o inventário exato");
    }
    let mut no_checkpoint = |_| Ok(());
    for entry in entries {
        let EntryKind::Regular(content) = &entry.kind else {
            continue;
        };
        let parent = open_existing_chain(
            generation,
            entry.relative.parent().unwrap_or_else(|| Path::new("")),
            trust,
        )?;
        if !verify_existing(
            &parent,
            entry
                .relative
                .file_name()
                .expect("entrada regular com nome"),
            content,
            false,
            trust,
            &mut no_checkpoint,
        )? {
            bail!("arquivo sumiu durante o preflight da geração");
        }
    }
    Ok(())
}

fn verify_generation<F: FnMut(InstallCheckpoint) -> Result<()>>(
    generation_parent: &impl AsFd,
    generation: &impl AsFd,
    entries: &[Entry],
    trust: &InstallTrust,
    hook: &mut F,
) -> Result<()> {
    // O preflight percorre e valida TODO o conteúdo antes do primeiro chmod.
    preflight_generation(generation, entries, trust)?;
    ensure_directory_mode(generation_parent, generation, trust, hook)?;

    let mut directories = entries
        .iter()
        .filter(|entry| matches!(entry.kind, EntryKind::Directory))
        .collect::<Vec<_>>();
    directories.sort_by_key(|entry| entry.relative.components().count());
    for entry in directories {
        let parent = open_existing_chain(
            generation,
            entry.relative.parent().unwrap_or_else(|| Path::new("")),
            trust,
        )?;
        let directory = rustix::fs::openat(
            &parent,
            entry
                .relative
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("diretório de licença sem nome"))?,
            directory_flags(),
            Mode::empty(),
        )?;
        ensure_directory_mode(&parent, &directory, trust, hook)?;
        rustix::fs::fsync(&directory)?;
    }
    for entry in entries {
        match &entry.kind {
            EntryKind::Directory => {}
            EntryKind::Regular(content) => {
                let parent = open_existing_chain(
                    generation,
                    entry.relative.parent().unwrap_or_else(|| Path::new("")),
                    trust,
                )?;
                if !verify_existing(
                    &parent,
                    entry
                        .relative
                        .file_name()
                        .expect("entrada regular com nome"),
                    content,
                    true,
                    trust,
                    hook,
                )? {
                    bail!("arquivo de licença sumiu no postflight");
                }
                verify_final(
                    &parent,
                    entry
                        .relative
                        .file_name()
                        .expect("entrada regular com nome"),
                    content,
                    trust,
                )?;
            }
            _ => bail!("tipo inesperado no snapshot de licenças"),
        }
    }
    rustix::fs::fsync(generation)?;
    Ok(())
}

fn materialize_generation<F: FnMut(InstallCheckpoint) -> Result<()>>(
    generation_parent: &impl AsFd,
    generation: &impl AsFd,
    entries: &[Entry],
    trust: &InstallTrust,
    hook: &mut F,
) -> Result<()> {
    // Nenhum chmod, mkdir ou unlink acontece antes de provar que tudo que já
    // existe é subconjunto factual do snapshot (mais um temporário cujo nome
    // recebe criptograficamente destino, tamanho e conteúdo esperado).
    preflight_staging(entries, generation, trust)?;
    ensure_directory_mode(generation_parent, generation, trust, hook)?;
    let mut directories = entries
        .iter()
        .filter(|entry| matches!(entry.kind, EntryKind::Directory))
        .collect::<Vec<_>>();
    directories.sort_by_key(|entry| entry.relative.components().count());
    for entry in directories {
        let parent_path = entry.relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = open_chain(generation, parent_path, trust)?;
        let name = entry
            .relative
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("diretório de licença sem nome"))?;
        let directory = open_or_create_dir(&parent, name, trust)?;
        ensure_directory_mode(&parent, &directory, trust, hook)?;
    }
    for entry in entries {
        let EntryKind::Regular(content) = &entry.kind else {
            continue;
        };
        let parent = open_chain(
            generation,
            entry.relative.parent().unwrap_or_else(|| Path::new("")),
            trust,
        )?;
        let name = entry
            .relative
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("arquivo de licença sem nome"))?;
        publish_file(&parent, name, content, trust, hook)?;
    }
    verify_generation(generation_parent, generation, entries, trust, hook)
}

fn open_optional_path(
    root: &impl AsFd,
    path: &Path,
    trust: &InstallTrust,
) -> Result<Option<OwnedFd>> {
    let mut current = rustix::fs::openat(root, ".", directory_flags(), Mode::empty())?;
    trust.validate_directory(&current, "target de licenças")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("caminho interno não canônico no preflight: {path:?}");
        };
        current = match rustix::fs::openat(&current, name, directory_flags(), Mode::empty()) {
            Ok(directory) => directory,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        trust.validate_directory(&current, "ancestral existente de licenças")?;
    }
    Ok(Some(current))
}

fn preflight_install_namespace(
    target: &impl AsFd,
    bundle: &LicenseBundle,
    trust: &InstallTrust,
) -> Result<()> {
    trust.validate_directory(target, "target para licenças")?;
    let media_path = Path::new(INSTALL_ROOT).join(MEDIA);
    let Some(media) = open_optional_path(target, &media_path, trust)? else {
        return Ok(());
    };
    let generation_name = OsStr::new(bundle.sha256());
    let generation =
        open_optional_dir(&media, generation_name, "geração final de licenças", trust)?;
    if let Some(generation) = &generation {
        preflight_generation(generation, bundle.entries(), trust)?;
    }
    let staging_name = OsString::from(format!(".minipax-license-{}.tmp", bundle.sha256()));
    let staging = open_optional_dir(&media, &staging_name, "staging de licenças", trust)?;
    if let Some(staging) = &staging {
        preflight_staging(bundle.entries(), staging, trust)?;
    }
    Ok(())
}

fn install_inner_with_trust<F: FnMut(InstallCheckpoint) -> Result<()>>(
    target: &Path,
    bundle: &LicenseBundle,
    trust: InstallTrust,
    mut hook: F,
) -> Result<()> {
    if !is_hash(&bundle.sha256) || sha256(&bundle.bytes) != bundle.sha256 {
        bail!("LICENSES_SHA256 não corresponde aos bytes de licenses.tar");
    }
    validate_canonical_archive(&bundle.bytes, &bundle.entries)?;

    let target_fd = open_path_anchored(target, directory_flags(), "target para licenças")
        .with_context(|| format!("não abri target para licenças: {}", target.display()))?;
    // Examina todos os nomes já existentes antes do primeiro mkdir/chmod/unlink.
    preflight_install_namespace(&target_fd, bundle, &trust)?;
    let install_path = Path::new(INSTALL_ROOT);
    let install_parent = open_chain(
        &target_fd,
        install_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("INSTALL_ROOT sem pai"))?,
        &trust,
    )?;
    let install_root = open_or_create_dir(
        &install_parent,
        install_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("INSTALL_ROOT sem nome"))?,
        &trust,
    )?;
    ensure_directory_mode(&install_parent, &install_root, &trust, &mut hook)?;
    let media = open_or_create_dir(&install_root, OsStr::new(MEDIA), &trust)?;
    ensure_directory_mode(&install_root, &media, &trust, &mut hook)?;

    let generation_name = OsStr::new(&bundle.sha256);
    if let Some(generation) =
        open_optional_dir(&media, generation_name, "geração final de licenças", &trust)?
    {
        return verify_generation(&media, &generation, &bundle.entries, &trust, &mut hook);
    }

    let staging_name = OsString::from(format!(".minipax-license-{}.tmp", bundle.sha256));
    let staging = open_or_create_dir(&media, &staging_name, &trust)?;
    materialize_generation(&media, &staging, &bundle.entries, &trust, &mut hook)?;
    rustix::fs::fsync(&staging)?;
    hook(InstallCheckpoint::GenerationReady)?;
    // O checkpoint permite simular queda e também torna explícita a última
    // fronteira mutável: reabra tudo depois dele antes do rename publicador.
    verify_generation(&media, &staging, &bundle.entries, &trust, &mut hook)?;
    rustix::fs::fsync(&staging)?;

    match rustix::fs::renameat_with(
        &media,
        &staging_name,
        &media,
        generation_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            rustix::fs::fsync(&media)?;
            hook(InstallCheckpoint::GenerationPublished)?;
        }
        // Outro instalador idêntico pode ter publicado o mesmo staging entre
        // nosso postflight e o rename. Em ambos os casos a única autoridade é
        // reabrir e verificar a geração final pelo nome hash.
        Err(Errno::EXIST | Errno::NOENT) => {}
        Err(Errno::NOSYS | Errno::INVAL) => {
            bail!("kernel não oferece rename NOREPLACE para publicar a geração de licenças")
        }
        Err(error) => return Err(std::io::Error::from(error).into()),
    }
    let generation =
        open_optional_dir(&media, generation_name, "geração final de licenças", &trust)?
            .ok_or_else(|| anyhow::anyhow!("geração de licenças sumiu após publicação"))?;
    verify_generation(&media, &generation, &bundle.entries, &trust, &mut hook)
}

fn install_inner<F: FnMut(InstallCheckpoint) -> Result<()>>(
    target: &Path,
    bundle: &LicenseBundle,
    hook: F,
) -> Result<()> {
    install_inner_with_trust(target, bundle, InstallTrust::current()?, hook)
}

/// Instala uma geração imutável em
/// `usr/share/licenses/distropica-release/media/<LICENSES_SHA256>/`.
/// Gerações anteriores permanecem lado a lado; uma atualização A→B nunca
/// mistura arquivos removidos ou alterados entre os dois snapshots.
pub fn install(target: &Path, bundle: &LicenseBundle) -> Result<()> {
    install_inner(target, bundle, |_| Ok(()))
}

#[cfg(test)]
pub(crate) fn write_test_bundle(newspeak: &Path, output: &Path) -> Result<()> {
    let own = [
        ("GPL-3.0-or-later.txt", b"GPL DE TESTE\n".as_slice()),
        ("NOTICE", b"NOTICE DE TESTE\n".as_slice()),
        ("LICENSING.md", b"ESCOPO DE TESTE\n".as_slice()),
    ];
    let base_files = newspeak.join("base/files");
    std::fs::create_dir_all(&base_files)?;
    for (name, bytes) in own {
        std::fs::write(base_files.join(name), bytes)?;
    }

    let evidence = b"GPL DE TESTE\n".to_vec();
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    files.insert(
        INDEX.into(),
        format!(
            "# pacote\tcomponente\tsha256\tprimeira-linha\nbase\t{}\t{}\t{}\n",
            encode_ascii_hex_field(b"distropica/GPL-3.0-or-later.txt (payload pr\xc3\xb3prio)"),
            sha256(&evidence),
            encode_ascii_hex_field(b"GPL DE TESTE")
        )
        .into_bytes(),
    );
    files.insert(README.into(), "Evidência de teste.\n".as_bytes().to_vec());
    files.insert(
        PACKAGES.into(),
        b"# pacote\tversao\tmundo\tlicenca\nbase\t1\tB\tGPL-3.0-or-later\n".to_vec(),
    );
    files.insert("base/GPL-3.0-or-later.txt".into(), evidence);
    files.insert(
        "distropica/GPL-3.0-or-later.txt".into(),
        b"GPL DE TESTE\n".to_vec(),
    );
    files.insert("distropica/NOTICE".into(), b"NOTICE DE TESTE\n".to_vec());
    files.insert(
        "distropica/LICENSING.md".into(),
        b"ESCOPO DE TESTE\n".to_vec(),
    );
    let manifest = files
        .iter()
        .map(|(path, bytes)| format!("{}  {path}\n", sha256(bytes)))
        .collect::<String>();
    files.insert(MANIFEST.into(), manifest.into_bytes());

    let mut directories = BTreeSet::new();
    for path in files.keys() {
        let mut parent = Path::new(path).parent();
        while let Some(value) = parent.filter(|value| !value.as_os_str().is_empty()) {
            directories.insert(value.to_path_buf());
            parent = value.parent();
        }
    }
    let mut entries = directories
        .into_iter()
        .map(|relative| Entry {
            relative,
            mode: 0o755,
            kind: EntryKind::Directory,
        })
        .chain(files.into_iter().map(|(path, content)| Entry {
            relative: PathBuf::from(path),
            mode: 0o644,
            kind: EntryKind::Regular(content),
        }))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.relative
            .as_os_str()
            .as_bytes()
            .cmp(right.relative.as_os_str().as_bytes())
    });
    let mut archive = Vec::new();
    write_canonical_archive(&entries, &mut archive)?;
    std::fs::write(output, archive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn generation_root(target: &Path, bundle: &LicenseBundle) -> PathBuf {
        target.join(INSTALL_ROOT).join(MEDIA).join(&bundle.sha256)
    }

    fn create_target(path: &Path) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn create_internal_tree(target: &Path, relative: &Path) -> PathBuf {
        let mut current = target.to_path_buf();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                panic!("fixture interna não canônica: {relative:?}");
            };
            current.push(name);
            if !current.exists() {
                std::fs::create_dir(&current).unwrap();
            }
            std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        current
    }

    fn staging_root(target: &Path, bundle: &LicenseBundle) -> PathBuf {
        target
            .join(INSTALL_ROOT)
            .join(MEDIA)
            .join(format!(".minipax-license-{}.tmp", bundle.sha256))
    }

    fn repack_with_manifest(mut entries: Vec<Entry>) -> Vec<u8> {
        let manifest = entries
            .iter()
            .filter_map(|entry| match &entry.kind {
                EntryKind::Regular(content) if entry.relative != Path::new(MANIFEST) => Some((
                    entry.relative.to_string_lossy().into_owned(),
                    sha256(content),
                )),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(path, hash)| format!("{hash}  {path}\n"))
            .collect::<String>()
            .into_bytes();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.relative == Path::new(MANIFEST))
            .unwrap();
        entry.kind = EntryKind::Regular(manifest);
        entries.sort_by(|left, right| {
            left.relative
                .as_os_str()
                .as_bytes()
                .cmp(right.relative.as_os_str().as_bytes())
        });
        let mut archive = Vec::new();
        write_canonical_archive(&entries, &mut archive).unwrap();
        archive
    }

    fn replace_regular(entries: &mut [Entry], path: &str, content: Vec<u8>) {
        let entry = entries
            .iter_mut()
            .find(|entry| entry.relative == Path::new(path))
            .unwrap();
        entry.kind = EntryKind::Regular(content);
    }

    fn bundle_from_entries(entries: Vec<Entry>) -> LicenseBundle {
        let expected = BTreeMap::from([
            (
                "distropica/GPL-3.0-or-later.txt".to_string(),
                b"GPL DE TESTE\n".to_vec(),
            ),
            (
                "distropica/NOTICE".to_string(),
                b"NOTICE DE TESTE\n".to_vec(),
            ),
            (
                "distropica/LICENSING.md".to_string(),
                b"ESCOPO DE TESTE\n".to_vec(),
            ),
        ]);
        load_unbound(repack_with_manifest(entries))
            .unwrap()
            .bind_expected(&expected)
            .unwrap()
    }

    fn refresh_checksum(header: &mut [u8]) {
        assert_eq!(header.len(), TAR_BLOCK_BYTES);
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let digits = format!("{checksum:06o}");
        assert_eq!(digits.len(), 6);
        header[148..154].copy_from_slice(digits.as_bytes());
        header[154] = 0;
        header[155] = b' ';
    }

    fn prepend_extension(archive: &[u8], entry_type: u8, content: &[u8]) -> Vec<u8> {
        let path = if entry_type == b'L' {
            b"././@LongLink".as_slice()
        } else {
            b"PaxHeaders/INDICE".as_slice()
        };
        let header = canonical_gnu_header(path, 0o644, content.len() as u64, entry_type).unwrap();
        let padding = (TAR_BLOCK_BYTES - content.len() % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
        let mut forged = Vec::with_capacity(header.len() + content.len() + padding + archive.len());
        forged.extend_from_slice(&header);
        forged.extend_from_slice(content);
        forged.resize(forged.len() + padding, 0);
        forged.extend_from_slice(archive);
        forged
    }

    #[test]
    fn bundle_valida_instala_e_recusa_extra_no_destino() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        assert_eq!(bundle.sha256, sha256(&bundle.bytes));

        let target = temp.path().join("target");
        create_target(&target);
        install(&target, &bundle).unwrap();
        assert_eq!(
            std::fs::read(generation_root(&target, &bundle).join("distropica/NOTICE")).unwrap(),
            b"NOTICE DE TESTE\n"
        );
        install(&target, &bundle).unwrap();
        std::fs::write(generation_root(&target, &bundle).join("extra"), b"extra").unwrap();
        assert!(install(&target, &bundle).is_err());
    }

    #[test]
    fn bundle_selado_expoe_somente_visoes_validadas() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        assert_eq!(bundle.sha256(), sha256(bundle.bytes()));
        assert!(!bundle.entries().is_empty());
        let package = bundle.packages().first().unwrap();
        assert_eq!(package.name(), "base");
        assert_eq!(package.version(), "1");
        assert_eq!(package.world(), "B");
        assert_eq!(package.license(), "GPL-3.0-or-later");
    }

    #[test]
    fn unbound_so_promove_consumindo_snapshot_newspeak_factual() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bytes = std::fs::read(&archive).unwrap();
        let unbound = load_unbound(bytes.clone()).unwrap();
        assert_eq!(unbound.sha256(), sha256(unbound.bytes()));
        assert_eq!(unbound.packages()[0].name(), "base");
        assert!(!unbound.entries().is_empty());

        let snapshot = [
            Entry {
                relative: PathBuf::from("base/files/GPL-3.0-or-later.txt"),
                mode: 0o644,
                kind: EntryKind::Regular(b"GPL DE TESTE\n".to_vec()),
            },
            Entry {
                relative: PathBuf::from("base/files/NOTICE"),
                mode: 0o644,
                kind: EntryKind::Regular(b"NOTICE DE TESTE\n".to_vec()),
            },
            Entry {
                relative: PathBuf::from("base/files/LICENSING.md"),
                mode: 0o644,
                kind: EntryKind::Regular(b"ESCOPO DE TESTE\n".to_vec()),
            },
        ];
        let bound = unbound.bind_newspeak_snapshot(&snapshot).unwrap();
        let target = temp.path().join("target");
        create_target(&target);
        install(&target, &bound).unwrap();

        let mut wrong = snapshot.to_vec();
        wrong[0].kind = EntryKind::Regular(b"texto errado\n".to_vec());
        assert!(load_unbound(bytes)
            .unwrap()
            .bind_newspeak_snapshot(&wrong)
            .is_err());
    }

    #[test]
    fn indice_hex_recusa_legado_nao_canonico_e_path_inseguro() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let original = load_path(&archive, &newspeak).unwrap();
        let evidence_hash = sha256(b"GPL DE TESTE\n");
        let valid_component =
            encode_ascii_hex_field(b"distropica/GPL-3.0-or-later.txt (payload pr\xc3\xb3prio)");
        let index = |component: &str, preview: &str| {
            format!(
                "# pacote\tcomponente\tsha256\tprimeira-linha\nbase\t{component}\t{evidence_hash}\t{preview}\n"
            )
            .into_bytes()
        };
        let load_index = |component: &str, preview: &str| {
            let mut entries = original.entries.clone();
            replace_regular(&mut entries, INDEX, index(component, preview));
            load_unbound(repack_with_manifest(entries))
        };

        assert!(load_index("caminho-legado", "preview-legado").is_err());
        assert!(load_index("hex:0", "hex:").is_err());
        assert!(load_index("hex:4A", "hex:").is_err());
        assert!(load_index(&valid_component, "preview-legado").is_err());
        assert!(load_index(&valid_component, "hex:0").is_err());
        assert!(load_index(&valid_component, "hex:4A").is_err());
        assert!(load_index(&encode_ascii_hex_field(b"path\\bad"), "hex:").is_err());
        for control in (0u8..=0x1f).chain(std::iter::once(0x7f)) {
            let component = [b'p', control];
            assert!(
                load_index(&encode_ascii_hex_field(&component), "hex:").is_err(),
                "componente aceitou controle ASCII {control:#04x}"
            );
            let path = Path::new(OsStr::from_bytes(&component));
            assert!(
                validate_relative(path, "teste").is_err(),
                "PATH aceitou controle ASCII {control:#04x}"
            );
        }
        assert!(validate_relative(Path::new("path\\bad"), "teste").is_err());

        // Preview é bytes factuais, não PATH: controles e um primeiro byte de
        // UTF-8 na fronteira permanecem seguros porque só aparecem como hex.
        let encoded_hostile_preview = encode_ascii_hex_field(b"A\t\\\x01\x7f\xc3");
        let accepted = load_index(&valid_component, &encoded_hostile_preview).unwrap();
        let index_bytes = accepted
            .entries()
            .iter()
            .find(|entry| entry.relative == Path::new(INDEX))
            .and_then(|entry| match &entry.kind {
                EntryKind::Regular(content) => Some(content),
                _ => None,
            })
            .unwrap();
        assert!(index_bytes.is_ascii());
        assert!(std::str::from_utf8(index_bytes)
            .unwrap()
            .contains(&encoded_hostile_preview));
    }

    #[test]
    fn uid_e_parent_gravavel_falham_antes_de_criar_qualquer_nome() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let current = InstallTrust::current().unwrap();

        let target_uid = temp.path().join("target-uid");
        create_target(&target_uid);
        let foreign_uid = if current.uid == u32::MAX {
            current.uid - 1
        } else {
            current.uid + 1
        };
        assert!(install_inner_with_trust(
            &target_uid,
            &bundle,
            InstallTrust { uid: foreign_uid },
            |_| Ok(())
        )
        .is_err());
        assert!(std::fs::read_dir(&target_uid).unwrap().next().is_none());

        let target_mode = temp.path().join("target-mode");
        create_target(&target_mode);
        std::fs::set_permissions(&target_mode, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(install_inner_with_trust(&target_mode, &bundle, current, |_| Ok(())).is_err());
        assert!(std::fs::read_dir(&target_mode).unwrap().next().is_none());
    }

    #[test]
    fn entrada_e_ancestral_symlink_falham_fechado() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let real = temp.path().join("real.tar");
        std::fs::rename(&archive, &real).unwrap();
        symlink(&real, &archive).unwrap();
        assert!(load_path(&archive, &newspeak).is_err());
        let alias = temp.path().join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(load_path(&alias.join("real.tar"), &newspeak).is_err());

        let bundle = load_path(&real, &newspeak).unwrap();
        let target = temp.path().join("target");
        let outside = temp.path().join("outside");
        create_target(&target);
        std::fs::create_dir(&outside).unwrap();
        let target_alias = temp.path().join("target-alias");
        symlink(&target, &target_alias).unwrap();
        assert!(install(&target_alias, &bundle).is_err());
        symlink(&outside, target.join("usr")).unwrap();
        assert!(install(&target, &bundle).is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[test]
    fn manifest_hash_e_tipo_extra_sao_rejeitados() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let valid = std::fs::read(&archive).unwrap();

        let mut changed = valid.clone();
        let offset = changed
            .windows(b"GPL DE TESTE".len())
            .position(|window| window == b"GPL DE TESTE")
            .unwrap();
        changed[offset] ^= 1;
        assert!(load_bytes(changed, &newspeak).is_err());

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "extra-link", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
        let special = builder.into_inner().unwrap();
        assert!(load_unbound(special).is_err());
    }

    #[test]
    fn manifesto_malformado_em_fronteira_utf8_falha_sem_panico() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let mut entries = load_path(&archive, &newspeak).unwrap().entries;
        let manifest = entries
            .iter_mut()
            .find(|entry| entry.relative == Path::new(MANIFEST))
            .unwrap();
        // O byte 64 cai dentro de 'é'. Slicing direto de &str nesse offset
        // causava panic em vez da recusa fechada esperada para input hostil.
        manifest.kind = EntryKind::Regular(format!("{}é  x\n", "a".repeat(63)).into_bytes());
        let malformed = crate::tree::pack(&entries, 0).unwrap();
        assert!(load_unbound(malformed).is_err());
    }

    #[test]
    fn arquivo_conflitante_nao_e_normalizado_antes_de_validar_conteudo() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let target = temp.path().join("target");
        create_target(&target);
        install(&target, &bundle).unwrap();

        let conflict = generation_root(&target, &bundle).join("base/GPL-3.0-or-later.txt");
        std::fs::write(&conflict, b"conteudo hostil\n").unwrap();
        std::fs::set_permissions(&conflict, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(install(&target, &bundle).is_err());
        assert_eq!(std::fs::read(&conflict).unwrap(), b"conteudo hostil\n");
        assert_eq!(
            std::fs::metadata(&conflict).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn preflight_final_valida_todo_conteudo_antes_de_chmod() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let target = temp.path().join("target");
        create_target(&target);
        install(&target, &bundle).unwrap();

        let generation = generation_root(&target, &bundle);
        let child = generation.join("base");
        let victim = child.join("GPL-3.0-or-later.txt");
        std::fs::write(&victim, b"conteudo estrangeiro\n").unwrap();
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(install(&target, &bundle).is_err());
        assert_eq!(
            std::fs::metadata(&generation).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&child).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"conteudo estrangeiro\n");
    }

    #[test]
    fn preflight_final_e_staging_sao_independentes_antes_de_chmod() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let target = temp.path().join("target");
        create_target(&target);
        install(&target, &bundle).unwrap();

        let generation = generation_root(&target, &bundle);
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o700)).unwrap();
        let staging = staging_root(&target, &bundle);
        create_internal_tree(&target, staging.strip_prefix(&target).unwrap());
        let foreign = staging.join(".minipax-license.tmp");
        std::fs::write(&foreign, b"temporario estrangeiro\n").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(install(&target, &bundle).is_err());
        assert_eq!(
            std::fs::metadata(&generation).unwrap().permissions().mode() & 0o7777,
            0o700,
            "o final não pode sofrer chmod antes do preflight independente do staging"
        );
        assert_eq!(
            std::fs::read(&foreign).unwrap(),
            b"temporario estrangeiro\n"
        );
    }

    #[test]
    fn fallback_hardlink_interrompido_e_reconciliado_no_retry() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("stage");
        create_target(&directory);
        let parent = File::open(&directory).unwrap();
        let trust = InstallTrust::current().unwrap();
        let name = OsStr::new("LICENSE");
        let content = b"licenca crash-safe\n";
        let receipt = temporary_receipt_name(name, content);
        let mut linked = false;
        let result = publish_file_with(
            &parent,
            name,
            content,
            &trust,
            &mut |checkpoint| {
                if checkpoint == InstallCheckpoint::FileLinked {
                    linked = true;
                    bail!("queda entre linkat e unlinkat");
                }
                Ok(())
            },
            |_| Err(Errno::NOSYS),
        );
        assert!(result.is_err());
        assert!(linked);
        let final_metadata = std::fs::metadata(directory.join(name)).unwrap();
        let temporary_metadata = std::fs::metadata(directory.join(&receipt)).unwrap();
        assert_eq!(final_metadata.ino(), temporary_metadata.ino());
        assert_eq!(final_metadata.nlink(), 2);

        publish_file(&parent, name, content, &trust, &mut |_| Ok(())).unwrap();
        assert_eq!(std::fs::read(directory.join(name)).unwrap(), content);
        assert!(!directory.join(receipt).exists());
        assert_eq!(std::fs::metadata(directory.join(name)).unwrap().nlink(), 1);
    }

    #[test]
    fn recibo_temporario_retomavel_e_colisao_divergente_preservada() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let entry = bundle
            .entries()
            .iter()
            .find(|entry| {
                entry.relative.parent() == Some(Path::new(""))
                    && matches!(entry.kind, EntryKind::Regular(_))
            })
            .unwrap();
        let EntryKind::Regular(content) = &entry.kind else {
            unreachable!();
        };
        let name = entry.relative.file_name().unwrap();
        let receipt = temporary_receipt_name(name, content);

        let target_resume = temp.path().join("target-resume");
        create_target(&target_resume);
        let stage_resume = staging_root(&target_resume, &bundle);
        create_internal_tree(
            &target_resume,
            stage_resume.strip_prefix(&target_resume).unwrap(),
        );
        let partial = &content[..content.len().min(7)];
        std::fs::write(stage_resume.join(&receipt), partial).unwrap();
        std::fs::set_permissions(
            stage_resume.join(&receipt),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        install(&target_resume, &bundle).unwrap();
        assert_eq!(
            std::fs::read(generation_root(&target_resume, &bundle).join(name)).unwrap(),
            content.as_slice()
        );

        let target_collision = temp.path().join("target-collision");
        create_target(&target_collision);
        let stage_collision = staging_root(&target_collision, &bundle);
        create_internal_tree(
            &target_collision,
            stage_collision.strip_prefix(&target_collision).unwrap(),
        );
        let planted = stage_collision.join(&receipt);
        std::fs::write(&planted, b"prefixo estrangeiro\n").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(install(&target_collision, &bundle).is_err());
        assert_eq!(std::fs::read(&planted).unwrap(), b"prefixo estrangeiro\n");
    }

    #[test]
    fn postflight_reabre_e_recusa_mutacao_depois_da_publicacao() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let target = temp.path().join("target");
        create_target(&target);
        let victim = staging_root(&target, &bundle).join("base/GPL-3.0-or-later.txt");
        let result = install_inner(&target, &bundle, |checkpoint| {
            if checkpoint == InstallCheckpoint::GenerationReady {
                std::fs::write(&victim, b"trocado depois da publicacao\n")?;
            }
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn staging_retomavel_publicacao_e_chmod_sao_crash_safe() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();
        let target = temp.path().join("target");
        create_target(&target);

        let mut stopped = false;
        let first = install_inner(&target, &bundle, |checkpoint| {
            if checkpoint == InstallCheckpoint::ModeDurable && !stopped {
                stopped = true;
                bail!("queda depois do chmod durável");
            }
            Ok(())
        });
        assert!(first.is_err());
        assert!(stopped);
        assert!(staging_root(&target, &bundle).is_dir());
        assert!(!generation_root(&target, &bundle).exists());

        let ready = install_inner(&target, &bundle, |checkpoint| {
            if checkpoint == InstallCheckpoint::GenerationReady {
                bail!("queda antes do rename");
            }
            Ok(())
        });
        assert!(ready.is_err());
        assert!(staging_root(&target, &bundle).is_dir());
        assert!(!generation_root(&target, &bundle).exists());

        let published = install_inner(&target, &bundle, |checkpoint| {
            if checkpoint == InstallCheckpoint::GenerationPublished {
                bail!("queda depois do rename e fsync do pai");
            }
            Ok(())
        });
        assert!(published.is_err());
        assert!(generation_root(&target, &bundle).is_dir());
        install(&target, &bundle).unwrap();

        let victim = generation_root(&target, &bundle).join("distropica/NOTICE");
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut repaired = false;
        let interrupted_repair = install_inner(&target, &bundle, |checkpoint| {
            if checkpoint == InstallCheckpoint::ModeDurable && !repaired {
                repaired = true;
                bail!("queda depois de persistir correção de modo");
            }
            Ok(())
        });
        assert!(interrupted_repair.is_err());
        assert!(repaired);
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        install(&target, &bundle).unwrap();
    }

    #[test]
    fn geracoes_a_e_b_coexistem_sem_residuo_removido_ou_alterado() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let original = load_path(&archive, &newspeak).unwrap();

        let mut a_entries = original.entries.clone();
        let removed = b"EVIDENCIA REMOVIDA EM B\n".to_vec();
        a_entries.push(Entry {
            relative: PathBuf::from("base/REMOVIDO"),
            mode: 0o644,
            kind: EntryKind::Regular(removed.clone()),
        });
        let a_index = format!(
            "# pacote\tcomponente\tsha256\tprimeira-linha\nbase\t{}\t{}\t{}\nbase\t{}\t{}\t{}\n",
            encode_ascii_hex_field(b"distropica/GPL-3.0-or-later.txt (payload pr\xc3\xb3prio)"),
            sha256(b"GPL DE TESTE\n"),
            encode_ascii_hex_field(b"GPL DE TESTE"),
            encode_ascii_hex_field(b"removido"),
            sha256(&removed),
            encode_ascii_hex_field(b"EVIDENCIA REMOVIDA EM B")
        );
        replace_regular(&mut a_entries, INDEX, a_index.into_bytes());
        let bundle_a = bundle_from_entries(a_entries);

        let mut b_entries = original.entries;
        replace_regular(
            &mut b_entries,
            README,
            b"Evidencia alterada na geracao B.\n".to_vec(),
        );
        let bundle_b = bundle_from_entries(b_entries);
        assert_ne!(bundle_a.sha256, bundle_b.sha256);

        let target = temp.path().join("target");
        create_target(&target);
        install(&target, &bundle_a).unwrap();
        install(&target, &bundle_b).unwrap();
        let root_a = generation_root(&target, &bundle_a);
        let root_b = generation_root(&target, &bundle_b);
        assert_eq!(
            std::fs::read(root_a.join("base/REMOVIDO")).unwrap(),
            removed
        );
        assert!(!root_b.join("base/REMOVIDO").exists());
        assert_ne!(
            std::fs::read(root_a.join(README)).unwrap(),
            std::fs::read(root_b.join(README)).unwrap()
        );
        install(&target, &bundle_a).unwrap();
        install(&target, &bundle_b).unwrap();
    }

    #[test]
    fn colisao_symlink_hardlink_e_entrada_estrangeira_falham_fechado() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();

        let target_symlink = temp.path().join("target-symlink");
        let outside = temp.path().join("outside");
        create_target(&target_symlink);
        std::fs::create_dir(&outside).unwrap();
        let media = target_symlink.join(INSTALL_ROOT).join(MEDIA);
        create_internal_tree(&target_symlink, &Path::new(INSTALL_ROOT).join(MEDIA));
        symlink(&outside, media.join(&bundle.sha256)).unwrap();
        assert!(install(&target_symlink, &bundle).is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());

        let target_hardlink = temp.path().join("target-hardlink");
        create_target(&target_hardlink);
        let stage = staging_root(&target_hardlink, &bundle);
        create_internal_tree(
            &target_hardlink,
            stage.strip_prefix(&target_hardlink).unwrap(),
        );
        let foreign = temp.path().join("foreign");
        std::fs::write(&foreign, b"conteudo estrangeiro\n").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&foreign, stage.join(INDEX)).unwrap();
        assert!(install(&target_hardlink, &bundle).is_err());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"conteudo estrangeiro\n");
        assert_eq!(std::fs::metadata(&foreign).unwrap().nlink(), 2);

        let target_foreign = temp.path().join("target-foreign");
        create_target(&target_foreign);
        let media = target_foreign.join(INSTALL_ROOT).join(MEDIA);
        create_internal_tree(&target_foreign, &Path::new(INSTALL_ROOT).join(MEDIA));
        std::fs::write(media.join(&bundle.sha256), b"nao e diretorio\n").unwrap();
        assert!(install(&target_foreign, &bundle).is_err());

        let target_temporary = temp.path().join("target-temporary");
        create_target(&target_temporary);
        let stage = staging_root(&target_temporary, &bundle);
        create_internal_tree(
            &target_temporary,
            stage.strip_prefix(&target_temporary).unwrap(),
        );
        let temporary = stage.join(".minipax-license.tmp");
        std::fs::write(&temporary, b"temporario estrangeiro\n").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(install(&target_temporary, &bundle).is_err());
        assert_eq!(
            std::fs::read(&temporary).unwrap(),
            b"temporario estrangeiro\n"
        );
    }

    #[test]
    fn indice_recusa_evidencia_ausente_e_extra_mesmo_com_manifesto_recalculado() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let bundle = load_path(&archive, &newspeak).unwrap();

        let mut missing = bundle.entries.clone();
        missing.retain(|entry| entry.relative != Path::new("base/GPL-3.0-or-later.txt"));
        assert!(load_unbound(repack_with_manifest(missing)).is_err());

        let mut extra = bundle.entries;
        extra.push(Entry {
            relative: PathBuf::from("base/EXTRA"),
            mode: 0o644,
            kind: EntryKind::Regular(b"extra\n".to_vec()),
        });
        assert!(load_unbound(repack_with_manifest(extra)).is_err());
    }

    fn collect_names(root: &Path, directory: &Path, output: &mut Vec<Vec<u8>>) {
        let mut children = std::fs::read_dir(directory)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let path = child.path();
            output.push(
                path.strip_prefix(root)
                    .unwrap()
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
            );
            if path.is_dir() {
                collect_names(root, &path, output);
            }
        }
    }

    #[test]
    fn tar_gnu_emitido_pelo_sbom_e_aceito_e_reprodutivel() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let rust_tar = temp.path().join("rust.tar");
        write_test_bundle(&newspeak, &rust_tar).unwrap();
        let mut entries = load_path(&rust_tar, &newspeak).unwrap().entries;
        let long_name = format!("base/{}", "l".repeat(120));
        let long_content = b"EVIDENCIA COM GNU LONGNAME\n".to_vec();
        entries.push(Entry {
            relative: PathBuf::from(&long_name),
            mode: 0o644,
            kind: EntryKind::Regular(long_content.clone()),
        });
        let old_index = entries
            .iter()
            .find(|entry| entry.relative == Path::new(INDEX))
            .and_then(|entry| match &entry.kind {
                EntryKind::Regular(content) => std::str::from_utf8(content).ok(),
                _ => None,
            })
            .unwrap();
        let mut index_lines = old_index
            .lines()
            .skip(1)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        index_lines.push(format!(
            "base\t{}\t{}\t{}",
            encode_ascii_hex_field(b"gnu-longname"),
            sha256(&long_content),
            encode_ascii_hex_field(b"EVIDENCIA COM GNU LONGNAME")
        ));
        index_lines.sort();
        let new_index = format!(
            "# pacote\tcomponente\tsha256\tprimeira-linha\n{}\n",
            index_lines.join("\n")
        );
        replace_regular(&mut entries, INDEX, new_index.into_bytes());
        let long_bundle = bundle_from_entries(entries);
        std::fs::write(&rust_tar, &long_bundle.bytes).unwrap();
        assert!(long_name.len() > 100);
        load_path(&rust_tar, &newspeak).unwrap();
        let tree = temp.path().join("licencas");
        std::fs::create_dir(&tree).unwrap();
        tar::Archive::new(File::open(&rust_tar).unwrap())
            .unpack(&tree)
            .unwrap();
        let mut names = Vec::new();
        collect_names(&tree, &tree, &mut names);
        names.sort();
        let list = temp.path().join("lista");
        let mut list_bytes = Vec::new();
        for name in names {
            list_bytes.extend_from_slice(&name);
            list_bytes.push(0);
        }
        std::fs::write(&list, list_bytes).unwrap();
        let first = temp.path().join("gnu-a.tar");
        let second = temp.path().join("gnu-b.tar");
        for output in [&first, &second] {
            let status = Command::new("tar")
                .current_dir(&tree)
                .arg("--create")
                .arg("--file")
                .arg(output)
                .arg("--format=gnu")
                .arg("--mtime=@0")
                .arg("--owner=0")
                .arg("--group=0")
                .arg("--numeric-owner")
                .arg("--mode=u+rwX,go+rX,go-w")
                .arg("--no-recursion")
                .arg("--null")
                .arg("--verbatim-files-from")
                .arg("--files-from")
                .arg(&list)
                .status()
                .unwrap();
            assert!(status.success());
            load_path(output, &newspeak).unwrap();
        }
        assert_eq!(
            std::fs::read(&first).unwrap(),
            std::fs::read(&second).unwrap()
        );
        assert_eq!(
            std::fs::read(&rust_tar).unwrap(),
            std::fs::read(&second).unwrap(),
            "o reempacotador interno precisa reproduzir byte a byte o GNU tar oficial"
        );
    }

    #[test]
    fn produtor_neutraliza_tar_options_e_bundle_atravessa_loader_rust() {
        let temp = tempfile::tempdir().unwrap();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("minipax precisa estar dentro do repositório");
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let mut hostile_line = vec![b'A'; 71];
        hostile_line.extend_from_slice(b"\xc3\xa9\t\\\x01Z\n");
        hostile_line.extend_from_slice(
            b"Permission is hereby granted, free of charge, to any person obtaining a copy.\n",
        );
        std::fs::write(source.join(MANIFEST), hostile_line).unwrap();

        let upstream = temp.path().join("upstream.tar.gz");
        let tar_output = Command::new("tar")
            .env_remove("TAR_OPTIONS")
            .arg("-czf")
            .arg(&upstream)
            .arg("-C")
            .arg(&source)
            .arg(MANIFEST)
            .output()
            .unwrap();
        assert!(
            tar_output.status.success(),
            "não criei fixture upstream: {}",
            String::from_utf8_lossy(&tar_output.stderr)
        );

        for (case, hostile_options) in [
            ("blocking", "--blocking-factor=1"),
            ("transform", "--transform=s,^INDICE$,ALTERADO,"),
            ("exclude", "--exclude=MANIFEST.sha256"),
        ] {
            let bundle_dir = temp.path().join(case);
            std::fs::create_dir_all(bundle_dir.join("upstream")).unwrap();
            std::fs::copy(&upstream, bundle_dir.join("upstream/fixture")).unwrap();
            std::fs::write(
                bundle_dir.join("INVENTARIO"),
                b"# pacote\tversao\tmundo\tlicenca\tsha256\torigem\tarquivo\ttipo\nfixture\t1\tB\tMIT\tfixture\thttps://example.invalid/fixture\tupstream/fixture\tupstream\n",
            )
            .unwrap();
            let output = Command::new(repo.join("bootstrap/sbom"))
                .arg("--bundle")
                .arg(&bundle_dir)
                .arg("--strict")
                .env("TAR_OPTIONS", hostile_options)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "produtor falhou sob TAR_OPTIONS={hostile_options}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            let produced = bundle_dir.join("licenses.tar");
            let bytes = std::fs::read(&produced).unwrap();
            assert_eq!(bytes.len() % GNU_TAR_RECORD_BYTES, 0);
            let bound = load_path(&produced, &repo.join("newspeak")).unwrap();
            assert!(bound.entries().iter().any(|entry| {
                entry.relative == Path::new("fixture/MANIFEST.sha256")
                    && matches!(entry.kind, EntryKind::Regular(_))
            }));
            let index = bound
                .entries()
                .iter()
                .find(|entry| entry.relative == Path::new(INDEX))
                .and_then(|entry| match &entry.kind {
                    EntryKind::Regular(content) => Some(content.as_slice()),
                    _ => None,
                })
                .unwrap();
            assert!(index.is_ascii());
            let expected_preview = format!("\thex:{}c3\n", "41".repeat(71));
            assert!(std::str::from_utf8(index)
                .unwrap()
                .contains(&expected_preview));
        }
    }

    #[test]
    fn tar_recusa_pax_longname_redundante_device_nomes_e_bytes_finais() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        let archive = temp.path().join("licenses.tar");
        write_test_bundle(&newspeak, &archive).unwrap();
        let valid = std::fs::read(&archive).unwrap();
        load_unbound(valid.clone()).unwrap();

        let longname = prepend_extension(&valid, b'L', b"INDICE\0");
        assert!(load_unbound(longname).is_err());
        let pax = prepend_extension(&valid, b'x', b"13 comment=x\n");
        assert!(load_unbound(pax).is_err());

        for (range, value) in [
            (265..269, b"root".as_slice()),
            (297..301, b"root".as_slice()),
            (329..336, b"0000001".as_slice()),
            (337..344, b"0000001".as_slice()),
        ] {
            let mut changed = valid.clone();
            changed[range].copy_from_slice(value);
            refresh_checksum(&mut changed[..TAR_BLOCK_BYTES]);
            let error = load_unbound(changed).unwrap_err().to_string();
            assert!(error.contains("byte-idêntico"), "erro inesperado: {error}");
        }

        let mut trailing_zero = valid.clone();
        trailing_zero.extend_from_slice(&[0; TAR_BLOCK_BYTES]);
        assert!(load_unbound(trailing_zero).is_err());
        let mut trailing_nonzero = valid;
        trailing_nonzero.push(1);
        assert!(load_unbound(trailing_nonzero).is_err());
    }

    #[test]
    fn limites_de_arquivo_archive_e_entradas_falham_antes_da_materializacao() {
        let temp = tempfile::tempdir().unwrap();
        let newspeak = temp.path().join("newspeak");
        std::fs::create_dir_all(newspeak.join("base/files")).unwrap();
        let oversized = temp.path().join("oversized.tar");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_LICENSE_ARCHIVE_BYTES + 1)
            .unwrap();
        assert!(load_path(&oversized, &newspeak).is_err());

        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(MAX_LICENSE_FILE_BYTES + 1);
        header.set_path("grande").unwrap();
        header.set_cksum();
        let mut declared = header.as_bytes().to_vec();
        declared.extend_from_slice(&[0u8; 1024]);
        assert!(load_unbound(declared).is_err());

        let entries = (0..=MAX_LICENSE_ENTRIES)
            .map(|index| Entry {
                relative: PathBuf::from(format!("d{index:05}")),
                mode: 0o755,
                kind: EntryKind::Directory,
            })
            .collect::<Vec<_>>();
        let too_many = crate::tree::pack(&entries, 0).unwrap();
        assert!(load_unbound(too_many).is_err());
    }
}
