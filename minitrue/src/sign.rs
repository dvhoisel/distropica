//! Assinatura minisign da própria árvore (SPEC-0009 §4).
//!
//! O consumidor de canal já exigia minisign, mas o produtor dependia do
//! binário `minisign` do HOSPEDEIRO — e a Distrópica não depende de
//! hospedeiro. Pedir `apt install minisign` para assinar a raiz de confiança
//! do canal é exatamente a inversão que este projeto recusa: a autoridade
//! sobre o que é publicado passaria a vir de um pacote que a máquina do
//! mantenedor por acaso tinha.
//!
//! Nada aqui é criptografia nova. O formato já era conhecido pela árvore — os
//! testes de `channel.rs` construíam assinaturas minisign à mão para provar o
//! verificador —, e a ed25519-dalek já estava presente por causa das
//! attestations. Isto apenas torna produtor e consumidor simétricos.
//!
//! Formato (o mesmo do minisign 0.x, variante pré-hasheada `ED`):
//!
//! ```text
//! chave secreta (158 bytes, base64 na segunda linha):
//!   [0..2]    algoritmo de assinatura  "Ed"
//!   [2..4]    algoritmo de KDF         0x0000 = sem senha; "Sc" = scrypt
//!   [4..6]    algoritmo de checksum    "B2"
//!   [6..38]   sal do KDF
//!   [38..46]  opslimit (u64 LE)
//!   [46..54]  memlimit (u64 LE)
//!   [54..62]  key_id
//!   [62..126] chave secreta ed25519 (semente ‖ pública)
//!   [126..158] checksum BLAKE2b-256 de (algoritmo ‖ key_id ‖ secreta)
//!
//! chave pública (42 bytes): "Ed" ‖ key_id ‖ pública
//!
//! assinatura:
//!   untrusted comment: <comentário>
//!   base64("ED" ‖ key_id ‖ sign(BLAKE2b-512(mensagem)))
//!   trusted comment: <comentário confiável>
//!   base64(sign(assinatura ‖ comentário confiável))
//! ```
//!
//! O comentário confiável entra na segunda assinatura; é isso que o torna
//! confiável, e é por isso que o timestamp vai ali e não no primeiro.

use crate::Fail;
use anyhow::Result;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey};
use scrypt::{scrypt_fallible, Params as ScryptParams};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Erro de saída 1, no formato que o `main` já traduz em mensagem e código.
fn erro(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fail {
        code: 1,
        msg: msg.into(),
    })
}

const SECRET_LEN: usize = 158;
const KEY_MATERIAL_LEN: usize = 104;
const PUBLIC_LEN: usize = 42;
const LEGACY_ALGORITHM: &[u8; 2] = b"Ed";
const PREHASHED_ALGORITHM: &[u8; 2] = b"ED";
const SCRYPT_ALGORITHM: &[u8; 2] = b"Sc";
const CHECKSUM_ALGORITHM: &[u8; 2] = b"B2";
const UNTRUSTED_PREFIX: &str = "untrusted comment: ";
const TRUSTED_PREFIX: &str = "trusted comment: ";
// O upstream reserva um byte para o NUL ao ler PASSWORDMAXBYTES=1024.
const MAX_PASSPHRASE_BYTES: usize = 1023;
// Faixa que o minisign/libsodium efetivamente produz. Aceitar números maiores
// vindos do arquivo permitiria que uma chave forjada pedisse dezenas de GiB.
const SCRYPT_OPSLIMIT_MIN: u64 = 32_768;
const SCRYPT_OPSLIMIT_MAX: u64 = 33_554_432;
const SCRYPT_MEMLIMIT_MIN: u64 = 16_777_216;
const SCRYPT_MEMLIMIT_MAX: u64 = 1_073_741_824;
const MAX_SECRET_FILE_BYTES: u64 = 16 * 1024;
const MAX_SIGNATURE_FILE_BYTES: u64 = 16 * 1024;
const MAX_CONTROL_FILE_BYTES: u64 = 4 * 1024;
const PASSPHRASE_READ_BYTES: usize = MAX_PASSPHRASE_BYTES + 3;
const MINISIGN_COMMENT_BYTES: usize = 1024;
const MINISIGN_TRUSTED_COMMENT_BYTES: usize = 8192;
// A árvore Newspeak tem o maior objeto que esta CLI precisa assinar. Manter o
// mesmo teto do extrator permite streaming sem transformar um pathname
// acidental em leitura ilimitada de disco/dispositivo.
const MAX_SIGNED_MESSAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

type Blake2b256 = Blake2b<U32>;

fn effective_uid() -> u32 {
    // SAFETY: geteuid não recebe ponteiros nem possui pré-condições.
    unsafe { libc::geteuid() }
}

fn validate_regular_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    what: &str,
    max_bytes: u64,
) -> Result<()> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(erro(format!(
            "{what} {}: exige arquivo regular real com um único link",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(erro(format!(
            "{what} {}: excede o limite de {max_bytes} bytes",
            path.display()
        )));
    }
    Ok(())
}

fn path_components(path: &Path, what: &str) -> Result<(bool, Vec<CString>)> {
    if path.as_os_str().is_empty() {
        return Err(erro(format!("{what}: caminho vazio")));
    }
    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::Normal(name) => names.push(
                CString::new(name.as_bytes())
                    .map_err(|_| erro(format!("{what}: componente contém NUL")))?,
            ),
            Component::ParentDir => names.push(c_name("..")),
            Component::Prefix(_) => {
                return Err(erro(format!("{what}: prefixo de caminho não suportado")))
            }
        }
    }
    Ok((absolute, names))
}

fn initial_directory(absolute: bool, what: &str) -> Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(if absolute {
            Path::new("/")
        } else {
            Path::new(".")
        })
        .map_err(|error| erro(format!("{what}: não abri âncora inicial: {error}")))
}

fn open_directory_component(parent: &fs::File, name: &CStr, what: &str) -> Result<fs::File> {
    // SAFETY: `name` e dirfd permanecem válidos durante openat.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(erro(format!(
            "{what}: ancestral não é diretório real sem symlink: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd recém-criado, ownership exclusivo.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn open_directory_path_nofollow(path: &Path, what: &str) -> Result<fs::File> {
    let (absolute, names) = path_components(path, what)?;
    let mut directory = initial_directory(absolute, what)?;
    for name in names {
        directory = open_directory_component(&directory, &name, what)?;
    }
    Ok(directory)
}

fn open_leaf_path_nofollow(path: &Path, what: &str) -> Result<fs::File> {
    let (absolute, mut names) = path_components(path, what)?;
    let leaf = names
        .pop()
        .ok_or_else(|| erro(format!("{what}: caminho não tem folha")))?;
    let mut directory = initial_directory(absolute, what)?;
    for name in names {
        directory = open_directory_component(&directory, &name, what)?;
    }
    // SAFETY: folha relativa ao último dirfd ancorado; nenhum componente foi
    // seguido como symlink.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(erro(format!(
            "{what} {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd recém-criado, ownership exclusivo.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn open_regular_nofollow(path: &Path, what: &str, max_bytes: u64) -> Result<fs::File> {
    let file = open_leaf_path_nofollow(path, what)?;
    let metadata = file
        .metadata()
        .map_err(|error| erro(format!("{what} {}: {error}", path.display())))?;
    validate_regular_metadata(&metadata, path, what, max_bytes)?;
    Ok(file)
}

fn open_secret_nofollow(path: &Path) -> Result<fs::File> {
    let file = open_regular_nofollow(path, "chave secreta", MAX_SECRET_FILE_BYTES)?;
    let metadata = file
        .metadata()
        .map_err(|error| erro(format!("chave secreta {}: {error}", path.display())))?;
    if metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(erro(format!(
            "chave secreta {}: precisa pertencer ao UID efetivo e não ser acessível por grupo/outros",
            path.display()
        )));
    }
    Ok(file)
}

fn open_message_nofollow(path: &Path) -> Result<fs::File> {
    let file = open_regular_nofollow(path, "arquivo a assinar", MAX_SIGNED_MESSAGE_BYTES)?;
    let metadata = file
        .metadata()
        .map_err(|error| erro(format!("arquivo a assinar {}: {error}", path.display())))?;
    if metadata.uid() != effective_uid() || metadata.mode() & 0o022 != 0 {
        return Err(erro(format!(
            "arquivo a assinar {}: precisa pertencer ao UID efetivo e não permitir escrita por grupo/outros",
            path.display()
        )));
    }
    Ok(file)
}

fn same_file_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.file_type().is_file()
        && after.file_type().is_file()
        && before.nlink() == 1
        && after.nlink() == 1
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn path_still_names_directory(path: &Path, expected: &fs::Metadata) -> bool {
    open_directory_path_nofollow(path, "diretório de saída")
        .and_then(|file| {
            file.metadata()
                .map_err(|error| erro(format!("diretório de saída: {error}")))
        })
        .is_ok_and(|observed| {
            observed.file_type().is_dir()
                && observed.dev() == expected.dev()
                && observed.ino() == expected.ino()
                && observed.uid() == effective_uid()
                && observed.mode() & 0o022 == 0
        })
}

fn hash_message(message: &mut fs::File, path: &Path) -> Result<([u8; 64], fs::Metadata)> {
    let before = message
        .metadata()
        .map_err(|error| erro(format!("arquivo a assinar {}: {error}", path.display())))?;
    let mut hasher = Blake2b512::new();
    let mut total = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = message
            .read(&mut chunk)
            .map_err(|error| erro(format!("arquivo a assinar {}: {error}", path.display())))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| erro("arquivo a assinar: tamanho transbordou"))?;
        if total > MAX_SIGNED_MESSAGE_BYTES {
            return Err(erro(format!(
                "arquivo a assinar {}: excede o limite de {MAX_SIGNED_MESSAGE_BYTES} bytes",
                path.display()
            )));
        }
        hasher.update(&chunk[..count]);
    }
    chunk.zeroize();
    publication_checkpoint("after_message_read")?;
    let after = message
        .metadata()
        .map_err(|error| erro(format!("arquivo a assinar {}: {error}", path.display())))?;
    if total != before.len() || !same_file_snapshot(&before, &after) {
        return Err(erro(format!(
            "arquivo a assinar {} mudou durante a leitura",
            path.display()
        )));
    }
    let digest: [u8; 64] = hasher.finalize().into();
    Ok((digest, before))
}

fn signature_leaf(path: &Path, what: &str) -> Result<CString> {
    let name = path
        .file_name()
        .ok_or_else(|| erro(format!("{what}: caminho não tem nome de arquivo")))?;
    CString::new(name.as_bytes()).map_err(|_| erro(format!("{what}: nome contém NUL")))
}

fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn deterministic_name(prefix: &str, fields: &[&[u8]]) -> Result<CString> {
    let digest = hash_fields(b"minitrue-fd-stage-v1\0", fields);
    CString::new(format!(".{prefix}-{}", hex::encode(digest)))
        .map_err(|_| erro("nome determinístico de staging contém NUL"))
}

fn c_name(name: &str) -> CString {
    CString::new(name).expect("nome interno sem NUL")
}

fn validate_parent_metadata(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(erro(format!(
            "diretório de saída {} precisa ser real, pertencer ao UID efetivo e não permitir escrita por grupo/outros (uid {}, modo {:04o})",
            path.display(),
            metadata.uid(),
            metadata.mode() & 0o7777,
        )));
    }
    Ok(())
}

struct ParentAnchor {
    file: fs::File,
    path: PathBuf,
    metadata: fs::Metadata,
}

impl ParentAnchor {
    fn open(path: &Path) -> Result<Self> {
        let named = fs::symlink_metadata(path)
            .map_err(|error| erro(format!("diretório de saída {}: {error}", path.display())))?;
        validate_parent_metadata(&named, path)?;
        let file = open_directory_path_nofollow(path, "diretório de saída")?;
        let metadata = file
            .metadata()
            .map_err(|error| erro(format!("diretório de saída {}: {error}", path.display())))?;
        validate_parent_metadata(&metadata, path)?;
        if named.dev() != metadata.dev() || named.ino() != metadata.ino() {
            return Err(erro(format!(
                "diretório de saída {} foi trocado durante a abertura",
                path.display()
            )));
        }
        loop {
            // SAFETY: flock opera somente sobre o descritor aberto.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(erro(format!(
                    "não adquiri lock do diretório de saída {}: {error}",
                    path.display()
                )));
            }
        }
        let anchor = Self {
            file,
            path: path.to_path_buf(),
            metadata,
        };
        anchor.ensure_still_named()?;
        Ok(anchor)
    }

    fn ensure_still_named(&self) -> Result<()> {
        if !path_still_names_directory(&self.path, &self.metadata) {
            return Err(erro(format!(
                "diretório de saída {} foi trocado durante a publicação",
                self.path.display()
            )));
        }
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.file.sync_all().map_err(|error| {
            erro(format!(
                "não sincronizei diretório de saída {}: {error}",
                self.path.display()
            ))
        })
    }
}

struct StageAnchor {
    file: fs::File,
    name: CString,
    metadata: fs::Metadata,
}

impl StageAnchor {
    fn open(parent: &ParentAnchor, name: &CStr) -> Result<Option<Self>> {
        // SAFETY: dirfd e C string permanecem vivos; o fd retornado ganha dono.
        let fd = unsafe {
            libc::openat(
                parent.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(erro(format!("não abri staging privado: {error}")));
        }
        // SAFETY: fd recém-criado, ownership exclusivo.
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = file
            .metadata()
            .map_err(|error| erro(format!("não inspecionei staging privado: {error}")))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != effective_uid()
            || metadata.mode() & 0o777 != 0o700
            || metadata.dev() != parent.metadata.dev()
        {
            return Err(erro(
                "staging precisa ser diretório real 0700, do UID efetivo e no filesystem do destino",
            ));
        }
        Ok(Some(Self {
            file,
            name: name.to_owned(),
            metadata,
        }))
    }

    fn create(parent: &ParentAnchor, name: CString) -> Result<Self> {
        // SAFETY: dirfd e nome permanecem válidos durante mkdirat.
        if unsafe { libc::mkdirat(parent.file.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(erro(format!(
                "não criei staging privado: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Um umask extremo pode remover até os bits do dono. Corrija por
        // dirfd antes da abertura, sem criar uma janela permissiva (0700 só
        // acrescenta acesso ao próprio UID efetivo).
        // SAFETY: o nome acabou de ser criado sob o parent confiável/flockado.
        if unsafe { libc::fchmodat(parent.file.as_raw_fd(), name.as_ptr(), 0o700, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: remove somente o diretório recém-criado, ainda vazio.
            let _ = unsafe {
                libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
            };
            return Err(erro(format!("não fixei modo 0700 do staging: {error}")));
        }
        let mut stage =
            Self::open(parent, &name)?.ok_or_else(|| erro("staging recém-criado sumiu"))?;
        stage
            .file
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|error| erro(format!("não fixei modo 0700 do staging: {error}")))?;
        stage.metadata = stage
            .file
            .metadata()
            .map_err(|error| erro(format!("não reinspecionei staging: {error}")))?;
        if stage.metadata.mode() & 0o777 != 0o700 {
            return Err(erro("staging não ficou com modo 0700"));
        }
        stage.sync()?;
        parent.sync()?;
        publication_checkpoint("after_mkdir")?;
        Ok(stage)
    }

    fn ensure_bound(&self, parent: &ParentAnchor) -> Result<()> {
        // SAFETY: O_PATH+NOFOLLOW observa a própria folha relativa ao parent.
        let fd = unsafe {
            libc::openat(
                parent.file.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(erro(format!(
                "nome do staging sumiu ou foi trocado: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: fd recém-criado, ownership exclusivo.
        let observed = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = observed
            .metadata()
            .map_err(|error| erro(format!("não inspecionei nome do staging: {error}")))?;
        if metadata.dev() != self.metadata.dev() || metadata.ino() != self.metadata.ino() {
            return Err(erro("nome do staging foi trocado durante a publicação"));
        }
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|error| erro(format!("não sincronizei staging: {error}")))
    }
}

struct LeafSnapshot {
    file: fs::File,
    metadata: fs::Metadata,
    bytes: Vec<u8>,
}

fn open_leaf_at(
    directory: &fs::File,
    directory_dev: u64,
    name: &CStr,
    what: &str,
    max_bytes: u64,
) -> Result<Option<LeafSnapshot>> {
    // SAFETY: dirfd/nome permanecem vivos; openat não retém ponteiros.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(erro(format!("{what}: {error}")));
    }
    // SAFETY: fd recém-criado, ownership exclusivo.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|error| erro(format!("{what}: {error}")))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != effective_uid()
        || before.dev() != directory_dev
        || before.len() > max_bytes
    {
        return Err(erro(format!(
            "{what}: exige regular do UID efetivo, no mesmo filesystem, com um link e até {max_bytes} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len())
            .ok()
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| erro(format!("{what}: tamanho inválido")))?,
    );
    (&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| erro(format!("{what}: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| erro(format!("{what}: {error}")))?;
    if bytes.len() as u64 != before.len() || !same_file_snapshot(&before, &after) {
        return Err(erro(format!("{what}: mudou durante a leitura")));
    }
    Ok(Some(LeafSnapshot {
        file,
        metadata: before,
        bytes,
    }))
}

fn write_new_leaf_at(
    directory: &fs::File,
    directory_dev: u64,
    name: &CStr,
    bytes: &[u8],
    mode: u32,
    what: &str,
) -> Result<(fs::File, fs::Metadata)> {
    // SAFETY: criação exclusiva relativa ao dirfd; ponteiros permanecem vivos.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(erro(format!("{what}: {}", std::io::Error::last_os_error())));
    }
    // SAFETY: fd recém-criado, ownership exclusivo.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)))
        .and_then(|()| file.sync_all())
        .map_err(|error| erro(format!("{what}: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| erro(format!("{what}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()
        || metadata.dev() != directory_dev
        || metadata.len() != bytes.len() as u64
        || metadata.mode() & 0o777 != mode
    {
        return Err(erro(format!(
            "{what}: selo do arquivo recém-criado diverge"
        )));
    }
    Ok((file, metadata))
}

fn unlink_known_leaf(directory: &fs::File, directory_dev: u64, name: &CStr) -> Result<()> {
    // SAFETY: O_PATH observa a própria folha sem seguir symlink.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(erro(format!("não inspecionei resíduo conhecido: {error}")));
    }
    // SAFETY: fd recém-criado, ownership exclusivo.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|error| erro(format!("não inspecionei resíduo conhecido: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()
        || metadata.dev() != directory_dev
    {
        return Err(erro(
            "resíduo conhecido foi trocado por folha não removível",
        ));
    }
    // O diretório é privado/confiável e está sob flock; o cotejo acima prende
    // a identidade no limite de ameaça entre UIDs.
    // SAFETY: nome relativo ao mesmo dirfd, sem seguir links.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(erro(format!(
            "não removi resíduo conhecido: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
fn publication_checkpoint(label: &str) -> Result<()> {
    let current = std::thread::current();
    let current_name = current.name().unwrap_or("");
    if std::env::var("MINITRUE_SIGN_ACTION_LABEL").as_deref() == Ok(label)
        && std::env::var("MINITRUE_SIGN_ACTION_THREAD").as_deref() == Ok(current_name)
    {
        let kind = std::env::var("MINITRUE_SIGN_ACTION_KIND")
            .map_err(|_| erro("ação de teste sem KIND"))?;
        let first = PathBuf::from(
            std::env::var_os("MINITRUE_SIGN_ACTION_FIRST")
                .ok_or_else(|| erro("ação de teste sem FIRST"))?,
        );
        let second = PathBuf::from(
            std::env::var_os("MINITRUE_SIGN_ACTION_SECOND")
                .ok_or_else(|| erro("ação de teste sem SECOND"))?,
        );
        match kind.as_str() {
            "swap" => {
                let third = PathBuf::from(
                    std::env::var_os("MINITRUE_SIGN_ACTION_THIRD")
                        .ok_or_else(|| erro("ação swap sem THIRD"))?,
                );
                fs::rename(&first, &third)
                    .and_then(|()| fs::rename(&second, &first))
                    .map_err(|error| erro(format!("ação swap de teste: {error}")))?;
            }
            "hardlink" => fs::hard_link(&first, &second)
                .map_err(|error| erro(format!("ação hardlink de teste: {error}")))?,
            "replace-stage" => {
                fs::rename(&first, &second)
                    .and_then(|()| fs::create_dir(&first))
                    .and_then(|()| fs::set_permissions(&first, fs::Permissions::from_mode(0o700)))
                    .map_err(|error| erro(format!("ação replace-stage de teste: {error}")))?;
            }
            _ => return Err(erro("KIND desconhecido na ação de teste")),
        }
    }
    if std::env::var("MINITRUE_SIGN_KILLPOINT").as_deref() == Ok(label) {
        // SAFETY: SIGKILL encerra exclusivamente o subprocesso de teste.
        unsafe { libc::raise(libc::SIGKILL) };
    }
    if std::env::var("MINITRUE_SIGN_FAULTPOINT").as_deref() == Ok(label) {
        return Err(erro(format!("fault point de teste: {label}")));
    }
    Ok(())
}

#[cfg(not(test))]
fn publication_checkpoint(_label: &str) -> Result<()> {
    Ok(())
}

const SIGN_OWNER: &str = "OWNER";
const SIGN_REQUEST: &str = "REQUEST";
const SIGN_READY: &str = "READY";
const SIGN_PAYLOAD: &str = "signature";

fn exact_leaf_at(
    directory: &fs::File,
    directory_dev: u64,
    name: &CStr,
    expected: &[u8],
    mode: u32,
    what: &str,
    max_bytes: u64,
) -> Result<Option<LeafSnapshot>> {
    let Some(leaf) = open_leaf_at(directory, directory_dev, name, what, max_bytes)? else {
        return Ok(None);
    };
    if leaf.metadata.mode() & 0o777 != mode || leaf.bytes != expected {
        return Err(erro(format!(
            "{what}: conteúdo ou modo diverge da requisição atual"
        )));
    }
    Ok(Some(leaf))
}

fn ensure_leaf_at(
    stage: &StageAnchor,
    name: &CStr,
    expected: &[u8],
    mode: u32,
    what: &str,
    max_bytes: u64,
) -> Result<LeafSnapshot> {
    if let Some(leaf) = open_leaf_at(&stage.file, stage.metadata.dev(), name, what, max_bytes)? {
        if leaf.metadata.mode() & 0o777 == mode && leaf.bytes == expected {
            leaf.file
                .sync_all()
                .map_err(|error| erro(format!("{what}: {error}")))?;
            return Ok(leaf);
        }
        unlink_known_leaf(&stage.file, stage.metadata.dev(), name)?;
        stage.sync()?;
    }
    let (file, metadata) = write_new_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        name,
        expected,
        mode,
        what,
    )?;
    stage.sync()?;
    Ok(LeafSnapshot {
        file,
        metadata,
        bytes: expected.to_vec(),
    })
}

fn discard_signature_stage(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    post_commit: bool,
) -> Result<()> {
    stage.ensure_bound(parent)?;
    for name in [SIGN_READY, SIGN_PAYLOAD, SIGN_REQUEST, SIGN_OWNER] {
        unlink_known_leaf(&stage.file, stage.metadata.dev(), &c_name(name))?;
    }
    stage.sync()?;
    stage.ensure_bound(parent)?;
    // Se houver qualquer nome desconhecido, AT_REMOVEDIR falha com ENOTEMPTY;
    // nunca fazemos varredura recursiva de conteúdo que não reconhecemos.
    // SAFETY: nome cotejado por inode e relativo ao parent ancorado.
    if unsafe {
        libc::unlinkat(
            parent.file.as_raw_fd(),
            stage.name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } != 0
    {
        return Err(erro(format!(
            "não removi staging vazio: {}",
            std::io::Error::last_os_error()
        )));
    }
    if post_commit {
        publication_checkpoint("after_stage_cleanup")?;
    }
    parent.sync()?;
    Ok(())
}

fn prepare_signature_stage(
    parent: &ParentAnchor,
    name: &CString,
    owner: &[u8],
    request: &[u8],
) -> Result<StageAnchor> {
    let mut stage = match StageAnchor::open(parent, name)? {
        Some(stage) => stage,
        None => StageAnchor::create(parent, name.clone())?,
    };

    let owner_name = c_name(SIGN_OWNER);
    let request_name = c_name(SIGN_REQUEST);
    let observed_owner = open_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &owner_name,
        "OWNER do signer",
        MAX_CONTROL_FILE_BYTES,
    )?;
    let observed_request = open_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &request_name,
        "REQUEST do signer",
        MAX_CONTROL_FILE_BYTES,
    )?;
    let reusable = observed_owner
        .as_ref()
        .is_some_and(|leaf| leaf.metadata.mode() & 0o777 == 0o600 && leaf.bytes == owner)
        && observed_request
            .as_ref()
            .is_some_and(|leaf| leaf.metadata.mode() & 0o777 == 0o600 && leaf.bytes == request);

    if !reusable && (observed_owner.is_some() || observed_request.is_some()) {
        // Stage incompleto (queda) ou request anterior ainda não publicada.
        // Como o parent é confiável e está sob flock, removemos apenas nomes
        // conhecidos e recomeçamos; conteúdo desconhecido faz falhar fechado.
        discard_signature_stage(parent, &stage, false)?;
        stage = StageAnchor::create(parent, name.clone())?;
    }

    ensure_leaf_at(
        &stage,
        &owner_name,
        owner,
        0o600,
        "OWNER do signer",
        MAX_CONTROL_FILE_BYTES,
    )?;
    publication_checkpoint("after_owner")?;
    ensure_leaf_at(
        &stage,
        &request_name,
        request,
        0o600,
        "REQUEST do signer",
        MAX_CONTROL_FILE_BYTES,
    )?;
    publication_checkpoint("after_request")?;
    parent.sync()?;
    Ok(stage)
}

fn ensure_message_path_snapshot(path: &Path, expected: &fs::Metadata) -> Result<()> {
    let file = open_message_nofollow(path)?;
    let observed = file
        .metadata()
        .map_err(|error| erro(format!("arquivo a assinar {}: {error}", path.display())))?;
    if !same_file_snapshot(expected, &observed) {
        return Err(erro(format!(
            "arquivo a assinar {} deixou de nomear o inode verificado",
            path.display()
        )));
    }
    Ok(())
}

fn signature_control_bytes(
    final_name: &CStr,
    message_digest: &[u8; 64],
    public_line: &str,
    payload: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let owner_id = hash_fields(b"minitrue-sign-owner-v1\0", &[final_name.to_bytes()]);
    let payload_hash: [u8; 32] = Blake2b256::digest(payload).into();
    let request_id = hash_fields(
        b"minitrue-sign-request-v1\0",
        &[
            final_name.to_bytes(),
            message_digest,
            public_line.as_bytes(),
            payload,
        ],
    );
    let owner = format!(
        "MINITRUE_SIGN_OWNER_FORMAT=1\nOUTPUT_BLAKE2B256={}\nOUTPUT_HEX={}\n",
        hex::encode(owner_id),
        hex::encode(final_name.to_bytes()),
    )
    .into_bytes();
    let request = format!(
        "MINITRUE_SIGN_REQUEST_FORMAT=1\nREQUEST_BLAKE2B256={}\nMESSAGE_BLAKE2B512={}\nPUBLIC={}\nPAYLOAD_LEN={}\nPAYLOAD_BLAKE2B256={}\n",
        hex::encode(request_id),
        hex::encode(message_digest),
        public_line,
        payload.len(),
        hex::encode(payload_hash),
    )
    .into_bytes();
    let ready = format!(
        "MINITRUE_SIGN_READY_FORMAT=1\nREQUEST_BLAKE2B256={}\nPAYLOAD_LEN={}\nPAYLOAD_BLAKE2B256={}\nMODE=0644\n",
        hex::encode(request_id),
        payload.len(),
        hex::encode(payload_hash),
    )
    .into_bytes();
    (owner, request, ready)
}

fn publish_signature(
    signature_path: &Path,
    message_path: &Path,
    message_snapshot: &fs::Metadata,
    message_digest: &[u8; 64],
    public_line: &str,
    payload: &[u8],
) -> Result<bool> {
    if payload.len() as u64 > MAX_SIGNATURE_FILE_BYTES {
        return Err(erro("assinatura excede o limite interno de publicação"));
    }
    let parent_path = signature_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = ParentAnchor::open(parent_path)?;
    let final_name = signature_leaf(signature_path, "assinatura final")?;
    let stage_name = deterministic_name("minitrue-sign", &[final_name.as_bytes()])?;
    let (owner, request, ready) =
        signature_control_bytes(&final_name, message_digest, public_line, payload);

    if let Some(existing) = exact_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        &final_name,
        payload,
        0o644,
        "assinatura final existente",
        MAX_SIGNATURE_FILE_BYTES,
    )? {
        existing
            .file
            .sync_all()
            .map_err(|error| erro(format!("assinatura final existente: {error}")))?;
        parent.sync()?;
        if let Some(stage) = StageAnchor::open(&parent, &stage_name)? {
            match exact_leaf_at(
                &stage.file,
                stage.metadata.dev(),
                &c_name(SIGN_OWNER),
                &owner,
                0o600,
                "OWNER residual do signer",
                MAX_CONTROL_FILE_BYTES,
            ) {
                Ok(Some(_)) => {
                    if let Err(error) = discard_signature_stage(&parent, &stage, true) {
                        eprintln!(
                            "minitrue: aviso: assinatura já publicada, mas staging residual não foi limpo: {error}"
                        );
                    }
                }
                Ok(None) | Err(_) => eprintln!(
                    "minitrue: aviso: assinatura já publicada; staging estranho foi preservado"
                ),
            }
        }
        parent.ensure_still_named()?;
        return Ok(false);
    }

    let stage = prepare_signature_stage(&parent, &stage_name, &owner, &request)?;
    let payload_name = c_name(SIGN_PAYLOAD);
    ensure_leaf_at(
        &stage,
        &payload_name,
        payload,
        0o644,
        "payload da assinatura",
        MAX_SIGNATURE_FILE_BYTES,
    )?;
    publication_checkpoint("after_payload")?;
    ensure_leaf_at(
        &stage,
        &c_name(SIGN_READY),
        &ready,
        0o600,
        "READY do signer",
        MAX_CONTROL_FILE_BYTES,
    )?;
    stage.sync()?;
    publication_checkpoint("after_ready_stage_sync")?;
    parent.sync()?;
    publication_checkpoint("after_ready_parent_sync")?;
    publication_checkpoint("after_ready")?;

    ensure_message_path_snapshot(message_path, message_snapshot)?;
    parent.ensure_still_named()?;
    stage.ensure_bound(&parent)?;
    let staged_payload = exact_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &payload_name,
        payload,
        0o644,
        "payload da assinatura antes da promoção",
        MAX_SIGNATURE_FILE_BYTES,
    )?
    .ok_or_else(|| erro("payload da assinatura sumiu antes da promoção"))?;
    let mut promoted_ours = false;
    if exact_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        &final_name,
        payload,
        0o644,
        "assinatura final concorrente",
        MAX_SIGNATURE_FILE_BYTES,
    )?
    .is_some()
    {
        // Outro processo cooperativo não passa pelo flock; um final exato é,
        // ainda assim, recibo suficiente para a mesma requisição.
        parent.sync()?;
    } else {
        match crate::linux::renameat2(
            stage.file.as_raw_fd(),
            &payload_name,
            parent.file.as_raw_fd(),
            &final_name,
            libc::RENAME_NOREPLACE,
        ) {
            Ok(()) => promoted_ours = true,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                exact_leaf_at(
                    &parent.file,
                    parent.metadata.dev(),
                    &final_name,
                    payload,
                    0o644,
                    "assinatura final concorrente",
                    MAX_SIGNATURE_FILE_BYTES,
                )?
                .ok_or_else(|| erro("destino apareceu sem conter a assinatura esperada"))?;
            }
            Err(error) => {
                return Err(erro(format!(
                    "não publiquei {}: {error}",
                    signature_path.display()
                )))
            }
        }
        publication_checkpoint("after_rename")?;
        // O destino primeiro garante o recibo público; o source dir em seguida
        // torna durável a remoção do nome interno.
        parent.sync()?;
        publication_checkpoint("after_parent_sync")?;
        stage.sync()?;
        publication_checkpoint("after_stage_sync")?;
    }

    let final_leaf = exact_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        &final_name,
        payload,
        0o644,
        "assinatura final publicada",
        MAX_SIGNATURE_FILE_BYTES,
    )?
    .ok_or_else(|| erro("assinatura final sumiu após a promoção"))?;
    if promoted_ours
        && (final_leaf.metadata.dev() != staged_payload.metadata.dev()
            || final_leaf.metadata.ino() != staged_payload.metadata.ino())
    {
        return Err(erro("assinatura final não é o inode preparado no staging"));
    }
    parent.ensure_still_named()?;

    if let Err(error) = discard_signature_stage(&parent, &stage, true) {
        eprintln!(
            "minitrue: aviso: assinatura publicada e sincronizada, mas staging não foi limpo: {error}"
        );
    }
    parent.ensure_still_named()?;
    Ok(true)
}

const KEY_OWNER: &str = "OWNER";
const KEY_REQUEST: &str = "REQUEST";
const KEY_READY: &str = "READY";
const KEY_SECRET: &str = "secret";
const KEY_PUBLIC: &str = "public";

struct SecretLeafSnapshot {
    file: fs::File,
    metadata: fs::Metadata,
    bytes: Zeroizing<Vec<u8>>,
}

fn open_secret_leaf_at(
    directory: &fs::File,
    directory_dev: u64,
    name: &CStr,
    what: &str,
) -> Result<Option<SecretLeafSnapshot>> {
    // SAFETY: abertura relativa ao dirfd; O_NOFOLLOW prende a folha real.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(erro(format!("{what}: {error}")));
    }
    // SAFETY: fd recém-criado, ownership exclusivo.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|error| erro(format!("{what}: {error}")))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != effective_uid()
        || before.dev() != directory_dev
        || before.mode() & 0o777 != 0o600
        || before.len() > MAX_SECRET_FILE_BYTES
    {
        return Err(erro(format!(
            "{what}: exige regular 0600 do UID efetivo, no mesmo filesystem, com um link e até {MAX_SECRET_FILE_BYTES} bytes"
        )));
    }
    let capacity = usize::try_from(before.len())
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or_else(|| erro(format!("{what}: tamanho inválido")))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    (&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| erro(format!("{what}: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| erro(format!("{what}: {error}")))?;
    if bytes.len() as u64 != before.len() || !same_file_snapshot(&before, &after) {
        return Err(erro(format!("{what}: mudou durante a leitura")));
    }
    Ok(Some(SecretLeafSnapshot {
        file,
        metadata: before,
        bytes,
    }))
}

fn exact_secret_leaf_at(
    directory: &fs::File,
    directory_dev: u64,
    name: &CStr,
    expected: &[u8],
    what: &str,
) -> Result<Option<SecretLeafSnapshot>> {
    let Some(leaf) = open_secret_leaf_at(directory, directory_dev, name, what)? else {
        return Ok(None);
    };
    if leaf.bytes.as_slice() != expected {
        return Err(erro(format!(
            "{what}: conteúdo diverge da requisição de keygen"
        )));
    }
    Ok(Some(leaf))
}

fn ensure_secret_leaf_at(
    stage: &StageAnchor,
    name: &CStr,
    expected: &[u8],
    what: &str,
) -> Result<SecretLeafSnapshot> {
    if let Some(leaf) = open_secret_leaf_at(&stage.file, stage.metadata.dev(), name, what)? {
        if leaf.bytes.as_slice() == expected {
            leaf.file
                .sync_all()
                .map_err(|error| erro(format!("{what}: {error}")))?;
            return Ok(leaf);
        }
        unlink_known_leaf(&stage.file, stage.metadata.dev(), name)?;
        stage.sync()?;
    }
    let (file, metadata) = write_new_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        name,
        expected,
        0o600,
        what,
    )?;
    stage.sync()?;
    Ok(SecretLeafSnapshot {
        file,
        metadata,
        bytes: Zeroizing::new(expected.to_vec()),
    })
}

fn keygen_public_text(key: &SecretKey) -> String {
    format!(
        "{UNTRUSTED_PREFIX}minisign public key {:016X}\n{}\n",
        u64::from_le_bytes(key.key_id),
        key.public_line()
    )
}

fn validate_keygen_pair(secret: &[u8], public: &[u8]) -> Result<String> {
    let key = secret_key_from_bytes(secret, None)?;
    let expected = keygen_public_text(&key);
    if public != expected.as_bytes() {
        return Err(erro(
            "par de keygen: chave pública não é a representação canônica derivada da secreta",
        ));
    }
    Ok(expected)
}

fn keygen_control_bytes(
    secret_name: &CStr,
    public_name: &CStr,
    secret: &[u8],
    public: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let owner_id = hash_fields(
        b"minitrue-keygen-owner-v1\0",
        &[secret_name.to_bytes(), public_name.to_bytes()],
    );
    let secret_hash: [u8; 32] = Blake2b256::digest(secret).into();
    let public_hash: [u8; 32] = Blake2b256::digest(public).into();
    let request_id = hash_fields(
        b"minitrue-keygen-request-v1\0",
        &[
            secret_name.to_bytes(),
            public_name.to_bytes(),
            &secret_hash,
            &public_hash,
        ],
    );
    let owner = format!(
        "MINITRUE_KEYGEN_OWNER_FORMAT=1\nOWNER_BLAKE2B256={}\nSECRET_HEX={}\nPUBLIC_HEX={}\n",
        hex::encode(owner_id),
        hex::encode(secret_name.to_bytes()),
        hex::encode(public_name.to_bytes()),
    )
    .into_bytes();
    let request = format!(
        "MINITRUE_KEYGEN_REQUEST_FORMAT=1\nREQUEST_BLAKE2B256={}\nSECRET_LEN={}\nSECRET_BLAKE2B256={}\nPUBLIC_LEN={}\nPUBLIC_BLAKE2B256={}\n",
        hex::encode(request_id),
        secret.len(),
        hex::encode(secret_hash),
        public.len(),
        hex::encode(public_hash),
    )
    .into_bytes();
    let ready = format!(
        "MINITRUE_KEYGEN_READY_FORMAT=1\nREQUEST_BLAKE2B256={}\nSECRET_MODE=0600\nPUBLIC_MODE=0644\n",
        hex::encode(request_id),
    )
    .into_bytes();
    (owner, request, ready)
}

fn keygen_owner_bytes(secret_name: &CStr, public_name: &CStr) -> Vec<u8> {
    // OWNER independe da entropia; usar buffers vazios e aproveitar somente a
    // primeira saída manteria duas implementações do mesmo selo. O cálculo
    // abaixo é a parte estável de `keygen_control_bytes` escrita explicitamente.
    let owner_id = hash_fields(
        b"minitrue-keygen-owner-v1\0",
        &[secret_name.to_bytes(), public_name.to_bytes()],
    );
    format!(
        "MINITRUE_KEYGEN_OWNER_FORMAT=1\nOWNER_BLAKE2B256={}\nSECRET_HEX={}\nPUBLIC_HEX={}\n",
        hex::encode(owner_id),
        hex::encode(secret_name.to_bytes()),
        hex::encode(public_name.to_bytes()),
    )
    .into_bytes()
}

fn discard_keygen_stage(parent: &ParentAnchor, stage: &StageAnchor, committed: bool) -> Result<()> {
    stage.ensure_bound(parent)?;
    for name in [KEY_READY, KEY_REQUEST, KEY_PUBLIC, KEY_SECRET, KEY_OWNER] {
        unlink_known_leaf(&stage.file, stage.metadata.dev(), &c_name(name))?;
    }
    stage.sync()?;
    stage.ensure_bound(parent)?;
    // SAFETY: stage foi cotejado por inode e só removemos nomes conhecidos.
    if unsafe {
        libc::unlinkat(
            parent.file.as_raw_fd(),
            stage.name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } != 0
    {
        return Err(erro(format!(
            "não removi staging do keygen: {}",
            std::io::Error::last_os_error()
        )));
    }
    if committed {
        publication_checkpoint("keygen_after_stage_cleanup")?;
    }
    parent.sync()?;
    Ok(())
}

struct KeygenMaterial {
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    public_text: String,
}

fn generate_keygen_material() -> Result<KeygenMaterial> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed)
        .map_err(|error| erro(format!("sem entropia para a chave: {error}")))?;
    let mut key_id = [0u8; 8];
    getrandom::getrandom(&mut key_id)
        .map_err(|error| erro(format!("sem entropia para o key_id: {error}")))?;
    let signing = SigningKey::from_bytes(&seed);

    let mut raw = Zeroizing::new(Vec::with_capacity(SECRET_LEN));
    raw.extend_from_slice(LEGACY_ALGORITHM);
    raw.extend_from_slice(&[0, 0]);
    raw.extend_from_slice(CHECKSUM_ALGORITHM);
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&key_id);
    raw.extend_from_slice(&*seed);
    raw.extend_from_slice(&signing.verifying_key().to_bytes());
    raw.extend_from_slice(&[0u8; 32]);
    debug_assert_eq!(raw.len(), SECRET_LEN);

    // O base64 ainda é a chave secreta. Prenda a alocação intermediária ao
    // `Zeroizing` antes de montar o arquivo final; `format!` copiaria os bytes e
    // descartaria sua `String` temporária sem limpeza.
    let encoded = Zeroizing::new(base64_encode(&raw));
    let header = format!("{UNTRUSTED_PREFIX}minisign encrypted secret key\n");
    let mut secret = Zeroizing::new(Vec::with_capacity(header.len() + encoded.len() + 1));
    secret.extend_from_slice(header.as_bytes());
    secret.extend_from_slice(encoded.as_bytes());
    secret.push(b'\n');
    let key = SecretKey { key_id, signing };
    let public_text = keygen_public_text(&key);
    let public = public_text.as_bytes().to_vec();
    Ok(KeygenMaterial {
        secret,
        public,
        public_text,
    })
}

/// Segredo vindo do descritor. Não implementa `Debug` nem `Display`, para que
/// uma propagação de erro não possa despejá-lo por acidente; `Drop` limpa
/// comprimento e capacidade do `Vec` com as garantias de `zeroize`.
pub(crate) struct Passphrase {
    // `Box` mantém endereço estável: mover `Passphrase` move apenas o ponteiro,
    // não copia o segredo pela pilha. O byte adicional detecta excesso sem
    // drenar um produtor ilimitado.
    bytes: Zeroizing<Box<[u8]>>,
    len: usize,
}

impl Passphrase {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Lê uma única passphrase de um descritor que o chamador já abriu.
///
/// O descritor original nunca é fechado: trabalhamos numa duplicata CLOEXEC.
/// A leitura vai até EOF enquanto o conteúdo ainda pode ser uma senha válida.
/// O primeiro byte que torna isso impossível encerra com erro imediatamente;
/// assim um pipe infinito não transforma o limite em espera ilimitada. LF ou
/// CRLF terminal é separador, não parte da senha.
pub(crate) fn read_passphrase_fd(fd: RawFd) -> Result<Passphrase> {
    if fd < 0 {
        return Err(erro("--passphrase-fd exige descritor não negativo"));
    }
    // SAFETY: F_DUPFD_CLOEXEC cria um descritor novo que passa a pertencer ao
    // `File`; o descritor original continua pertencendo ao chamador.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate == -1 {
        return Err(erro(format!(
            "--passphrase-fd {fd}: não duplicou descritor: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `duplicate` acabou de ser criado e tem ownership exclusivo aqui.
    let mut input = unsafe { fs::File::from_raw_fd(duplicate) };
    // Consultar a DUPLICATA fecha a janela fd-close/fd-reuse entre validação e
    // dup em processos que ganhem threads no futuro.
    // SAFETY: F_GETFL apenas consulta o descritor duplicado e estável.
    let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        return Err(erro(format!(
            "--passphrase-fd {fd}: descritor inválido: {}",
            std::io::Error::last_os_error()
        )));
    }
    if flags & libc::O_ACCMODE == libc::O_WRONLY {
        return Err(erro(format!(
            "--passphrase-fd {fd}: descritor não é legível"
        )));
    }
    // Esta interface é deliberadamente não interativa. Um TTY indicaria que
    // a senha pode aparecer com eco ou que o operador esperava um prompt que
    // não existe.
    // SAFETY: isatty só consulta a duplicata já validada acima.
    if unsafe { libc::isatty(input.as_raw_fd()) } == 1 {
        return Err(erro(format!(
            "--passphrase-fd {fd}: TTY recusado; forneça um pipe já aberto"
        )));
    }

    let mut passphrase = Passphrase {
        bytes: Zeroizing::new(vec![0u8; PASSPHRASE_READ_BYTES].into_boxed_slice()),
        len: 0,
    };
    loop {
        let count = input
            .read(&mut passphrase.bytes[passphrase.len..])
            .map_err(|error| erro(format!("--passphrase-fd {fd}: leitura falhou: {error}")))?;
        if count == 0 {
            break;
        }
        passphrase.len += count;
        if passphrase.len > MAX_PASSPHRASE_BYTES + 2 {
            return Err(erro(format!(
                "--passphrase-fd {fd}: passphrase excede {MAX_PASSPHRASE_BYTES} bytes"
            )));
        }
    }

    if passphrase.len != 0 && passphrase.bytes[passphrase.len - 1] == b'\n' {
        passphrase.len -= 1;
        if passphrase.len != 0 && passphrase.bytes[passphrase.len - 1] == b'\r' {
            passphrase.len -= 1;
        }
    }
    if passphrase.len > MAX_PASSPHRASE_BYTES {
        return Err(erro(format!(
            "--passphrase-fd {fd}: passphrase excede {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    if passphrase
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(erro(format!(
            "--passphrase-fd {fd}: passphrase contém NUL ou quebra de linha interna"
        )));
    }
    Ok(passphrase)
}

fn base64_decode(line: &str, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = line.trim();
    // `Engine::decode()` cria um `Vec` comum e, em erro tardio, pode descartá-lo
    // já contendo um prefixo da semente. Um buffer inicializado dentro de
    // `Zeroizing` cobre sucesso E erro; depois do sucesso, somente zeros ficam
    // na capacidade truncada.
    let mut decoded = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(encoded.len())]);
    let written = base64::engine::general_purpose::STANDARD
        .decode_slice(encoded, &mut decoded)
        .map_err(|error| erro(format!("{what}: base64 inválido: {error}")))?;
    decoded.truncate(written);
    Ok(decoded)
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Segunda linha de um arquivo minisign: a primeira é sempre comentário.
fn payload_line<'a>(text: &'a str, what: &str) -> Result<&'a str> {
    let mut lines = text.lines();
    let first = lines
        .next()
        .ok_or_else(|| erro(format!("{what}: arquivo vazio")))?;
    if !first.starts_with(UNTRUSTED_PREFIX) {
        return Err(erro(format!("{what}: falta a linha 'untrusted comment:'")));
    }
    let payload = lines
        .next()
        .ok_or_else(|| erro(format!("{what}: falta a linha de dados")))?;
    Ok(payload)
}

/// Reprodução literal de `pickparams()` do libsodium usado pelo minisign.
/// Os arquivos guardam `opslimit`/`memlimit`, não N/r/p; converter de outra
/// forma produziria uma chave aparentemente válida que só falha como "senha
/// errada".
fn minisign_scrypt_params(opslimit: u64, memlimit: u64) -> Result<ScryptParams> {
    if !(SCRYPT_OPSLIMIT_MIN..=SCRYPT_OPSLIMIT_MAX).contains(&opslimit)
        || !(SCRYPT_MEMLIMIT_MIN..=SCRYPT_MEMLIMIT_MAX).contains(&memlimit)
    {
        return Err(erro(
            "chave secreta: parâmetros scrypt fora da faixa segura do minisign",
        ));
    }

    let r = 8u32;
    let (max_n, p) = if opslimit < memlimit / 32 {
        (opslimit / (u64::from(r) * 4), 1u32)
    } else {
        let max_n = memlimit / (u64::from(r) * 128);
        let log_n = scrypt_log_n(max_n)?;
        let n = 1u64 << log_n;
        let max_rp = ((opslimit / 4) / n).min(0x3fff_ffff);
        let p = u32::try_from(max_rp)
            .ok()
            .map(|value| value / r)
            .filter(|value| *value != 0)
            .ok_or_else(|| erro("chave secreta: parâmetros scrypt inválidos"))?;
        return ScryptParams::new(log_n, r, p)
            .map_err(|_| erro("chave secreta: parâmetros scrypt inválidos"));
    };
    let log_n = scrypt_log_n(max_n)?;
    ScryptParams::new(log_n, r, p).map_err(|_| erro("chave secreta: parâmetros scrypt inválidos"))
}

fn scrypt_log_n(max_n: u64) -> Result<u8> {
    for log_n in 1u8..63 {
        if (1u64 << log_n) > max_n / 2 {
            return Ok(log_n);
        }
    }
    Err(erro("chave secreta: parâmetros scrypt inválidos"))
}

fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(erro(format!(
            "passphrase excede {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    if passphrase
        .iter()
        .any(|byte| matches!(*byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(erro("passphrase contém NUL ou quebra de linha"));
    }
    Ok(())
}

fn decrypt_key_material(raw: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    validate_passphrase(passphrase)?;
    let opslimit = u64::from_le_bytes(
        raw[38..46]
            .try_into()
            .map_err(|_| erro("chave secreta: opslimit truncado"))?,
    );
    let memlimit = u64::from_le_bytes(
        raw[46..54]
            .try_into()
            .map_err(|_| erro("chave secreta: memlimit truncado"))?,
    );
    let params = minisign_scrypt_params(opslimit, memlimit)?;
    let mut stream = Zeroizing::new(vec![0u8; KEY_MATERIAL_LEN]);
    scrypt_fallible(passphrase, &raw[6..38], &params, &mut stream)
        .map_err(|_| erro("chave secreta: derivação scrypt falhou"))?;
    let mut material = Zeroizing::new(raw[54..158].to_vec());
    for (dst, mask) in material.iter_mut().zip(stream.iter()) {
        *dst ^= mask;
    }
    Ok(material)
}

/// Deliberadamente SEM `derive(Debug)`: um `{:?}` num tipo que guarda a
/// semente ed25519 é como material secreto acaba em log de erro. Os testes
/// abaixo comparam a mensagem do erro, não o valor do sucesso, justamente
/// para não precisar disso.
pub struct SecretKey {
    key_id: [u8; 8],
    signing: SigningKey,
}

fn secret_key_from_bytes(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<SecretKey> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| erro(format!("chave secreta: texto UTF-8 inválido: {error}")))?;
    let payload = payload_line(text, "chave secreta")?;
    let raw = base64_decode(payload, "chave secreta")?;
    if raw.len() != SECRET_LEN {
        return Err(erro(format!(
            "chave secreta: esperava {SECRET_LEN} bytes, li {}",
            raw.len()
        )));
    }
    if &raw[0..2] != LEGACY_ALGORITHM {
        return Err(erro("chave secreta: algoritmo não é Ed25519"));
    }
    if &raw[4..6] != CHECKSUM_ALGORITHM {
        return Err(erro("chave secreta: checksum não é BLAKE2b"));
    }

    let encrypted = &raw[2..4] == SCRYPT_ALGORITHM;
    let material = if raw[2..4] == [0, 0] {
        if passphrase.is_some() {
            return Err(erro(
                "chave secreta sem senha: --passphrase-fd não se aplica",
            ));
        }
        Zeroizing::new(raw[54..158].to_vec())
    } else if encrypted {
        let passphrase = passphrase.ok_or_else(|| {
            erro("chave secreta protegida por senha: use --passphrase-fd N com um pipe já aberto")
        })?;
        decrypt_key_material(&raw, passphrase)?
    } else {
        return Err(erro("chave secreta: função de derivação desconhecida"));
    };

    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&material[0..8]);
    let secret = &material[8..72];
    let stored_checksum = &material[72..104];

    // O checksum do minisign existe para detectar senha errada. Chaves plain
    // do upstream têm o campo zerado; chaves Sc sempre precisam conferi-lo.
    if encrypted || stored_checksum != [0u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(LEGACY_ALGORITHM);
        hasher.update(key_id);
        hasher.update(secret);
        let calculated = Zeroizing::new(hasher.finalize().to_vec());
        if calculated.as_slice() != stored_checksum {
            let message = if encrypted {
                "chave secreta: senha incorreta ou chave cifrada corrompida"
            } else {
                "chave secreta: checksum não confere"
            };
            return Err(erro(message));
        }
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&secret[0..32]);
    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().to_bytes() != secret[32..64] {
        return Err(erro(
            "chave secreta: a parte pública não deriva da semente (chave corrompida)",
        ));
    }
    Ok(SecretKey { key_id, signing })
}

impl SecretKey {
    /// Atalho das regressões para a variante sem senha.
    #[cfg(test)]
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_passphrase(path, None)
    }

    /// Lê chave minisign plain (`\0\0`) ou protegida por scrypt (`Sc`). A
    /// passphrase só pode chegar da fronteira por descritor; este método recebe
    /// bytes para que o parser criptográfico permaneça independente da CLI.
    fn load_with_passphrase(path: &Path, passphrase: Option<&[u8]>) -> Result<Self> {
        let mut file = open_secret_nofollow(path)?;
        let snapshot = file
            .metadata()
            .map_err(|error| erro(format!("chave secreta {}: {error}", path.display())))?;
        validate_regular_metadata(&snapshot, path, "chave secreta", MAX_SECRET_FILE_BYTES)?;
        let capacity = usize::try_from(snapshot.len())
            .ok()
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| erro("chave secreta: tamanho inválido"))?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        (&mut file)
            .take(snapshot.len() + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                erro(format!(
                    "chave secreta {}: leitura falhou: {error}",
                    path.display()
                ))
            })?;
        if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
            return Err(erro(format!(
                "chave secreta {}: excede o limite de {MAX_SECRET_FILE_BYTES} bytes",
                path.display()
            )));
        }
        publication_checkpoint("after_secret_read")?;
        let after = file
            .metadata()
            .map_err(|error| erro(format!("chave secreta {}: {error}", path.display())))?;
        if bytes.len() as u64 != snapshot.len()
            || !same_file_snapshot(&snapshot, &after)
            || after.uid() != effective_uid()
            || after.mode() & 0o077 != 0
        {
            return Err(erro(format!(
                "chave secreta {} mudou durante a leitura",
                path.display()
            )));
        }
        secret_key_from_bytes(&bytes, passphrase)
    }

    pub fn public_line(&self) -> String {
        let mut raw = Vec::with_capacity(PUBLIC_LEN);
        raw.extend_from_slice(LEGACY_ALGORITHM);
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(&self.signing.verifying_key().to_bytes());
        base64_encode(&raw)
    }

    /// Assina `message` no formato pré-hasheado (`ED`), que é o que o
    /// minisign moderno produz e o que `minisign-verify` aceita nos dois
    /// modos.
    #[cfg(test)]
    pub fn sign(&self, message: &[u8], untrusted: &str, trusted: &str) -> Result<String> {
        let digest: [u8; 64] = Blake2b512::digest(message).into();
        self.sign_prehashed(&digest, untrusted, trusted)
    }

    fn sign_prehashed(&self, digest: &[u8; 64], untrusted: &str, trusted: &str) -> Result<String> {
        for (rotulo, texto, prefixo, limite) in [
            (
                "untrusted",
                untrusted,
                UNTRUSTED_PREFIX,
                MINISIGN_COMMENT_BYTES,
            ),
            (
                "trusted",
                trusted,
                TRUSTED_PREFIX,
                MINISIGN_TRUSTED_COMMENT_BYTES,
            ),
        ] {
            if texto
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
            {
                return Err(erro(format!(
                    "comentário {rotulo} não pode conter NUL ou quebra de linha"
                )));
            }
            // O buffer C do minisign inclui prefixo, LF e NUL terminal.
            if prefixo.len() + texto.len() + 2 > limite {
                return Err(erro(format!(
                    "comentário {rotulo} excede o limite compatível com minisign"
                )));
            }
        }
        let signature = self.signing.sign(digest);

        let mut first = Vec::with_capacity(2 + 8 + 64);
        first.extend_from_slice(PREHASHED_ALGORITHM);
        first.extend_from_slice(&self.key_id);
        first.extend_from_slice(&signature.to_bytes());

        // A assinatura global cobre assinatura ‖ comentário confiável: é o que
        // impede trocar o comentário sem invalidar o arquivo.
        let mut global_body = Vec::from(signature.to_bytes());
        global_body.extend_from_slice(trusted.as_bytes());
        let global = self.signing.sign(&global_body);

        Ok(format!(
            "{UNTRUSTED_PREFIX}{untrusted}\n{}\n{TRUSTED_PREFIX}{trusted}\n{}\n",
            base64_encode(&first),
            base64_encode(&global.to_bytes())
        ))
    }
}

fn recover_keygen_material(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    secret_name: &CStr,
    public_name: &CStr,
) -> Result<Option<KeygenMaterial>> {
    stage.ensure_bound(parent)?;
    let staged_secret = open_secret_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &c_name(KEY_SECRET),
        "secreta staged do keygen",
    )?;
    let final_secret = open_secret_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        secret_name,
        "secreta final do keygen",
    )?;
    let staged_public = open_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &c_name(KEY_PUBLIC),
        "pública staged do keygen",
        MAX_CONTROL_FILE_BYTES,
    )?;
    let final_public = open_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        public_name,
        "pública final do keygen",
        MAX_CONTROL_FILE_BYTES,
    )?;

    if let (Some(staged), Some(final_leaf)) = (&staged_secret, &final_secret) {
        if staged.bytes.as_slice() != final_leaf.bytes.as_slice() {
            return Err(erro(
                "recuperação do keygen: secreta final diverge da staged",
            ));
        }
    }
    if let (Some(staged), Some(final_leaf)) = (&staged_public, &final_public) {
        if staged.bytes != final_leaf.bytes {
            return Err(erro(
                "recuperação do keygen: pública final diverge da staged",
            ));
        }
    }
    for leaf in [&staged_public, &final_public].into_iter().flatten() {
        if leaf.metadata.mode() & 0o777 != 0o644 {
            return Err(erro("recuperação do keygen: pública não está em modo 0644"));
        }
    }

    let secret_source = staged_secret.as_ref().or(final_secret.as_ref());
    let public_source = staged_public.as_ref().or(final_public.as_ref());
    let (Some(secret_source), Some(public_source)) = (secret_source, public_source) else {
        return Ok(None);
    };
    let public_text = validate_keygen_pair(&secret_source.bytes, &public_source.bytes)?;
    let (owner, request, ready) = keygen_control_bytes(
        secret_name,
        public_name,
        &secret_source.bytes,
        &public_source.bytes,
    );
    for (name, expected, what) in [
        (KEY_OWNER, owner.as_slice(), "OWNER do keygen"),
        (KEY_REQUEST, request.as_slice(), "REQUEST do keygen"),
        (KEY_READY, ready.as_slice(), "READY do keygen"),
    ] {
        let Some(leaf) = exact_leaf_at(
            &stage.file,
            stage.metadata.dev(),
            &c_name(name),
            expected,
            0o600,
            what,
            MAX_CONTROL_FILE_BYTES,
        )?
        else {
            return Ok(None);
        };
        leaf.file
            .sync_all()
            .map_err(|error| erro(format!("{what}: {error}")))?;
    }
    secret_source
        .file
        .sync_all()
        .map_err(|error| erro(format!("secreta do keygen: {error}")))?;
    public_source
        .file
        .sync_all()
        .map_err(|error| erro(format!("pública do keygen: {error}")))?;
    stage.sync()?;
    parent.sync()?;
    Ok(Some(KeygenMaterial {
        secret: Zeroizing::new(secret_source.bytes.to_vec()),
        public: public_source.bytes.clone(),
        public_text,
    }))
}

fn existing_keygen_material(
    parent: &ParentAnchor,
    secret_name: &CStr,
    public_name: &CStr,
) -> Result<(Option<KeygenMaterial>, bool)> {
    let secret = open_secret_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        secret_name,
        "chave secreta final",
    )?;
    let public = open_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        public_name,
        "chave pública final",
        MAX_CONTROL_FILE_BYTES,
    )?;
    let any = secret.is_some() || public.is_some();
    let (Some(secret), Some(public)) = (secret, public) else {
        return Ok((None, any));
    };
    if public.metadata.mode() & 0o777 != 0o644 {
        return Err(erro("chave pública final precisa estar em modo 0644"));
    }
    let public_text = validate_keygen_pair(&secret.bytes, &public.bytes)?;
    secret
        .file
        .sync_all()
        .map_err(|error| erro(format!("chave secreta final: {error}")))?;
    public
        .file
        .sync_all()
        .map_err(|error| erro(format!("chave pública final: {error}")))?;
    parent.sync()?;
    Ok((
        Some(KeygenMaterial {
            secret: secret.bytes,
            public: public.bytes,
            public_text,
        }),
        true,
    ))
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Gera um par minisign novo. Sem isto a independência seria só parcial:
/// quem começa do zero ainda precisaria do minisign do hospedeiro para criar
/// a chave que o canal usa.
pub fn keygen(name: &str, secret_path: &Path, public_path: &Path) -> Result<()> {
    let secret_parent = output_parent(secret_path);
    let public_parent = output_parent(public_path);
    if secret_parent != public_parent {
        return Err(erro(
            "keygen crash-safe exige chave secreta e pública no mesmo diretório",
        ));
    }
    let secret_name = signature_leaf(secret_path, "chave secreta final")?;
    let public_name = signature_leaf(public_path, "chave pública final")?;
    if secret_name == public_name {
        return Err(erro("keygen exige nomes finais distintos"));
    }
    let parent = ParentAnchor::open(secret_parent)?;
    let stage_name = deterministic_name(
        "minitrue-keygen",
        &[secret_name.as_bytes(), public_name.as_bytes()],
    )?;
    let existing_stage = StageAnchor::open(&parent, &stage_name)?;
    let (complete, any_final) = existing_keygen_material(&parent, &secret_name, &public_name)?;

    if let Some(complete) = complete {
        // Um retry depois da promoção pode encontrar somente os finais. A
        // idempotência não se baseia em "existe": parseamos a secreta,
        // derivamos a pública canônica e prendemos ambas ao REQUEST calculado.
        let (_, expected_request, _) = keygen_control_bytes(
            &secret_name,
            &public_name,
            &complete.secret,
            &complete.public,
        );
        if let Some(stage) = existing_stage {
            match recover_keygen_material(&parent, &stage, &secret_name, &public_name) {
                Ok(Some(recovered))
                    if recovered.secret.as_slice() == complete.secret.as_slice()
                        && recovered.public == complete.public =>
                {
                    let request = exact_leaf_at(
                        &stage.file,
                        stage.metadata.dev(),
                        &c_name(KEY_REQUEST),
                        &expected_request,
                        0o600,
                        "REQUEST residual do keygen",
                        MAX_CONTROL_FILE_BYTES,
                    )?;
                    if request.is_some() {
                        if let Err(error) = discard_keygen_stage(&parent, &stage, true) {
                            eprintln!(
                                "minitrue: aviso: par já publicado, mas staging do keygen não foi limpo: {error}"
                            );
                        }
                    }
                }
                Ok(_) => {
                    return Err(erro(
                        "par final existe, mas o staging residual não o prende ao REQUEST esperado",
                    ))
                }
                Err(error) => {
                    return Err(erro(format!(
                        "par final existe, mas o staging residual não confere com o REQUEST esperado: {error}"
                    )))
                }
            }
        }
        parent.ensure_still_named()?;
        println!("chave de canal '{name}' já criada (retry idempotente):");
        println!("  secreta: {} (0600)", secret_path.display());
        println!("  pública: {}", public_path.display());
        print!("{}", complete.public_text);
        return Ok(());
    }

    let stage;
    let material;
    if let Some(existing) = existing_stage {
        match recover_keygen_material(&parent, &existing, &secret_name, &public_name)? {
            Some(recovered) => {
                stage = existing;
                material = recovered;
            }
            None if !any_final => {
                discard_keygen_stage(&parent, &existing, false)?;
                stage = StageAnchor::create(&parent, stage_name.clone())?;
                let owner = keygen_owner_bytes(&secret_name, &public_name);
                ensure_leaf_at(
                    &stage,
                    &c_name(KEY_OWNER),
                    &owner,
                    0o600,
                    "OWNER do keygen",
                    MAX_CONTROL_FILE_BYTES,
                )?;
                publication_checkpoint("keygen_after_owner")?;
                material = generate_keygen_material()?;
            }
            None => {
                return Err(erro(
                    "keygen encontrou final parcial sem REQUEST+READY recuperável",
                ))
            }
        }
    } else {
        if any_final {
            return Err(erro(
                "keygen encontrou apenas uma das chaves finais e nenhum staging recuperável",
            ));
        }
        stage = StageAnchor::create(&parent, stage_name.clone())?;
        let owner = keygen_owner_bytes(&secret_name, &public_name);
        ensure_leaf_at(
            &stage,
            &c_name(KEY_OWNER),
            &owner,
            0o600,
            "OWNER do keygen",
            MAX_CONTROL_FILE_BYTES,
        )?;
        publication_checkpoint("keygen_after_owner")?;
        material = generate_keygen_material()?;
    }

    let (owner, request, ready) = keygen_control_bytes(
        &secret_name,
        &public_name,
        &material.secret,
        &material.public,
    );
    ensure_leaf_at(
        &stage,
        &c_name(KEY_OWNER),
        &owner,
        0o600,
        "OWNER do keygen",
        MAX_CONTROL_FILE_BYTES,
    )?;
    ensure_secret_leaf_at(
        &stage,
        &c_name(KEY_SECRET),
        &material.secret,
        "secreta staged do keygen",
    )?;
    publication_checkpoint("keygen_after_secret")?;
    ensure_leaf_at(
        &stage,
        &c_name(KEY_PUBLIC),
        &material.public,
        0o644,
        "pública staged do keygen",
        MAX_CONTROL_FILE_BYTES,
    )?;
    publication_checkpoint("keygen_after_public")?;
    ensure_leaf_at(
        &stage,
        &c_name(KEY_REQUEST),
        &request,
        0o600,
        "REQUEST do keygen",
        MAX_CONTROL_FILE_BYTES,
    )?;
    publication_checkpoint("keygen_after_request")?;
    ensure_leaf_at(
        &stage,
        &c_name(KEY_READY),
        &ready,
        0o600,
        "READY do keygen",
        MAX_CONTROL_FILE_BYTES,
    )?;
    stage.sync()?;
    publication_checkpoint("keygen_after_ready_stage_sync")?;
    parent.sync()?;
    publication_checkpoint("keygen_after_ready_parent_sync")?;
    publication_checkpoint("keygen_after_ready")?;
    parent.ensure_still_named()?;
    stage.ensure_bound(&parent)?;

    let staged_secret = exact_secret_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &c_name(KEY_SECRET),
        &material.secret,
        "secreta staged antes da promoção",
    )?;
    let final_secret = exact_secret_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        &secret_name,
        &material.secret,
        "secreta final concorrente",
    )?;
    let mut promoted_secret = false;
    if final_secret.is_none() {
        let staged_secret = staged_secret
            .as_ref()
            .ok_or_else(|| erro("secreta staged sumiu antes da promoção"))?;
        match crate::linux::renameat2(
            stage.file.as_raw_fd(),
            &c_name(KEY_SECRET),
            parent.file.as_raw_fd(),
            &secret_name,
            libc::RENAME_NOREPLACE,
        ) {
            Ok(()) => promoted_secret = true,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                exact_secret_leaf_at(
                    &parent.file,
                    parent.metadata.dev(),
                    &secret_name,
                    &material.secret,
                    "secreta final concorrente",
                )?
                .ok_or_else(|| erro("secreta final apareceu sem ser a esperada"))?;
            }
            Err(error) => return Err(erro(format!("não publiquei chave secreta: {error}"))),
        }
        publication_checkpoint("keygen_after_secret_rename")?;
        parent.sync()?;
        publication_checkpoint("keygen_after_secret_parent_sync")?;
        stage.sync()?;
        publication_checkpoint("keygen_after_secret_stage_sync")?;
        if promoted_secret {
            let final_leaf = exact_secret_leaf_at(
                &parent.file,
                parent.metadata.dev(),
                &secret_name,
                &material.secret,
                "chave secreta publicada",
            )?
            .ok_or_else(|| erro("chave secreta sumiu após promoção"))?;
            if final_leaf.metadata.dev() != staged_secret.metadata.dev()
                || final_leaf.metadata.ino() != staged_secret.metadata.ino()
            {
                return Err(erro("chave secreta final não é o inode staged"));
            }
        }
    }

    let staged_public = exact_leaf_at(
        &stage.file,
        stage.metadata.dev(),
        &c_name(KEY_PUBLIC),
        &material.public,
        0o644,
        "pública staged antes da promoção",
        MAX_CONTROL_FILE_BYTES,
    )?;
    let final_public = exact_leaf_at(
        &parent.file,
        parent.metadata.dev(),
        &public_name,
        &material.public,
        0o644,
        "pública final concorrente",
        MAX_CONTROL_FILE_BYTES,
    )?;
    let mut promoted_public = false;
    if final_public.is_none() {
        let staged_public = staged_public
            .as_ref()
            .ok_or_else(|| erro("pública staged sumiu antes da promoção"))?;
        match crate::linux::renameat2(
            stage.file.as_raw_fd(),
            &c_name(KEY_PUBLIC),
            parent.file.as_raw_fd(),
            &public_name,
            libc::RENAME_NOREPLACE,
        ) {
            Ok(()) => promoted_public = true,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                exact_leaf_at(
                    &parent.file,
                    parent.metadata.dev(),
                    &public_name,
                    &material.public,
                    0o644,
                    "pública final concorrente",
                    MAX_CONTROL_FILE_BYTES,
                )?
                .ok_or_else(|| erro("pública final apareceu sem ser a esperada"))?;
            }
            Err(error) => return Err(erro(format!("não publiquei chave pública: {error}"))),
        }
        publication_checkpoint("keygen_after_public_rename")?;
        parent.sync()?;
        publication_checkpoint("keygen_after_public_parent_sync")?;
        stage.sync()?;
        publication_checkpoint("keygen_after_public_stage_sync")?;
        if promoted_public {
            let final_leaf = exact_leaf_at(
                &parent.file,
                parent.metadata.dev(),
                &public_name,
                &material.public,
                0o644,
                "chave pública publicada",
                MAX_CONTROL_FILE_BYTES,
            )?
            .ok_or_else(|| erro("chave pública sumiu após promoção"))?;
            if final_leaf.metadata.dev() != staged_public.metadata.dev()
                || final_leaf.metadata.ino() != staged_public.metadata.ino()
            {
                return Err(erro("chave pública final não é o inode staged"));
            }
        }
    }

    let (published, _) = existing_keygen_material(&parent, &secret_name, &public_name)?;
    let published = published.ok_or_else(|| erro("par final não ficou completo"))?;
    if published.secret.as_slice() != material.secret.as_slice()
        || published.public != material.public
    {
        return Err(erro("par final diverge do REQUEST preparado"));
    }
    parent.ensure_still_named()?;
    if let Err(error) = discard_keygen_stage(&parent, &stage, true) {
        eprintln!(
            "minitrue: aviso: par publicado e sincronizado, mas staging do keygen não foi limpo: {error}"
        );
    }
    parent.ensure_still_named()?;
    println!("chave de canal '{name}' criada:");
    println!("  secreta: {} (0600)", secret_path.display());
    println!("  pública: {}", public_path.display());
    print!("{}", material.public_text);
    Ok(())
}

/// Assina um arquivo, escrevendo `<arquivo>.minisig` ao lado (ou onde pedido).
pub fn sign_file(
    secret_path: &Path,
    message_path: &Path,
    signature_path: &Path,
    untrusted: Option<&str>,
    trusted: Option<&str>,
    expected_public: Option<&str>,
    passphrase: Option<&[u8]>,
) -> Result<()> {
    let expected_public = expected_public.ok_or_else(|| {
        erro("sign exige a chave pública esperada; recusar este vínculo permitiria assinar com um key_id plain adulterado")
    })?;
    let key = SecretKey::load_with_passphrase(secret_path, passphrase)?;
    let public_line = key.public_line();
    if public_line != expected_public {
        return Err(erro(
            "a chave secreta não corresponde à chave pública esperada",
        ));
    }
    let mut message = open_message_nofollow(message_path)?;
    let (digest, message_snapshot) = hash_message(&mut message, message_path)?;
    let name = message_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            erro("arquivo a assinar: nome precisa ser UTF-8 para o comentário minisign")
        })?;
    // O epoch da árvore, não a hora do relógio: um índice reassinado com o
    // mesmo conteúdo deve dar o mesmo arquivo, senão a mídia deixa de ser
    // reproduzível por causa da assinatura.
    let epoch = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| erro("SOURCE_DATE_EPOCH precisa ser inteiro decimal u64"))?
            .to_string(),
        Err(std::env::VarError::NotPresent) => "1704067200".into(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(erro("SOURCE_DATE_EPOCH precisa ser UTF-8 decimal"))
        }
    };
    let default_trusted = format!("timestamp:{epoch} file:{name}");
    let text = key.sign_prehashed(
        &digest,
        untrusted.unwrap_or("Distropica channel index"),
        trusted.unwrap_or(&default_trusted),
    )?;

    // Verifica com o MESMO verificador que o consumidor usa. Assinar e não
    // conferir seria confiar no código que acabou de ser escrito. A mensagem
    // é relida por uma NOVA abertura do pathname e em streaming. Reusar o fd
    // anterior só provaria o inode já aberto, não que o nome ainda aponta para
    // ele quando o sidecar for publicado.
    let public = minisign_verify::PublicKey::from_base64(&public_line).map_err(|error| {
        erro(format!(
            "chave pública derivada não é aceita pelo verificador: {error}"
        ))
    })?;
    let signature = minisign_verify::Signature::decode(&text)
        .map_err(|error| erro(format!("assinatura recém-escrita não decodifica: {error}")))?;
    let mut verify_message = open_message_nofollow(message_path)?;
    let verify_before = verify_message.metadata().map_err(|error| {
        erro(format!(
            "arquivo a assinar {}: {error}",
            message_path.display()
        ))
    })?;
    if !same_file_snapshot(&message_snapshot, &verify_before) {
        return Err(erro(format!(
            "arquivo a assinar {} deixou de nomear o inode assinado",
            message_path.display()
        )));
    }
    let mut verifier = public
        .verify_stream(&signature)
        .map_err(|error| erro(format!("assinatura recém-criada não inicia: {error}")))?;
    let mut verified_bytes = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = verify_message.read(&mut chunk).map_err(|error| {
            erro(format!(
                "arquivo a assinar {}: {error}",
                message_path.display()
            ))
        })?;
        if count == 0 {
            break;
        }
        verified_bytes = verified_bytes
            .checked_add(count as u64)
            .ok_or_else(|| erro("arquivo a assinar: tamanho transbordou"))?;
        if verified_bytes > MAX_SIGNED_MESSAGE_BYTES {
            return Err(erro(format!(
                "arquivo a assinar {}: excede o limite de {MAX_SIGNED_MESSAGE_BYTES} bytes",
                message_path.display()
            )));
        }
        verifier.update(&chunk[..count]);
    }
    chunk.zeroize();
    verifier
        .finalize()
        .map_err(|error| erro(format!("assinatura recém-criada não confere: {error}")))?;
    let message_after = verify_message.metadata().map_err(|error| {
        erro(format!(
            "arquivo a assinar {}: {error}",
            message_path.display()
        ))
    })?;
    if verified_bytes != message_snapshot.len()
        || !same_file_snapshot(&message_snapshot, &message_after)
    {
        return Err(erro(format!(
            "arquivo a assinar {} mudou durante a verificação",
            message_path.display()
        )));
    }

    let created = publish_signature(
        signature_path,
        message_path,
        &message_snapshot,
        &digest,
        &public_line,
        text.as_bytes(),
    )?;
    if created {
        println!("assinado: {}", signature_path.display());
    } else {
        println!(
            "já assinado (retry idempotente): {}",
            signature_path.display()
        );
    }
    println!("  chave pública: {public_line}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::symlink;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    // Vetor produzido independentemente com libsodium/PyNaCl: seed 01..20,
    // key_id 01..08, salt 20..3f, opslimit mínimo, memlimit mínimo. O teste
    // de interoperabilidade abaixo ainda o entrega ao minisign 0.12 real.
    const ENCRYPTED_TEST_KEY: &str = "RWRTY0IyICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8AgAAAAAAAAAAAAAEAAAAAyXEJbGZuL1r8dxdTRczHLVdrtA+gQoPo51m2/rWDi/F7ysc45TbSbJVRcBqVNDal4PgN9VMBQWkUjC6UPm4nSHF9Qr00WXV4XcytbKF5VeDs/T6V0kZNAPmSSsrELbOae3pMYlN+/PM=";
    const ENCRYPTED_TEST_PUBLIC: &str = "RWQBAgMEBQYHCHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk";
    const ENCRYPTED_TEST_PASSPHRASE: &[u8] = b"teste 0.13";
    static ACTION_LOCK: Mutex<()> = Mutex::new(());

    fn action_lock() -> std::sync::MutexGuard<'static, ()> {
        ACTION_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn temp_dir(nome: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "minitrue-sign-{nome}-{}-{}",
            std::process::id(),
            nome.len()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        base
    }

    fn encrypted_test_key(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("encrypted.key");
        fs::write(
            &path,
            format!("{UNTRUSTED_PREFIX}minisign encrypted secret key\n{ENCRYPTED_TEST_KEY}\n"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn protect_secret(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_message(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
        let path = path.as_ref();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o644)
            .open(path)
            .unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .unwrap();
        file.write_all(bytes.as_ref()).unwrap();
    }

    fn create_private_dir(path: impl AsRef<Path>) {
        let path = path.as_ref();
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn pipe_with(bytes: &[u8]) -> OwnedFd {
        let mut fds = [-1; 2];
        // SAFETY: `fds` aponta para dois inteiros válidos e ambos os
        // descritores retornados são imediatamente assumidos por RAII.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 retornou ownership exclusivo dos dois descritores.
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: idem; `File` fecha somente a ponta de escrita.
        let mut writer = unsafe { fs::File::from_raw_fd(fds[1]) };
        writer.write_all(bytes).unwrap();
        drop(writer);
        reader
    }

    fn passphrase_error(fd: RawFd) -> String {
        match read_passphrase_fd(fd) {
            Ok(_) => panic!("descritor indevido foi aceito"),
            Err(error) => error.to_string(),
        }
    }

    struct TestAction;

    impl Drop for TestAction {
        fn drop(&mut self) {
            for name in [
                "MINITRUE_SIGN_ACTION_LABEL",
                "MINITRUE_SIGN_ACTION_THREAD",
                "MINITRUE_SIGN_ACTION_KIND",
                "MINITRUE_SIGN_ACTION_FIRST",
                "MINITRUE_SIGN_ACTION_SECOND",
                "MINITRUE_SIGN_ACTION_THIRD",
            ] {
                std::env::remove_var(name);
            }
        }
    }

    fn test_action(
        label: &str,
        kind: &str,
        first: &Path,
        second: &Path,
        third: Option<&Path>,
    ) -> TestAction {
        let current = std::thread::current();
        std::env::set_var(
            "MINITRUE_SIGN_ACTION_THREAD",
            current.name().expect("thread de teste sem nome"),
        );
        std::env::set_var("MINITRUE_SIGN_ACTION_LABEL", label);
        std::env::set_var("MINITRUE_SIGN_ACTION_KIND", kind);
        std::env::set_var("MINITRUE_SIGN_ACTION_FIRST", first);
        std::env::set_var("MINITRUE_SIGN_ACTION_SECOND", second);
        if let Some(third) = third {
            std::env::set_var("MINITRUE_SIGN_ACTION_THIRD", third);
        } else {
            std::env::remove_var("MINITRUE_SIGN_ACTION_THIRD");
        }
        TestAction
    }

    fn signer_stage_path(signature: &Path) -> PathBuf {
        let final_name = signature_leaf(signature, "assinatura").unwrap();
        let stage_name = deterministic_name("minitrue-sign", &[final_name.as_bytes()]).unwrap();
        signature
            .parent()
            .unwrap()
            .join(std::ffi::OsStr::from_bytes(stage_name.as_bytes()))
    }

    fn run_ignored_child(test_filter: &str, vars: &[(&str, &str)]) -> std::process::ExitStatus {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--ignored", test_filter, "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in vars {
            command.env(name, value);
        }
        command.status().unwrap()
    }

    #[test]
    #[ignore]
    fn signer_crash_child() {
        let dir = PathBuf::from(std::env::var_os("MINITRUE_SIGN_CHILD_DIR").unwrap());
        let secret = PathBuf::from(std::env::var_os("MINITRUE_SIGN_CHILD_SECRET").unwrap());
        let expected = SecretKey::load(&secret).unwrap().public_line();
        sign_file(
            &secret,
            &dir.join("index"),
            &dir.join("index.minisig"),
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn keygen_crash_child() {
        let dir = PathBuf::from(std::env::var_os("MINITRUE_SIGN_CHILD_DIR").unwrap());
        keygen("crash", &dir.join("channel.key"), &dir.join("channel.pub")).unwrap();
    }

    #[test]
    fn keygen_produz_chave_que_assina_e_o_verificador_aceita() {
        let dir = temp_dir("ciclo");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("teste", &secret, &public).unwrap();

        let message = dir.join("index");
        write_message(&message, b"pkg 1 x86_64\n");
        let signature = dir.join("index.minisig");
        let esperada = SecretKey::load(&secret).unwrap().public_line();
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&esperada),
            None,
        )
        .unwrap();

        // A chave pública gravada tem de ser a mesma que a secreta deriva:
        // publicar uma e assinar com a outra é o erro que ninguém percebe até
        // o primeiro consumidor recusar o canal.
        let publicada = fs::read_to_string(&public).unwrap();
        assert!(publicada.contains(&esperada));

        let key = minisign_verify::PublicKey::from_base64(&esperada).unwrap();
        let texto = fs::read_to_string(&signature).unwrap();
        let sig = minisign_verify::Signature::decode(&texto).unwrap();
        key.verify(b"pkg 1 x86_64\n", &sig, false).unwrap();
        assert!(key.verify(b"outra coisa\n", &sig, false).is_err());
        if Command::new("minisign").arg("-v").output().is_ok() {
            assert!(Command::new("minisign")
                .arg("-Vm")
                .arg(&message)
                .arg("-x")
                .arg(&signature)
                .arg("-p")
                .arg(&public)
                .status()
                .unwrap()
                .success());
        }
    }

    #[test]
    fn comentario_da_publica_exibe_key_id_minisign_em_little_endian() {
        let key = SecretKey {
            key_id: [1, 2, 3, 4, 5, 6, 7, 8],
            signing: SigningKey::from_bytes(&[0x42; 32]),
        };
        let text = keygen_public_text(&key);
        assert!(
            text.starts_with("untrusted comment: minisign public key 0807060504030201\n"),
            "comentário incompatível com minisign: {text}"
        );
        let payload = payload_line(&text, "pública").unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .unwrap();
        assert_eq!(&raw[2..10], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn assinatura_e_deterministica_para_o_mesmo_conteudo() {
        let dir = temp_dir("determinismo");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let key = SecretKey::load(&secret).unwrap();
        let a = key.sign(b"mesmo", "c", "t").unwrap();
        let b = key.sign(b"mesmo", "c", "t").unwrap();
        assert_eq!(a, b, "ed25519 é determinístico; a saída também deve ser");
    }

    #[test]
    fn chave_publica_esperada_e_conferida_antes_de_assinar() {
        let dir = temp_dir("publica-esperada");
        let secret_a = dir.join("a.key");
        let secret_b = dir.join("b.key");
        keygen("a", &secret_a, &dir.join("a.pub")).unwrap();
        keygen("b", &secret_b, &dir.join("b.pub")).unwrap();
        let public_a = SecretKey::load(&secret_a).unwrap().public_line();
        let public_b = SecretKey::load(&secret_b).unwrap().public_line();
        let message = dir.join("index");
        let signature = dir.join("index.minisig");
        write_message(&message, b"pacote 1 x86_64\n");

        let missing = sign_file(&secret_a, &message, &signature, None, None, None, None)
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("pública esperada"),
            "erro inesperado: {missing}"
        );

        let error = sign_file(
            &secret_a,
            &message,
            &signature,
            None,
            None,
            Some(&public_b),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("não corresponde"),
            "erro inesperado: {error}"
        );
        assert!(
            !signature.exists(),
            "a divergência precisa ser detectada antes de escrever a assinatura"
        );

        sign_file(
            &secret_a,
            &message,
            &signature,
            None,
            None,
            Some(&public_a),
            None,
        )
        .unwrap();
        assert!(signature.is_file());
    }

    #[test]
    fn recusa_chave_com_senha_sem_fd_e_chave_corrompida() {
        let dir = temp_dir("recusa");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let texto = fs::read_to_string(&secret).unwrap();
        let payload = payload_line(&texto, "chave").unwrap();
        let mut raw = base64_decode(payload, "chave").unwrap();

        let mut com_senha = raw.clone();
        com_senha[2] = b'S';
        com_senha[3] = b'c';
        let caminho = dir.join("senha.key");
        fs::write(
            &caminho,
            format!("{UNTRUSTED_PREFIX}x\n{}\n", base64_encode(&com_senha)),
        )
        .unwrap();
        protect_secret(&caminho);
        let erro = match SecretKey::load(&caminho) {
            Ok(_) => panic!("aceitou chave protegida por senha"),
            Err(e) => e.to_string(),
        };
        assert!(erro.contains("senha"), "erro inesperado: {erro}");

        // Um bit trocado na semente tem de morrer na conferência semente →
        // pública, não virar assinatura de uma chave que ninguém verifica.
        raw[70] ^= 1;
        let caminho = dir.join("corrompida.key");
        fs::write(
            &caminho,
            format!("{UNTRUSTED_PREFIX}x\n{}\n", base64_encode(&raw)),
        )
        .unwrap();
        protect_secret(&caminho);
        let erro = match SecretKey::load(&caminho) {
            Ok(_) => panic!("aceitou chave com semente corrompida"),
            Err(e) => e.to_string(),
        };
        assert!(erro.contains("não deriva"), "erro inesperado: {erro}");
    }

    #[test]
    fn chave_cifrada_senha_correta_assina_e_verifica() {
        let dir = temp_dir("cifrada-correta");
        let secret = encrypted_test_key(&dir);
        let message = dir.join("index");
        let signature = dir.join("index.minisig");
        write_message(
            &message,
            b"pkg 1 x86_64 fingerprint pool/pkg.tar.zst hash\n",
        );

        let fd = pipe_with(b"teste 0.13\r\n");
        let passphrase = read_passphrase_fd(fd.as_raw_fd()).unwrap();
        assert_ne!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) }, -1);
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(ENCRYPTED_TEST_PUBLIC),
            Some(passphrase.as_bytes()),
        )
        .unwrap();

        let text = fs::read_to_string(&signature).unwrap();
        let decoded_signature = minisign_verify::Signature::decode(&text).unwrap();
        let public = minisign_verify::PublicKey::from_base64(ENCRYPTED_TEST_PUBLIC).unwrap();
        public
            .verify(
                b"pkg 1 x86_64 fingerprint pool/pkg.tar.zst hash\n",
                &decoded_signature,
                false,
            )
            .unwrap();
        if Command::new("minisign").arg("-v").output().is_ok() {
            let public_file = dir.join("encrypted.pub");
            fs::write(
                &public_file,
                format!("{UNTRUSTED_PREFIX}minisign public key\n{ENCRYPTED_TEST_PUBLIC}\n"),
            )
            .unwrap();
            assert!(Command::new("minisign")
                .arg("-Vm")
                .arg(&message)
                .arg("-x")
                .arg(&signature)
                .arg("-p")
                .arg(&public_file)
                .status()
                .unwrap()
                .success());
        }
    }

    #[test]
    fn chave_cifrada_senha_errada_falha_sem_sidecar() {
        let dir = temp_dir("cifrada-errada");
        let secret = encrypted_test_key(&dir);
        let message = dir.join("index");
        let signature = dir.join("index.minisig");
        write_message(&message, b"conteudo\n");

        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(ENCRYPTED_TEST_PUBLIC),
            Some(b"esta senha nao aparece no erro"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("senha incorreta"),
            "erro inesperado: {error}"
        );
        assert!(!error.contains("esta senha"), "o erro vazou a passphrase");
        assert!(!signature.exists(), "senha errada deixou sidecar");
    }

    #[test]
    fn chave_cifrada_publica_divergente_falha_sem_sidecar() {
        let dir = temp_dir("cifrada-publica");
        let secret = encrypted_test_key(&dir);
        let message = dir.join("index");
        let signature = dir.join("index.minisig");
        write_message(&message, b"conteudo\n");

        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some("RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Some(ENCRYPTED_TEST_PASSPHRASE),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("não corresponde"),
            "erro inesperado: {error}"
        );
        assert!(!signature.exists(), "pública divergente deixou sidecar");
    }

    #[test]
    fn passphrase_fd_recusa_invalido_escrita_tty_e_excesso() {
        let invalid = passphrase_error(-1);
        assert!(invalid.contains("não negativo"));

        let dir = temp_dir("fd-fronteiras");
        let write_only = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dir.join("somente-escrita"))
            .unwrap();
        let error = passphrase_error(write_only.as_raw_fd());
        assert!(error.contains("não é legível"));
        assert_ne!(
            unsafe { libc::fcntl(write_only.as_raw_fd(), libc::F_GETFD) },
            -1,
            "a rejeição fechou o fd do chamador"
        );

        // posix_openpt entrega um terminal real sem depender de /dev/tty ou de
        // haver uma sessão interativa no executor dos testes.
        // SAFETY: a chamada não recebe ponteiros e o retorno válido é assumido
        // imediatamente por OwnedFd.
        let tty_raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_CLOEXEC) };
        assert_ne!(tty_raw, -1, "ambiente Linux sem pseudoterminal");
        // SAFETY: posix_openpt retornou ownership exclusivo.
        let tty = unsafe { OwnedFd::from_raw_fd(tty_raw) };
        let error = passphrase_error(tty.as_raw_fd());
        assert!(error.contains("TTY"), "erro inesperado: {error}");

        let oversized = pipe_with(&vec![b'x'; MAX_PASSPHRASE_BYTES + 1]);
        let error = passphrase_error(oversized.as_raw_fd());
        assert!(error.contains("excede"), "erro inesperado: {error}");
        assert_ne!(
            unsafe { libc::fcntl(oversized.as_raw_fd(), libc::F_GETFD) },
            -1,
            "a leitura fechou o fd original"
        );
    }

    #[test]
    fn parametros_scrypt_exagerados_falham_antes_de_derivar() {
        let dir = temp_dir("scrypt-limite");
        let secret = encrypted_test_key(&dir);
        let text = fs::read_to_string(&secret).unwrap();
        let payload = payload_line(&text, "chave").unwrap();
        let mut raw = base64_decode(payload, "chave").unwrap();
        raw[46..54].copy_from_slice(&(SCRYPT_MEMLIMIT_MAX + 1).to_le_bytes());
        fs::write(
            &secret,
            format!("{UNTRUSTED_PREFIX}x\n{}\n", base64_encode(&raw)),
        )
        .unwrap();

        let error = SecretKey::load_with_passphrase(&secret, Some(ENCRYPTED_TEST_PASSPHRASE))
            .err()
            .expect("aceitou custo forjado")
            .to_string();
        raw.zeroize();
        assert!(error.contains("faixa segura"), "erro inesperado: {error}");

        // O maior custo compatível continua aceito, mas este teste só calcula
        // a reserva: não toca/aloca 1 GiB no executor. A implementação
        // vendorizada usa exatamente este tamanho com `try_reserve_exact` e
        // envolve B/V/T em Zeroizing antes da derivação.
        let max_params = minisign_scrypt_params(SCRYPT_OPSLIMIT_MAX, SCRYPT_MEMLIMIT_MAX).unwrap();
        let work = scrypt::scrypt_work_bytes(&max_params).unwrap();
        assert_eq!(work, 1_073_743_872);
    }

    #[test]
    fn signer_usa_somente_a_api_scrypt_fallible() {
        // O fork preserva a entrada infalível por compatibilidade upstream, mas
        // o signer não pode regredir para a variante que aborta em falha de
        // alocação e não limpa B/V/T. Monte os tokens para que a própria
        // asserção não os introduza no texto inspecionado.
        let source = include_str!("sign.rs");
        let infallible_call = ["scrypt", "("].concat();
        let fallible_call = ["scrypt_fallible", "("].concat();
        assert!(!source.contains(&infallible_call));
        assert!(source.contains(&fallible_call));
    }

    #[test]
    fn fixture_cifrada_e_interoperavel_com_minisign_local() {
        if Command::new("minisign").arg("-v").output().is_err() {
            return;
        }
        let dir = temp_dir("minisign-local");
        let secret = encrypted_test_key(&dir);
        let public = dir.join("test.pub");
        let message = dir.join("mensagem");
        let signature = dir.join("mensagem.minisig");
        fs::write(
            &public,
            format!("{UNTRUSTED_PREFIX}minisign public key\n{ENCRYPTED_TEST_PUBLIC}\n"),
        )
        .unwrap();
        write_message(&message, b"interoperabilidade 0.13\n");

        let mut child = Command::new("minisign")
            .args(["-S", "-s"])
            .arg(&secret)
            .arg("-m")
            .arg(&message)
            .arg("-x")
            .arg(&signature)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"teste 0.13\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "minisign recusou fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let verified = Command::new("minisign")
            .args(["-V", "-q", "-p"])
            .arg(&public)
            .arg("-m")
            .arg(&message)
            .arg("-x")
            .arg(&signature)
            .status()
            .unwrap();
        assert!(verified.success(), "minisign não verificou a assinatura");
    }

    #[test]
    fn retry_exato_e_idempotente_mas_final_divergente_falha() {
        let dir = temp_dir("sobrescrita");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("t", &secret, &public).unwrap();
        keygen("t", &secret, &public).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();

        let message = dir.join("m");
        write_message(&message, b"x");
        let signature = dir.join("m.minisig");
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();

        write_message(&message, b"y");
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("diverge"), "erro inesperado: {error}");
    }

    #[test]
    fn signer_recusa_symlink_e_hardlink_sem_deixar_sidecar() {
        let dir = temp_dir("links-entrada");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("t", &secret, &public).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let secret_link = dir.join("secret-link");
        symlink(&secret, &secret_link).unwrap();
        let message = dir.join("index");
        write_message(&message, b"conteudo\n");
        let signature = dir.join("index.minisig");
        assert!(sign_file(
            &secret_link,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .is_err());
        assert!(!signature.exists());

        fs::remove_file(secret_link).unwrap();
        let secret_hardlink = dir.join("secret-hardlink");
        fs::hard_link(&secret, &secret_hardlink).unwrap();
        let error = SecretKey::load(&secret_hardlink)
            .err()
            .expect("aceitou chave com dois links")
            .to_string();
        assert!(error.contains("único link"), "erro inesperado: {error}");
        fs::remove_file(secret_hardlink).unwrap();

        let message_link = dir.join("message-link");
        symlink(&message, &message_link).unwrap();
        assert!(sign_file(
            &secret,
            &message_link,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .is_err());
        assert!(!signature.exists());
        fs::remove_file(message_link).unwrap();

        let message_hardlink = dir.join("message-hardlink");
        fs::hard_link(&message, &message_hardlink).unwrap();
        let error = sign_file(
            &secret,
            &message_hardlink,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("único link"), "erro inesperado: {error}");
        assert!(!signature.exists());
    }

    #[test]
    fn signer_recusa_symlink_em_ancestral_e_swap_do_ancestral() {
        let _serial = action_lock();
        let dir = temp_dir("ancestral-input");
        let real = dir.join("real");
        create_private_dir(&real);
        let secret = real.join("k.key");
        keygen("t", &secret, &real.join("k.pub")).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let message = real.join("index");
        write_message(&message, b"conteudo\n");
        let through_link = dir.join("through-link");
        symlink(&real, &through_link).unwrap();
        let signature = dir.join("out.minisig");
        assert!(sign_file(
            &through_link.join("k.key"),
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .is_err());
        assert!(sign_file(
            &secret,
            &through_link.join("index"),
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .is_err());
        assert!(!signature.exists());

        let replacement = dir.join("replacement-parent");
        create_private_dir(&replacement);
        write_message(replacement.join("index"), b"conteudo\n");
        let old = dir.join("old-parent");
        let signature = dir.join("swap.minisig");
        let action = test_action("after_ready", "swap", &real, &replacement, Some(&old));
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(error.contains("inode"), "erro inesperado: {error}");
        assert!(!signature.exists());

        fs::create_dir(old.join("nested-output")).unwrap();
        let linked_output = dir.join("linked-output");
        symlink(&old, &linked_output).unwrap();
        let error = sign_file(
            &old.join("k.key"),
            &old.join("index"),
            &linked_output.join("nested-output/bad.minisig"),
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("ancestral"), "erro inesperado: {error}");
    }

    #[test]
    fn assinatura_e_publica_usam_create_new_sem_seguir_symlink() {
        let dir = temp_dir("links-saida");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("t", &secret, &public).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let message = dir.join("index");
        write_message(&message, b"conteudo\n");
        let victim = dir.join("vitima");
        fs::write(&victim, b"intacto").unwrap();
        let signature = dir.join("index.minisig");
        symlink(&victim, &signature).unwrap();
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("assinatura final"),
            "erro inesperado: {error}"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"intacto");
        assert!(fs::symlink_metadata(&signature)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(
            fs::read_dir(&dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".minitrue-")),
            "falha deixou staging da assinatura"
        );

        let other = temp_dir("publica-dangling");
        let secret = other.join("nova.key");
        let public = other.join("nova.pub");
        symlink(other.join("nao-existe"), &public).unwrap();
        assert!(keygen("t", &secret, &public).is_err());
        assert!(!secret.exists(), "falha da pública deixou chave secreta");
        assert!(fs::symlink_metadata(&public)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn troca_do_pathname_da_mensagem_antes_da_promocao_e_detectada() {
        let _serial = action_lock();
        let dir = temp_dir("swap-mensagem");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let message = dir.join("index");
        let replacement = dir.join("replacement");
        let backup = dir.join("original");
        let signature = dir.join("index.minisig");
        write_message(&message, b"conteudo assinado\n");
        write_message(&replacement, b"conteudo trocado\n");

        let action = test_action("after_ready", "swap", &message, &replacement, Some(&backup));
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(error.contains("inode"), "erro inesperado: {error}");
        assert!(!signature.exists());

        // O retry pertence à nova mensagem: REQUEST divergente descarta apenas
        // os nomes conhecidos do stage antigo e publica a assinatura nova.
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();
        let text = fs::read_to_string(&signature).unwrap();
        let sig = minisign_verify::Signature::decode(&text).unwrap();
        minisign_verify::PublicKey::from_base64(&expected)
            .unwrap()
            .verify(b"conteudo trocado\n", &sig, false)
            .unwrap();
    }

    #[test]
    fn nlink_inserido_durante_leitura_ou_staging_e_detectado() {
        let _serial = action_lock();
        let dir = temp_dir("nlink-race");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let message = dir.join("index");
        let signature = dir.join("index.minisig");
        write_message(&message, b"conteudo\n");

        let secret_link = dir.join("secret-race-link");
        let action = test_action("after_secret_read", "hardlink", &secret, &secret_link, None);
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(error.contains("mudou"), "erro inesperado: {error}");
        fs::remove_file(&secret_link).unwrap();

        let message_link = dir.join("message-race-link");
        let action = test_action(
            "after_message_read",
            "hardlink",
            &message,
            &message_link,
            None,
        );
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(error.contains("mudou"), "erro inesperado: {error}");
        fs::remove_file(&message_link).unwrap();

        let stage = signer_stage_path(&signature);
        let staged_payload = stage.join(SIGN_PAYLOAD);
        let extra_link = stage.join("extra-hardlink");
        let action = test_action(
            "after_payload",
            "hardlink",
            &staged_payload,
            &extra_link,
            None,
        );
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(error.contains("um link"), "erro inesperado: {error}");
        assert!(!signature.exists());
        fs::remove_file(extra_link).unwrap();
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();
    }

    #[test]
    fn stage_e_parent_substituidos_sao_detectados() {
        let _serial = action_lock();
        let dir = temp_dir("swap-stage-parent");
        let secret = dir.join("k.key");
        keygen("t", &secret, &dir.join("k.pub")).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let message = dir.join("index");
        write_message(&message, b"conteudo\n");

        let signature = dir.join("stage.minisig");
        let stage = signer_stage_path(&signature);
        let old_stage = dir.join("old-stage");
        let action = test_action("after_ready", "replace-stage", &stage, &old_stage, None);
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(error.contains("staging"), "erro inesperado: {error}");
        assert!(!signature.exists());
        fs::remove_dir(&stage).unwrap();
        fs::remove_dir_all(&old_stage).unwrap();

        let output = dir.join("output");
        create_private_dir(&output);
        let old_output = dir.join("old-output");
        let signature = output.join("parent.minisig");
        let action = test_action("after_ready", "replace-stage", &output, &old_output, None);
        let error = sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        drop(action);
        assert!(
            error.contains("diretório de saída"),
            "erro inesperado: {error}"
        );
        assert!(!signature.exists());
        fs::remove_dir(&output).unwrap();
        fs::remove_dir_all(&old_output).unwrap();

        let untrusted = dir.join("world-writable");
        fs::create_dir(&untrusted).unwrap();
        fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777)).unwrap();
        let error = sign_file(
            &secret,
            &message,
            &untrusted.join("bad.minisig"),
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("não permitir escrita"),
            "erro inesperado: {error}"
        );
    }

    #[test]
    fn signer_recupera_todos_os_killpoints_e_fault_pos_rename() {
        let base = temp_dir("kill-sign");
        let secret = base.join("k.key");
        keygen("t", &secret, &base.join("k.pub")).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let killpoints = [
            "after_mkdir",
            "after_owner",
            "after_request",
            "after_payload",
            "after_ready_stage_sync",
            "after_ready_parent_sync",
            "after_ready",
            "after_rename",
            "after_parent_sync",
            "after_stage_sync",
            "after_stage_cleanup",
        ];
        for (index, point) in killpoints.iter().enumerate() {
            let dir = base.join(format!("case-{index}"));
            create_private_dir(&dir);
            write_message(dir.join("index"), format!("mensagem {index}\n"));
            let status = run_ignored_child(
                "signer_crash_child",
                &[
                    ("MINITRUE_SIGN_CHILD_DIR", dir.to_str().unwrap()),
                    ("MINITRUE_SIGN_CHILD_SECRET", secret.to_str().unwrap()),
                    ("MINITRUE_SIGN_KILLPOINT", point),
                ],
            );
            assert_eq!(status.signal(), Some(libc::SIGKILL), "killpoint {point}");
            sign_file(
                &secret,
                &dir.join("index"),
                &dir.join("index.minisig"),
                None,
                None,
                Some(&expected),
                None,
            )
            .unwrap_or_else(|error| panic!("retry de {point}: {error}"));
            assert!(!signer_stage_path(&dir.join("index.minisig")).exists());
        }

        let dir = base.join("fault-after-rename");
        create_private_dir(&dir);
        write_message(dir.join("index"), b"fault\n");
        let status = run_ignored_child(
            "signer_crash_child",
            &[
                ("MINITRUE_SIGN_CHILD_DIR", dir.to_str().unwrap()),
                ("MINITRUE_SIGN_CHILD_SECRET", secret.to_str().unwrap()),
                ("MINITRUE_SIGN_FAULTPOINT", "after_rename"),
            ],
        );
        assert!(!status.success());
        sign_file(
            &secret,
            &dir.join("index"),
            &dir.join("index.minisig"),
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();
    }

    #[test]
    fn keygen_recupera_todos_os_killpoints() {
        let base = temp_dir("kill-keygen");
        let killpoints = [
            "after_mkdir",
            "keygen_after_owner",
            "keygen_after_secret",
            "keygen_after_public",
            "keygen_after_request",
            "keygen_after_ready_stage_sync",
            "keygen_after_ready_parent_sync",
            "keygen_after_ready",
            "keygen_after_secret_rename",
            "keygen_after_secret_parent_sync",
            "keygen_after_secret_stage_sync",
            "keygen_after_public_rename",
            "keygen_after_public_parent_sync",
            "keygen_after_public_stage_sync",
            "keygen_after_stage_cleanup",
        ];
        for (index, point) in killpoints.iter().enumerate() {
            let dir = base.join(format!("case-{index}"));
            create_private_dir(&dir);
            let status = run_ignored_child(
                "keygen_crash_child",
                &[
                    ("MINITRUE_SIGN_CHILD_DIR", dir.to_str().unwrap()),
                    ("MINITRUE_SIGN_KILLPOINT", point),
                ],
            );
            assert_eq!(status.signal(), Some(libc::SIGKILL), "killpoint {point}");
            let secret = dir.join("channel.key");
            let public = dir.join("channel.pub");
            keygen("crash", &secret, &public)
                .unwrap_or_else(|error| panic!("retry de {point}: {error}"));
            let key = SecretKey::load(&secret).unwrap();
            assert_eq!(
                fs::read_to_string(&public).unwrap(),
                keygen_public_text(&key)
            );
            assert_eq!(fs::metadata(&secret).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&public).unwrap().mode() & 0o777, 0o644);
            assert!(fs::read_dir(&dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".minitrue-keygen-")));
        }
    }

    #[test]
    fn assinatura_publicada_e_regular_duravel_e_modo_0644() {
        let dir = temp_dir("publicacao");
        let secret = dir.join("k.key");
        let public = dir.join("k.pub");
        keygen("t", &secret, &public).unwrap();
        let expected = SecretKey::load(&secret).unwrap().public_line();
        let message = dir.join("index");
        write_message(&message, vec![b'x'; 2 * 1024 * 1024 + 17]);
        let signature = dir.join("index.minisig");
        sign_file(
            &secret,
            &message,
            &signature,
            None,
            None,
            Some(&expected),
            None,
        )
        .unwrap();
        let metadata = fs::symlink_metadata(&signature).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
        assert!(fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".minitrue-")));
    }
}
