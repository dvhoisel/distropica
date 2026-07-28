//! Empacotamento determinístico do artefato (SPEC-0010 §4).
//!
//! O `STAGE` byte-a-byte idêntico (mesma receita + mesmo toolchain) só vira
//! um *hash* idêntico se o empacotamento também for determinístico. Este
//! módulo tara uma árvore normalizando tudo que é volátil:
//!
//! - ordem por nome armazenado (byte-a-byte), independente do `readdir`;
//! - `mtime` = `EPOCH` fixo (não o mtime do arquivo no disco);
//! - `uid`/`gid` = 0, `uname`/`gname` vazios (não o dono que buildou);
//! - modo mascarado em `07777`; nada de atime/ctime/device.
//!
//! O minitrue é o empacotador canônico da corroboração (SPEC-0010 §5): quem
//! confere a reprodutibilidade tara com o mesmo código, então o formato só
//! precisa ser determinístico — não idêntico ao do GNU tar.
//!
//! **Formato canônico v1** ([`PACK_FORMAT`]), versionado por um cabeçalho PAX
//! global no início do tar. O empacotador:
//!
//! - **transmite** cada arquivo (`arquivo → tar → hasher/saída`) sem carregar
//!   o conteúdo inteiro nem o tar inteiro em RAM;
//! - preserva **nomes não-UTF-8** (opera em bytes, não em `String`);
//! - preserva **hardlinks** (2ª+ ocorrência do mesmo inode vira entrada Link);
//! - **recusa** arquivos especiais (FIFO, dispositivo, socket) — não são
//!   empacotáveis e não deveriam estar num `STAGE`.
//!
//! **Formato v2** ([`PACK_FORMAT_XATTR`]) acrescenta **xattrs**, e com eles as
//! *file capabilities* (`security.capability`) de que dependem `dumpcap`,
//! `nmap` e `mtr-packet`. Sem isso um `setcap` no `STAGE` era descartado em
//! silêncio: o binário chegava sem privilégio e o `verify` nem reclamava,
//! porque a claim prendia só modo e conteúdo.
//!
//! A versão declarada no cabeçalho global é a **mínima exigida do leitor**,
//! não a do escritor: uma árvore sem xattr continua sendo empacotada como v1,
//! byte a byte. Isso é deliberado — subir a versão em todo artefato mudaria o
//! hash de todos eles e invalidaria de uma vez o `REPROCORR` pinado e cada
//! `ARTIFACT_HASH` já gravado, sem que nada de fato tivesse mudado.
//!
//! Limitações que **permanecem** (um `STAGE` que dependa delas empacota sem
//! elas): **ACLs** (`system.posix_acl_*`), `trusted.*` e **sparse files**.
//! Como dois builds da mesma receita produzem a mesma árvore, a ausência não
//! quebra o determinismo — mas quebra a fidelidade, e está registrada.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};

/// Versão do formato canônico de empacotamento, gravada num cabeçalho PAX
/// global no início do tar (`DISTROPICA.pack=<versão>`). Muda sempre que a
/// normalização muda — um leitor pode recusar versão que não entende.
pub const PACK_FORMAT: &str = "1";

/// Versão mínima de leitor exigida por um tar que carrega xattr.
pub const PACK_FORMAT_XATTR: &str = "2";

/// Prefixo do registro PAX por entrada: `DISTROPICA.xattr.<nome>=<hex>`. O
/// valor vai em hexadecimal porque xattr é binário — `security.capability` é
/// uma struct, e pode conter `\n`, que arruinaria um registro PAX cru.
pub const XATTR_PAX_PREFIX: &str = "DISTROPICA.xattr.";

/// Nome fixo da entrada de cabeçalho PAX por arquivo. Constante de propósito:
/// evita o mecanismo de nome longo do GNU tar e mantém o tar determinístico.
pub const XATTR_HEADER_NAME: &str = "pax_extended_header";

/// Namespaces capturados. `system.*` (ACL) e `trusted.*` ficam de fora: o
/// primeiro é a limitação ainda registrada, o segundo exige privilégio para
/// ser lido e viraria empacotamento que falha por acidente de permissão.
const XATTR_NAMESPACES: [&str; 2] = ["security.", "user."];

/// Tetos de sanidade — árvore legítima fica ordens de grandeza abaixo.
const MAX_XATTRS_PER_FILE: usize = 64;
const MAX_XATTR_VALUE: usize = 65_536;

pub(crate) fn format_supported(value: &str) -> bool {
    value == PACK_FORMAT || value == PACK_FORMAT_XATTR
}

struct Entry {
    abs: PathBuf,
    /// Nome armazenado no tar, em bytes crus (preserva não-UTF-8).
    name: Vec<u8>,
    md: Metadata,
    /// xattrs capturados, ordenados por nome (ordem canônica).
    xattrs: Vec<(String, Vec<u8>)>,
}

/// `Write` que computa o sha256 de tudo que passa e repassa a um inner.
/// Permite tarar em streaming enquanto se calcula o hash — o inner pode ser
/// um arquivo (grava o artefato) ou [`io::sink`] (só o hash).
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.inner.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Tara `dir` de forma determinística, escrevendo o tar em `out` (streaming)
/// e devolvendo o **sha256 hex** do tar. `epoch` é o `SOURCE_DATE_EPOCH` do
/// build, gravado como `mtime` de toda entrada.
///
/// Passe [`io::sink`] como `out` para só computar o hash sem gravar nada.
pub fn pack_deterministic<W: Write>(dir: &Path, epoch: u64, out: W) -> Result<String> {
    let mut entries: Vec<Entry> = Vec::new();
    collect(dir, dir, &mut entries)?;
    // Ordem canônica: pelo nome armazenado, byte-a-byte. Como o nome de um
    // diretório é prefixo do de seus filhos, o pai sempre precede o conteúdo.
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let hw = HashingWriter {
        inner: out,
        hasher: Sha256::new(),
    };
    let mut b = Builder::new(hw);
    b.follow_symlinks(false);

    // A versão é a mínima exigida do leitor: sem xattr na árvore, o tar
    // continua idêntico ao que o v1 produzia.
    let version = if entries.iter().any(|e| !e.xattrs.is_empty()) {
        PACK_FORMAT_XATTR
    } else {
        PACK_FORMAT
    };
    write_global_version(&mut b, version)?;

    // (dev, ino) -> primeiro nome armazenado, para preservar hardlinks.
    let mut seen: HashMap<(u64, u64), Vec<u8>> = HashMap::new();

    for e in &entries {
        let ft = e.md.file_type();
        let name = tar_path(&e.name);
        let mode = e.md.permissions().mode() & 0o7777;
        if !e.xattrs.is_empty() {
            write_xattr_header(&mut b, &e.xattrs)?;
        }
        let mut h = Header::new_gnu();
        h.set_mtime(epoch);
        h.set_uid(0);
        h.set_gid(0);
        let _ = h.set_username("");
        let _ = h.set_groupname("");

        if ft.is_dir() {
            h.set_entry_type(EntryType::Directory);
            h.set_mode(mode);
            h.set_size(0);
            b.append_data(&mut h, &name, io::empty())?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&e.abs)?;
            h.set_entry_type(EntryType::Symlink);
            h.set_mode(0o777);
            h.set_size(0);
            b.append_link(&mut h, &name, &target)?;
        } else if ft.is_file() {
            // Hardlink: a 2ª+ ocorrência do mesmo inode vira entrada Link,
            // apontando para o primeiro nome — preserva o vínculo e não
            // duplica o conteúdo.
            if e.md.nlink() > 1 {
                let key = (e.md.dev(), e.md.ino());
                if let Some(first) = seen.get(&key) {
                    let firstp = tar_path(first);
                    h.set_entry_type(EntryType::Link);
                    h.set_mode(mode);
                    h.set_size(0);
                    b.append_link(&mut h, &name, &firstp)?;
                    continue;
                }
                seen.insert(key, e.name.clone());
            }
            h.set_entry_type(EntryType::Regular);
            h.set_mode(mode);
            h.set_size(e.md.len());
            // Streaming: o arquivo é lido em blocos direto para o tar/hasher.
            // `.take(size)` casa o fluxo com o tamanho declarado no header
            // (defesa contra o arquivo crescer entre o stat e a leitura).
            let f = File::open(&e.abs)?.take(e.md.len());
            b.append_data(&mut h, &name, f)?;
        } else {
            // FIFO, dispositivo (bloco/char), socket — não empacotáveis.
            bail!(
                "pack: {} é um arquivo especial (FIFO/dispositivo/socket), \
                 não empacotável",
                e.abs.display()
            );
        }
    }

    let mut hw = b.into_inner()?;
    // `out` pode ser um BufWriter de arquivo: propaga inclusive falha tardia
    // de flush, em vez de deixá-la para o Drop (que não consegue devolver erro).
    hw.flush()?;
    Ok(hex::encode(hw.hasher.finalize()))
}

/// Hash do tar canônico de uma árvore vazia. Claims `d:` de mundo B só são
/// emitidas para diretórios vazios; calcular esta constante pelo mesmo writer
/// evita reler do filesystem um diretório recém-instalado e elimina a janela
/// entre a imagem selada e o manifesto.
pub fn empty_deterministic_hash() -> Result<String> {
    let hw = HashingWriter {
        inner: io::sink(),
        hasher: Sha256::new(),
    };
    let mut builder = Builder::new(hw);
    builder.follow_symlinks(false);
    write_global_version(&mut builder, PACK_FORMAT)?;
    let mut hw = builder.into_inner()?;
    hw.flush()?;
    Ok(hex::encode(hw.hasher.finalize()))
}

/// Coleta recursiva de todas as entradas sob `base`, operando em bytes.
fn collect(base: &Path, dir: &Path, out: &mut Vec<Entry>) -> Result<()> {
    for de in fs::read_dir(dir)? {
        let de = de?;
        let abs = de.path();
        let md = fs::symlink_metadata(&abs)?;
        let name = abs
            .strip_prefix(base)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        let is_dir = md.file_type().is_dir();
        // Symlink não carrega capability e seus xattrs não são instaláveis;
        // ler só de regular e diretório mantém o escopo honesto.
        let xattrs = if md.file_type().is_symlink() {
            Vec::new()
        } else {
            read_xattrs(&abs)?
        };
        out.push(Entry {
            abs: abs.clone(),
            name,
            md,
            xattrs,
        });
        if is_dir {
            collect(base, &abs, out)?;
        }
    }
    Ok(())
}

/// Nome de bytes → `Path` (Unix: `Path` é bytes, então preserva não-UTF-8).
fn tar_path(name: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(name))
}

/// Lê os xattrs de `path` **sem seguir symlink**, já ordenados por nome.
///
/// Sistema de arquivos sem suporte a xattr não é erro de empacotamento:
/// devolve vazio. O que seria erro é o oposto — ter xattr e não capturá-lo.
pub fn read_xattrs(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let size = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if size <= 0 {
        return match io::Error::last_os_error().raw_os_error() {
            _ if size == 0 => Ok(Vec::new()),
            Some(libc::ENOTSUP) | Some(libc::ENODATA) => Ok(Vec::new()),
            _ => Err(anyhow::anyhow!(
                "pack: não listei xattr de {}: {}",
                path.display(),
                io::Error::last_os_error()
            )),
        };
    }
    let mut names = vec![0u8; size as usize];
    let got = unsafe {
        libc::llistxattr(
            c_path.as_ptr(),
            names.as_mut_ptr().cast(),
            names.len() as libc::size_t,
        )
    };
    if got < 0 {
        bail!(
            "pack: não listei xattr de {}: {}",
            path.display(),
            io::Error::last_os_error()
        );
    }
    names.truncate(got as usize);

    let mut out = Vec::new();
    for raw in names.split(|byte| *byte == 0).filter(|n| !n.is_empty()) {
        let name = std::str::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("pack: xattr de nome não-UTF-8 em {}", path.display()))?;
        if !XATTR_NAMESPACES.iter().any(|ns| name.starts_with(ns)) {
            continue;
        }
        if out.len() >= MAX_XATTRS_PER_FILE {
            bail!(
                "pack: {} declara mais de {MAX_XATTRS_PER_FILE} xattrs",
                path.display()
            );
        }
        let c_name = std::ffi::CString::new(name)?;
        let len =
            unsafe { libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            bail!(
                "pack: não li o xattr {name} de {}: {}",
                path.display(),
                io::Error::last_os_error()
            );
        }
        if len as usize > MAX_XATTR_VALUE {
            bail!("pack: xattr {name} de {} tem {len} bytes", path.display());
        }
        let mut value = vec![0u8; len as usize];
        let got = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len() as libc::size_t,
            )
        };
        if got < 0 {
            bail!(
                "pack: não li o xattr {name} de {}: {}",
                path.display(),
                io::Error::last_os_error()
            );
        }
        value.truncate(got as usize);
        out.push((name.to_string(), value));
    }
    // Ordem canônica por nome: o `readdir` do xattr não é ordenado.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Escreve o cabeçalho PAX **por entrada** com os xattrs da próxima entrada.
fn write_xattr_header<W: Write>(b: &mut Builder<W>, xattrs: &[(String, Vec<u8>)]) -> Result<()> {
    let mut data = Vec::new();
    for (name, value) in xattrs {
        data.extend_from_slice(&pax_record(
            &format!("{XATTR_PAX_PREFIX}{name}"),
            &hex::encode(value),
        ));
    }
    let mut h = Header::new_gnu();
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mode(0);
    h.set_size(data.len() as u64);
    h.set_entry_type(EntryType::new(b'x'));
    b.append_data(&mut h, XATTR_HEADER_NAME, &data[..])?;
    Ok(())
}

/// Escreve o cabeçalho PAX **global** que versiona o formato. Fixo e
/// determinístico (mtime/uid/gid/modo zerados; conteúdo constante).
fn write_global_version<W: Write>(b: &mut Builder<W>, version: &str) -> Result<()> {
    let data = pax_record("DISTROPICA.pack", version);
    let mut h = Header::new_gnu();
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mode(0);
    h.set_size(data.len() as u64);
    h.set_entry_type(EntryType::new(b'g')); // 'g' = PAX global extended header
    b.append_data(&mut h, "pax_global_header", &data[..])?;
    Ok(())
}

/// Monta um registro PAX `"<len> <chave>=<valor>\n"`, onde `<len>` é o
/// comprimento total do registro (incluindo os próprios dígitos de `<len>`).
fn pax_record(key: &str, val: &str) -> Vec<u8> {
    let body = format!(" {key}={val}\n");
    let mut size = body.len() + 1;
    loop {
        let rec = format!("{size}{body}");
        if rec.len() == size {
            return rec.into_bytes();
        }
        size = rec.len();
    }
}

/// Lê `SOURCE_DATE_EPOCH` do ambiente ou usa o default fixo do projeto
/// (2024-01-01 UTC), o mesmo que o minitrue injeta em `install_source`.
pub fn epoch_from_env() -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1_704_067_200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tar::Archive;

    const EPOCH: u64 = 1_704_067_200;
    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Diretório temporário autolimpante (sem depender do crate `tempfile`).
    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            let n = CNT.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("mt-pack-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hash(dir: &Path) -> String {
        pack_deterministic(dir, EPOCH, io::sink()).unwrap()
    }
    fn bytes(dir: &Path) -> Vec<u8> {
        let mut v = Vec::new();
        pack_deterministic(dir, EPOCH, &mut v).unwrap();
        v
    }

    /// Põe um xattr `user.*` no caminho, devolvendo `false` se o sistema de
    /// arquivos não suporta — aí o teste não tem o que provar.
    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let c_name = std::ffi::CString::new(name).unwrap();
        let rc = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr().cast(),
                value.len() as libc::size_t,
                0,
            )
        };
        rc == 0
    }

    /// O xattr entra no hash e sobe a versão declarada — mas **só** quando
    /// existe. É o que preserva todo `REPROCORR`/`ARTIFACT_HASH` já gravado.
    #[test]
    fn xattr_muda_o_hash_e_a_versao_declarada() {
        let t = Tmp::new();
        fs::create_dir_all(t.path().join("usr/bin")).unwrap();
        let alvo = t.path().join("usr/bin/dumpcap");
        fs::write(&alvo, b"captura").unwrap();

        let sem_xattr = hash(t.path());
        let tar_sem = bytes(t.path());
        assert!(
            find_subslice(&tar_sem, b"DISTROPICA.pack=1\n").is_some(),
            "árvore sem xattr deveria continuar declarando v1"
        );

        if !set_xattr(&alvo, "user.distropica.teste", b"valor") {
            eprintln!("sistema de arquivos sem xattr; teste sem o que provar");
            return;
        }

        let com_xattr = hash(t.path());
        assert_ne!(
            sem_xattr, com_xattr,
            "xattr precisa entrar no hash: sem isso um setcap sumiria em silêncio"
        );
        let tar_com = bytes(t.path());
        assert!(find_subslice(&tar_com, b"DISTROPICA.pack=2\n").is_some());
        assert!(find_subslice(&tar_com, b"DISTROPICA.xattr.user.distropica.teste=").is_some());
        // Hex, não bytes crus: valor binário não pode quebrar o registro PAX.
        assert!(find_subslice(&tar_com, &hex::encode(b"valor").into_bytes()).is_some());

        // E continua determinístico.
        assert_eq!(com_xattr, hash(t.path()));
        assert_eq!(tar_com, bytes(t.path()));
    }

    #[test]
    fn xattr_lido_em_ordem_canonica() {
        let t = Tmp::new();
        let alvo = t.path().join("arquivo");
        fs::write(&alvo, b"x").unwrap();
        if !set_xattr(&alvo, "user.zzz", b"\x00\x01\n\xff") || !set_xattr(&alvo, "user.aaa", b"a") {
            eprintln!("sistema de arquivos sem xattr; teste sem o que provar");
            return;
        }
        let lidos = read_xattrs(&alvo).unwrap();
        let nomes: Vec<&str> = lidos.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(nomes, ["user.aaa", "user.zzz"], "ordem tem de ser canônica");
        // Valor binário com `\n` e byte nulo sobrevive intacto.
        assert_eq!(lidos[1].1, b"\x00\x01\n\xff");
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Uma árvore de teto com os casos difíceis.
    fn make_tree(root: &Path) {
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/tool"), b"#!/bin/sh\necho oi\n").unwrap();
        fs::set_permissions(root.join("usr/bin/tool"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("tool", root.join("usr/bin/tool-link")).unwrap();
        fs::create_dir_all(root.join("usr/share")).unwrap();
        fs::write(root.join("usr/share/data.txt"), b"plain\n").unwrap();
    }

    /// Entradas (tipo, nome, modo) do tar, pulando o cabeçalho global.
    fn read_entries(buf: &[u8]) -> Vec<(u8, Vec<u8>, u32)> {
        let mut ar = Archive::new(buf);
        let mut out = Vec::new();
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let h = e.header();
            let t = h.entry_type().as_byte();
            if t == b'g' {
                continue; // cabeçalho global de versão
            }
            out.push((t, e.path_bytes().into_owned(), h.mode().unwrap()));
        }
        out
    }

    #[test]
    fn deterministico_bit_a_bit() {
        let t = Tmp::new();
        make_tree(t.path());
        assert_eq!(bytes(t.path()), bytes(t.path()));
    }

    #[test]
    fn propaga_falha_de_flush_da_saida() {
        struct FlushFails;
        impl io::Write for FlushFails {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush tardio"))
            }
        }

        let t = Tmp::new();
        fs::write(t.path().join("arquivo"), b"conteudo").unwrap();
        let error = pack_deterministic(t.path(), EPOCH, FlushFails).unwrap_err();
        assert!(error.to_string().contains("flush tardio"));
    }

    #[test]
    fn independe_da_ordem_de_criacao() {
        let a = Tmp::new();
        let b = Tmp::new();
        // mesma árvore lógica, arquivos criados em ordens diferentes
        fs::create_dir_all(a.path().join("d")).unwrap();
        fs::write(a.path().join("d/z"), b"z").unwrap();
        fs::write(a.path().join("d/a"), b"a").unwrap();
        fs::write(a.path().join("m"), b"m").unwrap();
        fs::write(b.path().join("m"), b"m").unwrap();
        fs::create_dir_all(b.path().join("d")).unwrap();
        fs::write(b.path().join("d/a"), b"a").unwrap();
        fs::write(b.path().join("d/z"), b"z").unwrap();
        assert_eq!(hash(a.path()), hash(b.path()));
    }

    #[test]
    fn metadados_normalizados() {
        let t = Tmp::new();
        make_tree(t.path());
        let buf = bytes(t.path());
        let mut ar = Archive::new(&buf[..]);
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let h = e.header();
            if h.entry_type().as_byte() == b'g' {
                continue;
            }
            assert_eq!(h.mtime().unwrap(), EPOCH, "mtime não normalizado");
            assert_eq!(h.uid().unwrap(), 0, "uid não zerado");
            assert_eq!(h.gid().unwrap(), 0, "gid não zerado");
        }
    }

    #[test]
    fn primeira_entrada_e_versao_global() {
        let t = Tmp::new();
        make_tree(t.path());
        let b = bytes(t.path());
        let mut ar = Archive::new(&b[..]);
        let mut it = ar.entries().unwrap();
        let mut first = it.next().unwrap().unwrap();
        assert_eq!(first.header().entry_type().as_byte(), b'g');
        let mut s = String::new();
        first.read_to_string(&mut s).unwrap();
        assert!(
            s.contains(&format!("DISTROPICA.pack={PACK_FORMAT}")),
            "sem versão: {s:?}"
        );
    }

    #[test]
    fn ordem_dir_arquivo_symlink() {
        let t = Tmp::new();
        make_tree(t.path());
        let es = read_entries(&bytes(t.path()));
        // ordenado por nome, byte-a-byte
        let mut names: Vec<_> = es.iter().map(|(_, n, _)| n.clone()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "entradas fora de ordem");
        // modo e tipos preservados
        let tool = es.iter().find(|(_, n, _)| n == b"usr/bin/tool").unwrap();
        assert_eq!(tool.0, b'0');
        assert_eq!(tool.2, 0o755);
        let link = es
            .iter()
            .find(|(_, n, _)| n == b"usr/bin/tool-link")
            .unwrap();
        assert_eq!(link.0, b'2', "symlink deveria ser typeflag 2");
        names.dedup();
    }

    #[test]
    fn caminho_longo_gnu_longname() {
        let t = Tmp::new();
        let deep = t.path().join(
            "usr/lib/gcc/x86_64-distropica-linux-gnu/15.3.0/plugin/include/config/i386/sub/deeper",
        );
        fs::create_dir_all(&deep).unwrap();
        let long = deep.join("um-header-de-nome-bem-comprido.h");
        fs::write(&long, b"x\n").unwrap();
        let rel = long
            .strip_prefix(t.path())
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        assert!(
            rel.len() > 100,
            "caminho de teste precisa passar de 100 bytes"
        );
        let es = read_entries(&bytes(t.path()));
        assert!(
            es.iter().any(|(_, n, _)| *n == rel),
            "LongName não round-trippou"
        );
    }

    #[test]
    fn nome_nao_utf8() {
        let t = Tmp::new();
        let name = OsStr::from_bytes(b"esquisito-\xff-nome");
        fs::write(t.path().join(name), b"x").unwrap();
        // não deve entrar em pânico nem alterar o nome
        let es = read_entries(&bytes(t.path()));
        assert!(es
            .iter()
            .any(|(_, n, _)| n.as_slice() == b"esquisito-\xff-nome"));
    }

    #[test]
    fn hardlink_preservado() {
        let t = Tmp::new();
        fs::write(t.path().join("a"), b"conteudo").unwrap();
        fs::hard_link(t.path().join("a"), t.path().join("b")).unwrap();
        let es = read_entries(&bytes(t.path()));
        // "a" < "b": "a" é regular, "b" é hardlink (typeflag '1') para "a"
        let a = es.iter().find(|(_, n, _)| n == b"a").unwrap();
        let b = es.iter().find(|(_, n, _)| n == b"b").unwrap();
        assert_eq!(a.0, b'0', "a deveria ser regular");
        assert_eq!(b.0, b'1', "b deveria ser hardlink");
    }

    #[test]
    fn recusa_arquivo_especial() {
        let t = Tmp::new();
        // socket é um arquivo especial fácil de criar sem libc extra
        let _l = std::os::unix::net::UnixListener::bind(t.path().join("sock")).unwrap();
        let err = pack_deterministic(t.path(), EPOCH, io::sink()).unwrap_err();
        assert!(
            err.to_string().contains("especial"),
            "erro inesperado: {err}"
        );
    }
}
