//! Empacotamento determinístico do artefato (SPEC-0010 §4).
//!
//! O `STAGE` byte-a-byte idêntico (mesma receita + mesmo toolchain) só vira
//! um *hash* idêntico se o empacotamento também for determinístico. Este
//! módulo tara uma árvore normalizando tudo que é volátil:
//!
//! - ordem por nome armazenado (byte-a-byte; diretórios com `/` ao final),
//!   independente da ordem de `readdir` do filesystem;
//! - `mtime` = `EPOCH` fixo (não o mtime do arquivo no disco);
//! - `uid`/`gid` = 0, `uname`/`gname` vazios (não o dono que buildou);
//! - modo mascarado em `07777`; nada de atime/ctime/device.
//!
//! O minitrue é o empacotador canônico da corroboração (SPEC-0010 §5): quem
//! confere a reprodutibilidade tara com o mesmo código, então o formato só
//! precisa ser determinístico — não idêntico ao do GNU tar.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};

/// Tara `dir` de forma determinística. Devolve `(bytes_do_tar, sha256_hex)`.
///
/// `epoch` é o `SOURCE_DATE_EPOCH` do build (mesmo valor que o minitrue
/// injeta em `build()`), gravado como `mtime` de toda entrada.
pub fn pack_deterministic(dir: &Path, epoch: u64) -> Result<(Vec<u8>, String)> {
    let mut entries: Vec<(PathBuf, String, fs::FileType)> = Vec::new();
    collect(dir, dir, &mut entries)?;
    // Ordem canônica: pelo nome armazenado. Como o nome de um diretório é
    // prefixo do de seus filhos, o pai sempre precede o conteúdo.
    entries.sort_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));

    let mut b = Builder::new(Vec::new());
    for (abs, name, ft) in &entries {
        let md = fs::symlink_metadata(abs)?;
        let mode = md.permissions().mode() & 0o7777;
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
            b.append_data(&mut h, name, std::io::empty())?;
        } else if ft.is_symlink() {
            let target = fs::read_link(abs)?;
            h.set_entry_type(EntryType::Symlink);
            h.set_mode(0o777);
            h.set_size(0);
            b.append_link(&mut h, name, &target)?;
        } else {
            let data = fs::read(abs)?;
            h.set_entry_type(EntryType::Regular);
            h.set_mode(mode);
            h.set_size(data.len() as u64);
            b.append_data(&mut h, name, &data[..])?;
        }
    }

    let bytes = b.into_inner()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok((bytes, hex::encode(hasher.finalize())))
}

/// Coleta recursiva de todas as entradas sob `base`. Diretórios recebem `/`
/// no fim do nome armazenado (convenção tar, e desempata a ordenação).
fn collect(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, String, fs::FileType)>) -> Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let path = e.path();
        let ft = fs::symlink_metadata(&path)?.file_type();
        let mut rel = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
        if ft.is_dir() {
            rel.push('/');
            out.push((path.clone(), rel, ft));
            collect(base, &path, out)?;
        } else {
            out.push((path, rel, ft));
        }
    }
    Ok(())
}

/// Lê `SOURCE_DATE_EPOCH` do ambiente ou usa o default fixo do projeto
/// (2024-01-01 UTC), o mesmo que o minitrue injeta em `install_source`.
pub fn epoch_from_env() -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1_704_067_200)
}
