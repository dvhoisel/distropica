use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 50_000;

#[derive(Default)]
struct TreeBudget {
    bytes: u64,
    entries: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreePolicy {
    Newspeak,
    Overlay,
    Cache,
}

#[derive(Clone, Debug)]
pub enum EntryKind {
    Directory,
    Regular(Vec<u8>),
    Symlink(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub relative: PathBuf,
    pub mode: u32,
    pub kind: EntryKind,
}

fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

fn require_utf8_path(path: &Path, what: &str) -> Result<()> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("{what} contém caminho não UTF-8: {path:?}"))?;
    Ok(())
}

fn validate_relative(path: &Path, what: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        bail!("{what} contém caminho não canônico: {path:?}");
    }
    require_utf8_path(path, what)?;
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
    if !matches!(top, "etc" | "root" | "home" | "srv") {
        return false;
    }
    !(path == Path::new("etc/minitrue") || path.starts_with("etc/minitrue/"))
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

fn validate_symlink(relative: &Path, target: &Path, policy: TreePolicy) -> Result<()> {
    if policy != TreePolicy::Overlay {
        bail!(
            "{} contém symlink; somente overlays administrativos aceitam links",
            relative.display()
        );
    }
    if target.as_os_str().is_empty() || target.as_os_str().as_bytes().contains(&0) {
        bail!("symlink vazio/inválido em {}", relative.display());
    }
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let normalized = normalized_target(parent, target).ok_or_else(|| {
        anyhow::anyhow!(
            "symlink {} -> {} escapa do overlay",
            relative.display(),
            target.display()
        )
    })?;
    if !overlay_path_allowed(&normalized) {
        bail!(
            "symlink {} -> {} alcança namespace não administrativo",
            relative.display(),
            target.display()
        );
    }
    target
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("alvo de symlink não UTF-8 em {}", relative.display()))?;
    Ok(())
}

fn collect_dir(
    root: &Path,
    dir: &Path,
    policy: TreePolicy,
    out: &mut Vec<Entry>,
    budget: &mut TreeBudget,
) -> Result<()> {
    let mut children = fs::read_dir(dir)
        .with_context(|| format!("não li {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });
    for child in children {
        budget.entries += 1;
        if budget.entries > MAX_TREE_ENTRIES {
            bail!(
                "árvore excede o limite de desenvolvimento de {MAX_TREE_ENTRIES} entradas; streaming é gate de release"
            );
        }
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("entrada escapou da raiz da árvore"))?
            .to_path_buf();
        validate_relative(&relative, "árvore")?;
        if policy == TreePolicy::Overlay && !overlay_path_allowed(&relative) {
            bail!(
                "overlay só pode escrever em /etc, /root, /home ou /srv: /{}",
                relative.display()
            );
        }
        let metadata = fs::symlink_metadata(&path)?;
        let mode = metadata.permissions().mode() & 0o7777;
        let kind = if metadata.file_type().is_dir() {
            EntryKind::Directory
        } else if metadata.file_type().is_file() {
            if metadata.nlink() > 1 {
                bail!("hardlink não permitido na árvore: {}", path.display());
            }
            let remaining = MAX_TREE_BYTES.saturating_sub(budget.bytes);
            let mut content = Vec::new();
            fs::File::open(&path)?
                .take(remaining + 1)
                .read_to_end(&mut content)?;
            if content.len() as u64 > remaining {
                bail!(
                    "árvore excede o limite de desenvolvimento de {} MiB; streaming é gate de release",
                    MAX_TREE_BYTES / 1024 / 1024
                );
            }
            budget.bytes += content.len() as u64;
            EntryKind::Regular(content)
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            validate_symlink(&relative, &target, policy)?;
            EntryKind::Symlink(target)
        } else {
            bail!(
                "arquivo especial não permitido na árvore: {}",
                path.display()
            );
        };
        out.push(Entry {
            relative: relative.clone(),
            mode,
            kind,
        });
        if metadata.file_type().is_dir() {
            collect_dir(root, &path, policy, out, budget)?;
        }
    }
    Ok(())
}

pub fn collect(root: &Path, policy: TreePolicy) -> Result<Vec<Entry>> {
    crate::ensure_real_dir(root, "árvore")?;
    let mut entries = Vec::new();
    collect_dir(root, root, policy, &mut entries, &mut TreeBudget::default())?;
    entries.sort_by(|left, right| path_bytes(&left.relative).cmp(path_bytes(&right.relative)));
    Ok(entries)
}

pub fn pack(entries: &[Entry], epoch: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        builder.mode(tar::HeaderMode::Deterministic);
        for entry in entries {
            let mut header = tar::Header::new_gnu();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(epoch);
            header.set_mode(entry.mode);
            match &entry.kind {
                EntryKind::Directory => {
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_size(0);
                    header.set_cksum();
                    builder.append_data(&mut header, &entry.relative, std::io::empty())?;
                }
                EntryKind::Regular(content) => {
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(content.len() as u64);
                    header.set_cksum();
                    builder.append_data(&mut header, &entry.relative, Cursor::new(content))?;
                }
                EntryKind::Symlink(target) => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_link_name(target)?;
                    header.set_cksum();
                    builder.append_data(&mut header, &entry.relative, std::io::empty())?;
                }
            }
        }
        builder.finish()?;
    }
    Ok(bytes)
}

pub fn snapshot(root: &Path, policy: TreePolicy, epoch: u64) -> Result<(Vec<Entry>, Vec<u8>)> {
    let entries = collect(root, policy)?;
    let archive = pack(&entries, epoch)?;
    Ok((entries, archive))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn overlay_recusa_namespace_e_link_que_escapa() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("usr/bin")).unwrap();
        fs::write(temp.path().join("usr/bin/x"), b"x").unwrap();
        assert!(collect(temp.path(), TreePolicy::Overlay).is_err());

        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("etc/a")).unwrap();
        symlink("../../../usr/bin", temp.path().join("etc/a/x")).unwrap();
        assert!(collect(temp.path(), TreePolicy::Overlay).is_err());
    }

    #[test]
    fn pack_e_deterministico_e_sensivel() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("etc")).unwrap();
        fs::write(temp.path().join("etc/z"), b"um").unwrap();
        let (_, first) = snapshot(temp.path(), TreePolicy::Overlay, 10).unwrap();
        let (_, second) = snapshot(temp.path(), TreePolicy::Overlay, 10).unwrap();
        assert_eq!(first, second);
        fs::write(temp.path().join("etc/z"), b"dois").unwrap();
        let (_, changed) = snapshot(temp.path(), TreePolicy::Overlay, 10).unwrap();
        assert_ne!(first, changed);
    }
}
