use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CACHE_TREE_BYTES: u64 = 384 * 1024 * 1024;
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

pub(crate) const fn max_tree_bytes(policy: TreePolicy) -> u64 {
    match policy {
        TreePolicy::Cache => MAX_CACHE_TREE_BYTES,
        TreePolicy::Newspeak | TreePolicy::Overlay => MAX_TREE_BYTES,
    }
}

#[derive(Clone, Debug)]
pub enum EntryKind {
    Directory,
    Regular(Vec<u8>),
    Symlink(PathBuf),
}

fn valid_channel_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name.len() <= 128
        && !name.contains("..")
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'_' | b'.' | b'-')
        })
}

/// O cache de uma mídia online não carrega payloads: ele fecha somente as
/// configurações e os índices assinados necessários para o primeiro
/// `rectify --only-binary`. Os artefatos continuam vindo da URL HTTPS pinada.
///
/// Layout aceito:
/// `channel-config/<nome>` e
/// `channels/<nome>/{index,index.minisig}`.
pub fn validate_channel_bootstrap(entries: &[Entry]) -> Result<()> {
    let mut configs = BTreeSet::new();
    let mut snapshots: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in entries {
        let parts = entry
            .relative
            .iter()
            .map(|part| {
                part.to_str()
                    .ok_or_else(|| anyhow::anyhow!("bootstrap de canal contém nome não UTF-8"))
            })
            .collect::<Result<Vec<_>>>()?;
        match (parts.as_slice(), &entry.kind) {
            (["channel-config"], EntryKind::Directory) | (["channels"], EntryKind::Directory) => {}
            (["channel-config", name], EntryKind::Regular(_)) if valid_channel_name(name) => {
                configs.insert((*name).to_string());
            }
            (["channels", name], EntryKind::Directory) if valid_channel_name(name) => {
                snapshots.entry((*name).to_string()).or_default();
            }
            (["channels", name, file], EntryKind::Regular(_))
                if valid_channel_name(name) && matches!(*file, "index" | "index.minisig") =>
            {
                snapshots
                    .entry((*name).to_string())
                    .or_default()
                    .insert((*file).to_string());
            }
            _ => bail!(
                "cache online contém entrada fora do bootstrap de canal: {}",
                entry.relative.display()
            ),
        }
    }
    if configs.is_empty() {
        bail!("cache online não contém channel-config/<nome>");
    }
    for name in &configs {
        let files = snapshots.get(name).ok_or_else(|| {
            anyhow::anyhow!("canal {name} não possui snapshot assinado no cache online")
        })?;
        if files.len() != 2 || !files.contains("index") || !files.contains("index.minisig") {
            bail!("canal {name} exige channels/{name}/index e index.minisig");
        }
    }
    if snapshots.keys().any(|name| !configs.contains(name)) {
        bail!("cache online contém snapshot sem configuração correspondente");
    }
    Ok(())
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

fn canonical_mode(relative: &Path, policy: TreePolicy, metadata: &fs::Metadata) -> u32 {
    if metadata.file_type().is_dir() {
        if policy == TreePolicy::Overlay && relative == Path::new("root") {
            0o700
        } else {
            0o755
        }
    } else if metadata.file_type().is_symlink() {
        0o777
    } else if policy == TreePolicy::Overlay
        && matches!(
            relative.to_str(),
            Some("etc/shadow" | "etc/gshadow" | "etc/shadow-" | "etc/gshadow-")
        )
    {
        0o600
    } else if policy == TreePolicy::Cache {
        0o644
    } else if metadata.permissions().mode() & 0o111 != 0 {
        0o755
    } else {
        0o644
    }
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
        // Git só preserva o bit executável, não modos completos. O snapshot
        // precisa portanto derivar modos canônicos da política e do caminho,
        // em vez de herdar umask/chmod do checkout ou do cache local.
        let mode = canonical_mode(&relative, policy, &metadata);
        let kind = if metadata.file_type().is_dir() {
            EntryKind::Directory
        } else if metadata.file_type().is_file() {
            if metadata.nlink() > 1 {
                bail!("hardlink não permitido na árvore: {}", path.display());
            }
            let limit = max_tree_bytes(policy);
            let remaining = limit.saturating_sub(budget.bytes);
            let mut content = Vec::new();
            fs::File::open(&path)?
                .take(remaining + 1)
                .read_to_end(&mut content)?;
            if content.len() as u64 > remaining {
                bail!(
                    "árvore excede o limite de desenvolvimento de {} MiB; streaming é gate de release",
                    limit / 1024 / 1024
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn cache_tem_orcamento_maior_sem_relaxar_newspeak_e_overlay() {
        assert_eq!(max_tree_bytes(TreePolicy::Newspeak), 128 * 1024 * 1024);
        assert_eq!(max_tree_bytes(TreePolicy::Overlay), 128 * 1024 * 1024);
        assert_eq!(max_tree_bytes(TreePolicy::Cache), 384 * 1024 * 1024);
    }

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

    #[test]
    fn modos_sao_canonicos_e_independentes_do_umask_do_checkout() {
        let temp = tempfile::tempdir().unwrap();
        let etc = temp.path().join("etc");
        let root = temp.path().join("root");
        fs::create_dir(&etc).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(etc.join("shadow"), b"root:!:0:0:99999:7:::\n").unwrap();
        fs::write(etc.join("motd"), b"oi\n").unwrap();
        fs::write(root.join("login.sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o775)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(etc.join("shadow"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(etc.join("motd"), fs::Permissions::from_mode(0o664)).unwrap();
        fs::set_permissions(root.join("login.sh"), fs::Permissions::from_mode(0o775)).unwrap();

        let (entries, first) = snapshot(temp.path(), TreePolicy::Overlay, 10).unwrap();
        let modes = entries
            .iter()
            .map(|entry| (entry.relative.to_string_lossy().into_owned(), entry.mode))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(modes["etc"], 0o755);
        assert_eq!(modes["etc/shadow"], 0o600);
        assert_eq!(modes["etc/motd"], 0o644);
        assert_eq!(modes["root"], 0o700);
        assert_eq!(modes["root/login.sh"], 0o755);

        fs::set_permissions(&etc, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o711)).unwrap();
        fs::set_permissions(etc.join("shadow"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(etc.join("motd"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(root.join("login.sh"), fs::Permissions::from_mode(0o711)).unwrap();
        let (_, second) = snapshot(temp.path(), TreePolicy::Overlay, 10).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn bootstrap_online_aceita_so_config_e_indice_assinado_pareados() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("channel-config")).unwrap();
        fs::create_dir_all(temp.path().join("channels/oficial")).unwrap();
        fs::write(temp.path().join("channel-config/oficial"), b"config\n").unwrap();
        fs::write(temp.path().join("channels/oficial/index"), b"index\n").unwrap();
        fs::write(
            temp.path().join("channels/oficial/index.minisig"),
            b"assinatura\n",
        )
        .unwrap();
        let entries = collect(temp.path(), TreePolicy::Cache).unwrap();
        validate_channel_bootstrap(&entries).unwrap();

        fs::write(temp.path().join("objeto-binario"), b"payload").unwrap();
        let entries = collect(temp.path(), TreePolicy::Cache).unwrap();
        assert!(validate_channel_bootstrap(&entries).is_err());
        fs::remove_file(temp.path().join("objeto-binario")).unwrap();

        fs::remove_file(temp.path().join("channels/oficial/index.minisig")).unwrap();
        let entries = collect(temp.path(), TreePolicy::Cache).unwrap();
        assert!(validate_channel_bootstrap(&entries).is_err());
    }
}
