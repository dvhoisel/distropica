pub mod install;
pub mod media;
pub mod profile;
pub mod tree;

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub fn ensure_real_file(path: &Path, what: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("{what} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "{what} precisa ser arquivo regular real: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn ensure_real_dir(path: &Path, what: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("{what} {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("{what} precisa ser diretório real: {}", path.display());
    }
    Ok(())
}

/// Publica um arquivo temporário no mesmo filesystem sem jamais substituir
/// um nome que apareceu depois do preflight.
pub fn publish_noreplace(temporary: &Path, output: &Path) -> Result<()> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    use rustix::io::Errno;

    match renameat_with(CWD, temporary, CWD, output, RenameFlags::NOREPLACE) {
        Ok(()) => return Ok(()),
        Err(Errno::NOSYS | Errno::INVAL) => {}
        Err(error) => {
            return Err(std::io::Error::from(error)).with_context(|| {
                format!(
                    "não publiquei {} sem substituir uma saída existente",
                    output.display()
                )
            });
        }
    }

    std::fs::hard_link(temporary, output).with_context(|| {
        format!(
            "não publiquei {} sem substituir uma saída existente",
            output.display()
        )
    })?;
    let _ = std::fs::remove_file(temporary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publicacao_nao_substitui_nome_existente() {
        let directory = tempfile::tempdir().unwrap();
        let temporary = directory.path().join("temporary");
        let output = directory.path().join("output");
        std::fs::write(&temporary, b"novo").unwrap();
        std::fs::write(&output, b"existente").unwrap();
        assert!(publish_noreplace(&temporary, &output).is_err());
        assert_eq!(std::fs::read(output).unwrap(), b"existente");
        assert_eq!(std::fs::read(temporary).unwrap(), b"novo");
    }
}
