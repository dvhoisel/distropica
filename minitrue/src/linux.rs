//! Fronteiras pequenas para syscalls Linux ausentes de alguns bindings libc.

use std::ffi::CStr;
use std::io;

/// Executa `renameat2(2)` sem depender de a libc do alvo declarar o wrapper.
///
/// O crate `libc` expõe `renameat2` para glibc, mas não para musl. O número da
/// syscall e `syscall(2)` existem nos dois alvos Linux que o Minitrue suporta.
/// Manter os flags como argumento preserva tanto `RENAME_EXCHANGE` quanto
/// `RENAME_NOREPLACE`; em erro, `syscall` devolve -1 e deixa `errno` disponível
/// para `last_os_error`.
pub(crate) fn renameat2(
    old_dirfd: libc::c_int,
    old_path: &CStr,
    new_dirfd: libc::c_int,
    new_path: &CStr,
    flags: libc::c_uint,
) -> io::Result<()> {
    // SAFETY: os caminhos são C strings vivas durante a chamada; os demais
    // argumentos têm os tipos do ABI Linux de renameat2 e não há retenção de
    // ponteiros pelo kernel.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_dirfd,
            old_path.as_ptr(),
            new_dirfd,
            new_path.as_ptr(),
            flags,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "minitrue-renameat2-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn c_path(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    #[test]
    fn exchange_chega_ao_kernel_com_o_flag_correto() {
        let root = temp_dir("exchange");
        let left = root.join("left");
        let right = root.join("right");
        fs::create_dir(&left).unwrap();
        fs::create_dir(&right).unwrap();
        fs::write(left.join("era-left"), b"left").unwrap();
        fs::write(right.join("era-right"), b"right").unwrap();

        renameat2(
            libc::AT_FDCWD,
            &c_path(&left),
            libc::AT_FDCWD,
            &c_path(&right),
            libc::RENAME_EXCHANGE,
        )
        .unwrap();

        assert_eq!(fs::read(left.join("era-right")).unwrap(), b"right");
        assert_eq!(fs::read(right.join("era-left")).unwrap(), b"left");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn noreplace_preserva_errno_e_nao_substitui_o_destino() {
        let root = temp_dir("noreplace");
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"destination").unwrap();

        let error = renameat2(
            libc::AT_FDCWD,
            &c_path(&source),
            libc::AT_FDCWD,
            &c_path(&destination),
            libc::RENAME_NOREPLACE,
        )
        .unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(fs::read(&source).unwrap(), b"source");
        assert_eq!(fs::read(&destination).unwrap(), b"destination");
        fs::remove_dir_all(root).unwrap();
    }
}
