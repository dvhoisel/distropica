use crate::recipe::Recipe;
use crate::{fail, Ctx};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static DOWNLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_PINNED_OBJECT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Busca um objeto arbitrário já preso por SHA-256 (índice de canal, mundo B).
/// Compartilha o cache content-addressed das fontes, mas nunca aceita TOFU.
pub fn ensure_pinned_url(ctx: &Ctx, url: &str, want: &str) -> Result<PathBuf> {
    let canonical = want.len() == 64
        && want
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !canonical {
        return fail(2, format!("sha256 não canônico para {url}"));
    }
    let cache = ctx.cache_dir();
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    fs::create_dir_all(&cache)?;
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    let destination = cache.join(want);
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if metadata.file_type().is_file()
            && metadata.len() <= MAX_PINNED_OBJECT_BYTES
            && sha256_file(&destination)? == want
        {
            return Ok(destination);
        }
    }
    if ctx.offline {
        return fail(
            6,
            format!("--offline e artefato ausente/inválido no cache: {url}"),
        );
    }
    let (temporary, obtained) =
        download_temp_bounded(url, &cache, "canal", 0, Some(MAX_PINNED_OBJECT_BYTES))?;
    if obtained != want {
        let _ = fs::remove_file(&temporary);
        return fail(
            3,
            format!(
                "crimestop: artefato de canal diverge do índice assinado\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {obtained}"
            ),
        );
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(destination)
}

/// Garante cada artefato de SRC no cache, verificado por hash e — quando a
/// receita pina — por assinatura. Devolve (caminho, sha256) na ordem de SRC.
pub fn ensure_artifacts(ctx: &Ctx, r: &Recipe) -> Result<Vec<(PathBuf, String)>> {
    let cache = ctx.cache_dir();
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    fs::create_dir_all(&cache)?;
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;

    let mut got: Vec<(PathBuf, String)> = Vec::new();
    let mut tofu_hashes = Vec::new();
    for (i, url) in r.srcs.iter().enumerate() {
        let want = r.sha256.get(i).cloned();
        let (path, hash) = match want {
            Some(want) => {
                let dst = cache.join(&want);
                if fs::symlink_metadata(&dst).is_ok_and(|metadata| metadata.file_type().is_file())
                    && sha256_file(&dst)? == want
                {
                    (dst, want)
                } else {
                    if ctx.offline {
                        return fail(6, format!("--offline e artefato ausente do cache: {url}"));
                    }
                    let (tmp, hash) = download_temp(url, &cache, "baixando", i)?;
                    if hash != want {
                        let _ = fs::remove_file(&tmp);
                        return fail(
                            3,
                            format!(
                                "crimestop: o artefato diverge do registro oficial\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {hash}"
                            ),
                        );
                    }
                    if let Err(error) = fs::rename(&tmp, &dst) {
                        let _ = fs::remove_file(&tmp);
                        return Err(error.into());
                    }
                    (dst, want)
                }
            }
            None => {
                // TOFU explícito: primeira busca vira o registro, com alarde.
                if ctx.offline {
                    return fail(6, "--offline não combina com --tofu");
                }
                let (tmp, hash) = download_temp(url, &cache, "tofu", i)?;
                let dst = cache.join(&hash);
                match fs::symlink_metadata(&dst) {
                    Ok(metadata)
                        if metadata.file_type().is_file() && sha256_file(&dst)? == hash =>
                    {
                        fs::remove_file(&tmp)?;
                    }
                    Ok(_) => {
                        fs::remove_file(&tmp)?;
                        return fail(
                            3,
                            format!("cache TOFU contém objeto incompatível em {}", dst.display()),
                        );
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        if let Err(error) = fs::rename(&tmp, &dst) {
                            let _ = fs::remove_file(&tmp);
                            return Err(error.into());
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
                tofu_hashes.push(hash.clone());
                (dst, hash)
            }
        };
        eprintln!("  {} — sha256 confere", short(url));
        got.push((path, hash));
    }

    verify_signatures(ctx, r, &got)?;
    if !tofu_hashes.is_empty() {
        eprintln!("minitrue: AVISO TOFU — confiança na primeira vista. Cole na receita:");
        eprintln!("SHA256={}", tofu_hashes.join(" "));
    }
    Ok(got)
}

fn signature_cache_name(artifact_hash: &str, key: &str, url: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"minitrue-signature-cache-v1\0");
    for value in [artifact_hash, key, url] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("{}.minisig", hex::encode(hash.finalize()))
}

fn open_regular_nofollow(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(anyhow::anyhow!("{} não é arquivo regular", path.display()));
    }
    Ok(file)
}

fn verify_signature_file(
    artifact: &Path,
    signature: &Path,
    pk: &minisign_verify::PublicKey,
    sig_url: &str,
) -> Result<()> {
    let mut data = Vec::new();
    open_regular_nofollow(artifact)?.read_to_end(&mut data)?;
    let mut signature_bytes = Vec::new();
    open_regular_nofollow(signature)?.read_to_end(&mut signature_bytes)?;
    let sig_txt = String::from_utf8(signature_bytes).map_err(|_| crate::Fail {
        code: 7,
        msg: "assinatura não é UTF-8".into(),
    })?;
    let sig = minisign_verify::Signature::decode(&sig_txt).map_err(|e| crate::Fail {
        code: 7,
        msg: format!("assinatura mal-formada: {e}"),
    })?;
    pk.verify(&data, &sig, false).map_err(|e| {
        crate::Fail {
            code: 7,
            msg: format!(
                "crimestop (assinatura): {} não é de quem diz ser ({e})",
                short(sig_url)
            ),
        }
        .into()
    })
}

fn verify_signatures(ctx: &Ctx, r: &Recipe, artifacts: &[(PathBuf, String)]) -> Result<()> {
    if r.sigsums.is_some() {
        return fail(1, format!("{}: SIGSUMS chega no Marco 0.2", r.name));
    }
    let Some(key) = &r.sigkey else { return Ok(()) };
    if key.contains(".asc") || key.contains("BEGIN") {
        return fail(
            1,
            format!("{}: verificação OpenPGP chega no Marco 0.2", r.name),
        );
    }
    if r.sig.is_empty() {
        return fail(2, format!("{}: SIGKEY sem SIG", r.name));
    }
    let pk = minisign_verify::PublicKey::from_base64(key).map_err(|e| crate::Fail {
        code: 2,
        msg: format!("{}: SIGKEY inválida ({e})", r.name),
    })?;

    for (i, sig_url) in r.sig.iter().enumerate() {
        let (artifact, hash) = &artifacts[i];
        let sig_path = ctx
            .cache_dir()
            .join(signature_cache_name(hash, key, sig_url));
        let signature_cached =
            fs::symlink_metadata(&sig_path).is_ok_and(|metadata| metadata.file_type().is_file());
        let cached_valid =
            signature_cached && verify_signature_file(artifact, &sig_path, &pk, sig_url).is_ok();
        if !cached_valid {
            if ctx.offline {
                return fail(
                    7,
                    format!("--offline e assinatura ausente/inválida no cache: {sig_url}"),
                );
            }
            if fs::symlink_metadata(&sig_path).is_ok_and(|metadata| metadata.file_type().is_dir()) {
                return fail(
                    7,
                    format!(
                        "cache de assinatura não é arquivo regular: {}",
                        sig_path.display()
                    ),
                );
            }
            let (tmp, _) = download_temp(sig_url, &ctx.cache_dir(), "sig", i)?;
            if let Err(error) = verify_signature_file(artifact, &tmp, &pk, sig_url) {
                let _ = fs::remove_file(&tmp);
                return Err(error);
            }
            if let Err(error) = fs::rename(&tmp, &sig_path) {
                let _ = fs::remove_file(&tmp);
                return Err(error.into());
            }
        }
        eprintln!("  assinatura minisign confere — veio de quem sempre veio");
    }
    Ok(())
}

fn download_temp(url: &str, cache: &Path, label: &str, index: usize) -> Result<(PathBuf, String)> {
    download_temp_bounded(url, cache, label, index, None)
}

fn download_temp_bounded(
    url: &str,
    cache: &Path,
    label: &str,
    index: usize,
    max_bytes: Option<u64>,
) -> Result<(PathBuf, String)> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut reserved = None;
    for _ in 0..128 {
        let serial = DOWNLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = cache.join(format!(
            ".{label}-{}-{nanos:x}-{index}-{serial}",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                reserved = Some((path, file));
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (dst, mut file) = reserved.ok_or_else(|| {
        anyhow::anyhow!(
            "não consegui reservar temporário seguro em {}",
            cache.display()
        )
    })?;
    eprintln!("  buscando {}", short(url));
    let result = (|| -> Result<String> {
        let resp = ureq::get(url).call().map_err(|e| crate::Fail {
            code: 6,
            msg: format!("rede falhou em {url}: {e}"),
        })?;
        if max_bytes.is_some_and(|limit| {
            resp.header("Content-Length")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|declared| declared > limit)
        }) {
            return fail(6, format!("resposta de {url} excede o limite permitido"));
        }
        let mut reader = resp.into_reader();
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| crate::Fail {
                code: 6,
                msg: format!("rede caiu no meio de {url}: {e}"),
            })?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as u64)
                .ok_or_else(|| anyhow::anyhow!("download excedeu u64"))?;
            if max_bytes.is_some_and(|limit| total > limit) {
                return fail(6, format!("resposta de {url} excede o limite permitido"));
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }
        file.flush()?;
        Ok(hex::encode(hasher.finalize()))
    })();
    match result {
        Ok(hash) => Ok((dst, hash)),
        Err(error) => {
            let _ = fs::remove_file(&dst);
            Err(error)
        }
    }
}

pub fn sha256_file(p: &Path) -> Result<String> {
    let mut f = open_regular_nofollow(p)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn short(url: &str) -> &str {
    url.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn cache_de_assinatura_prende_hash_chave_e_url() {
        let base = signature_cache_name("hash", "key-a", "https://a/sig");
        assert_ne!(
            base,
            signature_cache_name("outro", "key-a", "https://a/sig")
        );
        assert_ne!(base, signature_cache_name("hash", "key-b", "https://a/sig"));
        assert_ne!(base, signature_cache_name("hash", "key-a", "https://b/sig"));
    }

    #[test]
    fn leitura_de_cache_recusa_symlink_e_fifo_sem_bloquear() {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-fetch-leaf-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let victim = root.join("victim");
        fs::write(&victim, b"dados").unwrap();
        let link = root.join("link");
        symlink(&victim, &link).unwrap();
        assert!(open_regular_nofollow(&link).is_err());

        let fifo = root.join("fifo");
        let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString válida, modo ordinário.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(open_regular_nofollow(&fifo).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
