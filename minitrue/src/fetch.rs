use crate::recipe::Recipe;
use crate::{fail, Ctx};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

/// Garante cada artefato de SRC no cache, verificado por hash e — quando a
/// receita pina — por assinatura. Devolve (caminho, sha256) na ordem de SRC.
pub fn ensure_artifacts(ctx: &Ctx, r: &Recipe) -> Result<Vec<(PathBuf, String)>> {
    let cache = ctx.cache_dir();
    fs::create_dir_all(&cache)?;

    let mut got: Vec<(PathBuf, String)> = Vec::new();
    for (i, url) in r.srcs.iter().enumerate() {
        let want = r.sha256.get(i).cloned();
        let (path, hash) = match want {
            Some(want) => {
                let dst = cache.join(&want);
                if dst.is_file() && sha256_file(&dst)? == want {
                    (dst, want)
                } else {
                    if ctx.offline {
                        return fail(6, format!("--offline e artefato ausente do cache: {url}"));
                    }
                    let tmp = cache.join(format!(".baixando-{}-{i}", std::process::id()));
                    let hash = download(url, &tmp)?;
                    if hash != want {
                        let _ = fs::remove_file(&tmp);
                        return fail(
                            3,
                            format!(
                                "crimestop: o artefato diverge do registro oficial\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {hash}"
                            ),
                        );
                    }
                    fs::rename(&tmp, &dst)?;
                    (dst, want)
                }
            }
            None => {
                // TOFU explícito: primeira busca vira o registro, com alarde.
                if ctx.offline {
                    return fail(6, "--offline não combina com --tofu");
                }
                let tmp = cache.join(format!(".tofu-{}-{i}", std::process::id()));
                let hash = download(url, &tmp)?;
                let dst = cache.join(&hash);
                let _ = fs::rename(&tmp, &dst);
                eprintln!("minitrue: AVISO TOFU — confiança na primeira vista. Cole na receita:");
                eprintln!("SHA256={hash}");
                (dst, hash)
            }
        };
        eprintln!("  {} — sha256 confere", short(url));
        got.push((path, hash));
    }

    verify_signatures(ctx, r, &got)?;
    Ok(got)
}

fn verify_signatures(ctx: &Ctx, r: &Recipe, artifacts: &[(PathBuf, String)]) -> Result<()> {
    if r.sigsums.is_some() {
        return fail(1, format!("{}: SIGSUMS chega no Marco 0.2", r.name));
    }
    let Some(key) = &r.sigkey else { return Ok(()) };
    if key.contains(".asc") || key.contains("BEGIN") {
        return fail(1, format!("{}: verificação OpenPGP chega no Marco 0.2", r.name));
    }
    if r.sig.is_empty() {
        return fail(2, format!("{}: SIGKEY sem SIG", r.name));
    }
    let pk = minisign_verify::PublicKey::from_base64(key)
        .map_err(|e| crate::Fail { code: 2, msg: format!("{}: SIGKEY inválida ({e})", r.name) })?;

    for (i, sig_url) in r.sig.iter().enumerate() {
        let (artifact, hash) = &artifacts[i];
        let sig_path = ctx.cache_dir().join(format!("{hash}.minisig"));
        if !sig_path.is_file() {
            if ctx.offline {
                return fail(6, format!("--offline e assinatura ausente do cache: {sig_url}"));
            }
            let tmp = ctx.cache_dir().join(format!(".sig-{}-{i}", std::process::id()));
            download(sig_url, &tmp)?;
            fs::rename(&tmp, &sig_path)?;
        }
        let data = fs::read(artifact)?;
        let sig_txt = fs::read_to_string(&sig_path)?;
        let sig = minisign_verify::Signature::decode(&sig_txt)
            .map_err(|e| crate::Fail { code: 7, msg: format!("assinatura mal-formada: {e}") })?;
        match pk.verify(&data, &sig, false) {
            Ok(()) => eprintln!("  assinatura minisign confere — veio de quem sempre veio"),
            Err(e) => {
                return fail(
                    7,
                    format!("crimestop (assinatura): {} não é de quem diz ser ({e})", short(sig_url)),
                )
            }
        }
    }
    Ok(())
}

fn download(url: &str, dst: &PathBuf) -> Result<String> {
    eprintln!("  buscando {}", short(url));
    let resp = ureq::get(url).call().map_err(|e| crate::Fail {
        code: 6,
        msg: format!("rede falhou em {url}: {e}"),
    })?;
    let mut reader = resp.into_reader();
    let mut file = fs::File::create(dst)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| crate::Fail { code: 6, msg: format!("rede caiu no meio de {url}: {e}") })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha256_file(p: &PathBuf) -> Result<String> {
    let mut f = fs::File::open(p)?;
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
    url.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or(url)
}
