use crate::openpgp::{
    cache_object_name, inspect_rejected_dsa_sha1, pinned_cert_from_keyring_subset,
    pinned_primary_cert_subset, verify_clearsigned_checksums, verify_detached,
    verify_detached_checksums, verify_legacy_dsa_waiver, CacheObjectKind, PinnedCert,
    SignatureClock, MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES, MAX_SIGNED_CHECKSUM_BYTES,
};
use crate::openpgp_schema::{
    parse_unsafe_signature_waiver, IndexedArtifactSignature, SignaturePlan, UnsafeSignatureWaiver,
    MAX_UNSAFE_SIGNATURE_WAIVER_BYTES,
};
use crate::recipe::Recipe;
use crate::{fail, Ctx};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static DOWNLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_PINNED_OBJECT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    dev: u64,
    ino: u64,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileSnapshot {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn content_identity_eq(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.nlink == other.nlink
            && self.len == other.len
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
    }
}

struct ArtifactFile {
    path: PathBuf,
    hash: String,
    file: fs::File,
    snapshot: FileSnapshot,
}

impl ArtifactFile {
    fn open(path: PathBuf) -> Result<Self> {
        let mut file = open_regular_nofollow(&path, MAX_PINNED_OBJECT_BYTES, "artefato no cache")?;
        let (hash, snapshot) =
            sha256_fd_stable(&mut file, MAX_PINNED_OBJECT_BYTES, "artefato no cache")?;
        let result = Self {
            path,
            hash,
            file,
            snapshot,
        };
        result.ensure_stable()?;
        Ok(result)
    }

    fn rewind(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn ensure_stable(&self) -> Result<()> {
        let observed = self.file.metadata()?;
        let observed_snapshot =
            validate_regular_metadata(&observed, MAX_PINNED_OBJECT_BYTES, "artefato no cache")?;
        if observed_snapshot != self.snapshot {
            anyhow::bail!(
                "artefato mudou durante hash/verificação: {}",
                self.path.display()
            );
        }
        let named = fs::symlink_metadata(&self.path)
            .with_context(|| format!("artefato deixou de existir: {}", self.path.display()))?;
        let named_snapshot =
            validate_regular_metadata(&named, MAX_PINNED_OBJECT_BYTES, "artefato no cache")?;
        if named_snapshot != self.snapshot {
            anyhow::bail!(
                "pathname do artefato foi trocado durante a verificação: {}",
                self.path.display()
            );
        }
        Ok(())
    }

    /// `rename(2)` pode alterar somente o ctime do inode. Depois da publicação
    /// controlada, aceita essa transição uma vez, preservando todos os campos
    /// que identificam/congelam o conteúdo, e estabelece o novo snapshot para
    /// a verificação criptográfica subsequente.
    fn renamed_to(&mut self, path: PathBuf) -> Result<()> {
        let observed = self.file.metadata()?;
        let next =
            validate_regular_metadata(&observed, MAX_PINNED_OBJECT_BYTES, "artefato publicado")?;
        if !self.snapshot.content_identity_eq(next) {
            anyhow::bail!("artefato mudou durante publicação em {}", path.display());
        }
        self.path = path;
        self.snapshot = next;
        self.ensure_stable()
    }

    fn rehash_same_fd(&mut self) -> Result<()> {
        let (hash, snapshot) = sha256_fd_stable(
            &mut self.file,
            MAX_PINNED_OBJECT_BYTES,
            "artefato autenticado por SIGSUMS",
        )?;
        if hash != self.hash || snapshot != self.snapshot {
            anyhow::bail!(
                "artefato mudou antes de conferir SIGSUMS: {}",
                self.path.display()
            );
        }
        Ok(())
    }
}

struct AuxiliaryObject {
    path: PathBuf,
    bytes: Vec<u8>,
    file: fs::File,
    snapshot: FileSnapshot,
    max_bytes: usize,
    label: String,
    temporary: bool,
}

impl AuxiliaryObject {
    fn open(path: PathBuf, max_bytes: usize, label: &str, temporary: bool) -> Result<Self> {
        let mut file = open_regular_nofollow(&path, max_bytes as u64, label)?;
        let (bytes, snapshot) = read_small_fd_stable(&mut file, max_bytes, label)?;
        let result = Self {
            path,
            bytes,
            file,
            snapshot,
            max_bytes,
            label: label.to_string(),
            temporary,
        };
        result.ensure_stable()?;
        Ok(result)
    }

    fn ensure_stable(&self) -> Result<()> {
        let observed =
            validate_regular_metadata(&self.file.metadata()?, self.max_bytes as u64, &self.label)?;
        if observed != self.snapshot {
            anyhow::bail!("{} mudou durante a verificação", self.label);
        }
        let named = fs::symlink_metadata(&self.path).with_context(|| {
            format!("{} deixou de existir: {}", self.label, self.path.display())
        })?;
        let named = validate_regular_metadata(&named, self.max_bytes as u64, &self.label)?;
        if named != self.snapshot {
            anyhow::bail!(
                "pathname de {} foi trocado durante a verificação: {}",
                self.label,
                self.path.display()
            );
        }
        Ok(())
    }

    fn reread(&mut self) -> Result<Vec<u8>> {
        let (bytes, snapshot) = read_small_fd_stable(&mut self.file, self.max_bytes, &self.label)?;
        if snapshot != self.snapshot || bytes != self.bytes {
            anyhow::bail!("{} mudou depois da verificação", self.label);
        }
        self.ensure_stable()?;
        Ok(bytes)
    }

    /// Aceita somente a mudança de ctime causada pelo rename controlado e
    /// prova que o nome publicado ainda aponta para o mesmo fd lido/verificado.
    fn renamed_to(&mut self, path: PathBuf) -> Result<()> {
        let next =
            validate_regular_metadata(&self.file.metadata()?, self.max_bytes as u64, &self.label)?;
        if !self.snapshot.content_identity_eq(next) {
            anyhow::bail!("{} mudou durante a publicação", self.label);
        }
        let named = fs::symlink_metadata(&path)?;
        let named = validate_regular_metadata(&named, self.max_bytes as u64, &self.label)?;
        if named != next {
            anyhow::bail!(
                "pathname publicado de {} não é o mesmo inode verificado",
                self.label
            );
        }
        self.path = path;
        self.snapshot = next;
        self.temporary = false;
        self.ensure_stable()
    }
}

impl Drop for AuxiliaryObject {
    fn drop(&mut self) {
        if self.temporary {
            if let Some(cache) = self.path.parent() {
                let _ = remove_if_same_snapshot(cache, &self.path, self.snapshot);
            }
        }
    }
}

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
    if ctx.offline {
        if !cache.is_dir() {
            return fail(6, "--offline e cache do minitrue ausente");
        }
    } else {
        fs::create_dir_all(&cache)?;
    }
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    let _cache_directory = trusted_cache_directory(&cache, !ctx.offline)?;
    let destination = cache.join(want);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            let artifact =
                ArtifactFile::open(destination.clone()).map_err(|error| crate::Fail {
                    code: if ctx.offline { 6 } else { 3 },
                    msg: format!(
                        "crimestop: objeto pinado inválido em {}: {error:#}",
                        destination.display()
                    ),
                })?;
            if artifact.hash != want {
                return fail(
                    3,
                    format!(
                        "crimestop: objeto pinado diverge\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {}",
                        artifact.hash
                    ),
                );
            }
            return Ok(destination);
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if ctx.offline {
        return fail(
            6,
            format!("--offline e artefato ausente/inválido no cache: {url}"),
        );
    }
    let (temporary, transport_hash) =
        download_temp_bounded(url, &cache, "canal", 0, Some(MAX_PINNED_OBJECT_BYTES))?;
    let mut candidate = match ArtifactFile::open(temporary.clone()) {
        Ok(candidate) => candidate,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if transport_hash != candidate.hash || candidate.hash != want {
        let obtained = candidate.hash.clone();
        drop(candidate);
        let _ = fs::remove_file(&temporary);
        return fail(
            3,
            format!(
                "crimestop: artefato de canal diverge do índice assinado\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {obtained}"
            ),
        );
    }
    if publish_noreplace(&cache, &temporary, &destination)? {
        candidate.renamed_to(destination.clone())?;
    } else {
        drop(candidate);
        let _ = fs::remove_file(&temporary);
        let winner = ArtifactFile::open(destination.clone()).map_err(|error| crate::Fail {
            code: 3,
            msg: format!(
                "crimestop: corrida publicou objeto pinado inválido em {}: {error:#}",
                destination.display()
            ),
        })?;
        if winner.hash != want {
            return fail(3, "crimestop: corrida publicou objeto pinado divergente");
        }
    }
    Ok(destination)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct AuthenticatedInputFact {
    pub origin_kind: String,
    pub identifier: String,
    pub sha256: String,
}

fn input_fact(kind: &str, identifier: String, sha256: String) -> AuthenticatedInputFact {
    AuthenticatedInputFact {
        origin_kind: kind.to_string(),
        identifier,
        sha256,
    }
}

fn frozen_input_fact(
    recipe: &Recipe,
    kind: &str,
    identifier: String,
    transport: &str,
    maximum: usize,
    expected_sha256: &str,
) -> Result<AuthenticatedInputFact> {
    let bytes = recipe.frozen_file_bytes(transport, maximum)?;
    let observed = hex::encode(Sha256::digest(&bytes));
    if observed != expected_sha256 {
        bail!("evidência congelada do waiver diverge do SHA-256 declarado");
    }
    Ok(input_fact(kind, identifier, observed))
}

/// Identidades auxiliares que o lock consegue declarar antes da autenticação.
/// Objetos HTTPS ainda não abertos usam `pending`; chaves/waivers vindos do
/// snapshot congelado de `files/` já carregam o hash dos bytes exatos.
pub(crate) fn signature_input_facts(r: &Recipe) -> Result<Vec<AuthenticatedInputFact>> {
    let mut facts = Vec::new();
    match &r.signature_plan {
        SignaturePlan::None => {}
        SignaturePlan::UnsafeUpstreamWaiver { transport } => {
            facts.extend(unsafe_waiver_input_facts(r, 1, transport, false)?);
        }
        SignaturePlan::LegacyMinisign {
            signature_urls,
            public_key,
        } => {
            let key_hash = hex::encode(Sha256::digest(public_key.as_bytes()));
            facts.push(input_fact(
                "signature-key",
                format!("recipe:SIGKEY=minisign:{key_hash}"),
                key_hash,
            ));
            for (index, url) in signature_urls.iter().enumerate() {
                facts.push(input_fact(
                    "signature",
                    // Minisign NÃO usa a forma indexada do OpenPGP. Ele tem uma
                    // chave só para todas as fontes — daí `SIGKEY=minisign:` sem
                    // índice —, e sua assinatura Ed25519 crua não tem validade
                    // nem expiração, então não há instante de referência a
                    // declarar. Emitir `SIG[n]` aqui fazia o validador cobrar
                    // EPOCH e exigir bijeção com `SIGKEY[n]`, duas regras que só
                    // fazem sentido no OpenPGP.
                    format!("recipe:SIG_MINISIGN[{}]={url}", index + 1),
                    "pending".to_string(),
                ));
            }
        }
        SignaturePlan::OpenPgpDetached { artifacts } => {
            for spec in artifacts {
                let key_bytes = r.frozen_file_bytes(&spec.key.transport, MAX_PUBLIC_KEY_BYTES)?;
                facts.push(input_fact(
                    "signature",
                    format!(
                        "recipe:SIG[{}]={};EPOCH={}",
                        spec.src_index, spec.signature_url, spec.signature_epoch
                    ),
                    "pending".to_string(),
                ));
                facts.push(input_fact(
                    "signature-key",
                    format!(
                        "recipe:SIGKEY[{}]={};FP={}",
                        spec.src_index, spec.key.transport, spec.key.primary_fingerprint
                    ),
                    hex::encode(Sha256::digest(&key_bytes)),
                ));
            }
        }
        SignaturePlan::IndexedArtifacts { artifacts } => {
            for spec in artifacts {
                match spec {
                    IndexedArtifactSignature::OpenPgpDetached(spec) => {
                        let key_bytes =
                            r.frozen_file_bytes(&spec.key.transport, MAX_PUBLIC_KEY_BYTES)?;
                        facts.push(input_fact(
                            "signature",
                            format!(
                                "recipe:SIG[{}]={};EPOCH={}",
                                spec.src_index, spec.signature_url, spec.signature_epoch
                            ),
                            "pending".to_string(),
                        ));
                        facts.push(input_fact(
                            "signature-key",
                            format!(
                                "recipe:SIGKEY[{}]={};FP={}",
                                spec.src_index, spec.key.transport, spec.key.primary_fingerprint
                            ),
                            hex::encode(Sha256::digest(&key_bytes)),
                        ));
                    }
                    IndexedArtifactSignature::UnsafeUpstreamWaiver {
                        src_index,
                        transport,
                    } => facts.extend(unsafe_waiver_input_facts(r, *src_index, transport, true)?),
                }
            }
        }
        SignaturePlan::OpenPgpChecksums {
            manifest_url,
            detached_signature_url,
            key,
            signature_epoch,
        } => {
            let key_bytes = r.frozen_file_bytes(&key.transport, MAX_PUBLIC_KEY_BYTES)?;
            facts.push(input_fact(
                "checksums",
                format!("recipe:SIGSUMS={manifest_url};EPOCH={signature_epoch}"),
                "pending".to_string(),
            ));
            if let Some(url) = detached_signature_url {
                facts.push(input_fact(
                    "signature",
                    format!("recipe:SIGSUMS_SIG={url};EPOCH={signature_epoch}"),
                    "pending".to_string(),
                ));
            }
            facts.push(input_fact(
                "signature-key",
                format!(
                    "recipe:SIGKEY[1]={};FP={}",
                    key.transport, key.primary_fingerprint
                ),
                hex::encode(Sha256::digest(&key_bytes)),
            ));
        }
    }
    facts.sort();
    facts.dedup();
    Ok(facts)
}

fn indexed_waiver_identifier(identifier: String, src_index: usize, indexed: bool) -> String {
    if indexed {
        format!("{identifier};SRC_INDEX={src_index}")
    } else {
        identifier
    }
}

fn unsafe_waiver_input_facts(
    recipe: &Recipe,
    src_index: usize,
    transport: &str,
    indexed: bool,
) -> Result<Vec<AuthenticatedInputFact>> {
    let offset = src_index
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("waiver não pode apontar para SRC_0"))?;
    let bytes = recipe.frozen_file_bytes(transport, MAX_UNSAFE_SIGNATURE_WAIVER_BYTES)?;
    let waiver = parse_unsafe_signature_waiver(&bytes)?;
    let common = waiver.common();
    if common.package != recipe.name
        || common.version != recipe.version
        || recipe.srcs.get(offset) != Some(&common.artifact_url)
        || recipe.sha256.get(offset) != Some(&common.artifact_sha256)
    {
        bail!("waiver de assinatura não corresponde à identidade de SRC_{src_index}");
    }
    let declaration = if indexed {
        format!("recipe:SIG_UNSAFE_WAIVER[{src_index}]={transport}")
    } else {
        format!("recipe:SIG_UNSAFE_WAIVER={transport}")
    };
    let mut facts = vec![input_fact(
        "signature-waiver",
        declaration,
        hex::encode(Sha256::digest(&bytes)),
    )];
    let identifier = |value| indexed_waiver_identifier(value, src_index, indexed);
    match waiver {
        UnsafeSignatureWaiver::InsecureData(waiver) => {
            facts.push(frozen_input_fact(
                recipe,
                "signature",
                identifier(format!(
                    "recipe:WAIVER_SIG_FILE={};URL={};EPOCH={}",
                    waiver.signature_file,
                    waiver.common.signature_url,
                    waiver.common.signature_epoch
                )),
                &waiver.signature_file,
                MAX_SIGNATURE_BYTES,
                &waiver.common.signature_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-key-source",
                identifier(format!(
                    "recipe:WAIVER_KEY_SOURCE_FILE={};URL={}",
                    waiver.public_key_source_file, waiver.public_key_source_url
                )),
                &waiver.public_key_source_file,
                MAX_WAIVER_KEY_SOURCE_BYTES,
                &waiver.public_key_source_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-key",
                identifier(format!(
                    "recipe:WAIVER_KEY_CERT_FILE={};FP={};EXTRACTION={}",
                    waiver.public_key_cert_file,
                    waiver.common.primary_fingerprint,
                    waiver.public_key_extraction
                )),
                &waiver.public_key_cert_file,
                MAX_PUBLIC_KEY_BYTES,
                &waiver.public_key_cert_sha256,
            )?);
        }
        UnsafeSignatureWaiver::ExpiredSigner(waiver) => {
            facts.push(frozen_input_fact(
                recipe,
                "signature",
                identifier(format!(
                    "recipe:WAIVER_SIG_FILE={};URL={};EPOCH={}",
                    waiver.signature_file,
                    waiver.common.signature_url,
                    waiver.common.signature_epoch
                )),
                &waiver.signature_file,
                MAX_SIGNATURE_BYTES,
                &waiver.common.signature_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-key-source",
                identifier(format!(
                    "recipe:WAIVER_KEY_SOURCE_FILE={};URL={}",
                    waiver.validation_cert_source_file, waiver.validation_cert_source_url
                )),
                &waiver.validation_cert_source_file,
                MAX_PUBLIC_KEY_BYTES,
                &waiver.validation_cert_source_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-key",
                identifier(format!(
                    "recipe:WAIVER_KEY_CERT_FILE={};FP={};EXTRACTION={}",
                    waiver.validation_cert_file,
                    waiver.common.primary_fingerprint,
                    waiver.validation_cert_extraction
                )),
                &waiver.validation_cert_file,
                MAX_PUBLIC_KEY_BYTES,
                &waiver.validation_cert_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-evidence",
                identifier(format!(
                    "recipe:WAIVER_ENDORSEMENT_FILE={};URL={};PAGE_DATE={};EXTRACTION={};VALIDATION_EPOCH={};EXPIRY_EPOCH={};OBSERVED_EPOCH={}",
                    waiver.official_endorsement_file,
                    waiver.official_endorsement_url,
                    waiver.official_endorsement_page_date,
                    waiver.official_endorsement_extraction,
                    waiver.validation_epoch,
                    waiver.validation_cert_expiry_epoch,
                    waiver.endorsement_observed_epoch
                )),
                &waiver.official_endorsement_file,
                MAX_WAIVER_HTML_BYTES,
                &waiver.official_endorsement_sha256,
            )?);
        }
        UnsafeSignatureWaiver::LegacyDsaData(waiver) => {
            facts.push(frozen_input_fact(
                recipe,
                "signature",
                identifier(format!(
                    "recipe:WAIVER_SIG_FILE={};URL={};EPOCH={}",
                    waiver.signature_file,
                    waiver.common.signature_url,
                    waiver.common.signature_epoch
                )),
                &waiver.signature_file,
                MAX_SIGNATURE_BYTES,
                &waiver.common.signature_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-key-source",
                identifier(format!(
                    "recipe:WAIVER_KEY_SOURCE_FILE={};URL={}",
                    waiver.cert_transport_file, waiver.cert_transport_url
                )),
                &waiver.cert_transport_file,
                MAX_PUBLIC_KEY_BYTES,
                &waiver.cert_transport_sha256,
            )?);
            facts.push(frozen_input_fact(
                recipe,
                "signature-key",
                identifier(format!(
                    "recipe:WAIVER_KEY_CERT_FILE={};FP={};EXTRACTION={}",
                    waiver.cert_file, waiver.common.primary_fingerprint, waiver.cert_extraction
                )),
                &waiver.cert_file,
                MAX_PUBLIC_KEY_BYTES,
                &waiver.cert_sha256,
            )?);
            for (field, file, url, hash, last_modified, extraction) in [
                (
                    "WAIVER_RELEASE_PAGE_FILE",
                    waiver.official_release_page_file.as_str(),
                    waiver.official_release_page_url.as_str(),
                    waiver.official_release_page_sha256.as_str(),
                    waiver.official_release_page_last_modified.as_str(),
                    waiver.official_release_page_extraction.as_str(),
                ),
                (
                    "WAIVER_FINGERPRINT_PAGE_FILE",
                    waiver.official_fingerprint_page_file.as_str(),
                    waiver.official_fingerprint_page_url.as_str(),
                    waiver.official_fingerprint_page_sha256.as_str(),
                    waiver.official_fingerprint_page_last_modified.as_str(),
                    waiver.official_fingerprint_page_extraction.as_str(),
                ),
            ] {
                facts.push(frozen_input_fact(
                    recipe,
                    "signature-evidence",
                    identifier(format!(
                        "recipe:{field}={file};URL={url};LAST_MODIFIED={last_modified};EXTRACTION={extraction}"
                    )),
                    file,
                    MAX_WAIVER_HTML_BYTES,
                    hash,
                )?);
            }
        }
    }
    Ok(facts)
}

pub(crate) struct AuthenticatedArtifacts {
    pub artifacts: Vec<(PathBuf, String)>,
    pub inputs: Vec<AuthenticatedInputFact>,
}

/// Garante cada artefato de SRC no cache, verificado por hash e — quando a
/// receita pina — por assinatura. Devolve também os hashes dos bytes auxiliares
/// (assinatura, manifesto e chave) realmente usados pela autenticação.
pub(crate) fn ensure_artifacts_authenticated(
    ctx: &Ctx,
    r: &Recipe,
) -> Result<AuthenticatedArtifacts> {
    let cache = ctx.cache_dir();
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    if ctx.offline {
        if !cache.is_dir() {
            return fail(6, "--offline e cache do minitrue ausente");
        }
    } else {
        fs::create_dir_all(&cache)?;
    }
    crate::install::ensure_real_directory_or_absent(&ctx.root, &cache, "cache do minitrue")?;
    let _cache_directory = trusted_cache_directory(&cache, !ctx.offline)?;

    let mut artifacts = Vec::new();
    #[cfg(feature = "tofu-authoring")]
    let mut tofu_hashes = Vec::new();
    for (i, url) in r.srcs.iter().enumerate() {
        let want = r.sha256.get(i).cloned();
        let artifact = match want {
            Some(want) => {
                let dst = cache.join(&want);
                match fs::symlink_metadata(&dst) {
                    Ok(_) => {
                        let artifact =
                            ArtifactFile::open(dst.clone()).map_err(|error| crate::Fail {
                                code: 3,
                                msg: format!(
                                    "crimestop: objeto de cache inválido em {}: {error:#}",
                                    dst.display()
                                ),
                            })?;
                        if artifact.hash != want {
                            return fail(
                                3,
                                format!(
                                    "crimestop: cache diverge do registro oficial\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {}",
                                    artifact.hash
                                ),
                            );
                        }
                        artifact
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        if ctx.offline {
                            return fail(
                                6,
                                format!("--offline e artefato ausente do cache: {url}"),
                            );
                        }
                        let (tmp, transport_hash) = download_temp_bounded(
                            url,
                            &cache,
                            "baixando",
                            i,
                            Some(MAX_PINNED_OBJECT_BYTES),
                        )?;
                        let mut candidate = match ArtifactFile::open(tmp.clone()) {
                            Ok(candidate) => candidate,
                            Err(error) => {
                                let _ = fs::remove_file(&tmp);
                                return Err(error);
                            }
                        };
                        if transport_hash != candidate.hash || candidate.hash != want {
                            let obtained = candidate.hash.clone();
                            drop(candidate);
                            let _ = fs::remove_file(&tmp);
                            return fail(
                                3,
                                format!(
                                    "crimestop: o artefato diverge do registro oficial\n  fonte:    {url}\n  esperado: {want}\n  obtido:   {obtained}"
                                ),
                            );
                        }
                        if publish_noreplace(&cache, &tmp, &dst)? {
                            candidate.renamed_to(dst)?;
                            candidate
                        } else {
                            drop(candidate);
                            let _ = fs::remove_file(&tmp);
                            let winner = ArtifactFile::open(dst.clone()).map_err(|error| {
                                crate::Fail {
                                    code: 3,
                                    msg: format!(
                                        "crimestop: corrida publicou cache inválido em {}: {error:#}",
                                        dst.display()
                                    ),
                                }
                            })?;
                            if winner.hash != want {
                                return fail(
                                    3,
                                    format!(
                                        "crimestop: corrida publicou hash divergente em {}",
                                        dst.display()
                                    ),
                                );
                            }
                            winner
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            None => {
                #[cfg(not(feature = "tofu-authoring"))]
                return fail(2, format!("{}: receita sem SHA256", r.name));

                #[cfg(feature = "tofu-authoring")]
                {
                    if !ctx.tofu_enabled() {
                        return fail(
                            2,
                            format!(
                                "{}: receita sem SHA256 (só com --tofu, e com aviso)",
                                r.name
                            ),
                        );
                    }
                    // TOFU explícito: primeira busca vira o registro, com alarde.
                    if ctx.offline {
                        return fail(6, "--offline não combina com --tofu");
                    }
                    let (tmp, transport_hash) = download_temp_bounded(
                        url,
                        &cache,
                        "tofu",
                        i,
                        Some(MAX_PINNED_OBJECT_BYTES),
                    )?;
                    let mut candidate = ArtifactFile::open(tmp.clone())?;
                    if candidate.hash != transport_hash {
                        drop(candidate);
                        let _ = fs::remove_file(&tmp);
                        return fail(3, "download TOFU mudou antes da publicação");
                    }
                    let hash = candidate.hash.clone();
                    let dst = cache.join(&hash);
                    let artifact = if publish_noreplace(&cache, &tmp, &dst)? {
                        candidate.renamed_to(dst)?;
                        candidate
                    } else {
                        drop(candidate);
                        let _ = fs::remove_file(&tmp);
                        let winner = ArtifactFile::open(dst.clone())?;
                        if winner.hash != hash {
                            return fail(
                                3,
                                format!(
                                    "cache TOFU contém objeto incompatível em {}",
                                    dst.display()
                                ),
                            );
                        }
                        winner
                    };
                    tofu_hashes.push(hash.clone());
                    artifact
                }
            }
        };
        eprintln!("  {} — sha256 confere", short(url));
        artifacts.push(artifact);
    }

    let inputs = verify_signatures(ctx, r, &mut artifacts)?;
    for artifact in &artifacts {
        artifact.ensure_stable().map_err(|error| crate::Fail {
            code: 3,
            msg: format!("crimestop: artefato instável após autenticação: {error:#}"),
        })?;
    }
    #[cfg(feature = "tofu-authoring")]
    if !tofu_hashes.is_empty() {
        eprintln!("minitrue: AVISO TOFU — confiança na primeira vista. Cole na receita:");
        eprintln!("SHA256={}", tofu_hashes.join(" "));
    }
    Ok(AuthenticatedArtifacts {
        artifacts: artifacts
            .into_iter()
            .map(|artifact| (artifact.path, artifact.hash))
            .collect(),
        inputs,
    })
}

pub fn ensure_artifacts(ctx: &Ctx, r: &Recipe) -> Result<Vec<(PathBuf, String)>> {
    Ok(ensure_artifacts_authenticated(ctx, r)?.artifacts)
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

fn validate_regular_metadata(
    metadata: &fs::Metadata,
    max_bytes: u64,
    label: &str,
) -> Result<FileSnapshot> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        anyhow::bail!("{label} exige arquivo regular real com um único link");
    }
    if metadata.len() > max_bytes {
        anyhow::bail!("{label} excede {max_bytes} bytes");
    }
    Ok(FileSnapshot::from_metadata(metadata))
}

fn open_regular_nofollow(path: &Path, max_bytes: u64, label: &str) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("abrindo {label} {}", path.display()))?;
    validate_regular_metadata(&file.metadata()?, max_bytes, label)?;
    Ok(file)
}

fn sha256_fd_stable(
    file: &mut fs::File,
    max_bytes: u64,
    label: &str,
) -> Result<(String, FileSnapshot)> {
    let before = validate_regular_metadata(&file.metadata()?, max_bytes, label)?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let remaining = max_bytes.saturating_sub(total);
        if remaining == 0 {
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 {
                anyhow::bail!("{label} cresceu além de {max_bytes} bytes");
            }
            break;
        }
        let allowed =
            usize::try_from(remaining.min(buffer.len() as u64)).expect("limitado pelo buffer");
        let read = file.read(&mut buffer[..allowed])?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    let after = validate_regular_metadata(&file.metadata()?, max_bytes, label)?;
    if before != after || total != before.len {
        anyhow::bail!("{label} mudou durante a leitura");
    }
    Ok((hex::encode(hasher.finalize()), after))
}

fn read_small_fd_stable(
    file: &mut fs::File,
    max_bytes: usize,
    label: &str,
) -> Result<(Vec<u8>, FileSnapshot)> {
    let before = FileSnapshot::from_metadata(&file.metadata()?);
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(before.len as usize);
    Read::by_ref(file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        anyhow::bail!("{label} excede {max_bytes} bytes");
    }
    let after = validate_regular_metadata(&file.metadata()?, max_bytes as u64, label)?;
    if before != after || bytes.len() as u64 != before.len {
        anyhow::bail!("{label} mudou durante a leitura");
    }
    Ok((bytes, after))
}

fn crypto_error<T>(recipe: &Recipe, what: &str, result: Result<T>) -> Result<T> {
    result.map_err(|error| {
        crate::Fail {
            code: 7,
            msg: format!("{}: crimestop ({what}): {error:#}", recipe.name),
        }
        .into()
    })
}

fn obtain_auxiliary(
    ctx: &Ctx,
    url: &str,
    cache_name: &str,
    max_bytes: usize,
    label: &str,
    index: usize,
) -> Result<AuxiliaryObject> {
    let destination = ctx.cache_dir().join(cache_name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            AuxiliaryObject::open(destination.clone(), max_bytes, label, false).map_err(|error| {
                crate::Fail {
                    code: 7,
                    msg: format!(
                        "cache de {label} inválido em {}: {error:#}",
                        destination.display()
                    ),
                }
                .into()
            })
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if ctx.offline {
                return fail(7, format!("--offline e {label} ausente no cache: {url}"));
            }
            let (path, _) =
                download_temp_bounded(url, &ctx.cache_dir(), label, index, Some(max_bytes as u64))?;
            match AuxiliaryObject::open(path.clone(), max_bytes, label, true) {
                Ok(object) => Ok(object),
                Err(error) => {
                    let _ = fs::remove_file(&path);
                    Err(error)
                }
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn publish_auxiliary(
    cache: &Path,
    object: &mut AuxiliaryObject,
    destination: &Path,
) -> Result<bool> {
    if !object.temporary {
        object.ensure_stable()?;
        return Ok(false);
    }
    object.ensure_stable()?;
    let published = publish_noreplace(cache, &object.path, destination)?;
    if published {
        if let Err(error) = object.renamed_to(destination.to_path_buf()) {
            // Se um processo trocou o temporário no intervalo mínimo entre a
            // prova e renameat2, o nome imutável não pode ficar envenenado.
            // A remoção é condicional ao snapshot observado pós-publicação.
            if let Ok(metadata) = fs::symlink_metadata(destination) {
                let published_snapshot = FileSnapshot::from_metadata(&metadata);
                let _ = remove_if_same_snapshot(cache, destination, published_snapshot);
            }
            return Err(error.context("objeto auxiliar mudou durante publicação"));
        }
    } else {
        let winner = AuxiliaryObject::open(
            destination.to_path_buf(),
            object.max_bytes,
            &object.label,
            false,
        )?;
        // Ao substituir `object`, Drop remove apenas o nosso temporário que
        // perdeu a corrida; o vencedor já foi reaberto com O_NOFOLLOW.
        *object = winner;
    }
    object.ensure_stable()?;
    Ok(published)
}

fn verify_minisign_bytes(
    artifact: &mut ArtifactFile,
    signature_bytes: &[u8],
    pk: &minisign_verify::PublicKey,
    sig_url: &str,
) -> Result<()> {
    let sig_txt =
        std::str::from_utf8(signature_bytes).context("assinatura minisign não é UTF-8")?;
    let sig =
        minisign_verify::Signature::decode(sig_txt).context("assinatura minisign mal-formada")?;
    let mut verifier = pk
        .verify_stream(&sig)
        .with_context(|| format!("{} não usa minisign prehashed", short(sig_url)))?;
    artifact.rewind()?;
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = artifact.file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("artefato minisign excedeu u64"))?;
        if total > MAX_PINNED_OBJECT_BYTES {
            anyhow::bail!("artefato minisign excede {MAX_PINNED_OBJECT_BYTES} bytes");
        }
        verifier.update(&buffer[..read]);
    }
    verifier
        .finalize()
        .with_context(|| format!("{} não é de quem diz ser", short(sig_url)))?;
    artifact.ensure_stable()
}

fn verify_signatures(
    ctx: &Ctx,
    r: &Recipe,
    artifacts: &mut [ArtifactFile],
) -> Result<Vec<AuthenticatedInputFact>> {
    let observed = match &r.signature_plan {
        SignaturePlan::None => Vec::new(),
        SignaturePlan::UnsafeUpstreamWaiver { transport } => {
            if artifacts.len() != 1 {
                return fail(
                    2,
                    format!("{}: waiver exige exatamente um artefato", r.name),
                );
            }
            let artifact = artifacts.first_mut().ok_or_else(|| crate::Fail {
                code: 2,
                msg: format!("{}: waiver sem artefato", r.name),
            })?;
            verify_unsafe_signature_waiver(r, 1, transport, artifact)?;
            Vec::new()
        }
        SignaturePlan::LegacyMinisign {
            signature_urls,
            public_key,
        } => verify_minisign_plan(ctx, r, artifacts, signature_urls, public_key)?,
        SignaturePlan::OpenPgpDetached { artifacts: specs } => {
            verify_openpgp_detached_plan(ctx, r, artifacts, specs)?
        }
        SignaturePlan::IndexedArtifacts { artifacts: specs } => {
            let detached: Vec<_> = specs
                .iter()
                .filter_map(|spec| match spec {
                    IndexedArtifactSignature::OpenPgpDetached(spec) => Some(spec.clone()),
                    IndexedArtifactSignature::UnsafeUpstreamWaiver { .. } => None,
                })
                .collect();
            let observed = verify_openpgp_detached_plan(ctx, r, artifacts, &detached)?;
            for spec in specs {
                if let IndexedArtifactSignature::UnsafeUpstreamWaiver {
                    src_index,
                    transport,
                } = spec
                {
                    let offset = src_index.checked_sub(1).ok_or_else(|| crate::Fail {
                        code: 2,
                        msg: format!("{}: waiver aponta para SRC_0", r.name),
                    })?;
                    let artifact = artifacts.get_mut(offset).ok_or_else(|| crate::Fail {
                        code: 2,
                        msg: format!("{}: waiver aponta para SRC ausente", r.name),
                    })?;
                    verify_unsafe_signature_waiver(r, *src_index, transport, artifact)?;
                }
            }
            observed
        }
        SignaturePlan::OpenPgpChecksums {
            manifest_url,
            detached_signature_url,
            key,
            signature_epoch,
        } => verify_openpgp_checksums_plan(
            ctx,
            r,
            artifacts,
            manifest_url,
            detached_signature_url.as_deref(),
            key,
            *signature_epoch,
        )?,
    };
    let mut facts = signature_input_facts(r)?;
    for observed in observed {
        let planned = facts
            .iter_mut()
            .find(|planned| {
                planned.origin_kind == observed.origin_kind
                    && planned.identifier == observed.identifier
            })
            .ok_or_else(|| anyhow::anyhow!("autenticação produziu input não planejado"))?;
        planned.sha256 = observed.sha256;
    }
    if facts.iter().any(|fact| fact.sha256 == "pending") {
        bail!("autenticação não observou todos os inputs auxiliares planejados");
    }
    Ok(facts)
}

const MAX_WAIVER_HTML_BYTES: usize = 256 * 1024;
const MAX_WAIVER_KEY_SOURCE_BYTES: usize = 8 * 1024 * 1024;

fn verify_unsafe_signature_waiver(
    recipe: &Recipe,
    src_index: usize,
    transport: &str,
    artifact: &mut ArtifactFile,
) -> Result<()> {
    let bytes = recipe.frozen_file_bytes(transport, MAX_UNSAFE_SIGNATURE_WAIVER_BYTES)?;
    let waiver = parse_unsafe_signature_waiver(&bytes).map_err(|error| crate::Fail {
        code: 2,
        msg: format!(
            "{}: waiver de assinatura upstream inválido: {error:#}",
            recipe.name
        ),
    })?;
    let offset = src_index.checked_sub(1).ok_or_else(|| crate::Fail {
        code: 2,
        msg: format!("{}: waiver não pode apontar para SRC_0", recipe.name),
    })?;
    let Some(artifact_url) = recipe.srcs.get(offset) else {
        return fail(
            2,
            format!(
                "{}: waiver aponta para SRC_{src_index} ausente",
                recipe.name
            ),
        );
    };
    let Some(artifact_sha256) = recipe.sha256.get(offset) else {
        return fail(
            2,
            format!("{}: waiver sem SHA256 para SRC_{src_index}", recipe.name),
        );
    };
    let common = waiver.common();
    if common.package != recipe.name
        || common.version != recipe.version
        || common.artifact_url != *artifact_url
        || common.artifact_sha256 != *artifact_sha256
        || artifact.hash != *artifact_sha256
    {
        return fail(
            2,
            format!(
                "{}: assinatura-insegura não corresponde exatamente à recipe/SRC_{src_index}/SHA256",
                recipe.name,
            ),
        );
    }
    match &waiver {
        UnsafeSignatureWaiver::InsecureData(waiver) => {
            crypto_error(
                recipe,
                "prova factual do waiver v1",
                (|| {
                    let signature = frozen_waiver_evidence(
                        recipe,
                        &waiver.signature_file,
                        MAX_SIGNATURE_BYTES,
                        &waiver.common.signature_sha256,
                        "assinatura v1",
                    )?;
                    let key_source = frozen_waiver_evidence(
                        recipe,
                        &waiver.public_key_source_file,
                        MAX_WAIVER_KEY_SOURCE_BYTES,
                        &waiver.public_key_source_sha256,
                        "fonte da chave v1",
                    )?;
                    let cert_bytes = frozen_waiver_evidence(
                        recipe,
                        &waiver.public_key_cert_file,
                        MAX_PUBLIC_KEY_BYTES,
                        &waiver.public_key_cert_sha256,
                        "certificado extraído v1",
                    )?;
                    let cert = match waiver.public_key_extraction.as_str() {
                        "HTML_FIRST_ASCII_ARMOR_PUBLIC_KEY_BLOCK" => {
                            let extracted = first_ascii_armored_public_key(&key_source)?;
                            if extracted != cert_bytes {
                                bail!("certificado v1 diverge da extração HTML fechada");
                            }
                            PinnedCert::from_bytes(
                                &cert_bytes,
                                &waiver.common.primary_fingerprint,
                                &[],
                            )?
                        }
                        "OPENPGP_CERT_BY_PRIMARY_FINGERPRINT" => pinned_cert_from_keyring_subset(
                            &key_source,
                            &cert_bytes,
                            &waiver.common.primary_fingerprint,
                        )?,
                        _ => bail!("regra de extração v1 inesperada"),
                    };
                    let metadata = inspect_rejected_dsa_sha1(
                        &signature,
                        &cert,
                        waiver.common.signature_epoch,
                    )?;
                    if metadata.signing_pk_algorithm != 17
                        || metadata.signing_key_bits != 1024
                        || metadata.dsa_q_bits != 160
                        || metadata.hash_algorithm != 2
                    {
                        bail!("declaração DSA-1024/SHA1 do waiver v1 não é factual");
                    }
                    artifact.rewind()?;
                    if verify_detached(
                        &mut artifact.file,
                        &signature,
                        &cert,
                        SignatureClock::from_unix_seconds(waiver.common.review_epoch)?,
                    )
                    .is_ok()
                    {
                        bail!("motor normal aceitou DSA/SHA1 fora do waiver v1");
                    }
                    artifact.ensure_stable()?;
                    Ok(())
                })(),
            )?;
            eprintln!(
                "  AVISO: {} {} sem prova de autoria — upstream oferece {}/{} recusado; waiver v1 revisado em {}",
                recipe.name,
                recipe.version,
                waiver.common.signature_algorithm,
                waiver.common.signature_hash,
                waiver.common.review_date
            );
            eprintln!(
                "  evidência v1: sig={} sha256={} epoch={} fp={} key-source={} source-sha256={} extraction={} cert-sha256={} review-epoch={} motivo={}",
                waiver.common.signature_url,
                waiver.common.signature_sha256,
                waiver.common.signature_epoch,
                waiver.common.primary_fingerprint,
                waiver.public_key_source_url,
                waiver.public_key_source_sha256,
                waiver.public_key_extraction,
                waiver.public_key_cert_sha256,
                waiver.common.review_epoch,
                waiver.common.reason
            );
        }
        UnsafeSignatureWaiver::ExpiredSigner(waiver) => {
            crypto_error(
                recipe,
                "prova factual do waiver v2",
                (|| {
                    let signature = frozen_waiver_evidence(
                        recipe,
                        &waiver.signature_file,
                        MAX_SIGNATURE_BYTES,
                        &waiver.common.signature_sha256,
                        "assinatura v2",
                    )?;
                    let cert_source = frozen_waiver_evidence(
                        recipe,
                        &waiver.validation_cert_source_file,
                        MAX_PUBLIC_KEY_BYTES,
                        &waiver.validation_cert_source_sha256,
                        "certificado-fonte v2",
                    )?;
                    let cert_bytes = frozen_waiver_evidence(
                        recipe,
                        &waiver.validation_cert_file,
                        MAX_PUBLIC_KEY_BYTES,
                        &waiver.validation_cert_sha256,
                        "certificado extraído v2",
                    )?;
                    let endorsement = frozen_waiver_evidence(
                        recipe,
                        &waiver.official_endorsement_file,
                        MAX_WAIVER_HTML_BYTES,
                        &waiver.official_endorsement_sha256,
                        "endosso oficial v2",
                    )?;
                    require_v2_endorsement(waiver, &endorsement)?;
                    let cert = pinned_primary_cert_subset(
                        &cert_source,
                        &cert_bytes,
                        &waiver.common.primary_fingerprint,
                    )?;
                    let validation_clock =
                        SignatureClock::from_unix_seconds(waiver.validation_epoch)?;
                    if cert.primary_expiration_epoch_at(validation_clock)?
                        != Some(waiver.validation_cert_expiry_epoch)
                    {
                        bail!("VALIDATION_CERT_EXPIRY_EPOCH diverge da selfsig histórica");
                    }
                    artifact.rewind()?;
                    let report =
                        verify_detached(&mut artifact.file, &signature, &cert, validation_clock)?;
                    if report.signature_creation_epoch != waiver.validation_epoch {
                        bail!("creation time da assinatura v2 diverge de VALIDATION_EPOCH");
                    }
                    if report.signing_pk_algorithm != 1
                        || report.signing_key_bits != Some(2560)
                        || report.hash_algorithm != 10
                    {
                        bail!(
                            "assinatura v2 não é RSA-2560/SHA512 factual: pk={} bits={:?} hash={}",
                            report.signing_pk_algorithm,
                            report.signing_key_bits,
                            report.hash_algorithm
                        );
                    }
                    artifact.ensure_stable()?;

                    artifact.rewind()?;
                    if verify_detached(
                        &mut artifact.file,
                        &signature,
                        &cert,
                        SignatureClock::from_unix_seconds(waiver.common.review_epoch)?,
                    )
                    .is_ok()
                    {
                        bail!("motor normal aceitou certificado v2 no REVIEW_EPOCH");
                    }
                    artifact.ensure_stable()?;
                    Ok(())
                })(),
            )?;
            eprintln!(
                "  waiver v2 comprovado: {} {} foi assinado por {} em {}; cert expirou em {} e o motor recusa no review {}",
                recipe.name,
                recipe.version,
                waiver.common.primary_fingerprint,
                waiver.validation_epoch,
                waiver.validation_cert_expiry_epoch,
                waiver.common.review_epoch
            );
        }
        UnsafeSignatureWaiver::LegacyDsaData(waiver) => {
            crypto_error(
                recipe,
                "prova factual do waiver v3",
                (|| {
                    let signature = frozen_waiver_evidence(
                        recipe,
                        &waiver.signature_file,
                        MAX_SIGNATURE_BYTES,
                        &waiver.common.signature_sha256,
                        "assinatura v3",
                    )?;
                    let cert_source = frozen_waiver_evidence(
                        recipe,
                        &waiver.cert_transport_file,
                        MAX_PUBLIC_KEY_BYTES,
                        &waiver.cert_transport_sha256,
                        "certificado-fonte v3",
                    )?;
                    let cert_bytes = frozen_waiver_evidence(
                        recipe,
                        &waiver.cert_file,
                        MAX_PUBLIC_KEY_BYTES,
                        &waiver.cert_sha256,
                        "certificado extraído v3",
                    )?;
                    let release_page = frozen_waiver_evidence(
                        recipe,
                        &waiver.official_release_page_file,
                        MAX_WAIVER_HTML_BYTES,
                        &waiver.official_release_page_sha256,
                        "página oficial da release v3",
                    )?;
                    let fingerprint_page = frozen_waiver_evidence(
                        recipe,
                        &waiver.official_fingerprint_page_file,
                        MAX_WAIVER_HTML_BYTES,
                        &waiver.official_fingerprint_page_sha256,
                        "página oficial do fingerprint v3",
                    )?;
                    require_v3_pages(waiver, &release_page, &fingerprint_page)?;
                    let cert = pinned_primary_cert_subset(
                        &cert_source,
                        &cert_bytes,
                        &waiver.common.primary_fingerprint,
                    )?;
                    artifact.rewind()?;
                    let report = verify_legacy_dsa_waiver(
                        &mut artifact.file,
                        &signature,
                        &cert,
                        waiver.common.signature_epoch,
                    )?;
                    if report.primary_fingerprint != waiver.common.primary_fingerprint {
                        bail!("prova DSA v3 diverge da primária pinada");
                    }
                    artifact.ensure_stable()?;

                    artifact.rewind()?;
                    if verify_detached(
                        &mut artifact.file,
                        &signature,
                        &cert,
                        SignatureClock::from_unix_seconds(waiver.common.review_epoch)?,
                    )
                    .is_ok()
                    {
                        bail!("motor normal aceitou DSA sobre dados fora do waiver v3");
                    }
                    artifact.ensure_stable()?;
                    Ok(())
                })(),
            )?;
            eprintln!(
                "  waiver v3 confinado: prova matemática {}/{} de {} em {}; motor normal continua recusando DSA-data",
                waiver.common.signature_algorithm,
                waiver.common.signature_hash,
                waiver.common.primary_fingerprint,
                waiver.common.signature_epoch
            );
        }
    }
    Ok(())
}

fn frozen_waiver_evidence(
    recipe: &Recipe,
    transport: &str,
    maximum: usize,
    expected_sha256: &str,
    label: &str,
) -> Result<Vec<u8>> {
    let bytes = recipe.frozen_file_bytes(transport, maximum)?;
    let observed = hex::encode(Sha256::digest(&bytes));
    if observed != expected_sha256 {
        bail!("{label} diverge do SHA-256 pinado: esperado {expected_sha256}, obtido {observed}");
    }
    Ok(bytes)
}

fn first_ascii_armored_public_key(source: &[u8]) -> Result<&[u8]> {
    const BEGIN: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
    const END: &[u8] = b"-----END PGP PUBLIC KEY BLOCK-----\n";
    let starts: Vec<_> = source
        .windows(BEGIN.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == BEGIN).then_some(index))
        .collect();
    if starts.len() != 1 {
        bail!("fonte HTML v1 não contém exatamente um bloco de chave");
    }
    let tail = &source[starts[0]..];
    let ends: Vec<_> = tail
        .windows(END.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == END).then_some(index + END.len()))
        .collect();
    if ends.len() != 1 {
        bail!("fonte HTML v1 não contém exatamente um fim de bloco de chave");
    }
    Ok(&tail[..ends[0]])
}

fn grouped_openpgp_fingerprint(fingerprint: &str) -> String {
    let groups: Vec<_> = fingerprint
        .as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).expect("fingerprint ASCII"))
        .collect();
    let middle = groups.len() / 2;
    groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            if index == 0 {
                (*group).to_string()
            } else if index == middle {
                format!("  {group}")
            } else {
                format!(" {group}")
            }
        })
        .collect::<Vec<_>>()
        .concat()
}

fn require_once(haystack: &str, needle: &str, label: &str) -> Result<()> {
    if haystack.matches(needle).count() != 1 {
        bail!("{label} não contém exatamente uma ocorrência de {needle:?}");
    }
    Ok(())
}

fn require_v2_endorsement(
    waiver: &crate::openpgp_schema::ExpiredSignerSignatureWaiver,
    bytes: &[u8],
) -> Result<()> {
    let page = std::str::from_utf8(bytes).context("endosso oficial v2 não é UTF-8")?;
    require_once(
        page,
        &grouped_openpgp_fingerprint(&waiver.common.primary_fingerprint),
        "endosso oficial v2",
    )?;
    require_once(
        page,
        &format!("Last modified: {}", waiver.official_endorsement_page_date),
        "endosso oficial v2",
    )
}

fn require_v3_pages(
    waiver: &crate::openpgp_schema::LegacyDsaDataSignatureWaiver,
    release_bytes: &[u8],
    fingerprint_bytes: &[u8],
) -> Result<()> {
    let release =
        std::str::from_utf8(release_bytes).context("página oficial da release v3 não é UTF-8")?;
    let release_modified = format!(
        "Last modifications on {}",
        waiver.official_release_page_last_modified
    );
    let artifact_link = format!("href=\"{}\"", waiver.common.artifact_url);
    let signature_link = format!("href=\"{}\"", waiver.common.signature_url);
    for needle in [
        artifact_link.as_str(),
        signature_link.as_str(),
        "href=\"/downloads/enge.gpg\"",
        "andreas.enge@inria.fr",
        release_modified.as_str(),
    ] {
        require_once(release, needle, "página oficial da release v3")?;
    }
    let fingerprint = std::str::from_utf8(fingerprint_bytes)
        .context("página oficial do fingerprint v3 não é UTF-8")?;
    let grouped_fingerprint = grouped_openpgp_fingerprint(&waiver.common.primary_fingerprint);
    let fingerprint_modified = format!(
        "Last modifications on {}",
        waiver.official_fingerprint_page_last_modified
    );
    for needle in [
        grouped_fingerprint.as_str(),
        "andreas.enge@inria.fr",
        fingerprint_modified.as_str(),
    ] {
        require_once(fingerprint, needle, "página oficial do fingerprint v3")?;
    }
    Ok(())
}

fn verify_minisign_plan(
    ctx: &Ctx,
    recipe: &Recipe,
    artifacts: &mut [ArtifactFile],
    signature_urls: &[String],
    public_key_text: &str,
) -> Result<Vec<AuthenticatedInputFact>> {
    if signature_urls.len() != artifacts.len() {
        return fail(2, format!("{}: plano minisign inconsistente", recipe.name));
    }
    let public_key =
        minisign_verify::PublicKey::from_base64(public_key_text).map_err(|error| crate::Fail {
            code: 7,
            msg: format!("{}: SIGKEY minisign inválida: {error}", recipe.name),
        })?;
    let mut facts = Vec::new();
    for (index, (artifact, signature_url)) in artifacts.iter_mut().zip(signature_urls).enumerate() {
        let cache_name = signature_cache_name(&artifact.hash, public_key_text, signature_url);
        let destination = ctx.cache_dir().join(&cache_name);
        let mut object = obtain_auxiliary(
            ctx,
            signature_url,
            &cache_name,
            MAX_SIGNATURE_BYTES,
            "assinatura-minisign",
            index,
        )?;
        crypto_error(
            recipe,
            "assinatura minisign",
            verify_minisign_bytes(artifact, &object.bytes, &public_key, signature_url),
        )?;
        object.ensure_stable().map_err(|error| crate::Fail {
            code: 7,
            msg: format!("{}: cache minisign mudou: {error:#}", recipe.name),
        })?;
        if object.temporary {
            publish_auxiliary(&ctx.cache_dir(), &mut object, &destination)?;
            let final_bytes = object.reread().map_err(|error| crate::Fail {
                code: 7,
                msg: format!(
                    "{}: cache minisign publicado é inválido: {error:#}",
                    recipe.name
                ),
            })?;
            crypto_error(
                recipe,
                "assinatura minisign publicada",
                verify_minisign_bytes(artifact, &final_bytes, &public_key, signature_url),
            )?;
        }
        facts.push(input_fact(
            "signature",
            format!("recipe:SIG_MINISIGN[{}]={signature_url}", index + 1),
            hex::encode(Sha256::digest(&object.bytes)),
        ));
        eprintln!("  assinatura minisign confere — veio de quem sempre veio");
    }
    Ok(facts)
}

fn pinned_openpgp_cert(
    recipe: &Recipe,
    key: &crate::openpgp_schema::OpenPgpKeySpec,
) -> Result<PinnedCert> {
    let bytes = recipe.frozen_file_bytes(&key.transport, MAX_PUBLIC_KEY_BYTES)?;
    crypto_error(
        recipe,
        "chave OpenPGP pinada",
        PinnedCert::from_bytes(&bytes, &key.primary_fingerprint, &[]),
    )
}

fn verify_openpgp_detached_bytes(
    recipe: &Recipe,
    artifact: &mut ArtifactFile,
    signature: &[u8],
    cert: &PinnedCert,
    clock: SignatureClock,
) -> Result<()> {
    artifact.rewind()?;
    let report = crypto_error(
        recipe,
        "assinatura OpenPGP destacada",
        verify_detached(&mut artifact.file, signature, cert, clock),
    )?;
    artifact.ensure_stable().map_err(|error| crate::Fail {
        code: 7,
        msg: format!(
            "{}: artefato mudou durante assinatura OpenPGP: {error:#}",
            recipe.name
        ),
    })?;
    eprintln!(
        "  OpenPGP confere — primária {}, emissor {}, epoch {}",
        report.primary_fingerprint, report.signing_fingerprint, report.verification_epoch
    );
    Ok(())
}

fn verify_openpgp_detached_plan(
    ctx: &Ctx,
    recipe: &Recipe,
    artifacts: &mut [ArtifactFile],
    specs: &[crate::openpgp_schema::DetachedArtifactSpec],
) -> Result<Vec<AuthenticatedInputFact>> {
    let mut facts = Vec::new();
    for spec in specs {
        let index = spec
            .src_index
            .checked_sub(1)
            .filter(|index| *index < artifacts.len())
            .ok_or_else(|| crate::Fail {
                code: 2,
                msg: format!("{}: índice OpenPGP fora de SRC", recipe.name),
            })?;
        let artifact = &mut artifacts[index];
        let cert = pinned_openpgp_cert(recipe, &spec.key)?;
        let clock = crypto_error(
            recipe,
            "SIG_EPOCH",
            SignatureClock::from_sig_epoch(&spec.signature_epoch.to_string()),
        )?;
        let cache_name = crypto_error(
            recipe,
            "namespace de cache OpenPGP",
            cache_object_name(
                CacheObjectKind::DetachedSignature,
                &artifact.hash,
                &spec.signature_url,
                &cert,
                clock,
            ),
        )?;
        let destination = ctx.cache_dir().join(&cache_name);
        let mut object = obtain_auxiliary(
            ctx,
            &spec.signature_url,
            &cache_name,
            MAX_SIGNATURE_BYTES,
            "assinatura-openpgp",
            index,
        )?;
        verify_openpgp_detached_bytes(recipe, artifact, &object.bytes, &cert, clock)?;
        object.ensure_stable().map_err(|error| crate::Fail {
            code: 7,
            msg: format!("{}: cache OpenPGP mudou: {error:#}", recipe.name),
        })?;
        if object.temporary {
            publish_auxiliary(&ctx.cache_dir(), &mut object, &destination)?;
            let final_bytes = object.reread().map_err(|error| crate::Fail {
                code: 7,
                msg: format!(
                    "{}: cache OpenPGP publicado é inválido: {error:#}",
                    recipe.name
                ),
            })?;
            verify_openpgp_detached_bytes(recipe, artifact, &final_bytes, &cert, clock)?;
        }
        facts.push(input_fact(
            "signature",
            format!(
                "recipe:SIG[{}]={};EPOCH={}",
                spec.src_index, spec.signature_url, spec.signature_epoch
            ),
            hex::encode(Sha256::digest(&object.bytes)),
        ));
    }
    Ok(facts)
}

fn artifact_set_binding(artifacts: &[ArtifactFile]) -> String {
    if let [artifact] = artifacts {
        return artifact.hash.clone();
    }
    let mut digest = Sha256::new();
    digest.update(b"minitrue-sigsums-artifacts-v1\0");
    digest.update((artifacts.len() as u64).to_be_bytes());
    for artifact in artifacts {
        digest.update((artifact.hash.len() as u64).to_be_bytes());
        digest.update(artifact.hash.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn source_basename(recipe: &Recipe, index: usize) -> Result<String> {
    let source = recipe.srcs.get(index).ok_or_else(|| crate::Fail {
        code: 2,
        msg: format!("{}: SRC ausente no índice SIGSUMS", recipe.name),
    })?;
    let parsed = url::Url::parse(source).map_err(|error| crate::Fail {
        code: 2,
        msg: format!("{}: SRC inválida para SIGSUMS: {error}", recipe.name),
    })?;
    let basename = parsed
        .path_segments()
        .and_then(|mut segments| segments.rfind(|part| !part.is_empty()))
        .filter(|part| !part.is_empty())
        .ok_or_else(|| crate::Fail {
            code: 2,
            msg: format!("{}: SRC sem basename para SIGSUMS", recipe.name),
        })?;
    Ok(basename.to_string())
}

fn verify_openpgp_checksums_bytes(
    recipe: &Recipe,
    artifacts: &mut [ArtifactFile],
    manifest: &[u8],
    detached_signature: Option<&[u8]>,
    cert: &PinnedCert,
    clock: SignatureClock,
) -> Result<()> {
    for (index, artifact) in artifacts.iter_mut().enumerate() {
        artifact.rehash_same_fd().map_err(|error| crate::Fail {
            code: 7,
            msg: format!(
                "{}: artefato mudou antes de SIGSUMS: {error:#}",
                recipe.name
            ),
        })?;
        let basename = source_basename(recipe, index)?;
        let result = if let Some(signature) = detached_signature {
            verify_detached_checksums(manifest, signature, cert, clock, &basename, &artifact.hash)
        } else {
            verify_clearsigned_checksums(manifest, cert, clock, &basename, &artifact.hash)
        };
        let report = crypto_error(recipe, "SIGSUMS OpenPGP", result)?;
        artifact.ensure_stable().map_err(|error| crate::Fail {
            code: 7,
            msg: format!("{}: artefato mudou durante SIGSUMS: {error:#}", recipe.name),
        })?;
        eprintln!(
            "  SIGSUMS confere para {basename} — primária {}, emissor {}, epoch {}",
            report.primary_fingerprint, report.signing_fingerprint, report.verification_epoch
        );
    }
    Ok(())
}

fn verify_openpgp_checksums_plan(
    ctx: &Ctx,
    recipe: &Recipe,
    artifacts: &mut [ArtifactFile],
    manifest_url: &str,
    detached_signature_url: Option<&str>,
    key: &crate::openpgp_schema::OpenPgpKeySpec,
    signature_epoch: u64,
) -> Result<Vec<AuthenticatedInputFact>> {
    let cert = pinned_openpgp_cert(recipe, key)?;
    let clock = crypto_error(
        recipe,
        "SIGSUMS_EPOCH",
        SignatureClock::from_sig_epoch(&signature_epoch.to_string()),
    )?;
    let binding = artifact_set_binding(artifacts);
    let manifest_name = crypto_error(
        recipe,
        "namespace de cache SIGSUMS",
        cache_object_name(
            CacheObjectKind::SignedChecksums,
            &binding,
            manifest_url,
            &cert,
            clock,
        ),
    )?;
    let manifest_destination = ctx.cache_dir().join(&manifest_name);
    let mut manifest = obtain_auxiliary(
        ctx,
        manifest_url,
        &manifest_name,
        MAX_SIGNED_CHECKSUM_BYTES,
        "sigsums",
        0,
    )?;

    let (mut detached, detached_destination) = if let Some(url) = detached_signature_url {
        let name = crypto_error(
            recipe,
            "namespace de cache da assinatura SIGSUMS",
            cache_object_name(
                CacheObjectKind::ChecksumsSignature,
                &binding,
                url,
                &cert,
                clock,
            ),
        )?;
        let destination = ctx.cache_dir().join(&name);
        let object = obtain_auxiliary(
            ctx,
            url,
            &name,
            MAX_SIGNATURE_BYTES,
            "assinatura-sigsums",
            0,
        )?;
        (Some(object), Some(destination))
    } else {
        (None, None)
    };

    verify_openpgp_checksums_bytes(
        recipe,
        artifacts,
        &manifest.bytes,
        detached.as_ref().map(|object| object.bytes.as_slice()),
        &cert,
        clock,
    )?;
    manifest.ensure_stable().map_err(|error| crate::Fail {
        code: 7,
        msg: format!("{}: cache SIGSUMS mudou: {error:#}", recipe.name),
    })?;
    if let Some(object) = detached.as_ref() {
        object.ensure_stable().map_err(|error| crate::Fail {
            code: 7,
            msg: format!(
                "{}: cache da assinatura SIGSUMS mudou: {error:#}",
                recipe.name
            ),
        })?;
    }
    let downloaded = manifest.temporary || detached.as_ref().is_some_and(|object| object.temporary);
    if manifest.temporary {
        publish_auxiliary(&ctx.cache_dir(), &mut manifest, &manifest_destination)?;
    }
    if let (Some(object), Some(destination)) = (&mut detached, &detached_destination) {
        if object.temporary {
            publish_auxiliary(&ctx.cache_dir(), object, destination)?;
        }
    }
    if downloaded {
        let final_manifest = manifest.reread().map_err(|error| crate::Fail {
            code: 7,
            msg: format!(
                "{}: cache SIGSUMS publicado é inválido: {error:#}",
                recipe.name
            ),
        })?;
        let final_signature = detached
            .as_mut()
            .map(|object| {
                object.reread().map_err(|error| crate::Fail {
                    code: 7,
                    msg: format!(
                        "{}: assinatura SIGSUMS publicada é inválida: {error:#}",
                        recipe.name
                    ),
                })
            })
            .transpose()?;
        verify_openpgp_checksums_bytes(
            recipe,
            artifacts,
            &final_manifest,
            final_signature.as_deref(),
            &cert,
            clock,
        )?;
    }
    let mut facts = vec![input_fact(
        "checksums",
        format!("recipe:SIGSUMS={manifest_url};EPOCH={signature_epoch}"),
        hex::encode(Sha256::digest(&manifest.bytes)),
    )];
    if let (Some(url), Some(object)) = (detached_signature_url, detached.as_ref()) {
        facts.push(input_fact(
            "signature",
            format!("recipe:SIGSUMS_SIG={url};EPOCH={signature_epoch}"),
            hex::encode(Sha256::digest(&object.bytes)),
        ));
    }
    Ok(facts)
}

fn cache_leaf(path: &Path, cache: &Path) -> Result<CString> {
    if path.parent() != Some(cache) {
        anyhow::bail!(
            "objeto de cache fora do diretório ancorado: {}",
            path.display()
        );
    }
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("objeto de cache sem basename"))?;
    CString::new(name.as_bytes()).context("basename de cache contém NUL")
}

/// Abre a âncora do cache por fd, confirma owner e retira permissões de escrita
/// de grupo/outros antes que qualquer pathname imutável seja publicado. A
/// checagem do nome antes/depois impede operar num diretório substituído.
fn trusted_cache_directory(cache: &Path, repair_permissions: bool) -> Result<fs::File> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(cache)
        .with_context(|| format!("abrindo diretório de cache {}", cache.display()))?;
    let mut metadata = directory.metadata()?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("cache não é diretório real: {}", cache.display());
    }
    // SAFETY: geteuid não dereferencia ponteiro e não tem precondições.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        anyhow::bail!(
            "cache {} pertence ao uid {}, não ao uid efetivo {}",
            cache.display(),
            metadata.uid(),
            effective_uid
        );
    }
    let original_mode = metadata.permissions().mode();
    if original_mode & 0o022 != 0 {
        if !repair_permissions {
            anyhow::bail!(
                "cache somente-leitura permite escrita por grupo/outros: {}",
                cache.display()
            );
        }
        directory.set_permissions(fs::Permissions::from_mode(original_mode & !0o022))?;
        directory.sync_all()?;
        metadata = directory.metadata()?;
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        anyhow::bail!(
            "cache permite escrita por grupo/outros: {}",
            cache.display()
        );
    }
    let named = fs::symlink_metadata(cache)?;
    if !named.file_type().is_dir()
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
        || named.uid() != metadata.uid()
        || named.permissions().mode() != metadata.permissions().mode()
    {
        anyhow::bail!("pathname do diretório de cache foi trocado");
    }
    Ok(directory)
}

/// Remove uma publicação comprometida somente enquanto o nome ainda aponta
/// para o snapshot exato que acabamos de observar. Se houver nova corrida, o
/// arquivo é preservado e a chamada continua falhando fechada.
fn remove_if_same_snapshot(cache: &Path, path: &Path, expected: FileSnapshot) -> Result<bool> {
    let directory = trusted_cache_directory(cache, true)?;
    let observed = fs::symlink_metadata(path)?;
    if FileSnapshot::from_metadata(&observed) != expected {
        return Ok(false);
    }
    let leaf = cache_leaf(path, cache)?;
    // Última observação imediatamente antes de unlinkat. O diretório não é
    // gravável por grupo/outros; apenas processos sob a mesma autoridade do
    // Minitrue ainda poderiam disputar este intervalo.
    let observed = fs::symlink_metadata(path)?;
    if FileSnapshot::from_metadata(&observed) != expected {
        return Ok(false);
    }
    // SAFETY: `directory` e `leaf` são válidos; flags zero removem só arquivo.
    let status = unsafe { libc::unlinkat(directory.as_raw_fd(), leaf.as_ptr(), 0) };
    if status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(true)
}

/// Publica sem jamais substituir um nome existente. `false` significa que
/// outro processo venceu a corrida; o chamador reabre e reverifica o vencedor.
fn publish_noreplace(cache: &Path, temporary: &Path, destination: &Path) -> Result<bool> {
    let directory = trusted_cache_directory(cache, true)?;
    let source = cache_leaf(temporary, cache)?;
    let target = cache_leaf(destination, cache)?;
    match crate::linux::renameat2(
        directory.as_raw_fd(),
        &source,
        directory.as_raw_fd(),
        &target,
        libc::RENAME_NOREPLACE,
    ) {
        Ok(()) => {
            directory.sync_all()?;
            Ok(true)
        }
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(false),
        Err(error) => Err(error.into()),
    }
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
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
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
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
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
    let mut file = open_regular_nofollow(p, MAX_PINNED_OBJECT_BYTES, "objeto para SHA-256")?;
    let (hash, _) = sha256_fd_stable(&mut file, MAX_PINNED_OBJECT_BYTES, "objeto para SHA-256")?;
    Ok(hash)
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
    const PRIMARY: &str = "AA1CF9EC4AE71CA1BF646C3AFCC8AE079B1EAEC6";
    const ARTIFACT_HASH: &str = "76f06b835e1cfcfb00c69194f3d74a74d89ee85fb845e4a4ee0a3e7689b1aa19";
    const SIGNATURE_EPOCH: u64 = 1_767_225_721;
    const PUBLIC_KEY: &[u8] = include_bytes!("../tests/fixtures/openpgp/public.asc");
    const ARTIFACT: &[u8] = include_bytes!("../tests/fixtures/openpgp/artifact-1.0.tar.xz");
    const ARTIFACT_SIGNATURE: &[u8] =
        include_bytes!("../tests/fixtures/openpgp/artifact-1.0.tar.xz.asc");
    const CHECKSUMS: &[u8] = include_bytes!("../tests/fixtures/openpgp/sha256sums.txt");
    const CHECKSUMS_SIGNATURE: &[u8] =
        include_bytes!("../tests/fixtures/openpgp/sha256sums.txt.asc");
    const CLEARSIGNED_CHECKSUMS: &[u8] = include_bytes!("../tests/fixtures/openpgp/sha256sums.asc");

    fn openpgp_case(fields: &str) -> (PathBuf, Ctx, Recipe) {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-fetch-openpgp-{}-{serial}", std::process::id()));
        let recipe_dir = root.join("var/lib/minitrue/newspeak/foo");
        fs::create_dir_all(recipe_dir.join("files")).unwrap();
        fs::write(recipe_dir.join("files/test.asc"), PUBLIC_KEY).unwrap();
        fs::set_permissions(
            recipe_dir.join("files/test.asc"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::write(
            recipe_dir.join("recipe"),
            format!(
                "NAME=foo\nVERSION=1\nKIND=source\nLICENSE=NOASSERTION\nSRC=https://up.invalid/artifact-1.0.tar.xz\nSHA256={ARTIFACT_HASH}\n{fields}\nbuild(){{ :; }}\n"
            ),
        )
        .unwrap();
        let cache = root.join("var/cache/minitrue");
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(cache.join(ARTIFACT_HASH), ARTIFACT).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let recipe = crate::recipe::load(&ctx, "foo").unwrap();
        (root, ctx, recipe)
    }

    fn copy_real_recipe(project: &Path, root: &Path, package: &str) {
        let source = project.join("newspeak").join(package);
        let destination = root.join("var/lib/minitrue/newspeak").join(package);
        fs::create_dir_all(destination.join("files")).unwrap();
        fs::copy(source.join("recipe"), destination.join("recipe")).unwrap();
        for entry in fs::read_dir(source.join("files")).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            fs::copy(
                entry.path(),
                destination.join("files").join(entry.file_name()),
            )
            .unwrap();
        }
    }

    fn real_waiver_case(package: &str, artifact_fixture: &str) -> (PathBuf, Ctx, Recipe) {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-fetch-waiver-{package}-{}-{serial}",
            std::process::id()
        ));
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("minitrue deve viver dentro do projeto");
        copy_real_recipe(project, &root, package);
        let cache = root.join("var/cache/minitrue");
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let recipe = crate::recipe::load(&ctx, package).unwrap();
        assert_eq!(recipe.sha256.len(), 1);
        fs::copy(
            project
                .join("minitrue/tests/fixtures/openpgp")
                .join(artifact_fixture),
            cache.join(&recipe.sha256[0]),
        )
        .unwrap();
        (root, ctx, recipe)
    }

    fn real_mathlibs_case() -> (PathBuf, Ctx, Recipe) {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-fetch-waiver-mathlibs-{}-{serial}",
            std::process::id()
        ));
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("minitrue deve viver dentro do projeto");
        copy_real_recipe(project, &root, "mathlibs-glibc");
        let cache = root.join("var/cache/minitrue");
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let recipe = crate::recipe::load(&ctx, "mathlibs-glibc").unwrap();
        for (hash, fixture) in
            recipe
                .sha256
                .iter()
                .zip(["gmp-6.3.0.tar.xz", "mpfr-4.2.2.tar.xz", "mpc-1.4.1.tar.xz"])
        {
            fs::copy(
                project
                    .join("minitrue/tests/fixtures/openpgp")
                    .join(fixture),
                cache.join(hash),
            )
            .unwrap();
        }
        let SignaturePlan::IndexedArtifacts { artifacts } = &recipe.signature_plan else {
            panic!("mathlibs deve usar plano indexado misto")
        };
        let detached = artifacts
            .iter()
            .find_map(|spec| match spec {
                IndexedArtifactSignature::OpenPgpDetached(spec) => Some(spec),
                IndexedArtifactSignature::UnsafeUpstreamWaiver { .. } => None,
            })
            .expect("MPFR normal ausente");
        assert_eq!(detached.src_index, 2);
        let cert = pinned_openpgp_cert(&recipe, &detached.key).unwrap();
        let clock = SignatureClock::from_unix_seconds(detached.signature_epoch).unwrap();
        let cache_name = cache_object_name(
            CacheObjectKind::DetachedSignature,
            &recipe.sha256[1],
            &detached.signature_url,
            &cert,
            clock,
        )
        .unwrap();
        fs::copy(
            project.join("minitrue/tests/fixtures/openpgp/mpfr-4.2.2.tar.xz.sig"),
            cache.join(cache_name),
        )
        .unwrap();
        (root, ctx, recipe)
    }

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
        assert!(open_regular_nofollow(&link, 1024, "teste").is_err());

        let hardlink = root.join("hardlink");
        fs::hard_link(&victim, &hardlink).unwrap();
        assert!(open_regular_nofollow(&hardlink, 1024, "teste").is_err());

        let fifo = root.join("fifo");
        let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString válida, modo ordinário.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(open_regular_nofollow(&fifo, 1024, "teste").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn openpgp_detached_offline_revalida_cache_e_preserva_codigo_sete() {
        let fields = format!(
            "SIG_1=https://up.invalid/artifact-1.0.tar.xz.asc\nSIG_EPOCH_1={SIGNATURE_EPOCH}\nSIGKEY_1=files/test.asc\nSIGKEY_FP_1={PRIMARY}"
        );
        let (root, ctx, recipe) = openpgp_case(&fields);
        let SignaturePlan::OpenPgpDetached { artifacts } = &recipe.signature_plan else {
            panic!("plano OpenPGP esperado")
        };
        let cert = pinned_openpgp_cert(&recipe, &artifacts[0].key).unwrap();
        let clock = SignatureClock::from_unix_seconds(SIGNATURE_EPOCH).unwrap();
        let cache_name = cache_object_name(
            CacheObjectKind::DetachedSignature,
            ARTIFACT_HASH,
            &artifacts[0].signature_url,
            &cert,
            clock,
        )
        .unwrap();
        let signature_path = ctx.cache_dir().join(cache_name);
        fs::write(&signature_path, ARTIFACT_SIGNATURE).unwrap();

        let got = ensure_artifacts(&ctx, &recipe).unwrap();
        assert_eq!(got[0].1, ARTIFACT_HASH);

        fs::write(&signature_path, b"assinatura adulterada\n").unwrap();
        let error = ensure_artifacts(&ctx, &recipe).unwrap_err();
        assert_eq!(error.downcast_ref::<crate::Fail>().unwrap().code, 7);
        let _ = fs::remove_dir_all(root);
    }

    fn populate_sigsums_cache(ctx: &Ctx, recipe: &Recipe, detached: bool) {
        let SignaturePlan::OpenPgpChecksums {
            manifest_url,
            detached_signature_url,
            key,
            signature_epoch,
        } = &recipe.signature_plan
        else {
            panic!("plano SIGSUMS esperado")
        };
        let cert = pinned_openpgp_cert(recipe, key).unwrap();
        let clock = SignatureClock::from_unix_seconds(*signature_epoch).unwrap();
        let manifest_name = cache_object_name(
            CacheObjectKind::SignedChecksums,
            ARTIFACT_HASH,
            manifest_url,
            &cert,
            clock,
        )
        .unwrap();
        fs::write(
            ctx.cache_dir().join(manifest_name),
            if detached {
                CHECKSUMS
            } else {
                CLEARSIGNED_CHECKSUMS
            },
        )
        .unwrap();
        if let Some(url) = detached_signature_url {
            let name = cache_object_name(
                CacheObjectKind::ChecksumsSignature,
                ARTIFACT_HASH,
                url,
                &cert,
                clock,
            )
            .unwrap();
            fs::write(ctx.cache_dir().join(name), CHECKSUMS_SIGNATURE).unwrap();
        }
    }

    #[test]
    fn ambos_sigsums_integrados_reusam_hash_do_mesmo_fd() {
        let clear_fields = format!(
            "SIGSUMS=https://up.invalid/sha256sums.asc\nSIGSUMS_EPOCH={SIGNATURE_EPOCH}\nSIGKEY_1=files/test.asc\nSIGKEY_FP_1={PRIMARY}"
        );
        let (clear_root, clear_ctx, clear_recipe) = openpgp_case(&clear_fields);
        populate_sigsums_cache(&clear_ctx, &clear_recipe, false);
        ensure_artifacts(&clear_ctx, &clear_recipe).unwrap();
        let _ = fs::remove_dir_all(clear_root);

        let detached_fields = format!(
            "SIGSUMS=https://up.invalid/sha256sums.txt\nSIGSUMS_SIG=https://up.invalid/sha256sums.txt.asc\nSIGSUMS_EPOCH={SIGNATURE_EPOCH}\nSIGKEY_1=files/test.asc\nSIGKEY_FP_1={PRIMARY}"
        );
        let (detached_root, detached_ctx, detached_recipe) = openpgp_case(&detached_fields);
        populate_sigsums_cache(&detached_ctx, &detached_recipe, true);
        ensure_artifacts(&detached_ctx, &detached_recipe).unwrap();
        let _ = fs::remove_dir_all(detached_root);
    }

    #[test]
    fn waivers_v2_e_v3_revalidam_provas_reais_no_runtime_offline() {
        for (package, fixture, expected_facts) in [
            ("gmp", "gmp-6.3.0.tar.xz", 5),
            ("mpc", "mpc-1.4.1.tar.xz", 6),
        ] {
            let (root, ctx, recipe) = real_waiver_case(package, fixture);
            let authenticated = ensure_artifacts_authenticated(&ctx, &recipe).unwrap();
            assert_eq!(authenticated.artifacts[0].1, recipe.sha256[0]);
            assert_eq!(authenticated.inputs.len(), expected_facts);
            assert!(authenticated
                .inputs
                .iter()
                .all(|fact| fact.sha256 != "pending"));
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn mathlibs_misto_autentica_tres_src_e_materializa_facts_por_indice() {
        let (root, ctx, recipe) = real_mathlibs_case();
        let authenticated = ensure_artifacts_authenticated(&ctx, &recipe).unwrap();
        assert_eq!(authenticated.artifacts.len(), 3);
        assert_eq!(
            authenticated
                .artifacts
                .iter()
                .map(|(_, hash)| hash.as_str())
                .collect::<Vec<_>>(),
            recipe.sha256.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(authenticated.inputs.len(), 13);
        assert!(authenticated
            .inputs
            .iter()
            .all(|fact| fact.sha256 != "pending"));
        let identifiers: std::collections::BTreeSet<_> = authenticated
            .inputs
            .iter()
            .map(|fact| fact.identifier.as_str())
            .collect();
        assert_eq!(identifiers.len(), authenticated.inputs.len());
        assert!(identifiers
            .iter()
            .any(|value| value.starts_with("recipe:SIG_UNSAFE_WAIVER[1]=")));
        assert!(identifiers
            .iter()
            .any(|value| value.starts_with("recipe:SIG_UNSAFE_WAIVER[3]=")));
        assert!(identifiers
            .iter()
            .filter(|value| value.contains("recipe:WAIVER_"))
            .all(|value| value.ends_with(";SRC_INDEX=1") || value.ends_with(";SRC_INDEX=3")));
        assert!(identifiers
            .iter()
            .any(|value| value.starts_with("recipe:SIG[2]=")));
        assert!(identifiers
            .iter()
            .any(|value| value.starts_with("recipe:SIGKEY[2]=")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mathlibs_indexado_fecha_plan_canonico_e_persistivel() {
        let (root, ctx, _) = real_mathlibs_case();
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("minitrue deve viver dentro do projeto");
        let tree = root.join("var/lib/minitrue/newspeak");
        fs::remove_dir_all(&tree).unwrap();
        let package = tree.join("mathlibs-glibc");
        fs::create_dir_all(package.join("files")).unwrap();
        for entry in fs::read_dir(project.join("newspeak/mathlibs-glibc/files")).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            fs::copy(entry.path(), package.join("files").join(entry.file_name())).unwrap();
        }
        let original = fs::read_to_string(project.join("newspeak/mathlibs-glibc/recipe")).unwrap();
        let mut recipe = String::from("NAME=mathlibs-glibc\nVERSION=6.3.0\nKIND=binary\n");
        for line in original.lines() {
            if line.starts_with("LICENSE=")
                || line.starts_with("SRC=")
                || line.starts_with("SHA256=")
                || line.starts_with("SIG_")
                || line.starts_with("SIGKEY_")
            {
                recipe.push_str(line);
                recipe.push('\n');
            }
        }
        recipe.push_str("install_pkg() { :; }\n");
        fs::write(package.join("recipe"), recipe).unwrap();

        let mut plan = crate::plan::resolve(
            &ctx,
            &["mathlibs-glibc".to_string()],
            crate::install::BinaryPolicy::PreferBinary,
            crate::plan::AbiPolicy::Development,
            crate::channel::LoadMode::Mutating,
        )
        .unwrap();
        plan.authenticate_objects(&ctx, false).unwrap();
        plan.revalidate_tree(&ctx).unwrap();
        let bytes = plan.canonical_bytes().unwrap();
        crate::plan::verify_canonical(&bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(text.matches("SRC_INDEX=1").count(), 4);
        assert_eq!(text.matches("recipe:SIG%5B2%5D=").count(), 1);
        assert_eq!(text.matches("recipe:SIGKEY%5B2%5D=").count(), 1);
        assert_eq!(text.matches("SRC_INDEX=3").count(), 5);
        let lock = plan.persist(&ctx).unwrap();
        assert!(root
            .join("var/lib/minitrue/plan-locks")
            .join(format!("{lock}.lock"))
            .is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pathname_trocado_e_publicacao_sobrescrita_falham_fechados() {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-fetch-race-{}-{serial}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("artifact");
        fs::write(&path, ARTIFACT).unwrap();
        let artifact = ArtifactFile::open(path.clone()).unwrap();
        fs::rename(&path, root.join("old")).unwrap();
        fs::write(&path, ARTIFACT).unwrap();
        assert!(artifact.ensure_stable().is_err());

        let temporary = root.join("temporary");
        let destination = root.join("destination");
        fs::write(&temporary, b"novo").unwrap();
        fs::write(&destination, b"existente").unwrap();
        assert!(!publish_noreplace(&root, &temporary, &destination).unwrap());
        assert_eq!(fs::read(&destination).unwrap(), b"existente");
        assert_eq!(fs::read(&temporary).unwrap(), b"novo");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn auxiliar_trocado_nunca_e_publicado_nem_removido_pelo_drop() {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("mt-fetch-aux-race-{}-{serial}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let temporary = root.join("temporary");
        let displaced = root.join("displaced");
        let destination = root.join("immutable");
        fs::write(&temporary, b"assinatura verificada").unwrap();
        let mut object = AuxiliaryObject::open(temporary.clone(), 1024, "auxiliar", true).unwrap();

        // Simula o swap depois da leitura criptográfica, antes do rename.
        fs::rename(&temporary, &displaced).unwrap();
        fs::write(&temporary, b"veneno").unwrap();
        assert!(publish_auxiliary(&root, &mut object, &destination).is_err());
        drop(object);

        assert!(!destination.exists());
        assert_eq!(fs::read(&temporary).unwrap(), b"veneno");
        assert_eq!(fs::read(&displaced).unwrap(), b"assinatura verificada");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn limpeza_condicional_preserva_inode_que_venceu_nova_corrida() {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-fetch-conditional-unlink-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("published");
        fs::write(&path, b"primeiro").unwrap();
        let old = FileSnapshot::from_metadata(&fs::symlink_metadata(&path).unwrap());
        fs::rename(&path, root.join("old")).unwrap();
        fs::write(&path, b"vencedor").unwrap();

        assert!(!remove_if_same_snapshot(&root, &path, old).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"vencedor");
        let current = FileSnapshot::from_metadata(&fs::symlink_metadata(&path).unwrap());
        assert!(remove_if_same_snapshot(&root, &path, current).unwrap());
        assert!(!path.exists());
        let _ = fs::remove_dir_all(root);
    }
}
