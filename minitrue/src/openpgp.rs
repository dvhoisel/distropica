//! Verificação OpenPGP hermética para artefatos upstream (SPEC-0004 §5).
//!
//! Este módulo deliberadamente não sabe buscar chaves, assinaturas ou
//! manifestos. Todos os bytes entram pelo chamador, vindos da árvore
//! `newspeak` ou do cache local. Não há keyserver, trustdb, `gpg`, relógio
//! implícito nem fallback de confiança: a âncora é o fingerprint primário
//! canônico pinado na receita e o instante da política é sempre o `SIG_EPOCH`
//! explícito daquele objeto — nunca o `EPOCH` de build.

use anyhow::{anyhow, bail, Context, Result};
use sequoia_openpgp as openpgp;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::cert::CertParser;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, GoodChecksum, MessageLayer, MessageStructure, VerificationHelper,
    VerifierBuilder,
};
use openpgp::parse::Parse;
use openpgp::policy::{AsymmetricAlgorithm, HashAlgoSecurity, StandardPolicy};
use openpgp::serialize::SerializeInto;
use openpgp::types::{HashAlgorithm, SignatureType};
use openpgp::{Cert, Fingerprint, KeyHandle};

/// Identidade do contrato criptográfico e do namespace de cache.
pub const OPENPGP_ENGINE_FORMAT: &str = "3";

/// Chaves públicas versionadas devem ser pequenas. Um keyring inteiro ou uma
/// resposta de keyserver não é uma chave pinada de receita.
pub const MAX_PUBLIC_KEY_BYTES: usize = 1024 * 1024;
/// Uma assinatura destacada normal tem poucos KiB; 1 MiB já acomoda folga sem
/// permitir que o parser vire um sumidouro de memória.
pub const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;
/// Listas kernel.org crescem com o tempo, mas ficam muito abaixo de 16 MiB.
pub const MAX_SIGNED_CHECKSUM_BYTES: usize = 16 * 1024 * 1024;
/// Mesmo teto já usado pelo cache de fontes do Minitrue.
pub const MAX_SIGNED_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Instante reprodutível no qual certificado, subchave, assinatura e política
/// são avaliados. Nunca se passa `None` para a Sequoia (que usaria o relógio).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureClock {
    signature_epoch: u64,
    system_time: SystemTime,
}

impl SignatureClock {
    pub fn from_sig_epoch(value: &str) -> Result<Self> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            bail!("SIG_EPOCH deve ser inteiro decimal canônico");
        }
        let seconds: u64 = value.parse().context("SIG_EPOCH excede u64")?;
        Self::from_unix_seconds(seconds)
    }

    pub fn from_unix_seconds(seconds: u64) -> Result<Self> {
        // Os timestamps OpenPGP v4 são u32. Recusar um horizonte que o formato
        // não consegue representar evita conversões diferentes entre backends.
        if seconds > u32::MAX as u64 {
            bail!("SIG_EPOCH excede o horizonte OpenPGP u32");
        }
        let system_time = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| anyhow!("SIG_EPOCH fora do SystemTime"))?;
        Ok(Self {
            signature_epoch: seconds,
            system_time,
        })
    }

    pub fn signature_epoch(self) -> u64 {
        self.signature_epoch
    }

    fn system_time(self) -> SystemTime {
        self.system_time
    }
}

/// Política criptográfica versionada do motor. O instante também é preso no
/// objeto de política: `StandardPolicy::new()` consultaria o relógio dentro de
/// `Policy::signature`, mesmo que o parser recebesse um tempo explícito.
///
/// Compatibilidade legada existe só na certificação: SHA-1 onde Sequoia exige
/// resistência à segunda pré-imagem e DSA-1024 para validar selfsig/binding.
/// O helper recusa explicitamente DSA e SHA-1 na assinatura que cobre os dados,
/// mesmo quando o certificado precisa dessas exceções para ligar uma subchave
/// RSA moderna à primária histórica.
fn verification_policy(clock: SignatureClock) -> StandardPolicy<'static> {
    let mut policy = StandardPolicy::at(clock.system_time());
    policy.accept_hash_property(
        HashAlgorithm::SHA1,
        HashAlgoSecurity::SecondPreImageResistance,
    );
    policy.accept_asymmetric_algo(AsymmetricAlgorithm::DSA1024);
    policy
}

/// Chave pública local, já reduzida à âncora de confiança da receita.
#[derive(Clone)]
pub struct PinnedCert {
    cert: Cert,
    primary: Fingerprint,
    allowed_signers: BTreeSet<Fingerprint>,
    transport_sha256: String,
}

impl std::fmt::Debug for PinnedCert {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedCert")
            .field("primary", &self.primary.to_string())
            .field(
                "allowed_signers",
                &self
                    .allowed_signers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .field("transport_sha256", &self.transport_sha256)
            .finish_non_exhaustive()
    }
}

impl PinnedCert {
    /// Carrega exatamente um certificado público e coteja o fingerprint da
    /// chave primária. `allowed_signers`, quando não vazio, estreita ainda
    /// mais a política a fingerprints de chaves/subchaves daquele certificado.
    pub fn from_bytes(
        bytes: &[u8],
        expected_primary: &str,
        allowed_signers: &[String],
    ) -> Result<Self> {
        if bytes.is_empty() {
            bail!("SIGKEY OpenPGP vazia");
        }
        if bytes.len() > MAX_PUBLIC_KEY_BYTES {
            bail!("SIGKEY OpenPGP excede {MAX_PUBLIC_KEY_BYTES} bytes");
        }

        let primary = canonical_fingerprint(expected_primary, "SIGKEY_FP")?;
        let mut parsed = CertParser::from_bytes(bytes).context("SIGKEY OpenPGP mal-formada")?;
        let cert = parsed
            .next()
            .ok_or_else(|| anyhow!("SIGKEY OpenPGP não contém certificado"))?
            .context("SIGKEY OpenPGP contém certificado inválido")?;
        if let Some(extra) = parsed.next() {
            // Mesmo um segundo certificado inválido é material extra: não se
            // escolhe silenciosamente uma chave dentro de um keyring.
            let detail = extra
                .err()
                .map(|error| format!(" ({error})"))
                .unwrap_or_default();
            bail!("SIGKEY OpenPGP contém mais de um certificado{detail}");
        }
        if cert.is_tsk() {
            bail!("SIGKEY OpenPGP contém material secreto");
        }
        if cert.fingerprint() != primary {
            bail!(
                "SIGKEY_FP diverge da chave primária: esperado {}, obtido {}",
                primary,
                cert.fingerprint()
            );
        }

        let cert_keys: BTreeSet<Fingerprint> =
            cert.keys().map(|key| key.key().fingerprint()).collect();
        let mut signers = BTreeSet::new();
        for signer in allowed_signers {
            let fingerprint = canonical_fingerprint(signer, "fingerprint de subchave")?;
            if !cert_keys.contains(&fingerprint) {
                bail!(
                    "fingerprint de subchave {} não pertence à primária {}",
                    fingerprint,
                    primary
                );
            }
            if !signers.insert(fingerprint.clone()) {
                bail!("fingerprint de subchave repetido: {fingerprint}");
            }
        }

        Ok(Self {
            cert,
            primary,
            allowed_signers: signers,
            transport_sha256: sha256_bytes(bytes),
        })
    }

    pub fn primary_fingerprint(&self) -> String {
        self.primary.to_string()
    }

    pub fn transport_sha256(&self) -> &str {
        &self.transport_sha256
    }

    /// Expiração que a selfsig efetivamente válida seleciona no instante
    /// explícito. Usado pelo waiver v2 para cotejar o epoch declarado, sem
    /// consultar o relógio nem aceitar uma selfsig criada no futuro.
    pub fn primary_expiration_epoch_at(&self, clock: SignatureClock) -> Result<Option<u64>> {
        let policy = verification_policy(clock);
        let valid = self
            .cert
            .with_policy(&policy, clock.system_time())
            .context("certificado não é válido no VALIDATION_EPOCH")?;
        valid
            .primary_key()
            .key_expiration_time()
            .map(|expiration| {
                expiration
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .map_err(|_| anyhow!("expiração do certificado antecede Unix epoch"))
            })
            .transpose()
    }
}

/// Reproduz as regras de extração dos waivers v2/v3 sem confiar no
/// transporte. O certificado reduzido precisa ser literalmente primária + um
/// User ID + sua selfsig, e cada packet precisa existir byte por byte no
/// certificado-fonte de uma única primária. O fingerprint autentica a chave;
/// a prova de subconjunto impede injetar uma selfsig obtida de outro material.
pub fn pinned_primary_cert_subset(
    source_bytes: &[u8],
    extracted_bytes: &[u8],
    expected_primary: &str,
) -> Result<PinnedCert> {
    let source = PinnedCert::from_bytes(source_bytes, expected_primary, &[])?;
    let extracted = PinnedCert::from_bytes(extracted_bytes, expected_primary, &[])?;
    require_cert_packets_subset(&source.cert, &extracted, true)?;
    Ok(extracted)
}

/// Variante de extração para um keyring multi-cert versionado. Nenhum cert
/// é escolhido por key ID curto: a seleção usa a primária completa e o
/// certificado reduzido ainda precisa ser subconjunto packet-a-packet.
pub fn pinned_cert_from_keyring_subset(
    source_bytes: &[u8],
    extracted_bytes: &[u8],
    expected_primary: &str,
) -> Result<PinnedCert> {
    const MAX_EVIDENCE_KEYRING_BYTES: usize = 8 * 1024 * 1024;
    if source_bytes.is_empty() || source_bytes.len() > MAX_EVIDENCE_KEYRING_BYTES {
        bail!("keyring de evidência vazio ou grande demais");
    }
    let primary = canonical_fingerprint(expected_primary, "PRIMARY_FINGERPRINT")?;
    let mut selected = None;
    for parsed in CertParser::from_bytes(source_bytes).context("keyring de evidência inválido")? {
        let cert = parsed.context("keyring de evidência contém certificado inválido")?;
        if cert.fingerprint() == primary && selected.replace(cert).is_some() {
            bail!("keyring de evidência repete a primária pinada");
        }
    }
    let source = selected.ok_or_else(|| anyhow!("keyring não contém a primária pinada"))?;
    if source.is_tsk() {
        bail!("keyring de evidência contém material secreto da primária");
    }
    let extracted = PinnedCert::from_bytes(extracted_bytes, expected_primary, &[])?;
    require_cert_packets_subset(&source, &extracted, false)?;
    Ok(extracted)
}

fn require_cert_packets_subset(
    source: &Cert,
    extracted: &PinnedCert,
    require_minimal_primary: bool,
) -> Result<()> {
    let extracted_packets: Vec<_> = extracted.cert.clone().into_packets().collect();
    if require_minimal_primary
        && (extracted_packets.len() != 3
            || !matches!(extracted_packets[0], openpgp::Packet::PublicKey(_))
            || !matches!(extracted_packets[1], openpgp::Packet::UserID(_))
            || !matches!(extracted_packets[2], openpgp::Packet::Signature(_))
            || extracted.cert.keys().count() != 1)
    {
        bail!("certificado extraído deve ser exatamente primária+UID+selfsig");
    }

    let mut source_packets: Vec<Vec<u8>> = source
        .clone()
        .into_packets()
        .map(|packet| {
            packet
                .to_vec()
                .context("falha ao serializar packet do certificado-fonte")
        })
        .collect::<Result<_>>()?;
    for packet in extracted_packets {
        let bytes = packet
            .to_vec()
            .context("falha ao serializar packet do certificado extraído")?;
        let Some(position) = source_packets
            .iter()
            .position(|candidate| candidate == &bytes)
        else {
            bail!("certificado extraído contém packet ausente do certificado-fonte");
        };
        source_packets.swap_remove(position);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedDataSignatureMetadata {
    pub primary_fingerprint: String,
    pub signature_creation_epoch: u64,
    pub signing_pk_algorithm: u8,
    pub signing_key_bits: usize,
    pub dsa_q_bits: usize,
    pub hash_algorithm: u8,
    pub signature_type: SignatureType,
}

/// Inspeciona a prova factual do waiver v1 sem jamais validá-la como
/// assinatura aceitável. O packet precisa ser exatamente DSA-1024/q160 +
/// SHA-1 emitido pela primária pinada; o chamador ainda exige que o motor
/// normal recuse a assinatura sobre o artefato real.
pub fn inspect_rejected_dsa_sha1(
    signature_bytes: &[u8],
    cert: &PinnedCert,
    expected_creation_epoch: u64,
) -> Result<RejectedDataSignatureMetadata> {
    require_nonempty_bounded(
        signature_bytes,
        MAX_SIGNATURE_BYTES,
        "assinatura recusada do waiver v1",
    )?;
    SignatureClock::from_unix_seconds(expected_creation_epoch)?;
    let pile = openpgp::PacketPile::from_bytes(signature_bytes)
        .context("assinatura recusada do waiver v1 mal-formada")?;
    let packets: Vec<_> = pile.descendants().collect();
    if packets.len() != 1 {
        bail!("waiver v1 exige exatamente um packet de assinatura");
    }
    let openpgp::Packet::Signature(signature) = packets[0] else {
        bail!("waiver v1 não contém packet de assinatura");
    };
    let primary = cert.cert.primary_key().key();
    let openpgp::crypto::mpi::PublicKey::DSA { p, q, .. } = primary.mpis() else {
        bail!("waiver v1 exige primária DSA");
    };
    if signature.typ() != SignatureType::Binary
        || u8::from(signature.pk_algo()) != 17
        || signature.hash_algo() != HashAlgorithm::SHA1
        || p.bits() != 1024
        || q.bits() != 160
    {
        bail!("waiver v1 factual não é DSA-1024/q160 + SHA1 binário");
    }
    let creation_epoch = signature
        .signature_creation_time()
        .ok_or_else(|| anyhow!("assinatura v1 não declara creation time"))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("assinatura v1 antecede Unix epoch"))?
        .as_secs();
    if creation_epoch != expected_creation_epoch {
        bail!("SIGNATURE_EPOCH v1 diverge do packet factual");
    }
    let issuers = signature.get_issuers();
    let primary_handle = KeyHandle::from(cert.primary.clone());
    if issuers.is_empty()
        || issuers
            .iter()
            .any(|issuer| !issuer.aliases(primary_handle.clone()))
    {
        bail!("issuer do waiver v1 não é a primária pinada");
    }
    Ok(RejectedDataSignatureMetadata {
        primary_fingerprint: cert.primary.to_string(),
        signature_creation_epoch: creation_epoch,
        signing_pk_algorithm: 17,
        signing_key_bits: p.bits(),
        dsa_q_bits: q.bits(),
        hash_algorithm: u8::from(HashAlgorithm::SHA1),
        signature_type: signature.typ(),
    })
}

/// Prova mínima devolvida pelo motor e adequada para diagnóstico/evidência.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub primary_fingerprint: String,
    pub signing_fingerprint: String,
    pub signature_creation_epoch: u64,
    pub verification_epoch: u64,
    pub signature_type: SignatureType,
    pub signing_pk_algorithm: u8,
    pub signing_key_bits: Option<usize>,
    pub hash_algorithm: u8,
}

#[derive(Clone)]
struct StrictHelper {
    cert: Cert,
    primary: Fingerprint,
    allowed_signers: BTreeSet<Fingerprint>,
    require_cleartext_framework: bool,
    verification_epoch: u64,
    report: Option<VerificationReport>,
}

impl StrictHelper {
    fn new(cert: &PinnedCert, require_cleartext_framework: bool, verification_epoch: u64) -> Self {
        Self {
            cert: cert.cert.clone(),
            primary: cert.primary.clone(),
            allowed_signers: cert.allowed_signers.clone(),
            require_cleartext_framework,
            verification_epoch,
            report: None,
        }
    }

    fn accept(&mut self, good: &GoodChecksum<'_>) -> Result<()> {
        let observed_primary = good.ka.cert().fingerprint();
        if observed_primary != self.primary {
            bail!(
                "assinatura OpenPGP validou sob primária não pinada: {}",
                observed_primary
            );
        }
        let signing = good.ka.key().fingerprint();
        if !self.allowed_signers.is_empty() && !self.allowed_signers.contains(&signing) {
            bail!("assinatura OpenPGP usa subchave não pinada: {}", signing);
        }
        // `verification_policy` admite DSA-1024 somente para que uma primária
        // antiga autentique selfsigs/bindings. Nunca deixe essa compatibilidade
        // alcançar a assinatura do artefato ou manifesto propriamente dita.
        if u8::from(good.sig.pk_algo()) == 17 || u8::from(good.ka.key().pk_algo()) == 17 {
            bail!("assinatura OpenPGP de dados usa DSA, proibido pelo motor");
        }
        if good.sig.hash_algo() == HashAlgorithm::SHA1 {
            bail!("assinatura OpenPGP de dados usa SHA-1, proibido pelo motor");
        }
        let signature_type = good.sig.typ();
        let expected_type = if self.require_cleartext_framework {
            SignatureType::Text
        } else {
            SignatureType::Binary
        };
        if signature_type != expected_type {
            bail!(
                "tipo de assinatura OpenPGP inesperado: esperado {:?}, obtido {:?}",
                expected_type,
                signature_type,
            );
        }
        let creation = good
            .sig
            .signature_creation_time()
            .ok_or_else(|| anyhow!("assinatura OpenPGP não declara creation time"))?;
        let creation_epoch = creation
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow!("assinatura OpenPGP antecede o Unix epoch"))?
            .as_secs();
        if creation_epoch > self.verification_epoch {
            bail!("assinatura OpenPGP foi criada após o instante de verificação pinado");
        }
        if let Some(expiration) = good.ka.key_expiration_time() {
            let expiration_epoch = expiration
                .duration_since(UNIX_EPOCH)
                .map_err(|_| anyhow!("expiração da chave antecede Unix epoch"))?
                .as_secs();
            if self.verification_epoch >= expiration_epoch {
                bail!(
                    "chave OpenPGP expirou em {expiration_epoch} antes do instante pinado {}",
                    self.verification_epoch
                );
            }
        }
        self.report = Some(VerificationReport {
            primary_fingerprint: observed_primary.to_string(),
            signing_fingerprint: signing.to_string(),
            signature_creation_epoch: creation_epoch,
            verification_epoch: self.verification_epoch,
            signature_type,
            signing_pk_algorithm: u8::from(good.ka.key().pk_algo()),
            signing_key_bits: good.ka.key().mpis().bits(),
            hash_algorithm: u8::from(good.sig.hash_algo()),
        });
        Ok(())
    }

    fn finish(self) -> Result<VerificationReport> {
        self.report
            .ok_or_else(|| anyhow!("assinatura OpenPGP não produziu prova válida"))
    }
}

impl VerificationHelper for StrictHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        // A chave vem exclusivamente da receita; `ids` nunca dispara busca,
        // trustdb ou consulta de rede.
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
        if structure.processed_csf_message() != self.require_cleartext_framework {
            bail!("envelope OpenPGP inesperado para o mecanismo declarado");
        }
        let mut layers = structure.into_iter();
        let layer = layers
            .next()
            .ok_or_else(|| anyhow!("mensagem OpenPGP sem camada de assinatura"))?;
        if layers.next().is_some() {
            bail!("mensagem OpenPGP contém camadas extras");
        }
        let MessageLayer::SignatureGroup { mut results } = layer else {
            bail!("mensagem OpenPGP não é um grupo simples de assinatura");
        };
        if results.len() != 1 {
            bail!(
                "esperada exatamente uma assinatura OpenPGP, obtidas {}",
                results.len()
            );
        }
        let good = results
            .pop()
            .expect("comprimento conferido")
            .map_err(openpgp::Error::from)?;
        self.accept(&good)
    }
}

/// Verifica uma assinatura destacada contra os bytes exatos do artefato. O
/// `Read` é drenado até EOF e limitado, portanto não se materializa um tarball
/// de vários GiB em memória.
pub fn verify_detached<R>(
    artifact: R,
    signature: &[u8],
    cert: &PinnedCert,
    clock: SignatureClock,
) -> Result<VerificationReport>
where
    R: Read + Send + Sync,
{
    require_nonempty_bounded(signature, MAX_SIGNATURE_BYTES, "assinatura OpenPGP")?;
    let helper = StrictHelper::new(cert, false, clock.signature_epoch());
    let policy = verification_policy(clock);
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
        .context("assinatura OpenPGP destacada mal-formada")?
        .with_policy(&policy, clock.system_time(), helper)
        .context("assinatura OpenPGP recusada pela política")?;
    verifier
        .verify_reader(BoundedReader::new(artifact, MAX_SIGNED_ARTIFACT_BYTES))
        .context("assinatura OpenPGP destacada não confere")?;
    verifier.into_helper().finish()
}

/// Exceção matemática deliberadamente separada do motor normal para o
/// waiver v3. Ela cobre somente DSA com p=2048/q=256 e SHA-256, emitido pela
/// própria primária pinada. Não concede validade temporal ao certificado: as
/// páginas oficiais versionadas pelo waiver são a âncora do fingerprint, e
/// esta rotina comprova apenas que aquela primária assinou os bytes exatos.
///
/// O caminho normal [`verify_detached`] continua recusando qualquer DSA sobre
/// dados. Manter uma API separada torna impossível ativar a exceção por engano
/// numa receita `SIG_n`/`SIGSUMS`.
pub fn verify_legacy_dsa_waiver<R>(
    artifact: R,
    signature_bytes: &[u8],
    cert: &PinnedCert,
    expected_creation_epoch: u64,
) -> Result<VerificationReport>
where
    R: Read,
{
    require_nonempty_bounded(
        signature_bytes,
        MAX_SIGNATURE_BYTES,
        "assinatura DSA do waiver v3",
    )?;
    SignatureClock::from_unix_seconds(expected_creation_epoch)?;

    let pile = openpgp::PacketPile::from_bytes(signature_bytes)
        .context("assinatura DSA do waiver v3 mal-formada")?;
    let packets: Vec<_> = pile.descendants().collect();
    if packets.len() != 1 {
        bail!(
            "waiver v3 exige exatamente um packet de assinatura, obtidos {}",
            packets.len()
        );
    }
    let openpgp::Packet::Signature(signature) = packets[0] else {
        bail!("waiver v3 não contém packet de assinatura");
    };
    if signature.typ() != SignatureType::Binary
        || u8::from(signature.pk_algo()) != 17
        || signature.hash_algo() != HashAlgorithm::SHA256
    {
        bail!("waiver v3 exige assinatura binária DSA-2048-Q256/SHA256");
    }
    let creation_epoch = signature
        .signature_creation_time()
        .ok_or_else(|| anyhow!("assinatura DSA do waiver v3 não declara creation time"))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("assinatura DSA do waiver v3 antecede o Unix epoch"))?
        .as_secs();
    if creation_epoch != expected_creation_epoch {
        bail!(
            "creation time DSA diverge do waiver: esperado {expected_creation_epoch}, obtido {creation_epoch}"
        );
    }

    let primary = cert.cert.primary_key().key();
    let openpgp::crypto::mpi::PublicKey::DSA { p, q, .. } = primary.mpis() else {
        bail!("waiver v3 exige chave primária DSA");
    };
    if p.bits() != 2048 || q.bits() != 256 {
        bail!(
            "waiver v3 exige DSA p=2048/q=256, obtido p={}/q={}",
            p.bits(),
            q.bits()
        );
    }
    let issuers = signature.get_issuers();
    let primary_handle = KeyHandle::from(cert.primary.clone());
    if issuers.is_empty()
        || issuers
            .iter()
            .any(|issuer| !issuer.aliases(primary_handle.clone()))
    {
        bail!("issuer DSA do waiver v3 não é a primária pinada");
    }

    let mut hash = HashAlgorithm::SHA256
        .context()
        .context("backend não oferece SHA-256 para waiver v3")?
        .for_signature(signature.version());
    if let Some(salt) = signature.salt() {
        hash.update(salt);
    }
    let mut reader = BoundedReader::new(artifact, MAX_SIGNED_ARTIFACT_BYTES);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("falha ao ler artefato para waiver v3")?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    signature
        .verify_hash(primary, hash)
        .context("prova matemática DSA do waiver v3 não confere")?;

    Ok(VerificationReport {
        primary_fingerprint: cert.primary.to_string(),
        signing_fingerprint: primary.fingerprint().to_string(),
        signature_creation_epoch: creation_epoch,
        verification_epoch: expected_creation_epoch,
        signature_type: signature.typ(),
        signing_pk_algorithm: u8::from(signature.pk_algo()),
        signing_key_bits: primary.mpis().bits(),
        hash_algorithm: u8::from(signature.hash_algo()),
    })
}

/// Verifica uma lista de checksums assinada pelo Cleartext Signature
/// Framework e exige a linha SHA-256 exata do artefato.
pub fn verify_clearsigned_checksums(
    signed_checksums: &[u8],
    cert: &PinnedCert,
    clock: SignatureClock,
    artifact_name: &str,
    expected_sha256: &str,
) -> Result<VerificationReport> {
    require_nonempty_bounded(
        signed_checksums,
        MAX_SIGNED_CHECKSUM_BYTES,
        "SIGSUMS clearsigned",
    )?;
    let helper = StrictHelper::new(cert, true, clock.signature_epoch());
    let policy = verification_policy(clock);
    let mut verifier = VerifierBuilder::from_bytes(signed_checksums)
        .context("SIGSUMS clearsigned mal-formado")?
        .with_policy(&policy, clock.system_time(), helper)
        .context("SIGSUMS clearsigned recusado pela política")?;
    let mut cleartext = Vec::new();
    verifier
        .read_to_end(&mut cleartext)
        .context("assinatura do SIGSUMS clearsigned não confere")?;
    if cleartext.len() > MAX_SIGNED_CHECKSUM_BYTES {
        bail!("conteúdo autenticado de SIGSUMS excede {MAX_SIGNED_CHECKSUM_BYTES} bytes");
    }
    require_checksum_line(&cleartext, artifact_name, expected_sha256)?;
    verifier.into_helper().finish()
}

/// Verifica o padrão CMake: manifesto em claro mais assinatura OpenPGP
/// destacada. Só depois da assinatura conferir a lista é interpretada.
pub fn verify_detached_checksums(
    checksums: &[u8],
    signature: &[u8],
    cert: &PinnedCert,
    clock: SignatureClock,
    artifact_name: &str,
    expected_sha256: &str,
) -> Result<VerificationReport> {
    require_nonempty_bounded(checksums, MAX_SIGNED_CHECKSUM_BYTES, "manifesto SIGSUMS")?;
    let report = verify_detached(io::Cursor::new(checksums), signature, cert, clock)?;
    require_checksum_line(checksums, artifact_name, expected_sha256)?;
    Ok(report)
}

/// Namespace determinístico para objetos auxiliares do cache. O nome inclui
/// toda a decisão de confiança disponível antes do download; ainda assim o
/// consumidor deve reabrir e reverificar o objeto a cada uso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheObjectKind {
    DetachedSignature,
    SignedChecksums,
    ChecksumsSignature,
}

impl CacheObjectKind {
    fn label(self) -> &'static str {
        match self {
            Self::DetachedSignature => "detached-signature",
            Self::SignedChecksums => "signed-checksums",
            Self::ChecksumsSignature => "checksums-signature",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::DetachedSignature => "openpgp-sig",
            Self::SignedChecksums => "openpgp-sums",
            Self::ChecksumsSignature => "openpgp-sums-sig",
        }
    }
}

pub fn cache_object_name(
    kind: CacheObjectKind,
    artifact_sha256: &str,
    object_url: &str,
    cert: &PinnedCert,
    clock: SignatureClock,
) -> Result<String> {
    require_sha256(artifact_sha256, "SHA256 do artefato")?;
    require_https_url(object_url, "URL do objeto OpenPGP")?;
    let mut digest = Sha256::new();
    digest.update(b"minitrue-openpgp-cache\0");
    let primary = cert.primary_fingerprint();
    let epoch = clock.signature_epoch().to_string();
    for value in [
        OPENPGP_ENGINE_FORMAT,
        kind.label(),
        artifact_sha256,
        object_url,
        primary.as_str(),
        cert.transport_sha256(),
        epoch.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update((cert.allowed_signers.len() as u64).to_be_bytes());
    for signer in &cert.allowed_signers {
        let signer = signer.to_string();
        digest.update((signer.len() as u64).to_be_bytes());
        digest.update(signer.as_bytes());
    }
    Ok(format!(
        "{}.{}",
        hex::encode(digest.finalize()),
        kind.suffix()
    ))
}

fn canonical_fingerprint(value: &str, field: &str) -> Result<Fingerprint> {
    let valid_len = value.len() == 40 || value.len() == 64;
    if !valid_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        bail!("{field} deve ser fingerprint OpenPGP hexadecimal maiúsculo canônico");
    }
    value
        .parse::<Fingerprint>()
        .with_context(|| format!("{field} não representa fingerprint OpenPGP"))
}

fn require_nonempty_bounded(bytes: &[u8], maximum: usize, label: &str) -> Result<()> {
    if bytes.is_empty() {
        bail!("{label} vazio");
    }
    if bytes.len() > maximum {
        bail!("{label} excede {maximum} bytes");
    }
    Ok(())
}

fn require_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} deve ser SHA-256 hexadecimal minúsculo canônico");
    }
    Ok(())
}

fn require_https_url(value: &str, field: &str) -> Result<()> {
    let parsed = url::Url::parse(value).with_context(|| format!("{field} inválida"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        bail!("{field} deve ser HTTPS sem credenciais nem fragmento");
    }
    Ok(())
}

fn require_artifact_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.bytes().any(|byte| {
            byte == b'/'
                || byte == b'\\'
                || byte == 0
                || byte.is_ascii_control()
                || byte.is_ascii_whitespace()
        })
    {
        bail!("nome do artefato no SIGSUMS não é basename canônico");
    }
    Ok(())
}

pub(crate) fn require_checksum_line(
    manifest: &[u8],
    artifact_name: &str,
    expected_sha256: &str,
) -> Result<()> {
    require_artifact_name(artifact_name)?;
    require_sha256(expected_sha256, "SHA256 esperado")?;
    let text = std::str::from_utf8(manifest).context("SIGSUMS autenticado não é UTF-8")?;
    let mut observed: Option<String> = None;
    let mut names = BTreeSet::new();
    for (number, raw_line) in text.lines().enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.len() < 67 {
            bail!("SIGSUMS: linha {} mal-formada", number + 1);
        }
        let (hash, remainder) = line.split_at(64);
        if !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("SIGSUMS: linha {} não começa com SHA-256", number + 1);
        }
        let name = if let Some(name) = remainder.strip_prefix("  ") {
            name
        } else if let Some(name) = remainder.strip_prefix(" *") {
            name
        } else {
            bail!("SIGSUMS: separador inválido na linha {}", number + 1);
        };
        require_artifact_name(name)
            .with_context(|| format!("SIGSUMS: filename inválido na linha {}", number + 1))?;
        if !names.insert(name.to_string()) {
            bail!("SIGSUMS repete a entrada de {name}");
        }
        if name == artifact_name {
            observed = Some(hash.to_ascii_lowercase());
        }
    }
    let observed = observed.ok_or_else(|| anyhow!("SIGSUMS não contém {artifact_name}"))?;
    if observed != expected_sha256 {
        bail!(
            "SIGSUMS diverge para {artifact_name}: esperado {expected_sha256}, obtido {observed}"
        );
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    exhausted_limit: bool,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            remaining: maximum,
            exhausted_limit: false,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            if self.exhausted_limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artefato OpenPGP excede o limite",
                ));
            }
            let mut extra = [0u8; 1];
            let read = self.inner.read(&mut extra)?;
            if read == 0 {
                return Ok(0);
            }
            self.exhausted_limit = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artefato OpenPGP excede o limite",
            ));
        }
        let allowed = usize::try_from(self.remaining.min(output.len() as u64))
            .expect("limitado pelo tamanho de output");
        let read = self.inner.read(&mut output[..allowed])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}
