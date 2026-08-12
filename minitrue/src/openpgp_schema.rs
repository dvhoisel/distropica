//! Schema fail-closed dos campos de assinatura da SPEC-0004 §5.
//!
//! O coletor literal existe para que os novos campos OpenPGP não precisem ser
//! obtidos com `. recipe`/`source`: substituição de comando, expansão de
//! variável e efeitos colaterais de shell são recusados antes da semântica.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpKeySpec {
    pub transport: String,
    pub primary_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedArtifactSpec {
    /// Índice humano/canônico da SPEC (`SRC_1`, nunca zero-based).
    pub src_index: usize,
    pub signature_url: String,
    pub key: OpenPgpKeySpec,
    pub signature_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexedArtifactSignature {
    OpenPgpDetached(DetachedArtifactSpec),
    UnsafeUpstreamWaiver {
        /// Índice humano/canônico da SPEC (`SRC_1`, nunca zero-based).
        src_index: usize,
        transport: String,
    },
}

pub const MAX_UNSAFE_SIGNATURE_WAIVER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureWaiverCommon {
    pub review_date: String,
    pub review_epoch: u64,
    pub package: String,
    pub version: String,
    pub artifact_url: String,
    pub artifact_sha256: String,
    pub signature_url: String,
    pub signature_sha256: String,
    pub signature_epoch: u64,
    pub primary_fingerprint: String,
    pub signature_algorithm: String,
    pub signature_hash: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsecureDataSignatureWaiver {
    pub common: SignatureWaiverCommon,
    pub signature_file: String,
    pub public_key_source_file: String,
    pub public_key_source_url: String,
    pub public_key_source_sha256: String,
    pub public_key_cert_file: String,
    pub public_key_extraction: String,
    pub public_key_cert_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredSignerSignatureWaiver {
    pub common: SignatureWaiverCommon,
    pub signature_file: String,
    pub validation_epoch: u64,
    pub validation_cert_source_file: String,
    pub validation_cert_source_url: String,
    pub validation_cert_source_sha256: String,
    pub validation_cert_file: String,
    pub validation_cert_extraction: String,
    pub validation_cert_sha256: String,
    pub validation_cert_expiry_epoch: u64,
    pub official_endorsement_file: String,
    pub official_endorsement_url: String,
    pub official_endorsement_sha256: String,
    pub official_endorsement_page_date: String,
    pub endorsement_observed_epoch: u64,
    pub official_endorsement_extraction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDsaDataSignatureWaiver {
    pub common: SignatureWaiverCommon,
    pub signature_file: String,
    pub cert_transport_file: String,
    pub cert_transport_url: String,
    pub cert_transport_sha256: String,
    pub cert_file: String,
    pub cert_extraction: String,
    pub cert_sha256: String,
    pub official_release_page_file: String,
    pub official_release_page_url: String,
    pub official_release_page_sha256: String,
    pub official_release_page_last_modified: String,
    pub official_release_page_extraction: String,
    pub official_fingerprint_page_file: String,
    pub official_fingerprint_page_url: String,
    pub official_fingerprint_page_sha256: String,
    pub official_fingerprint_page_last_modified: String,
    pub official_fingerprint_page_extraction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsafeSignatureWaiver {
    InsecureData(InsecureDataSignatureWaiver),
    ExpiredSigner(ExpiredSignerSignatureWaiver),
    LegacyDsaData(LegacyDsaDataSignatureWaiver),
}

impl UnsafeSignatureWaiver {
    pub fn common(&self) -> &SignatureWaiverCommon {
        match self {
            Self::InsecureData(waiver) => &waiver.common,
            Self::ExpiredSigner(waiver) => &waiver.common,
            Self::LegacyDsaData(waiver) => &waiver.common,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignaturePlan {
    None,
    /// Renúncia explícita e auditável quando o upstream publica somente uma
    /// assinatura que a política criptográfica recusa. Não autentica o
    /// artefato e nunca relaxa o motor; o SHA-256 continua obrigatório.
    UnsafeUpstreamWaiver {
        transport: String,
    },
    /// Compatibilidade do Zig: continua no motor minisign já existente.
    LegacyMinisign {
        signature_urls: Vec<String>,
        public_key: String,
    },
    OpenPgpDetached {
        artifacts: Vec<DetachedArtifactSpec>,
    },
    /// Plano bijetivo para receitas multi-SRC nas quais alguns artefatos usam
    /// OpenPGP normal e outros exigem um waiver estrito. Cada SRC aparece
    /// exatamente uma vez e mecanismos não podem se sobrepor no mesmo índice.
    IndexedArtifacts {
        artifacts: Vec<IndexedArtifactSignature>,
    },
    OpenPgpChecksums {
        manifest_url: String,
        /// `None` significa Cleartext Signature Framework (kernel.org).
        /// `Some` significa manifesto + assinatura destacada (CMake).
        detached_signature_url: Option<String>,
        key: OpenPgpKeySpec,
        signature_epoch: u64,
    },
}

/// Extrai somente campos OpenPGP novos, como atribuições literais no cabeçalho
/// da receita. Não executa shell e não expande sequer `$VERSION`: as migrações
/// devem registrar URLs/fingerprints/chaves como valores completos revisáveis.
pub fn collect_literal_openpgp_fields(recipe: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(recipe).context("recipe não é UTF-8")?;
    let mut fields = BTreeMap::new();
    let mut function_section = false;
    for (line_number, raw) in text.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if starts_recipe_function(trimmed) {
            function_section = true;
            continue;
        }
        let Some((name, raw_value)) = trimmed.split_once('=') else {
            if contains_openpgp_identifier(trimmed) {
                bail!("campo OpenPGP mal-formado na linha {}", line_number + 1);
            }
            continue;
        };
        if !looks_like_openpgp_field(name) {
            if contains_openpgp_identifier(name) {
                bail!(
                    "campo OpenPGP deve usar atribuição literal direta (linha {})",
                    line_number + 1
                );
            }
            continue;
        }
        if function_section {
            bail!(
                "campo OpenPGP fora do cabeçalho declarativo (linha {})",
                line_number + 1
            );
        }
        if trimmed.len() != line.len() {
            bail!(
                "campo OpenPGP deve começar na coluna 1 (linha {})",
                line_number + 1
            );
        }
        if name != name.trim() || name.is_empty() {
            bail!(
                "nome de campo OpenPGP inválido na linha {}",
                line_number + 1
            );
        }
        let value = literal_assignment_value(raw_value)
            .with_context(|| format!("campo {name} na linha {}", line_number + 1))?;
        if fields.insert(name.to_string(), value).is_some() {
            bail!("campo OpenPGP {name} atribuído mais de uma vez");
        }
    }
    Ok(fields)
}

/// Interpreta os valores já coletados. O mapa pode também incluir os dois
/// campos legacy (`SIG`, `SIGKEY`) para que o chamador escolha um único plano.
pub fn parse_signature_plan(
    src_count: usize,
    fields: &BTreeMap<String, String>,
) -> Result<SignaturePlan> {
    for (name, value) in fields {
        if looks_like_signature_field(name) || name == "SIGKEY" {
            reject_shell_material(name, value)?;
        }
        if name.starts_with("SIG") && !is_known_signature_field(name) {
            bail!("campo de assinatura desconhecido: {name}");
        }
        if value.is_empty() {
            bail!("campo de assinatura {name} não pode ser vazio");
        }
    }
    if src_count == 0 {
        if !fields.is_empty() {
            bail!("receita sem SRC não pode declarar assinatura upstream");
        }
        return Ok(SignaturePlan::None);
    }

    let legacy_sig = nonempty(fields, "SIG");
    let legacy_key = nonempty(fields, "SIGKEY");
    let sigsums = nonempty(fields, "SIGSUMS");
    let sigsums_signature = nonempty(fields, "SIGSUMS_SIG");
    let sigsums_epoch = nonempty(fields, "SIGSUMS_EPOCH");
    let unsafe_waiver = nonempty(fields, "SIG_UNSAFE_WAIVER");
    let indexed = indexed_names(fields)?;

    if fields.contains_key("SIG_UNSAFE_WAIVER") {
        let transport =
            unsafe_waiver.ok_or_else(|| anyhow!("SIG_UNSAFE_WAIVER não pode ser vazio"))?;
        if src_count != 1 {
            bail!("SIG_UNSAFE_WAIVER v1 exige exatamente um SRC");
        }
        if fields.keys().any(|name| name != "SIG_UNSAFE_WAIVER") {
            bail!("SIG_UNSAFE_WAIVER não pode ser misturado com assinatura upstream");
        }
        require_waiver_transport(transport)?;
        return Ok(SignaturePlan::UnsafeUpstreamWaiver {
            transport: transport.to_string(),
        });
    }

    // Este nome existiu durante o desenho inicial do schema, mas nunca deve
    // virar um pino global implícito: cada chave OpenPGP pertence ao artefato
    // indexado correspondente (ou a SIGKEY_FP_1 no caso de SIGSUMS).
    if fields.contains_key("SIGKEY_FP") {
        bail!("SIGKEY_FP sem índice não é permitido");
    }

    if legacy_sig.is_some() || legacy_key.is_some() {
        if sigsums.is_some()
            || sigsums_signature.is_some()
            || sigsums_epoch.is_some()
            || !indexed.is_empty()
        {
            bail!("minisign legacy não pode ser misturado com OpenPGP/SIGSUMS");
        }
        let signatures = legacy_sig.ok_or_else(|| anyhow!("SIGKEY sem SIG"))?;
        let key = legacy_key.ok_or_else(|| anyhow!("SIG sem SIGKEY"))?;
        let signature_urls: Vec<String> = signatures
            .split_ascii_whitespace()
            .map(str::to_string)
            .collect();
        if signature_urls.len() != src_count {
            bail!("SIG e SRC com contagens diferentes");
        }
        for url in &signature_urls {
            require_https_url(url, "SIG")?;
        }
        if key.starts_with("files/") || key.contains("BEGIN") || key.split_whitespace().count() != 1
        {
            bail!("SIGKEY minisign legacy deve ser chave base64 em uma linha");
        }
        return Ok(SignaturePlan::LegacyMinisign {
            signature_urls,
            public_key: key.to_string(),
        });
    }

    if sigsums_signature.is_some() && sigsums.is_none() {
        bail!("SIGSUMS_SIG exige SIGSUMS");
    }
    if sigsums_epoch.is_some() && sigsums.is_none() {
        bail!("SIGSUMS_EPOCH exige SIGSUMS");
    }
    if let Some(manifest_url) = sigsums {
        if indexed.iter().any(|(_, family)| *family == "SIG") {
            bail!("SIGSUMS e SIG_n são mecanismos mutuamente exclusivos");
        }
        let permitted: BTreeSet<(usize, &'static str)> =
            [(1, "SIGKEY"), (1, "SIGKEY_FP")].into_iter().collect();
        if let Some((index, family)) = indexed.iter().find(|entry| !permitted.contains(*entry)) {
            bail!("SIGSUMS não permite {family}_{index}");
        }
        require_https_url(manifest_url, "SIGSUMS")?;
        let detached_signature_url = sigsums_signature
            .map(|url| {
                require_https_url(url, "SIGSUMS_SIG")?;
                Ok::<_, anyhow::Error>(url.to_string())
            })
            .transpose()?;
        let key = indexed_key(fields, 1)?;
        let signature_epoch = parse_signature_epoch(
            sigsums_epoch.ok_or_else(|| anyhow!("SIGSUMS exige SIGSUMS_EPOCH"))?,
            "SIGSUMS_EPOCH",
        )?;
        return Ok(SignaturePlan::OpenPgpChecksums {
            manifest_url: manifest_url.to_string(),
            detached_signature_url,
            key,
            signature_epoch,
        });
    }

    if indexed.is_empty() {
        return Ok(SignaturePlan::None);
    }
    parse_indexed_artifact_plan(src_count, fields, &indexed)
}

const NORMAL_INDEXED_FAMILIES: [&str; 4] = ["SIG", "SIG_EPOCH", "SIGKEY", "SIGKEY_FP"];

/// Fecha a bijeção posicional entre o namespace OpenPGP indexado e `SRC`.
///
/// Um slot possui exatamente uma das duas formas abaixo:
///
/// - a tuple normal completa `SIG_n`/`SIG_EPOCH_n`/`SIGKEY_n`/`SIGKEY_FP_n`;
/// - somente `SIG_UNSAFE_WAIVER_n`.
///
/// A presença de waiver em qualquer outro slot não relaxa a tuple normal.
/// Percorrer todo `1..=src_count`, depois de recusar índices externos, torna
/// buracos, campos cruzados e sobreposição falhas do schema, antes do motor.
fn parse_indexed_artifact_plan(
    src_count: usize,
    fields: &BTreeMap<String, String>,
    indexed: &BTreeSet<(usize, &'static str)>,
) -> Result<SignaturePlan> {
    if let Some((index, family)) = indexed
        .iter()
        .find(|(index, _)| *index == 0 || *index > src_count)
    {
        bail!("{family}_{index} não corresponde a nenhum SRC");
    }
    let has_indexed_waiver = indexed
        .iter()
        .any(|(_, family)| *family == "SIG_UNSAFE_WAIVER");
    if has_indexed_waiver && src_count < 2 {
        bail!("SIG_UNSAFE_WAIVER_n é exclusivo de receita multi-SRC");
    }
    let mut indexed_artifacts = Vec::with_capacity(src_count);
    for index in 1..=src_count {
        let waiver = nonempty(fields, &format!("SIG_UNSAFE_WAIVER_{index}"));
        let present_normal: Vec<&str> = NORMAL_INDEXED_FAMILIES
            .into_iter()
            .filter(|family| fields.contains_key(&format!("{family}_{index}")))
            .collect();
        if let Some(transport) = waiver {
            if !present_normal.is_empty() {
                bail!("SRC_{index} não pode misturar waiver e OpenPGP normal");
            }
            require_indexed_waiver_transport(transport, index)?;
            indexed_artifacts.push(IndexedArtifactSignature::UnsafeUpstreamWaiver {
                src_index: index,
                transport: transport.to_string(),
            });
            continue;
        }

        if present_normal.len() != NORMAL_INDEXED_FAMILIES.len() {
            let missing = NORMAL_INDEXED_FAMILIES
                .into_iter()
                .filter(|family| !present_normal.contains(family))
                .map(|family| format!("{family}_{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("SRC_{index} exige tuple OpenPGP normal completa; campos ausentes: {missing}");
        }

        let signature = required_indexed(fields, "SIG", index)?;
        require_https_url(signature, &format!("SIG_{index}"))?;
        let detached = DetachedArtifactSpec {
            src_index: index,
            signature_url: signature.to_string(),
            key: indexed_key(fields, index)?,
            signature_epoch: parse_signature_epoch(
                required_indexed(fields, "SIG_EPOCH", index)?,
                &format!("SIG_EPOCH_{index}"),
            )?,
        };
        indexed_artifacts.push(IndexedArtifactSignature::OpenPgpDetached(detached));
    }
    if has_indexed_waiver {
        Ok(SignaturePlan::IndexedArtifacts {
            artifacts: indexed_artifacts,
        })
    } else {
        let detached_artifacts = indexed_artifacts
            .into_iter()
            .map(|artifact| match artifact {
                IndexedArtifactSignature::OpenPgpDetached(detached) => detached,
                IndexedArtifactSignature::UnsafeUpstreamWaiver { .. } => {
                    unreachable!("has_indexed_waiver=false exclui waiver")
                }
            })
            .collect();
        Ok(SignaturePlan::OpenPgpDetached {
            artifacts: detached_artifacts,
        })
    }
}

fn indexed_key(fields: &BTreeMap<String, String>, index: usize) -> Result<OpenPgpKeySpec> {
    let transport = required_indexed(fields, "SIGKEY", index)?;
    require_key_transport(transport, &format!("SIGKEY_{index}"))?;
    let fingerprint = required_indexed(fields, "SIGKEY_FP", index)?;
    require_fingerprint(fingerprint, &format!("SIGKEY_FP_{index}"))?;
    Ok(OpenPgpKeySpec {
        transport: transport.to_string(),
        primary_fingerprint: fingerprint.to_string(),
    })
}

fn indexed_names(fields: &BTreeMap<String, String>) -> Result<BTreeSet<(usize, &'static str)>> {
    let mut result = BTreeSet::new();
    for name in fields.keys() {
        if name == "SIG_UNSAFE_WAIVER" {
            continue;
        }
        let parsed = [
            "SIG_UNSAFE_WAIVER",
            "SIGKEY_FP",
            "SIGKEY",
            "SIG_EPOCH",
            "SIG",
        ]
        .into_iter()
        .find_map(|family| {
            name.strip_prefix(family)
                .and_then(|suffix| suffix.strip_prefix('_'))
                .map(|index| (family, index))
        });
        let Some((family, raw_index)) = parsed else {
            continue;
        };
        if raw_index.is_empty()
            || raw_index.starts_with('0')
            || !raw_index.bytes().all(|byte| byte.is_ascii_digit())
        {
            bail!("índice OpenPGP não canônico em {name}");
        }
        let index: usize = raw_index
            .parse()
            .with_context(|| format!("índice OpenPGP excede usize em {name}"))?;
        if !result.insert((index, family)) {
            bail!("campo OpenPGP repetido: {name}");
        }
    }
    Ok(result)
}

fn required_indexed<'a>(
    fields: &'a BTreeMap<String, String>,
    family: &str,
    index: usize,
) -> Result<&'a str> {
    let name = format!("{family}_{index}");
    nonempty(fields, &name).ok_or_else(|| anyhow!("campo OpenPGP obrigatório ausente: {name}"))
}

fn nonempty<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn literal_assignment_value(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    let value = if raw.starts_with('"') || raw.starts_with('\'') {
        let quote = raw.as_bytes()[0] as char;
        if raw.len() < 2 || !raw.ends_with(quote) {
            bail!("aspas não balanceadas");
        }
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.bytes().any(|byte| {
        byte == b'$'
            || byte == b'`'
            || byte == b'\\'
            || byte == b'\''
            || byte == b'"'
            || byte == b';'
            || byte == b'|'
            || byte == b'&'
            || byte == b'<'
            || byte == b'>'
            || byte.is_ascii_control()
            || byte.is_ascii_whitespace()
    }) {
        bail!("valor deve ser literal único, sem expansão/comando de shell");
    }
    Ok(value.to_string())
}

fn reject_shell_material(name: &str, value: &str) -> Result<()> {
    if value.contains("$(")
        || value.contains('`')
        || value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        bail!("{name} contém substituição/comando de shell");
    }
    Ok(())
}

fn require_key_transport(value: &str, field: &str) -> Result<()> {
    let Some(name) = value.strip_prefix("files/") else {
        bail!("{field} deve apontar para files/*.asc");
    };
    if name.is_empty()
        || !name.ends_with(".asc")
        || name.contains('/')
        || name == ".asc"
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        bail!("{field} deve apontar para basename canônico files/*.asc");
    }
    Ok(())
}

fn require_waiver_transport(value: &str) -> Result<()> {
    let Some(name) = value.strip_prefix("files/") else {
        bail!("SIG_UNSAFE_WAIVER deve apontar para files/assinatura-insegura");
    };
    if name != "assinatura-insegura" {
        bail!("SIG_UNSAFE_WAIVER v1 exige files/assinatura-insegura");
    }
    Ok(())
}

fn require_indexed_waiver_transport(value: &str, index: usize) -> Result<()> {
    let expected = format!("files/assinatura-insegura-{index}");
    if value != expected {
        bail!("SIG_UNSAFE_WAIVER_{index} exige {expected}");
    }
    Ok(())
}

fn require_evidence_transport(value: &str, field: &str) -> Result<()> {
    let Some(name) = value.strip_prefix("files/") else {
        bail!("{field} deve apontar para um auxiliar congelado em files/");
    };
    if name.is_empty()
        || name.contains('/')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        bail!("{field} não é transporte files/ canônico");
    }
    Ok(())
}

/// Interpreta o arquivo de renúncia sem shell, comentários ou campos livres.
/// Cada versão é deliberadamente estreita ao caso factual que documenta:
/// ampliar motivos/algoritmos exige nova versão normativa.
pub fn parse_unsafe_signature_waiver(bytes: &[u8]) -> Result<UnsafeSignatureWaiver> {
    if bytes.is_empty() || bytes.len() > MAX_UNSAFE_SIGNATURE_WAIVER_BYTES {
        bail!("assinatura-insegura vazia ou grande demais");
    }
    if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') || bytes.contains(&0) {
        bail!("assinatura-insegura exige UTF-8/LF canônico com newline final");
    }
    let text = std::str::from_utf8(bytes).context("assinatura-insegura não é UTF-8")?;
    let mut fields = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') || line.trim() != line {
            bail!(
                "assinatura-insegura tem linha vazia/comentário/espaço na linha {}",
                line_number + 1
            );
        }
        let (name, value) = line.split_once('=').ok_or_else(|| {
            anyhow!(
                "assinatura-insegura sem atribuição na linha {}",
                line_number + 1
            )
        })?;
        if name.is_empty()
            || value.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            bail!(
                "assinatura-insegura tem campo inválido na linha {}",
                line_number + 1
            );
        }
        if fields.insert(name, value).is_some() {
            bail!("assinatura-insegura repete {name}");
        }
    }
    match fields.get("FORMAT").copied() {
        Some("minitrue-insecure-upstream-signature-v1") => {
            parse_insecure_data_signature_waiver(&fields)
        }
        Some("minitrue-expired-signer-endorsement-v2") => {
            parse_expired_signer_signature_waiver(&fields)
        }
        Some("minitrue-legacy-dsa-data-math-v3") => parse_legacy_dsa_data_signature_waiver(&fields),
        _ => bail!("FORMAT de assinatura-insegura não suportado"),
    }
}

const COMMON_WAIVER_FIELDS: [&str; 13] = [
    "REVIEW_DATE",
    "REVIEW_EPOCH",
    "PACKAGE",
    "VERSION",
    "ARTIFACT_URL",
    "ARTIFACT_SHA256",
    "SIGNATURE_URL",
    "SIGNATURE_SHA256",
    "SIGNATURE_EPOCH",
    "PRIMARY_FINGERPRINT",
    "SIGNATURE_ALGORITHM",
    "SIGNATURE_HASH",
    "REASON",
];

fn parse_insecure_data_signature_waiver(
    fields: &BTreeMap<&str, &str>,
) -> Result<UnsafeSignatureWaiver> {
    const EXTRA: [&str; 7] = [
        "SIGNATURE_FILE",
        "PUBLIC_KEY_SOURCE_FILE",
        "PUBLIC_KEY_SOURCE_URL",
        "PUBLIC_KEY_SOURCE_SHA256",
        "PUBLIC_KEY_CERT_FILE",
        "PUBLIC_KEY_EXTRACTION",
        "PUBLIC_KEY_CERT_SHA256",
    ];
    require_exact_waiver_fields(fields, &EXTRA, "v1")?;
    let common = parse_waiver_common(fields)?;
    require_evidence_transport(fields["SIGNATURE_FILE"], "SIGNATURE_FILE")?;
    require_evidence_transport(fields["PUBLIC_KEY_SOURCE_FILE"], "PUBLIC_KEY_SOURCE_FILE")?;
    require_https_url(fields["PUBLIC_KEY_SOURCE_URL"], "PUBLIC_KEY_SOURCE_URL")?;
    require_sha256(
        fields["PUBLIC_KEY_SOURCE_SHA256"],
        "PUBLIC_KEY_SOURCE_SHA256",
    )?;
    require_sha256(fields["PUBLIC_KEY_CERT_SHA256"], "PUBLIC_KEY_CERT_SHA256")?;
    require_evidence_transport(fields["PUBLIC_KEY_CERT_FILE"], "PUBLIC_KEY_CERT_FILE")?;
    if !matches!(
        fields["PUBLIC_KEY_EXTRACTION"],
        "HTML_FIRST_ASCII_ARMOR_PUBLIC_KEY_BLOCK" | "OPENPGP_CERT_BY_PRIMARY_FINGERPRINT"
    ) {
        bail!("PUBLIC_KEY_EXTRACTION não é regra fechada do formato v1");
    }
    if common.signature_algorithm != "DSA-1024"
        || common.signature_hash != "SHA1"
        || common.reason != "SHA1_DATA_REJECTED"
    {
        bail!("assinatura-insegura v1 só cobre DSA-1024/SHA1_DATA_REJECTED");
    }
    Ok(UnsafeSignatureWaiver::InsecureData(
        InsecureDataSignatureWaiver {
            common,
            signature_file: fields["SIGNATURE_FILE"].to_string(),
            public_key_source_file: fields["PUBLIC_KEY_SOURCE_FILE"].to_string(),
            public_key_source_url: fields["PUBLIC_KEY_SOURCE_URL"].to_string(),
            public_key_source_sha256: fields["PUBLIC_KEY_SOURCE_SHA256"].to_string(),
            public_key_cert_file: fields["PUBLIC_KEY_CERT_FILE"].to_string(),
            public_key_extraction: fields["PUBLIC_KEY_EXTRACTION"].to_string(),
            public_key_cert_sha256: fields["PUBLIC_KEY_CERT_SHA256"].to_string(),
        },
    ))
}

fn parse_expired_signer_signature_waiver(
    fields: &BTreeMap<&str, &str>,
) -> Result<UnsafeSignatureWaiver> {
    const EXTRA: [&str; 15] = [
        "SIGNATURE_FILE",
        "VALIDATION_EPOCH",
        "VALIDATION_CERT_SOURCE_FILE",
        "VALIDATION_CERT_SOURCE_URL",
        "VALIDATION_CERT_SOURCE_SHA256",
        "VALIDATION_CERT_FILE",
        "VALIDATION_CERT_EXTRACTION",
        "VALIDATION_CERT_SHA256",
        "VALIDATION_CERT_EXPIRY_EPOCH",
        "OFFICIAL_ENDORSEMENT_FILE",
        "OFFICIAL_ENDORSEMENT_URL",
        "OFFICIAL_ENDORSEMENT_SHA256",
        "OFFICIAL_ENDORSEMENT_PAGE_DATE",
        "ENDORSEMENT_OBSERVED_EPOCH",
        "OFFICIAL_ENDORSEMENT_EXTRACTION",
    ];
    require_exact_waiver_fields(fields, &EXTRA, "v2")?;
    let common = parse_waiver_common(fields)?;
    require_evidence_transport(fields["SIGNATURE_FILE"], "SIGNATURE_FILE")?;
    let validation_epoch = parse_signature_epoch(fields["VALIDATION_EPOCH"], "VALIDATION_EPOCH")?;
    let validation_cert_expiry_epoch = parse_signature_epoch(
        fields["VALIDATION_CERT_EXPIRY_EPOCH"],
        "VALIDATION_CERT_EXPIRY_EPOCH",
    )?;
    if validation_epoch != common.signature_epoch {
        bail!("VALIDATION_EPOCH deve ser exatamente SIGNATURE_EPOCH no formato v2");
    }
    if validation_cert_expiry_epoch <= validation_epoch
        || validation_cert_expiry_epoch >= common.review_epoch
    {
        bail!("certificado v2 deve ser válido na assinatura e expirado na revisão");
    }
    require_https_url(
        fields["VALIDATION_CERT_SOURCE_URL"],
        "VALIDATION_CERT_SOURCE_URL",
    )?;
    require_evidence_transport(
        fields["VALIDATION_CERT_SOURCE_FILE"],
        "VALIDATION_CERT_SOURCE_FILE",
    )?;
    require_sha256(
        fields["VALIDATION_CERT_SOURCE_SHA256"],
        "VALIDATION_CERT_SOURCE_SHA256",
    )?;
    require_evidence_transport(fields["VALIDATION_CERT_FILE"], "VALIDATION_CERT_FILE")?;
    require_sha256(fields["VALIDATION_CERT_SHA256"], "VALIDATION_CERT_SHA256")?;
    if fields["VALIDATION_CERT_EXTRACTION"] != "OPENPGP_CERT_BY_PRIMARY_FINGERPRINT_EXPORT_MINIMAL"
    {
        bail!("VALIDATION_CERT_EXTRACTION não é regra fechada do formato v2");
    }
    require_https_url(
        fields["OFFICIAL_ENDORSEMENT_URL"],
        "OFFICIAL_ENDORSEMENT_URL",
    )?;
    require_evidence_transport(
        fields["OFFICIAL_ENDORSEMENT_FILE"],
        "OFFICIAL_ENDORSEMENT_FILE",
    )?;
    require_sha256(
        fields["OFFICIAL_ENDORSEMENT_SHA256"],
        "OFFICIAL_ENDORSEMENT_SHA256",
    )?;
    let endorsement_date = fields["OFFICIAL_ENDORSEMENT_PAGE_DATE"];
    require_canonical_date(endorsement_date, "OFFICIAL_ENDORSEMENT_PAGE_DATE")?;
    let endorsement_observed_epoch = parse_signature_epoch(
        fields["ENDORSEMENT_OBSERVED_EPOCH"],
        "ENDORSEMENT_OBSERVED_EPOCH",
    )?;
    if endorsement_observed_epoch != common.review_epoch {
        bail!("ENDORSEMENT_OBSERVED_EPOCH deve ser exatamente REVIEW_EPOCH");
    }
    if endorsement_date <= unix_utc_date(validation_cert_expiry_epoch).as_str()
        || endorsement_date > common.review_date.as_str()
    {
        bail!("endosso oficial v2 deve ser posterior à expiração e não futuro");
    }
    if fields["OFFICIAL_ENDORSEMENT_EXTRACTION"] != "HTML_EXACT_PRIMARY_FINGERPRINT" {
        bail!("OFFICIAL_ENDORSEMENT_EXTRACTION não é regra fechada do formato v2");
    }
    if common.signature_algorithm != "RSA-2560"
        || common.signature_hash != "SHA512"
        || common.reason != "VALID_AT_CREATION_CERT_EXPIRED_AT_REVIEW_OFFICIAL_FP_REENDORSED"
    {
        bail!("assinatura-insegura v2 só cobre RSA-2560/SHA512 e expiração reendossada");
    }
    Ok(UnsafeSignatureWaiver::ExpiredSigner(
        ExpiredSignerSignatureWaiver {
            common,
            signature_file: fields["SIGNATURE_FILE"].to_string(),
            validation_epoch,
            validation_cert_source_file: fields["VALIDATION_CERT_SOURCE_FILE"].to_string(),
            validation_cert_source_url: fields["VALIDATION_CERT_SOURCE_URL"].to_string(),
            validation_cert_source_sha256: fields["VALIDATION_CERT_SOURCE_SHA256"].to_string(),
            validation_cert_file: fields["VALIDATION_CERT_FILE"].to_string(),
            validation_cert_extraction: fields["VALIDATION_CERT_EXTRACTION"].to_string(),
            validation_cert_sha256: fields["VALIDATION_CERT_SHA256"].to_string(),
            validation_cert_expiry_epoch,
            official_endorsement_file: fields["OFFICIAL_ENDORSEMENT_FILE"].to_string(),
            official_endorsement_url: fields["OFFICIAL_ENDORSEMENT_URL"].to_string(),
            official_endorsement_sha256: fields["OFFICIAL_ENDORSEMENT_SHA256"].to_string(),
            official_endorsement_page_date: endorsement_date.to_string(),
            endorsement_observed_epoch,
            official_endorsement_extraction: fields["OFFICIAL_ENDORSEMENT_EXTRACTION"].to_string(),
        },
    ))
}

fn parse_legacy_dsa_data_signature_waiver(
    fields: &BTreeMap<&str, &str>,
) -> Result<UnsafeSignatureWaiver> {
    const EXTRA: [&str; 17] = [
        "SIGNATURE_FILE",
        "CERT_TRANSPORT_FILE",
        "CERT_TRANSPORT_URL",
        "CERT_TRANSPORT_SHA256",
        "CERT_FILE",
        "CERT_EXTRACTION",
        "CERT_SHA256",
        "OFFICIAL_RELEASE_PAGE_FILE",
        "OFFICIAL_RELEASE_PAGE_URL",
        "OFFICIAL_RELEASE_PAGE_SHA256",
        "OFFICIAL_RELEASE_PAGE_LAST_MODIFIED",
        "OFFICIAL_RELEASE_PAGE_EXTRACTION",
        "OFFICIAL_FINGERPRINT_PAGE_FILE",
        "OFFICIAL_FINGERPRINT_PAGE_URL",
        "OFFICIAL_FINGERPRINT_PAGE_SHA256",
        "OFFICIAL_FINGERPRINT_PAGE_LAST_MODIFIED",
        "OFFICIAL_FINGERPRINT_PAGE_EXTRACTION",
    ];
    require_exact_waiver_fields(fields, &EXTRA, "v3")?;
    let common = parse_waiver_common(fields)?;
    for field in [
        "SIGNATURE_FILE",
        "CERT_TRANSPORT_FILE",
        "CERT_FILE",
        "OFFICIAL_RELEASE_PAGE_FILE",
        "OFFICIAL_FINGERPRINT_PAGE_FILE",
    ] {
        require_evidence_transport(fields[field], field)?;
    }
    for field in [
        "CERT_TRANSPORT_URL",
        "OFFICIAL_RELEASE_PAGE_URL",
        "OFFICIAL_FINGERPRINT_PAGE_URL",
    ] {
        require_https_url(fields[field], field)?;
    }
    for field in [
        "CERT_TRANSPORT_SHA256",
        "CERT_SHA256",
        "OFFICIAL_RELEASE_PAGE_SHA256",
        "OFFICIAL_FINGERPRINT_PAGE_SHA256",
    ] {
        require_sha256(fields[field], field)?;
    }
    if fields["CERT_EXTRACTION"] != "OPENPGP_EXACT_PRIMARY_FROM_SINGLE_CERT"
        || fields["OFFICIAL_RELEASE_PAGE_EXTRACTION"]
            != "HTML_EXACT_RELEASE_SIGNATURE_KEY_LINK_AND_EMAIL"
        || fields["OFFICIAL_FINGERPRINT_PAGE_EXTRACTION"]
            != "HTML_EXACT_PRIMARY_FINGERPRINT_AND_EMAIL"
    {
        bail!("regra de extração não é fechada do formato v3");
    }
    let release_date = fields["OFFICIAL_RELEASE_PAGE_LAST_MODIFIED"];
    let fingerprint_date = fields["OFFICIAL_FINGERPRINT_PAGE_LAST_MODIFIED"];
    require_canonical_date(release_date, "OFFICIAL_RELEASE_PAGE_LAST_MODIFIED")?;
    require_canonical_date(fingerprint_date, "OFFICIAL_FINGERPRINT_PAGE_LAST_MODIFIED")?;
    if release_date > common.review_date.as_str() || fingerprint_date > common.review_date.as_str()
    {
        bail!("página oficial v3 não pode ser futura à revisão");
    }
    if common.signature_algorithm != "DSA-2048-Q256"
        || common.signature_hash != "SHA256"
        || common.reason != "DSA_DATA_OUTSIDE_STANDARD_POLICY_MATH_VERIFIED_OFFICIAL_FP"
    {
        bail!("assinatura-insegura v3 só cobre DSA-2048-Q256/SHA256 matematicamente verificado");
    }
    Ok(UnsafeSignatureWaiver::LegacyDsaData(
        LegacyDsaDataSignatureWaiver {
            common,
            signature_file: fields["SIGNATURE_FILE"].to_string(),
            cert_transport_file: fields["CERT_TRANSPORT_FILE"].to_string(),
            cert_transport_url: fields["CERT_TRANSPORT_URL"].to_string(),
            cert_transport_sha256: fields["CERT_TRANSPORT_SHA256"].to_string(),
            cert_file: fields["CERT_FILE"].to_string(),
            cert_extraction: fields["CERT_EXTRACTION"].to_string(),
            cert_sha256: fields["CERT_SHA256"].to_string(),
            official_release_page_file: fields["OFFICIAL_RELEASE_PAGE_FILE"].to_string(),
            official_release_page_url: fields["OFFICIAL_RELEASE_PAGE_URL"].to_string(),
            official_release_page_sha256: fields["OFFICIAL_RELEASE_PAGE_SHA256"].to_string(),
            official_release_page_last_modified: release_date.to_string(),
            official_release_page_extraction: fields["OFFICIAL_RELEASE_PAGE_EXTRACTION"]
                .to_string(),
            official_fingerprint_page_file: fields["OFFICIAL_FINGERPRINT_PAGE_FILE"].to_string(),
            official_fingerprint_page_url: fields["OFFICIAL_FINGERPRINT_PAGE_URL"].to_string(),
            official_fingerprint_page_sha256: fields["OFFICIAL_FINGERPRINT_PAGE_SHA256"]
                .to_string(),
            official_fingerprint_page_last_modified: fingerprint_date.to_string(),
            official_fingerprint_page_extraction: fields["OFFICIAL_FINGERPRINT_PAGE_EXTRACTION"]
                .to_string(),
        },
    ))
}

fn require_exact_waiver_fields(
    fields: &BTreeMap<&str, &str>,
    extra: &[&str],
    version: &str,
) -> Result<()> {
    let expected: BTreeSet<_> = ["FORMAT"]
        .into_iter()
        .chain(COMMON_WAIVER_FIELDS)
        .chain(extra.iter().copied())
        .collect();
    if fields.len() != expected.len() || fields.keys().any(|name| !expected.contains(name)) {
        bail!("assinatura-insegura não contém exatamente os campos do formato {version}");
    }
    Ok(())
}

fn parse_waiver_common(fields: &BTreeMap<&str, &str>) -> Result<SignatureWaiverCommon> {
    let review_date = fields["REVIEW_DATE"];
    require_canonical_date(review_date, "REVIEW_DATE")?;
    let review_epoch = parse_signature_epoch(fields["REVIEW_EPOCH"], "REVIEW_EPOCH")?;
    let signature_epoch = parse_signature_epoch(fields["SIGNATURE_EPOCH"], "SIGNATURE_EPOCH")?;
    if review_epoch < signature_epoch {
        bail!("REVIEW_EPOCH antecede SIGNATURE_EPOCH");
    }
    if review_date != unix_utc_date(review_epoch) {
        bail!("REVIEW_DATE não corresponde ao dia UTC de REVIEW_EPOCH");
    }
    for (name, value) in [
        ("ARTIFACT_URL", fields["ARTIFACT_URL"]),
        ("SIGNATURE_URL", fields["SIGNATURE_URL"]),
    ] {
        require_https_url(value, name)?;
    }
    for (name, value) in [
        ("ARTIFACT_SHA256", fields["ARTIFACT_SHA256"]),
        ("SIGNATURE_SHA256", fields["SIGNATURE_SHA256"]),
    ] {
        require_sha256(value, name)?;
    }
    require_fingerprint(fields["PRIMARY_FINGERPRINT"], "PRIMARY_FINGERPRINT")?;
    for name in ["PACKAGE", "VERSION"] {
        if !fields[name]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
        {
            bail!("{name} não é canônico em assinatura-insegura");
        }
    }
    Ok(SignatureWaiverCommon {
        review_date: review_date.to_string(),
        review_epoch,
        package: fields["PACKAGE"].to_string(),
        version: fields["VERSION"].to_string(),
        artifact_url: fields["ARTIFACT_URL"].to_string(),
        artifact_sha256: fields["ARTIFACT_SHA256"].to_string(),
        signature_url: fields["SIGNATURE_URL"].to_string(),
        signature_sha256: fields["SIGNATURE_SHA256"].to_string(),
        signature_epoch,
        primary_fingerprint: fields["PRIMARY_FINGERPRINT"].to_string(),
        signature_algorithm: fields["SIGNATURE_ALGORITHM"].to_string(),
        signature_hash: fields["SIGNATURE_HASH"].to_string(),
        reason: fields["REASON"].to_string(),
    })
}

fn require_canonical_date(value: &str, field: &str) -> Result<()> {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        bail!("{field} deve usar YYYY-MM-DD canônico");
    }
    // Rejeita datas como 2026-99-99 sem depender do relógio civil do host.
    let year: i32 = value[..4].parse().context("ano inválido")?;
    let month: u32 = value[5..7].parse().context("mês inválido")?;
    let day: u32 = value[8..10].parse().context("dia inválido")?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days {
        bail!("{field} não é data civil válida");
    }
    Ok(())
}

fn unix_utc_date(epoch: u64) -> String {
    let days = (epoch as i64).div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
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

fn require_fingerprint(value: &str, field: &str) -> Result<()> {
    if !(value.len() == 40 || value.len() == 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        bail!("{field} deve ser fingerprint OpenPGP hexadecimal maiúsculo canônico");
    }
    Ok(())
}

fn parse_signature_epoch(value: &str, field: &str) -> Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("{field} deve ser Unix epoch decimal canônico");
    }
    let epoch: u64 = value
        .parse()
        .with_context(|| format!("{field} excede u64"))?;
    if epoch > u32::MAX as u64 {
        bail!("{field} excede o horizonte OpenPGP u32");
    }
    Ok(epoch)
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

fn starts_recipe_function(line: &str) -> bool {
    fn identifier_prefix(value: &str) -> Option<(&str, &str)> {
        let length = value
            .char_indices()
            .take_while(|(index, character)| {
                if *index == 0 {
                    *character == '_' || character.is_ascii_alphabetic()
                } else {
                    *character == '_' || character.is_ascii_alphanumeric()
                }
            })
            .last()
            .map(|(index, character)| index + character.len_utf8())?;
        Some(value.split_at(length))
    }

    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix("function") {
        if rest
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_whitespace())
        {
            return identifier_prefix(rest.trim_start()).is_some();
        }
    }
    let Some((_name, rest)) = identifier_prefix(line) else {
        return false;
    };
    let Some(after_open) = rest.trim_start().strip_prefix('(') else {
        return false;
    };
    after_open.trim_start().starts_with(')')
}

fn looks_like_openpgp_field(name: &str) -> bool {
    // Colete também famílias desconhecidas. Elas serão recusadas pelo parser,
    // mas precisam passar primeiro pela validação literal: ignorar `SIGFOO`
    // aqui permitiria que `SIGFOO=$(comando)` chegasse ao `source` da receita.
    name.starts_with("SIG")
}

fn contains_openpgp_identifier(line: &str) -> bool {
    line.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(looks_like_openpgp_field)
}

fn looks_like_signature_field(name: &str) -> bool {
    name == "SIG"
        || name == "SIGSUMS"
        || name == "SIGSUMS_SIG"
        || name == "SIGSUMS_EPOCH"
        || name == "SIGKEY_FP"
        || name.starts_with("SIG_")
        || name.starts_with("SIGKEY_")
}

fn is_known_signature_field(name: &str) -> bool {
    matches!(
        name,
        "SIG" | "SIGKEY" | "SIGSUMS" | "SIGSUMS_SIG" | "SIGSUMS_EPOCH" | "SIG_UNSAFE_WAIVER"
    ) || [
        "SIG_UNSAFE_WAIVER",
        "SIGKEY_FP",
        "SIGKEY",
        "SIG_EPOCH",
        "SIG",
    ]
    .into_iter()
    .any(|family| {
        name.strip_prefix(family)
            .and_then(|suffix| suffix.strip_prefix('_'))
            .is_some_and(|index| !index.is_empty())
    })
}
