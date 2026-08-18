//! Resolvedor único e lock tipado da SPEC-0013 §§6–8.
//!
//! `plan`, `rectify` e `cache verify --closure` entram por [`resolve`]. A
//! diferença entre eles é capacidade: leitura não publica snapshot/lock;
//! aplicação só publica os mesmos bytes depois do preflight completo.

use crate::audit;
use crate::channel::{self, LoadMode};
use crate::install::{self, BinaryPolicy};
use crate::recipe::{self, Kind, Recipe};
use crate::{fail, Ctx};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

pub const PLAN_LOCK_FORMAT: &str = "1";
const NEWSPEAK_TREE_FORMAT: &str = "1";
const PLAN_SLICE_FORMAT: &str = "1";
const ARCH: &str = "x86_64";
const MAX_PLAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_PLAN_ENTRIES: usize = 100_000;
const MAX_PUBLICATION_NAME_BYTES: usize = 255;
const MAX_LIVE_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const LIVE_COMPONENT_ENTRY_SCHEMA: &str = "ENTRY_SCHEMA=id|variant|status|materiality|role|artifact_kind|origin_kind|source_id|provenance|license|license_evidence_sha256|input_sha256|payload_sha256|config_sha256|contract_sha256|toolchain_id|toolchain_sha256";
const LIVE_PAYLOAD_SCHEMA: &str = "PAYLOAD_SCHEMA=id|variant|materiality|role|artifact_kind|origin_kind|source_id|provenance|license|license_evidence_sha256|payload_sha256";
static PLAN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn plan_publication_checkpoint(label: &str) -> Result<()> {
    if std::env::var("MINITRUE_PLAN_KILLPOINT").as_deref() == Ok(label) {
        // SAFETY: usado somente para encerrar o processo que executa o teste
        // de recuperação; SIGKILL não possui handler nem estado intermediário.
        unsafe { libc::raise(libc::SIGKILL) };
    }
    if std::env::var("MINITRUE_PLAN_FAULTPOINT").as_deref() == Ok(label) {
        bail!("fault point de publicação PLAN: {label}");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiPolicy {
    Development,
    Strict,
}

impl AbiPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Strict => "strict",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Materiality {
    Runtime,
    CacheOnly,
    IdentityOnly,
}

impl Materiality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::CacheOnly => "cache-only",
            Self::IdentityOnly => "identity-only",
        }
    }

    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Runtime, _) | (_, Self::Runtime) => Self::Runtime,
            (Self::CacheOnly, _) | (_, Self::CacheOnly) => Self::CacheOnly,
            _ => Self::IdentityOnly,
        }
    }

    fn is_material(self) -> bool {
        self != Self::IdentityOnly
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RootRole {
    Install,
    Availability,
}

impl RootRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Availability => "availability",
        }
    }

    fn materiality(self) -> Materiality {
        match self {
            Self::Install => Materiality::Runtime,
            Self::Availability => Materiality::CacheOnly,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanPurpose {
    Rectify,
    Sync,
    CacheClosure,
    Media,
    ChannelEmit,
}

impl PlanPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rectify => "rectify",
            Self::Sync => "sync",
            Self::CacheClosure => "cache-closure",
            Self::Media => "media",
            Self::ChannelEmit => "channel-emit",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "rectify" => Ok(Self::Rectify),
            "sync" => Ok(Self::Sync),
            "cache-closure" => Ok(Self::CacheClosure),
            "media" => Ok(Self::Media),
            "channel-emit" => Ok(Self::ChannelEmit),
            _ => bail!("PURPOSE inválido"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PlanRoot {
    pub name: String,
    pub role: RootRole,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum EdgeKind {
    Runtime,
    Aggregation,
    Build,
    Toolchain,
    Runner,
}

impl EdgeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Aggregation => "aggregation",
            Self::Build => "build",
            Self::Toolchain => "toolchain",
            Self::Runner => "runner",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanAction {
    Keep,
    Meta,
    Vendor,
    Channel,
    Source,
}

impl PlanAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Meta => "meta",
            Self::Vendor => "vendor",
            Self::Channel => "channel",
            Self::Source => "source",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlanNode {
    pub name: String,
    pub version: String,
    pub kind: Kind,
    pub world: &'static str,
    pub action: PlanAction,
    pub origin: String,
    pub fingerprint: String,
    pub materiality: Materiality,
    pub payload_sha256: String,
    pub license: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PlanEdge {
    pub from: String,
    pub kind: EdgeKind,
    pub to: String,
    pub expected_fingerprint: String,
    pub materiality: Materiality,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PlanArtifact {
    package: String,
    origin_kind: String,
    materiality: Materiality,
    transport_sha256: String,
    reprocorr: String,
    channel_index_sha256: String,
    channel_lock_sha256: String,
    producer_plan_lock_sha256: String,
    channel_release_root: String,
    identifier: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AbiRequire {
    package: String,
    object: String,
    namespace: String,
    name: String,
    versions: String,
    provider_package: String,
    provider_object: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AbiProvide {
    package: String,
    object: String,
    namespace: String,
    name: String,
    versions: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AbiStatic {
    package: String,
    object: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AbiPending {
    package: String,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AbiNone {
    package: String,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PlanOrphan {
    pub package: String,
    pub kind: String,
    pub reason: String,
    pub record_fact_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PlanPredictedResidue {
    pub package: String,
    pub kind: String,
    pub reason: String,
    pub expected_fingerprint: String,
    pub action: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialIdentity {
    pub name: String,
    pub version: String,
    pub kind: String,
    pub world: String,
    pub role: String,
    pub fingerprint: String,
    pub payload_sha256: String,
    pub license: String,
    pub material_id: String,
    pub provenance_sha256: String,
    pub provenance_kind: String,
    pub provenance_id: String,
    pub artifacts: Vec<MaterialArtifactIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialArtifactIdentity {
    pub kind: String,
    pub role: String,
    pub transport_sha256: String,
    pub reprocorr: String,
    pub channel_index_sha256: String,
    pub channel_lock_sha256: String,
    pub producer_plan_lock_sha256: String,
    pub channel_release_root: String,
    pub identifier: String,
}

/// Materialidade declarada por um manifesto externo do ambiente vivo. Ela é
/// separada de [`Materiality`]: `material` é uma classificação de inventário;
/// `role=runtime` é a função do objeto na mídia.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveMateriality {
    Material,
    IdentityOnly,
}

impl LiveMateriality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Material => "material",
            Self::IdentityOnly => "identity-only",
        }
    }

    pub fn is_material(self) -> bool {
        self == Self::Material
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveMaterialStatus {
    Consumed,
    Produced,
    Measured,
    NotConsumed,
}

impl LiveMaterialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Consumed => "consumed",
            Self::Produced => "produced",
            Self::Measured => "measured",
            Self::NotConsumed => "not-consumed",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LiveArtifactIdentity {
    pub kind: String,
    pub identifier: String,
    pub sha256: String,
}

/// Identidade externa já derivada dos bytes canônicos LIVE_* autenticados.
/// O bundle de licenças consome `materiality`, `license` e a evidência sem
/// precisar interpretar recipes nem confundir toolchains com payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveMaterialIdentity {
    pub id: String,
    pub variant: String,
    pub status: LiveMaterialStatus,
    pub materiality: LiveMateriality,
    pub role: Materiality,
    pub artifact_kind: String,
    pub origin_kind: String,
    pub source_id: String,
    pub provenance_id: String,
    pub license: String,
    pub license_evidence_sha256: String,
    pub payload_sha256: String,
    pub material_id: String,
    pub provenance_sha256: String,
    pub artifacts: Vec<LiveArtifactIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveMaterialImport {
    pub authority_kind: String,
    pub authority_sha256: String,
    pub runner_proof_sha256: String,
    pub components_sha256: String,
    pub build_contract_sha256: String,
    pub identities: Vec<LiveMaterialIdentity>,
}

/// Âncoras fornecidas pelo pipeline/perfil que autoriza a mídia. O campo
/// `AUTHENTICATED=yes` dentro do próprio proof não substitui estes hashes.
pub struct LiveMediaAnchors<'a> {
    pub expected_authority_sha256: &'a str,
    pub expected_runner_proof_sha256: &'a str,
}

pub struct LiveMediaDocuments<'a> {
    pub lock: &'a [u8],
    pub components: &'a [u8],
    pub runner_proof: &'a [u8],
}

impl LiveMaterialImport {
    pub fn material_identities(&self) -> &[LiveMaterialIdentity] {
        &self.identities
    }

    pub fn materials(&self) -> impl Iterator<Item = &LiveMaterialIdentity> {
        self.identities
            .iter()
            .filter(|identity| identity.materiality.is_material())
    }

    pub fn identity_only_facts(&self) -> impl Iterator<Item = &LiveMaterialIdentity> {
        self.identities
            .iter()
            .filter(|identity| identity.materiality == LiveMateriality::IdentityOnly)
    }
}

pub(crate) struct FinalizedMaterials {
    pub lock_sha256: String,
    pub identities: Vec<MaterialIdentity>,
}

pub struct ResolvedPlan {
    pub(crate) roots: Vec<PlanRoot>,
    pub(crate) recipes: BTreeMap<String, Recipe>,
    pub(crate) fingerprints: HashMap<String, String>,
    pub(crate) nodes: BTreeMap<String, PlanNode>,
    pub(crate) edges: Vec<PlanEdge>,
    pub(crate) order: Vec<String>,
    pub(crate) channels: channel::Resolution,
    tree_sha256: String,
    build_contract_sha256: String,
    binary_policy: BinaryPolicy,
    purpose: PlanPurpose,
    abi_policy: AbiPolicy,
    artifacts: Vec<PlanArtifact>,
    abi_requires: Vec<AbiRequire>,
    abi_provides: Vec<AbiProvide>,
    abi_static: Vec<AbiStatic>,
    abi_none: Vec<AbiNone>,
    abi_pending: Vec<AbiPending>,
    abi_audit_sha256: String,
    pub(crate) orphans: Vec<PlanOrphan>,
    pub(crate) predicted_residues: Vec<PlanPredictedResidue>,
    objects_authenticated: Cell<bool>,
    tree_revalidated: Cell<bool>,
}

fn kind_str(kind: Kind) -> &'static str {
    match kind {
        Kind::Binary => "binary",
        Kind::Source => "source",
        Kind::Meta => "meta",
    }
}

fn world(kind: Kind) -> &'static str {
    match kind {
        Kind::Binary => "A",
        Kind::Source => "B",
        Kind::Meta => "META",
    }
}

fn policy_str(policy: BinaryPolicy) -> &'static str {
    match policy {
        BinaryPolicy::PreferBinary => "prefer-binary",
        BinaryPolicy::SourceOnly => "source-only",
        BinaryPolicy::BinaryOnly => "only-binary",
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_hash_material(tag: &[u8], parts: impl IntoIterator<Item = Vec<u8>>) -> String {
    let mut hash = Sha256::new();
    hash.update(tag);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hex::encode(hash.finalize())
}

#[derive(Clone, Debug)]
struct ParsedLiveComponent {
    raw_line: String,
    id: String,
    variant: String,
    status: LiveMaterialStatus,
    materiality: LiveMateriality,
    role: Materiality,
    artifact_kind: String,
    origin_kind: String,
    source_id: String,
    provenance: String,
    license: String,
    license_evidence_sha256: String,
    input_sha256: String,
    payload_sha256: String,
    config_sha256: String,
    contract_sha256: String,
    toolchain_id: String,
    toolchain_sha256: String,
}

#[derive(Clone, Debug)]
struct ParsedLiveComponents {
    mode: String,
    release_inputs_complete: String,
    epoch: String,
    runner_proof_sha256: String,
    entries_sha256: String,
    build_contract_sha256: String,
    entries: Vec<ParsedLiveComponent>,
}

#[derive(Clone, Debug)]
struct ParsedLiveRunnerProof {
    mode: String,
    authenticated: String,
    runner_id: String,
    runner_path: String,
    runner_sha256: String,
    builder_id: String,
    builder_lock_sha256: String,
    builder_rootfs_tree_sha256: String,
    source_snapshot_sha256: String,
    helper_binary_sha256: String,
    epoch: String,
}

#[derive(Clone, Debug)]
struct ParsedLiveLock {
    mode: String,
    release_eligible: String,
    boot_efi_sha256: String,
    components_sha256: String,
    runner_proof_sha256: String,
    embed_proof_sha256: String,
    entries_sha256: String,
    build_contract_sha256: String,
    epoch: String,
    initramfs_blob_sha256: String,
    initramfs_cpio_sha256: String,
    embedded_components_sha256: String,
    helper_binary_sha256: String,
    source_snapshot_sha256: String,
    builder_lock_sha256: String,
    builder_rootfs_tree_sha256: String,
    payload_provenance: String,
    payload_license: String,
    payload_license_evidence_sha256: String,
    payload_sha256: String,
}

fn canonical_live_lines<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a str>> {
    if bytes.is_empty()
        || bytes.len() > MAX_LIVE_MANIFEST_BYTES
        || !bytes.ends_with(b"\n")
        || bytes
            .iter()
            .any(|byte| *byte != b'\n' && !(0x20..=0x7e).contains(byte))
    {
        bail!("{label} não é texto ASCII canônico terminado em LF");
    }
    let text = std::str::from_utf8(bytes).context("manifesto LIVE não é ASCII")?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.is_empty() || lines.iter().any(|line| line.is_empty()) {
        bail!("{label} contém linha vazia");
    }
    Ok(lines)
}

fn live_value<'a>(lines: &[&'a str], index: &mut usize, key: &str, label: &str) -> Result<&'a str> {
    let line = lines
        .get(*index)
        .ok_or_else(|| anyhow::anyhow!("{label} terminou antes de {key}"))?;
    *index += 1;
    let prefix = format!("{key}=");
    let value = line
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("{label} esperava {key} na linha {}", *index))?;
    if value.is_empty() {
        bail!("{label} contém {key} vazio");
    }
    Ok(value)
}

fn canonical_live_decimal(value: &str, label: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("{label} não é decimal"))?;
    if parsed.to_string() != value {
        bail!("{label} não é decimal canônico");
    }
    Ok(parsed)
}

fn require_live_sha256(value: &str, label: &str) -> Result<()> {
    if !canonical_sha256(value) {
        bail!("{label} não é SHA-256 canônico");
    }
    Ok(())
}

fn safe_live_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && !matches!(byte, b'|' | b'='))
}

fn canonical_live_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && !value.ends_with('/')
        && !value.contains("//")
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn parse_live_status(value: &str) -> Result<LiveMaterialStatus> {
    match value {
        "consumed" => Ok(LiveMaterialStatus::Consumed),
        "produced" => Ok(LiveMaterialStatus::Produced),
        "measured" => Ok(LiveMaterialStatus::Measured),
        "not-consumed" => Ok(LiveMaterialStatus::NotConsumed),
        _ => bail!("ENTRY LIVE contém status desconhecido"),
    }
}

fn validate_live_artifact_kind(value: &str) -> Result<()> {
    if !matches!(
        value,
        "config"
            | "source"
            | "payload"
            | "provenance"
            | "tool"
            | "linked-input"
            | "overlay"
            | "script"
    ) {
        bail!("ENTRY LIVE contém artifact_kind desconhecido");
    }
    Ok(())
}

fn validate_live_origin_kind(value: &str) -> Result<()> {
    if !matches!(
        value,
        "repo"
            | "official-tar"
            | "built-from-source"
            | "built-from-official-source"
            | "built-from-crates"
            | "provided-static"
            | "development-prebuilt"
            | "generated"
            | "toolchain"
            | "builder-rootfs"
    ) {
        bail!("ENTRY LIVE contém origin_kind desconhecido");
    }
    Ok(())
}

fn validate_live_material_license(license: &str, evidence: &str, label: &str) -> Result<()> {
    if license.trim() != license
        || license.is_empty()
        || license == "-"
        || license == "NOASSERTION"
        || license == "NONE"
        || license.contains('|')
        || !canonical_sha256(evidence)
        || evidence == EMPTY_SHA256
    {
        bail!("{label}: material exige LICENSE/evidência factual canônica");
    }
    Ok(())
}

fn parse_live_component(line: &str, contract_sha256: &str) -> Result<ParsedLiveComponent> {
    let payload = line
        .strip_prefix("ENTRY=")
        .ok_or_else(|| anyhow::anyhow!("LIVE_COMPONENTS esperava ENTRY"))?;
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 17 || fields.iter().any(|field| field.is_empty()) {
        bail!("ENTRY LIVE não tem exatamente 17 campos não vazios");
    }
    for (index, field) in fields.iter().enumerate() {
        if index != 9 && !safe_live_atom(field) {
            bail!("ENTRY LIVE contém campo atômico não canônico");
        }
    }
    if fields[1] != "live-efi" {
        bail!("ENTRY LIVE contém variant desconhecida");
    }
    let status = parse_live_status(fields[2])?;
    let (materiality, role) = match (fields[3], fields[4]) {
        ("material", "runtime") => (LiveMateriality::Material, Materiality::Runtime),
        ("identity-only", "identity-only") => {
            (LiveMateriality::IdentityOnly, Materiality::IdentityOnly)
        }
        _ => bail!("ENTRY LIVE mistura materiality/role incoerentes"),
    };
    validate_live_artifact_kind(fields[5])?;
    validate_live_origin_kind(fields[6])?;
    for (index, label) in [
        (10, "LICENSE_EVIDENCE_SHA256"),
        (11, "INPUT_SHA256"),
        (12, "PAYLOAD_SHA256"),
        (13, "CONFIG_SHA256"),
        (14, "CONTRACT_SHA256"),
        (16, "TOOLCHAIN_SHA256"),
    ] {
        require_live_sha256(fields[index], label)?;
    }
    if fields[14] != contract_sha256 {
        bail!("ENTRY LIVE diverge de BUILD_CONTRACT_SHA256");
    }
    match materiality {
        LiveMateriality::Material => {
            if !matches!(
                status,
                LiveMaterialStatus::Consumed | LiveMaterialStatus::Produced
            ) || fields[7] == "-"
                || fields[8] == "-"
                || fields[11] == EMPTY_SHA256
                || fields[12] == EMPTY_SHA256
            {
                bail!("ENTRY material não contém input/payload/source/proveniência factuais");
            }
            validate_live_material_license(fields[9], fields[10], fields[0])?;
        }
        LiveMateriality::IdentityOnly => {
            if fields[9] != "-" || fields[10] != EMPTY_SHA256 {
                bail!("ENTRY identity-only exige LICENSE=- e evidência vazia");
            }
        }
    }
    Ok(ParsedLiveComponent {
        raw_line: line.to_string(),
        id: fields[0].to_string(),
        variant: fields[1].to_string(),
        status,
        materiality,
        role,
        artifact_kind: fields[5].to_string(),
        origin_kind: fields[6].to_string(),
        source_id: fields[7].to_string(),
        provenance: fields[8].to_string(),
        license: fields[9].to_string(),
        license_evidence_sha256: fields[10].to_string(),
        input_sha256: fields[11].to_string(),
        payload_sha256: fields[12].to_string(),
        config_sha256: fields[13].to_string(),
        contract_sha256: fields[14].to_string(),
        toolchain_id: fields[15].to_string(),
        toolchain_sha256: fields[16].to_string(),
    })
}

fn parse_live_components(bytes: &[u8]) -> Result<ParsedLiveComponents> {
    let lines = canonical_live_lines(bytes, "LIVE_COMPONENTS")?;
    let mut index = 0usize;
    if lines.get(index).copied() != Some("LIVE_COMPONENTS_FORMAT=1") {
        bail!("LIVE_COMPONENTS_FORMAT inválido");
    }
    index += 1;
    if live_value(&lines, &mut index, "VARIANT", "LIVE_COMPONENTS")? != "live-efi" {
        bail!("LIVE_COMPONENTS contém variant desconhecida");
    }
    let mode = live_value(&lines, &mut index, "BUILD_MODE", "LIVE_COMPONENTS")?.to_string();
    let release_inputs_complete = live_value(
        &lines,
        &mut index,
        "RELEASE_INPUTS_COMPLETE",
        "LIVE_COMPONENTS",
    )?
    .to_string();
    if live_value(&lines, &mut index, "RELEASE_ELIGIBLE", "LIVE_COMPONENTS")? != "no" {
        bail!("LIVE_COMPONENTS não pode auto-promover RELEASE_ELIGIBLE");
    }
    let epoch = live_value(&lines, &mut index, "SOURCE_DATE_EPOCH", "LIVE_COMPONENTS")?;
    canonical_live_decimal(epoch, "SOURCE_DATE_EPOCH")?;
    let runner_proof_sha256 =
        live_value(&lines, &mut index, "RUNNER_PROOF_SHA256", "LIVE_COMPONENTS")?;
    let entries_sha256 = live_value(&lines, &mut index, "ENTRIES_SHA256", "LIVE_COMPONENTS")?;
    let build_contract_sha256 = live_value(
        &lines,
        &mut index,
        "BUILD_CONTRACT_SHA256",
        "LIVE_COMPONENTS",
    )?;
    for (value, label) in [
        (runner_proof_sha256, "RUNNER_PROOF_SHA256"),
        (entries_sha256, "ENTRIES_SHA256"),
        (build_contract_sha256, "BUILD_CONTRACT_SHA256"),
    ] {
        require_live_sha256(value, label)?;
    }
    let entry_count_text = live_value(&lines, &mut index, "ENTRY_COUNT", "LIVE_COMPONENTS")?;
    let entry_count_u64 = canonical_live_decimal(entry_count_text, "ENTRY_COUNT")?;
    let entry_count = usize::try_from(entry_count_u64).context("ENTRY_COUNT excede usize")?;
    if entry_count == 0 || entry_count > MAX_PLAN_ENTRIES {
        bail!("ENTRY_COUNT vazio ou excessivo");
    }
    if lines.get(index).copied() != Some(LIVE_COMPONENT_ENTRY_SCHEMA) {
        bail!("ENTRY_SCHEMA LIVE não é o schema congelado");
    }
    index += 1;
    if lines.len() != index + entry_count {
        bail!("ENTRY_COUNT não corresponde exatamente às linhas ENTRY");
    }
    let entries_offset: usize = lines[..index].iter().map(|line| line.len() + 1).sum();
    if sha256(&bytes[entries_offset..]) != entries_sha256 {
        bail!("ENTRIES_SHA256 diverge dos bytes ENTRY canônicos");
    }
    let mut entries = Vec::with_capacity(entry_count);
    let mut previous_key: Option<(String, String)> = None;
    let mut has_material = false;
    let mut has_identity = false;
    for line in &lines[index..] {
        let entry = parse_live_component(line, build_contract_sha256)?;
        if mode == "release" && entry.origin_kind == "development-prebuilt" {
            bail!("LIVE_COMPONENTS release contém origem development-prebuilt");
        }
        let key = (entry.variant.clone(), entry.id.clone());
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            bail!("ENTRY LIVE não está C-sort/único por (variant,id)");
        }
        if entry.id == "boot-efi" {
            bail!("ENTRY LIVE colide com PAYLOAD externo boot-efi");
        }
        has_material |= entry.materiality == LiveMateriality::Material;
        has_identity |= entry.materiality == LiveMateriality::IdentityOnly;
        previous_key = Some(key);
        entries.push(entry);
    }
    if !has_material || !has_identity {
        bail!("LIVE_COMPONENTS exige ao menos um material e uma identidade");
    }
    match (mode.as_str(), release_inputs_complete.as_str()) {
        ("release", "yes") | ("development", "no") => {}
        _ => bail!("BUILD_MODE/RELEASE_INPUTS_COMPLETE incoerentes"),
    }
    Ok(ParsedLiveComponents {
        mode,
        release_inputs_complete,
        epoch: epoch.to_string(),
        runner_proof_sha256: runner_proof_sha256.to_string(),
        entries_sha256: entries_sha256.to_string(),
        build_contract_sha256: build_contract_sha256.to_string(),
        entries,
    })
}

fn parse_live_runner_proof(bytes: &[u8]) -> Result<ParsedLiveRunnerProof> {
    let lines = canonical_live_lines(bytes, "LIVE_RUNNER_PROOF")?;
    let mut index = 0usize;
    if lines.get(index).copied() != Some("LIVE_RUNNER_PROOF_FORMAT=1") {
        bail!("LIVE_RUNNER_PROOF_FORMAT inválido");
    }
    index += 1;
    if live_value(&lines, &mut index, "VARIANT", "LIVE_RUNNER_PROOF")? != "live-efi" {
        bail!("LIVE_RUNNER_PROOF contém variant desconhecida");
    }
    let mode = live_value(&lines, &mut index, "BUILD_MODE", "LIVE_RUNNER_PROOF")?.to_string();
    let authenticated =
        live_value(&lines, &mut index, "AUTHENTICATED", "LIVE_RUNNER_PROOF")?.to_string();
    let runner_id = live_value(&lines, &mut index, "RUNNER_ID", "LIVE_RUNNER_PROOF")?;
    let runner_path = live_value(&lines, &mut index, "RUNNER_PATH", "LIVE_RUNNER_PROOF")?;
    let runner_sha256 = live_value(&lines, &mut index, "RUNNER_SHA256", "LIVE_RUNNER_PROOF")?;
    let builder_id = live_value(&lines, &mut index, "BUILDER_ID", "LIVE_RUNNER_PROOF")?;
    let builder_lock_sha256 = live_value(
        &lines,
        &mut index,
        "BUILDER_LOCK_SHA256",
        "LIVE_RUNNER_PROOF",
    )?;
    let builder_rootfs_tree_sha256 = live_value(
        &lines,
        &mut index,
        "BUILDER_ROOTFS_TREE_SHA256",
        "LIVE_RUNNER_PROOF",
    )?;
    let source_snapshot_sha256 = live_value(
        &lines,
        &mut index,
        "SOURCE_SNAPSHOT_SHA256",
        "LIVE_RUNNER_PROOF",
    )?;
    let mut proof_hashes = vec![
        ("RUNNER_SHA256", runner_sha256),
        ("BUILDER_LOCK_SHA256", builder_lock_sha256),
        ("BUILDER_ROOTFS_TREE_SHA256", builder_rootfs_tree_sha256),
        ("SOURCE_SNAPSHOT_SHA256", source_snapshot_sha256),
    ];
    let mut helper_binary_sha256 = None;
    for key in [
        "BUILD_EFI_SOURCE_SHA256",
        "LIVE_LOCK_SOURCE_SHA256",
        "LIVE_LOCK_HELPER_SOURCE_SHA256",
        "LIVE_LOCK_HELPER_BINARY_SHA256",
        "BUSYBOX_CONFIG_SHA256",
        "LINUX_TAR_SHA256",
        "BUSYBOX_TAR_SHA256",
        "E2FSPROGS_TAR_SHA256",
        "NCURSES_TAR_SHA256",
        "UTIL_LINUX_TAR_SHA256",
        "MINIPAX_BINARY_SHA256",
        "MINITRUE_BINARY_SHA256",
        "ZIG_TAR_SHA256",
        "ZIG_BINARY_SHA256",
        "MUSL_TREE_SHA256",
    ] {
        let value = live_value(&lines, &mut index, key, "LIVE_RUNNER_PROOF")?;
        if key == "LIVE_LOCK_HELPER_BINARY_SHA256" {
            helper_binary_sha256 = Some(value.to_string());
        }
        proof_hashes.push((key, value));
    }
    let epoch = live_value(&lines, &mut index, "SOURCE_DATE_EPOCH", "LIVE_RUNNER_PROOF")?;
    if index != lines.len() {
        bail!("LIVE_RUNNER_PROOF contém linha extra");
    }
    canonical_live_decimal(epoch, "SOURCE_DATE_EPOCH do Runner Proof")?;
    if !safe_live_atom(runner_id) || !safe_live_atom(builder_id) {
        bail!("Runner Proof contém identidade não canônica");
    }
    match (mode.as_str(), authenticated.as_str()) {
        ("release", "yes") => {
            if !canonical_live_absolute_path(runner_path) {
                bail!("Runner Proof release exige RUNNER_PATH absoluto canônico");
            }
        }
        ("development", "no") => {
            if !safe_live_atom(runner_path) {
                bail!("Runner Proof development exige RUNNER_PATH atômico");
            }
        }
        _ => bail!("BUILD_MODE/AUTHENTICATED incoerentes no Runner Proof"),
    }
    for (label, value) in proof_hashes {
        require_live_sha256(value, label)?;
        if mode == "release" && value == EMPTY_SHA256 {
            bail!("Runner Proof release contém pin vazio em {label}");
        }
    }
    Ok(ParsedLiveRunnerProof {
        mode,
        authenticated,
        runner_id: runner_id.to_string(),
        runner_path: runner_path.to_string(),
        runner_sha256: runner_sha256.to_string(),
        builder_id: builder_id.to_string(),
        builder_lock_sha256: builder_lock_sha256.to_string(),
        builder_rootfs_tree_sha256: builder_rootfs_tree_sha256.to_string(),
        source_snapshot_sha256: source_snapshot_sha256.to_string(),
        helper_binary_sha256: helper_binary_sha256
            .ok_or_else(|| anyhow::anyhow!("Runner Proof sem hash binário do helper"))?,
        epoch: epoch.to_string(),
    })
}

fn parse_live_lock(bytes: &[u8]) -> Result<ParsedLiveLock> {
    let lines = canonical_live_lines(bytes, "LIVE_LOCK")?;
    let mut index = 0usize;
    if lines.get(index).copied() != Some("LIVE_LOCK_FORMAT=1") {
        bail!("LIVE_LOCK_FORMAT inválido");
    }
    index += 1;
    if live_value(&lines, &mut index, "VARIANT", "LIVE_LOCK")? != "live-efi" {
        bail!("LIVE_LOCK contém variant desconhecida");
    }
    let mode = live_value(&lines, &mut index, "BUILD_MODE", "LIVE_LOCK")?.to_string();
    let release_eligible =
        live_value(&lines, &mut index, "RELEASE_ELIGIBLE", "LIVE_LOCK")?.to_string();
    if live_value(&lines, &mut index, "AUTHORITY_KIND", "LIVE_LOCK")? != "live-lock" {
        bail!("LIVE_LOCK contém AUTHORITY_KIND desconhecido");
    }
    let boot_efi_sha256 = live_value(&lines, &mut index, "BOOT_EFI_SHA256", "LIVE_LOCK")?;
    let components_sha256 = live_value(&lines, &mut index, "COMPONENTS_SHA256", "LIVE_LOCK")?;
    let runner_proof_sha256 = live_value(&lines, &mut index, "RUNNER_PROOF_SHA256", "LIVE_LOCK")?;
    let embed_proof_sha256 = live_value(&lines, &mut index, "EMBED_PROOF_SHA256", "LIVE_LOCK")?;
    let entries_sha256 = live_value(&lines, &mut index, "ENTRIES_SHA256", "LIVE_LOCK")?;
    let build_contract_sha256 =
        live_value(&lines, &mut index, "BUILD_CONTRACT_SHA256", "LIVE_LOCK")?;
    let epoch = live_value(&lines, &mut index, "SOURCE_DATE_EPOCH", "LIVE_LOCK")?;
    let initramfs_blob_sha256 =
        live_value(&lines, &mut index, "INITRAMFS_BLOB_SHA256", "LIVE_LOCK")?;
    let initramfs_cpio_sha256 =
        live_value(&lines, &mut index, "INITRAMFS_CPIO_SHA256", "LIVE_LOCK")?;
    let embedded_components_sha256 = live_value(
        &lines,
        &mut index,
        "EMBEDDED_COMPONENTS_SHA256",
        "LIVE_LOCK",
    )?;
    let helper_binary_sha256 = live_value(
        &lines,
        &mut index,
        "LIVE_LOCK_HELPER_BINARY_SHA256",
        "LIVE_LOCK",
    )?;
    let source_snapshot_sha256 =
        live_value(&lines, &mut index, "SOURCE_SNAPSHOT_SHA256", "LIVE_LOCK")?;
    let builder_lock_sha256 = live_value(&lines, &mut index, "BUILDER_LOCK_SHA256", "LIVE_LOCK")?;
    let builder_rootfs_tree_sha256 = live_value(
        &lines,
        &mut index,
        "BUILDER_ROOTFS_TREE_SHA256",
        "LIVE_LOCK",
    )?;
    if lines.get(index).copied() != Some(LIVE_PAYLOAD_SCHEMA) {
        bail!("PAYLOAD_SCHEMA LIVE não é o schema congelado");
    }
    index += 1;
    let payload_line = lines
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("LIVE_LOCK sem PAYLOAD"))?;
    index += 1;
    if index != lines.len() {
        bail!("LIVE_LOCK contém linha extra");
    }
    canonical_live_decimal(epoch, "SOURCE_DATE_EPOCH do LIVE_LOCK")?;
    match (mode.as_str(), release_eligible.as_str()) {
        ("release", "yes") | ("development", "no") => {}
        _ => bail!("BUILD_MODE/RELEASE_ELIGIBLE incoerentes no LIVE_LOCK"),
    }
    for (value, label) in [
        (boot_efi_sha256, "BOOT_EFI_SHA256"),
        (components_sha256, "COMPONENTS_SHA256"),
        (runner_proof_sha256, "RUNNER_PROOF_SHA256"),
        (embed_proof_sha256, "EMBED_PROOF_SHA256"),
        (entries_sha256, "ENTRIES_SHA256"),
        (build_contract_sha256, "BUILD_CONTRACT_SHA256"),
        (initramfs_blob_sha256, "INITRAMFS_BLOB_SHA256"),
        (initramfs_cpio_sha256, "INITRAMFS_CPIO_SHA256"),
        (embedded_components_sha256, "EMBEDDED_COMPONENTS_SHA256"),
        (helper_binary_sha256, "LIVE_LOCK_HELPER_BINARY_SHA256"),
        (source_snapshot_sha256, "SOURCE_SNAPSHOT_SHA256"),
        (builder_lock_sha256, "BUILDER_LOCK_SHA256"),
        (builder_rootfs_tree_sha256, "BUILDER_ROOTFS_TREE_SHA256"),
    ] {
        require_live_sha256(value, label)?;
    }
    if initramfs_blob_sha256 != initramfs_cpio_sha256 {
        bail!("LIVE_LOCK declara blob/cpio do initramfs divergentes");
    }
    let payload = payload_line
        .strip_prefix("PAYLOAD=")
        .ok_or_else(|| anyhow::anyhow!("LIVE_LOCK esperava PAYLOAD"))?;
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 11 || fields.iter().any(|field| field.is_empty()) {
        bail!("PAYLOAD LIVE não tem exatamente 11 campos não vazios");
    }
    if fields[..7]
        != [
            "boot-efi",
            "live-efi",
            "material",
            "runtime",
            "payload",
            "built-from-source",
            "generated:linux-efi-stub",
        ]
    {
        bail!("PAYLOAD LIVE não descreve o boot-efi factual");
    }
    let expected_provenance = format!("embed-proof:{embed_proof_sha256}");
    if fields[7] != expected_provenance {
        bail!("PAYLOAD LIVE diverge do EMBED_PROOF_SHA256");
    }
    validate_live_material_license(fields[8], fields[9], "boot-efi")?;
    require_live_sha256(fields[10], "PAYLOAD_SHA256 do boot-efi")?;
    if fields[10] != boot_efi_sha256 || fields[10] == EMPTY_SHA256 {
        bail!("PAYLOAD boot-efi diverge de BOOT_EFI_SHA256");
    }
    Ok(ParsedLiveLock {
        mode,
        release_eligible,
        boot_efi_sha256: boot_efi_sha256.to_string(),
        components_sha256: components_sha256.to_string(),
        runner_proof_sha256: runner_proof_sha256.to_string(),
        embed_proof_sha256: embed_proof_sha256.to_string(),
        entries_sha256: entries_sha256.to_string(),
        build_contract_sha256: build_contract_sha256.to_string(),
        epoch: epoch.to_string(),
        initramfs_blob_sha256: initramfs_blob_sha256.to_string(),
        initramfs_cpio_sha256: initramfs_cpio_sha256.to_string(),
        embedded_components_sha256: embedded_components_sha256.to_string(),
        helper_binary_sha256: helper_binary_sha256.to_string(),
        source_snapshot_sha256: source_snapshot_sha256.to_string(),
        builder_lock_sha256: builder_lock_sha256.to_string(),
        builder_rootfs_tree_sha256: builder_rootfs_tree_sha256.to_string(),
        payload_provenance: fields[7].to_string(),
        payload_license: fields[8].to_string(),
        payload_license_evidence_sha256: fields[9].to_string(),
        payload_sha256: fields[10].to_string(),
    })
}

fn effective_recipe_names(ctx: &Ctx) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for tree in ctx.newspeak_paths() {
        if !recipe::validate_newspeak_tree(&tree)? {
            continue;
        }
        let entries = match fs::read_dir(&tree) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut candidates = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nome de receita não é UTF-8"))?;
            recipe::validate_name(&name)?;
            let package_metadata = fs::symlink_metadata(entry.path())?;
            if package_metadata.file_type().is_symlink() {
                bail!(
                    "pacote Newspeak não pode ser symlink: {}",
                    entry.path().display()
                );
            }
            if !package_metadata.file_type().is_dir() {
                continue;
            }
            let recipe_path = entry.path().join("recipe");
            match fs::symlink_metadata(&recipe_path) {
                Ok(metadata) if metadata.file_type().is_file() && metadata.nlink() == 1 => {
                    candidates.push(name)
                }
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    bail!("recipe não pode ser symlink: {}", recipe_path.display())
                }
                Ok(metadata) if metadata.file_type().is_file() => {
                    bail!("recipe precisa ter nlink=1: {}", recipe_path.display())
                }
                Ok(_) => bail!("recipe precisa ser regular: {}", recipe_path.display()),
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
        }
        candidates.sort();
        for name in candidates {
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
    }
    names.sort();
    Ok(names)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableMetadata {
    dev: u64,
    ino: u64,
    nlink: u64,
    len: u64,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl StableMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mode: metadata.mode(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct TreeMetadataEntry {
    name: Vec<u8>,
    dev: u64,
    ino: u64,
    nlink: u64,
    len: u64,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    symlink_target: Option<Vec<u8>>,
}

fn tree_metadata_snapshot(base: &Path) -> Result<Vec<TreeMetadataEntry>> {
    fn visit(base: &Path, path: &Path, out: &mut Vec<TreeMetadataEntry>) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        let name = path.strip_prefix(base)?.as_os_str().as_bytes().to_vec();
        let symlink_target = if metadata.file_type().is_symlink() {
            Some(fs::read_link(path)?.as_os_str().as_bytes().to_vec())
        } else {
            None
        };
        out.push(TreeMetadataEntry {
            name,
            dev: metadata.dev(),
            ino: metadata.ino(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mode: metadata.mode(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            symlink_target,
        });
        if metadata.file_type().is_dir() {
            let directory = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            if StableMetadata::from(&directory.metadata()?) != StableMetadata::from(&metadata) {
                bail!("files mudou enquanto o inventário era aberto");
            }
            let mut children = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            children.sort_by(|left, right| {
                left.file_name()
                    .as_bytes()
                    .cmp(right.file_name().as_bytes())
            });
            for child in children {
                visit(base, &child.path(), out)?;
            }
        }
        Ok(())
    }

    let mut entries = Vec::new();
    visit(base, base, &mut entries)?;
    entries.sort();
    Ok(entries)
}

fn read_recipe_stable(path: &Path) -> Result<Vec<u8>> {
    const MAX_RECIPE_BYTES: u64 = 16 * 1024 * 1024;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = StableMetadata::from(&file.metadata()?);
    if before.mode & libc::S_IFMT != libc::S_IFREG
        || before.nlink != 1
        || before.len > MAX_RECIPE_BYTES
    {
        bail!(
            "recipe não é regular nlink=1 dentro do limite: {}",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(before.len as usize);
    Read::by_ref(&mut file)
        .take(MAX_RECIPE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = StableMetadata::from(&file.metadata()?);
    let reopened = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let at_path = StableMetadata::from(&reopened.metadata()?);
    if before != after || after != at_path || bytes.len() as u64 != before.len {
        bail!("recipe mudou durante o snapshot: {}", path.display());
    }
    Ok(bytes)
}

fn pack_files_stable(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("files precisa ser diretório real: {}", path.display());
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = StableMetadata::from(&directory.metadata()?);
    let before_tree = tree_metadata_snapshot(path)?;
    let mut archive = Vec::new();
    crate::pack::pack_deterministic(path, 0, &mut archive)?;
    let after_tree = tree_metadata_snapshot(path)?;
    let after = StableMetadata::from(&directory.metadata()?);
    let reopened = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let at_path = StableMetadata::from(&reopened.metadata()?);
    if before != after || after != at_path || before_tree != after_tree {
        bail!("files mudou durante o snapshot: {}", path.display());
    }
    Ok(Some(archive))
}

/// Hash dos bytes efetivos da árvore, e não do pathname/uid/mtime do host.
/// `pack_deterministic` normaliza os metadados não semânticos de `files/`;
/// nome, recipe e tar canônico recebem prefixos de comprimento inequívocos.
fn newspeak_tree_hash(ctx: &Ctx) -> Result<(String, Vec<String>)> {
    let names = effective_recipe_names(ctx)?;
    let mut hash = Sha256::new();
    hash.update(b"NEWSPEAK_TREE_FORMAT=");
    hash.update(NEWSPEAK_TREE_FORMAT.as_bytes());
    hash.update(b"\0");
    hash.update((names.len() as u64).to_be_bytes());
    for name in &names {
        let recipe_path = recipe::find(ctx, name)?;
        let recipe_bytes = read_recipe_stable(&recipe_path)?;
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((recipe_bytes.len() as u64).to_be_bytes());
        hash.update(&recipe_bytes);
        let files = recipe_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("receita sem diretório pai"))?
            .join("files");
        match pack_files_stable(&files)? {
            Some(archive) => {
                hash.update([1]);
                hash.update((archive.len() as u64).to_be_bytes());
                hash.update(&archive);
            }
            None => hash.update([0]),
        }
    }
    Ok((hex::encode(hash.finalize()), names))
}

fn load_frozen_tree(ctx: &Ctx) -> Result<(String, BTreeMap<String, Recipe>)> {
    let (before, names) = newspeak_tree_hash(ctx)?;
    let mut recipes = BTreeMap::new();
    for name in &names {
        recipes.insert(name.clone(), recipe::load(ctx, name)?);
    }
    let (after, after_names) = newspeak_tree_hash(ctx)?;
    if before != after || names != after_names {
        return fail(
            2,
            "árvore Newspeak mudou enquanto o plano era congelado; repita",
        );
    }
    Ok((before, recipes))
}

fn identity_visit(
    name: &str,
    all: &BTreeMap<String, Recipe>,
    seen: &mut HashSet<String>,
    stack: &mut Vec<String>,
    out: &mut Vec<Recipe>,
) -> Result<()> {
    if stack.iter().any(|item| item == name) {
        return fail(
            2,
            format!("ciclo de identidade: {} -> {name}", stack.join(" -> ")),
        );
    }
    if !seen.insert(name.to_string()) {
        return Ok(());
    }
    let recipe = all.get(name).ok_or_else(|| crate::Fail {
        code: 2,
        msg: format!("dependência {name} não existe no snapshot Newspeak"),
    })?;
    stack.push(name.to_string());
    for dependency in recipe.deps.iter().chain(recipe.build_deps.iter()) {
        identity_visit(dependency, all, seen, stack, out)?;
    }
    for dependency in recipe.toolchain_build_deps() {
        identity_visit(dependency, all, seen, stack, out)?;
    }
    for dependency in recipe.runner_build_deps() {
        identity_visit(dependency, all, seen, stack, out)?;
    }
    for dependency in recipe.ccache_build_deps() {
        identity_visit(dependency, all, seen, stack, out)?;
    }
    stack.pop();
    out.push(recipe.clone());
    Ok(())
}

fn needs_install(
    ctx: &Ctx,
    recipe: &Recipe,
    fingerprint: &str,
    policy: BinaryPolicy,
    allow_intermediate: bool,
) -> Result<bool> {
    match recipe.kind {
        Kind::Binary => {
            install::binary_needs_install_for_plan(ctx, recipe, fingerprint, allow_intermediate)
        }
        Kind::Source => install::source_needs_install_for_plan(
            ctx,
            recipe,
            fingerprint,
            policy,
            allow_intermediate,
        ),
        Kind::Meta => {
            install::meta_needs_install_for_plan(ctx, recipe, fingerprint, allow_intermediate)
        }
    }
}

fn initial_node(
    ctx: &Ctx,
    recipe: &Recipe,
    fingerprint: &str,
    policy: BinaryPolicy,
    allow_intermediate: bool,
    force_materialization: bool,
) -> Result<PlanNode> {
    let needed = force_materialization
        || needs_install(ctx, recipe, fingerprint, policy, allow_intermediate)?;
    let (action, origin, payload) = if !needed {
        let (origin, payload) =
            install::installed_plan_material(ctx, recipe)?.ok_or_else(|| {
                anyhow::anyhow!("{}: estado keep perdeu o registro factual", recipe.name)
            })?;
        (PlanAction::Keep, origin, payload)
    } else {
        match recipe.kind {
            Kind::Binary => (
                PlanAction::Vendor,
                "vendor".to_string(),
                "pending".to_string(),
            ),
            Kind::Source => (
                PlanAction::Source,
                "fonte".to_string(),
                "pending".to_string(),
            ),
            Kind::Meta => (PlanAction::Meta, "meta".to_string(), "-".to_string()),
        }
    };
    Ok(PlanNode {
        name: recipe.name.clone(),
        version: recipe.version.clone(),
        kind: recipe.kind,
        world: world(recipe.kind),
        action,
        origin,
        fingerprint: fingerprint.to_string(),
        materiality: Materiality::IdentityOnly,
        payload_sha256: payload,
        license: match recipe.kind {
            Kind::Meta if recipe.license.is_none() => "-".to_string(),
            Kind::Binary | Kind::Source => recipe
                .license
                .clone()
                .ok_or_else(|| anyhow::anyhow!("{}: payload sem LICENSE", recipe.name))?,
            Kind::Meta => bail!("{}: metapacote não pode declarar LICENSE", recipe.name),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn activate(
    ctx: &Ctx,
    name: &str,
    requested_materiality: Materiality,
    purpose: PlanPurpose,
    policy: BinaryPolicy,
    mode: LoadMode,
    allow_legacy_channel: bool,
    strict_media: bool,
    intermediate_records: &BTreeSet<String>,
    force_materialization: bool,
    recipes: &BTreeMap<String, Recipe>,
    fingerprints: &HashMap<String, String>,
    nodes: &mut BTreeMap<String, PlanNode>,
    catalog: &mut Option<channel::Catalog>,
    channel_keep_candidates: &mut BTreeSet<String>,
    active_edges: &mut HashMap<(String, EdgeKind, String), Materiality>,
    done: &mut HashMap<String, Materiality>,
    stack: &mut Vec<String>,
    order: &mut Vec<String>,
) -> Result<()> {
    if done
        .get(name)
        .is_some_and(|current| current.merge(requested_materiality) == *current)
    {
        return Ok(());
    }
    if stack.iter().any(|item| item == name) {
        return fail(
            2,
            format!("ciclo no plano material: {} -> {name}", stack.join(" -> ")),
        );
    }
    let recipe = recipes
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("closure perdeu a receita {name}"))?;
    let fingerprint = fingerprints
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("closure perdeu o fingerprint de {name}"))?;
    let needed = force_materialization
        || needs_install(
            ctx,
            recipe,
            fingerprint,
            policy,
            intermediate_records.contains(name),
        )?;
    // Sync compara a origem instalada com a origem desejada pela política,
    // inclusive quando o record corrente é íntegro. Sem isso BinaryOnly e
    // PreferBinary manteriam silenciosamente um payload local só porque ele
    // não precisava de reparo físico.
    let choose_desired_origin = recipe.kind == Kind::Source
        && (purpose == PlanPurpose::Sync
            || (purpose == PlanPurpose::Media
                && (requested_materiality == Materiality::Runtime
                    || policy != BinaryPolicy::SourceOnly)));
    let from_channel = if recipe.kind == Kind::Source
        && (needed || choose_desired_origin)
        && policy != BinaryPolicy::SourceOnly
    {
        if catalog.is_none() {
            *catalog = Some(channel::Catalog::load_mode(
                ctx,
                mode,
                allow_legacy_channel,
            )?);
        }
        catalog
            .as_mut()
            .expect("catálogo inicializado")
            .select(recipe, fingerprint)?
    } else {
        false
    };
    if recipe.kind == Kind::Source
        && (needed || (strict_media && requested_materiality == Materiality::Runtime))
        && (policy == BinaryPolicy::BinaryOnly
            || (strict_media && requested_materiality == Materiality::Runtime))
        && !from_channel
    {
        // A recusa tem duas causas distintas, e nomear a errada manda quem
        // depura procurar uma flag que não passou. `--only-binary` é escolha do
        // chamador; a mídia estrita é estrutural — ela COMPÕE e não compila,
        // então todo runtime KIND=source precisa vir do canal.
        let causa = if strict_media && requested_materiality == Materiality::Runtime {
            "mídia estrita não compila em runtime"
        } else {
            "--only-binary"
        };
        return fail(
            5,
            format!(
                "{name} {}: {causa} e nenhum canal aceitável oferece esta identidade",
                recipe.version
            ),
        );
    }

    {
        let node = nodes
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("plano perdeu o nó {name}"))?;
        node.materiality = node.materiality.merge(requested_materiality);
        if from_channel {
            if !strict_media && !needed && node.action == PlanAction::Keep {
                channel_keep_candidates.insert(name.to_string());
            }
            node.action = PlanAction::Channel;
            node.origin = "channel".to_string();
        } else if strict_media && node.materiality == Materiality::Runtime {
            match recipe.kind {
                Kind::Source => {
                    return fail(
                        5,
                        format!(
                            "{name} {}: mídia estrita runtime exige canal release exato",
                            recipe.version
                        ),
                    )
                }
                Kind::Binary => {
                    node.action = PlanAction::Vendor;
                    node.origin = "vendor".to_string();
                    node.payload_sha256 = "pending".to_string();
                }
                Kind::Meta => {}
            }
        } else if strict_media && node.materiality == Materiality::CacheOnly {
            match recipe.kind {
                Kind::Source => {
                    node.action = PlanAction::Source;
                    node.origin = "fonte".to_string();
                    node.payload_sha256 = "pending".to_string();
                }
                Kind::Binary => {
                    node.action = PlanAction::Vendor;
                    node.origin = "vendor".to_string();
                    node.payload_sha256 = "pending".to_string();
                }
                Kind::Meta => {}
            }
        } else if choose_desired_origin
            && policy == BinaryPolicy::PreferBinary
            && node.action == PlanAction::Keep
            && node.origin.starts_with("canal:")
        {
            // O canal desejado deixou de oferecer esta identidade: a origem
            // preferida volta a ser a fonte local, portanto Keep não é correto.
            node.action = PlanAction::Source;
            node.origin = "fonte".to_string();
            node.payload_sha256 = "pending".to_string();
        }
    }

    stack.push(name.to_string());
    let just_compiled_locally = intermediate_records.contains(name)
        && recipe.kind == Kind::Source
        && install::read_meta_strict(&ctx.records_dir().join(name))?
            .is_some_and(|meta| meta.get("ORIGIN").map(String::as_str) == Some("fonte"));
    let compile_locally = recipe.kind == Kind::Source
        && (nodes
            .get(name)
            .is_some_and(|node| node.action == PlanAction::Source)
            || just_compiled_locally);
    for dependency in &recipe.deps {
        let edge_kind = if recipe.kind == Kind::Meta {
            EdgeKind::Aggregation
        } else {
            EdgeKind::Runtime
        };
        active_edges
            .entry((name.to_string(), edge_kind, dependency.clone()))
            .and_modify(|role| *role = role.merge(requested_materiality))
            .or_insert(requested_materiality);
        activate(
            ctx,
            dependency,
            requested_materiality,
            purpose,
            policy,
            mode,
            allow_legacy_channel,
            strict_media,
            intermediate_records,
            force_materialization,
            recipes,
            fingerprints,
            nodes,
            catalog,
            channel_keep_candidates,
            active_edges,
            done,
            stack,
            order,
        )?;
    }
    if compile_locally {
        for dependency in &recipe.build_deps {
            active_edges
                .entry((name.to_string(), EdgeKind::Build, dependency.clone()))
                .and_modify(|role| *role = role.merge(requested_materiality))
                .or_insert(requested_materiality);
            activate(
                ctx,
                dependency,
                requested_materiality,
                purpose,
                policy,
                mode,
                allow_legacy_channel,
                strict_media,
                intermediate_records,
                force_materialization,
                recipes,
                fingerprints,
                nodes,
                catalog,
                channel_keep_candidates,
                active_edges,
                done,
                stack,
                order,
            )?;
        }
        for dependency in recipe.toolchain_build_deps() {
            active_edges
                .entry((
                    name.to_string(),
                    EdgeKind::Toolchain,
                    dependency.to_string(),
                ))
                .and_modify(|role| *role = role.merge(requested_materiality))
                .or_insert(requested_materiality);
            activate(
                ctx,
                dependency,
                requested_materiality,
                purpose,
                policy,
                mode,
                allow_legacy_channel,
                strict_media,
                intermediate_records,
                force_materialization,
                recipes,
                fingerprints,
                nodes,
                catalog,
                channel_keep_candidates,
                active_edges,
                done,
                stack,
                order,
            )?;
        }
        for dependency in recipe.ccache_build_deps() {
            // A aresta viaja como Toolchain de propósito: o formato do
            // PLAN_LOCK já conhece esse tipo, o payload materializa inteiro
            // na view (o masquerade executa /usr/bin/ccache lá dentro), e
            // nenhum parser precisa aprender um tipo novo quando o portão
            // ligar.
            active_edges
                .entry((
                    name.to_string(),
                    EdgeKind::Toolchain,
                    dependency.to_string(),
                ))
                .and_modify(|role| *role = role.merge(requested_materiality))
                .or_insert(requested_materiality);
            activate(
                ctx,
                dependency,
                requested_materiality,
                purpose,
                policy,
                mode,
                allow_legacy_channel,
                strict_media,
                intermediate_records,
                force_materialization,
                recipes,
                fingerprints,
                nodes,
                catalog,
                channel_keep_candidates,
                active_edges,
                done,
                stack,
                order,
            )?;
        }
        for dependency in recipe.runner_build_deps() {
            active_edges
                .entry((name.to_string(), EdgeKind::Runner, dependency.to_string()))
                .and_modify(|role| *role = role.merge(requested_materiality))
                .or_insert(requested_materiality);
            activate(
                ctx,
                dependency,
                requested_materiality,
                purpose,
                policy,
                mode,
                allow_legacy_channel,
                strict_media,
                intermediate_records,
                force_materialization,
                recipes,
                fingerprints,
                nodes,
                catalog,
                channel_keep_candidates,
                active_edges,
                done,
                stack,
                order,
            )?;
        }
    }
    stack.pop();
    let resolved_materiality = done
        .get(name)
        .copied()
        .unwrap_or(Materiality::IdentityOnly)
        .merge(requested_materiality);
    let previous = done.insert(name.to_string(), resolved_materiality);
    if previous.is_none() {
        order.push(name.to_string());
    }
    Ok(())
}

fn edge_list(
    recipes: &BTreeMap<String, Recipe>,
    fingerprints: &HashMap<String, String>,
    active: &HashMap<(String, EdgeKind, String), Materiality>,
) -> Result<Vec<PlanEdge>> {
    let mut edges = BTreeSet::new();
    for recipe in recipes.values() {
        let mut add = |kind: EdgeKind, dependency: &str| -> Result<()> {
            let expected = fingerprints.get(dependency).ok_or_else(|| {
                anyhow::anyhow!("aresta {} -> {dependency} sem fingerprint", recipe.name)
            })?;
            let key = (recipe.name.clone(), kind, dependency.to_string());
            edges.insert(PlanEdge {
                from: recipe.name.clone(),
                kind,
                to: dependency.to_string(),
                expected_fingerprint: expected.clone(),
                materiality: active
                    .get(&key)
                    .copied()
                    .unwrap_or(Materiality::IdentityOnly),
            });
            Ok(())
        };
        for dependency in &recipe.deps {
            add(
                if recipe.kind == Kind::Meta {
                    EdgeKind::Aggregation
                } else {
                    EdgeKind::Runtime
                },
                dependency,
            )?;
        }
        for dependency in &recipe.build_deps {
            add(EdgeKind::Build, dependency)?;
        }
        for dependency in recipe.toolchain_build_deps() {
            add(EdgeKind::Toolchain, dependency)?;
        }
        for dependency in recipe.ccache_build_deps() {
            add(EdgeKind::Toolchain, dependency)?;
        }
        for dependency in recipe.runner_build_deps() {
            add(EdgeKind::Runner, dependency)?;
        }
    }
    Ok(edges.into_iter().collect())
}

fn material_order(nodes: &BTreeMap<String, PlanNode>, edges: &[PlanEdge]) -> Result<Vec<String>> {
    fn visit(
        name: &str,
        adjacency: &BTreeMap<String, Vec<String>>,
        seen: &mut HashSet<String>,
        stack: &mut Vec<String>,
        out: &mut Vec<String>,
    ) -> Result<()> {
        if seen.contains(name) {
            return Ok(());
        }
        if stack.iter().any(|item| item == name) {
            return fail(
                2,
                format!("ciclo na ordem material: {} -> {name}", stack.join(" -> ")),
            );
        }
        stack.push(name.to_string());
        if let Some(dependencies) = adjacency.get(name) {
            for dependency in dependencies {
                visit(dependency, adjacency, seen, stack, out)?;
            }
        }
        stack.pop();
        seen.insert(name.to_string());
        out.push(name.to_string());
        Ok(())
    }

    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in edges.iter().filter(|edge| edge.materiality.is_material()) {
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    for dependencies in adjacency.values_mut() {
        dependencies.sort();
        dependencies.dedup();
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for name in nodes
        .values()
        .filter(|node| node.materiality.is_material())
        .map(|node| node.name.as_str())
    {
        visit(name, &adjacency, &mut seen, &mut Vec::new(), &mut out)?;
    }
    Ok(out)
}

/// Quem respondeu pelos objetos upstream deste nó.
///
/// O SRC pinado é fato da RECEITA e viaja sempre: o hash está escrito lá, e a
/// impressão digital do pacote já o cobre. A evidência de assinatura upstream
/// — a assinatura destacada, o manifesto de checksums e a chave que os julga —
/// é outra coisa: ela descreve BYTES QUE ALGUÉM BAIXOU E CONFERIU. Só pode
/// viajar no nó de quem de fato o fez.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UpstreamEvidence {
    /// Esta máquina autenticou os objetos, ou vai autenticá-los antes de
    /// construir. A evidência é dela.
    Observed,
    /// O payload chegou pronto de um canal. Quem autenticou o upstream foi o
    /// PRODUTOR, e a prova disso é o `record-channel` do nó; repetir aqui os
    /// fatos de assinatura seria afirmar uma observação que nunca houve — e é
    /// por isso que eles saíam com transporte `pending`, valor que o fechamento
    /// completo recusa, e com razão.
    FromChannel,
}

fn input_artifacts(
    recipe: &Recipe,
    origin_kind: &str,
    materiality: Materiality,
    evidence: UpstreamEvidence,
) -> Result<Vec<PlanArtifact>> {
    let mut artifacts: Vec<PlanArtifact> = recipe
        .srcs
        .iter()
        .zip(&recipe.sha256)
        .enumerate()
        .map(|(index, (url, hash))| PlanArtifact {
            package: recipe.name.clone(),
            origin_kind: origin_kind.to_string(),
            materiality,
            transport_sha256: hash.clone(),
            reprocorr: "-".to_string(),
            channel_index_sha256: "-".to_string(),
            channel_lock_sha256: "-".to_string(),
            producer_plan_lock_sha256: "-".to_string(),
            channel_release_root: "-".to_string(),
            identifier: format!("recipe:SRC[{}]={url}", index + 1),
        })
        .collect();
    if recipe.srcs.is_empty() {
        if recipe.kind != Kind::Source {
            bail!("{}: payload vendor não pode omitir SRC", recipe.name);
        }
        artifacts.push(PlanArtifact {
            package: recipe.name.clone(),
            origin_kind: "source-empty".to_string(),
            materiality,
            transport_sha256: "-".to_string(),
            reprocorr: "-".to_string(),
            channel_index_sha256: "-".to_string(),
            channel_lock_sha256: "-".to_string(),
            producer_plan_lock_sha256: "-".to_string(),
            channel_release_root: "-".to_string(),
            identifier: "recipe:SRC=none".to_string(),
        });
    }
    let signature_facts = match evidence {
        UpstreamEvidence::Observed => crate::fetch::signature_input_facts(recipe)?,
        // Tudo ou nada. As regras de coerência do validador são bijeções entre
        // assinatura, chave e slot SRC: deixar a chave sem a assinatura que ela
        // julga é recusado explicitamente, e com razão. Ou o nó responde pela
        // evidência inteira, ou não responde por nenhuma.
        UpstreamEvidence::FromChannel => Vec::new(),
    };
    for input in signature_facts {
        artifacts.push(PlanArtifact {
            package: recipe.name.clone(),
            origin_kind: input.origin_kind,
            materiality: Materiality::IdentityOnly,
            transport_sha256: input.sha256,
            reprocorr: "-".to_string(),
            channel_index_sha256: "-".to_string(),
            channel_lock_sha256: "-".to_string(),
            producer_plan_lock_sha256: "-".to_string(),
            channel_release_root: "-".to_string(),
            identifier: input.identifier,
        });
    }
    artifacts.sort();
    artifacts.dedup();
    Ok(artifacts)
}

fn factual_artifact(ctx: &Ctx, node: &PlanNode) -> Result<Option<PlanArtifact>> {
    if node.kind == Kind::Meta {
        return Ok(None);
    }
    let record = ctx.records_dir().join(&node.name);
    let meta = install::read_meta_strict(&record)?
        .ok_or_else(|| anyhow::anyhow!("{}: keep sem registro", node.name))?;
    let origin = meta
        .get("ORIGIN")
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{}: keep sem ORIGIN", node.name))?;
    if let Some(channel_name) = origin.strip_prefix("canal:") {
        return Ok(Some(PlanArtifact {
            package: node.name.clone(),
            origin_kind: "record-channel".to_string(),
            materiality: node.materiality,
            transport_sha256: meta
                .get("CHANNEL_SHA256")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{}: record sem CHANNEL_SHA256", node.name))?,
            reprocorr: meta
                .get("ARTIFACT_HASH")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{}: record sem ARTIFACT_HASH", node.name))?,
            channel_index_sha256: meta
                .get("CHANNEL_INDEX_SHA256")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{}: record sem CHANNEL_INDEX_SHA256", node.name))?,
            channel_lock_sha256: meta
                .get("CHANNEL_LOCK_SHA256")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{}: record sem CHANNEL_LOCK_SHA256", node.name))?,
            producer_plan_lock_sha256: meta
                .get("CHANNEL_PRODUCER_PLAN_LOCK_SHA256")
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}: record sem CHANNEL_PRODUCER_PLAN_LOCK_SHA256",
                        node.name
                    )
                })?,
            channel_release_root: meta
                .get("CHANNEL_RELEASE_ROOT")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{}: record sem CHANNEL_RELEASE_ROOT", node.name))?,
            identifier: format!(
                "record:channel:{channel_name}:path={}",
                meta.get("CHANNEL_PATH")
                    .ok_or_else(|| anyhow::anyhow!("{}: record sem CHANNEL_PATH", node.name))?
            ),
        }));
    }
    let (kind, reprocorr, identifier) = match origin {
        "fonte" => (
            "record-source",
            meta.get("ARTIFACT_HASH")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("{}: record B sem ARTIFACT_HASH", node.name))?,
            "record:source-stage".to_string(),
        ),
        "vendor" => (
            "record-vendor",
            node.payload_sha256.clone(),
            "record:vendor-manifest".to_string(),
        ),
        _ => bail!("{}: ORIGIN factual não canônico: {origin}", node.name),
    };
    let transport_sha256 = if kind == "record-vendor" {
        install::verify_historical_record(ctx, &record, &node.name)?
    } else {
        "-".to_string()
    };
    Ok(Some(PlanArtifact {
        package: node.name.clone(),
        origin_kind: kind.to_string(),
        materiality: node.materiality,
        transport_sha256,
        reprocorr,
        channel_index_sha256: "-".to_string(),
        channel_lock_sha256: "-".to_string(),
        producer_plan_lock_sha256: "-".to_string(),
        channel_release_root: "-".to_string(),
        identifier,
    }))
}

fn abi_snapshot_covers_package(snapshot: &audit::PlanAbiSnapshot, package: &str) -> bool {
    snapshot
        .static_objects
        .iter()
        .any(|fact| fact.package == package)
        || snapshot
            .providers
            .iter()
            .any(|provider| provider.package == package)
        || snapshot
            .facts
            .iter()
            .any(|fact| fact.package == package || fact.provider_package == package)
}

fn cache_input_set_sha256(package: &str, artifacts: &[PlanArtifact]) -> Result<String> {
    let mut lines: Vec<String> = artifacts
        .iter()
        .filter(|artifact| {
            artifact.package == package && artifact.materiality == Materiality::CacheOnly
        })
        .map(artifact_record_line)
        .collect();
    lines.sort();
    if lines.is_empty()
        || lines.iter().any(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            fields.get(4).is_none_or(|hash| !canonical_sha256(hash))
        })
    {
        bail!("{package}: cache-only não possui conjunto material factual de inputs");
    }
    Ok(canonical_hash_material(
        b"MINITRUE-CACHE-INPUT-SET-V1\0",
        lines.into_iter().map(String::into_bytes),
    ))
}

fn finalize_media_cache_payloads(plan: &mut ResolvedPlan) -> Result<()> {
    if plan.purpose != PlanPurpose::Media || plan.abi_policy != AbiPolicy::Strict {
        return Ok(());
    }
    let packages: Vec<String> = plan
        .nodes
        .values()
        .filter(|node| {
            node.materiality == Materiality::CacheOnly
                && matches!(node.action, PlanAction::Vendor | PlanAction::Source)
        })
        .map(|node| node.name.clone())
        .collect();
    for package in packages {
        let payload = cache_input_set_sha256(&package, &plan.artifacts)?;
        plan.nodes
            .get_mut(&package)
            .expect("pacote coletado do mesmo mapa")
            .payload_sha256 = payload;
    }
    Ok(())
}

fn finalize_abi(plan: &mut ResolvedPlan, ctx: &Ctx) -> Result<()> {
    let material: Vec<String> = plan
        .nodes
        .values()
        .filter(|node| node.materiality.is_material() && node.kind != Kind::Meta)
        .map(|node| node.name.clone())
        .collect();
    if material.is_empty() {
        plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
        return Ok(());
    }
    let mut requires = BTreeSet::new();
    let mut provides = BTreeSet::new();
    let mut static_objects = BTreeSet::new();
    let mut none = BTreeSet::new();
    for package in &material {
        let node = plan.nodes.get(package).expect("pacote material coletado");
        if plan.purpose == PlanPurpose::Media && node.materiality == Materiality::CacheOnly {
            none.insert(AbiNone {
                package: package.clone(),
                reason: "cache-only-nao-aplicavel".to_string(),
            });
            continue;
        }
        let factual = plan.nodes.get(package).is_some_and(|node| {
            node.action == PlanAction::Keep
                || (plan.purpose == PlanPurpose::Media
                    && node.materiality == Materiality::Runtime
                    && node.action == PlanAction::Vendor
                    && canonical_sha256(&node.payload_sha256))
        });
        if !factual {
            plan.abi_pending.push(AbiPending {
                package: package.clone(),
                reason: "payload-nao-observado".to_string(),
            });
            continue;
        }
        match audit::plan_snapshot(ctx, std::slice::from_ref(package)) {
            Ok(snapshot) if snapshot.complete => {
                // A prova é por payload, não pela closure agregada. Um pacote
                // sem ABI própria continua precisando de ABI_NONE mesmo que
                // uma dependência possua providers/fatos ABI.
                let package_has_abi = abi_snapshot_covers_package(&snapshot, package);
                for provider in snapshot.providers {
                    provides.insert(AbiProvide {
                        package: provider.package,
                        object: provider.object,
                        namespace: provider.namespace,
                        name: provider.name,
                        versions: provider.versions,
                    });
                }
                for fact in snapshot.facts {
                    requires.insert(AbiRequire {
                        package: fact.package,
                        object: fact.object,
                        namespace: fact.kind,
                        name: fact.requirement,
                        versions: fact.versions,
                        provider_package: fact.provider_package,
                        provider_object: fact.provider_object,
                    });
                }
                for fact in snapshot.static_objects {
                    static_objects.insert(AbiStatic {
                        package: fact.package,
                        object: fact.object,
                    });
                }
                if !package_has_abi {
                    none.insert(AbiNone {
                        package: package.clone(),
                        reason: "payload-sem-abi-observada".to_string(),
                    });
                }
            }
            Ok(snapshot) => {
                eprintln!(
                    "  ABI de {package}: auditoria incompleta ({} erro(s), {} ausente(s))",
                    snapshot.error_count, snapshot.missing_count
                );
                plan.abi_pending.push(AbiPending {
                    package: package.clone(),
                    reason: "auditoria-incompleta".to_string(),
                });
            }
            Err(error) => {
                eprintln!("  ABI de {package}: auditoria indisponível: {error:#}");
                plan.abi_pending.push(AbiPending {
                    package: package.clone(),
                    reason: "auditoria-indisponivel".to_string(),
                });
            }
        }
    }
    plan.abi_requires = requires.into_iter().collect();
    plan.abi_provides = provides.into_iter().collect();
    plan.abi_static = static_objects.into_iter().collect();
    plan.abi_none = none.into_iter().collect();
    plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
    plan.abi_pending.sort();
    plan.abi_pending.dedup();
    let deferred_media_channel = plan.purpose == PlanPurpose::Media
        && plan.abi_policy == AbiPolicy::Strict
        && !plan.abi_pending.is_empty()
        && plan.abi_pending.iter().all(|pending| {
            plan.nodes
                .get(&pending.package)
                .is_some_and(|node| node.action == PlanAction::Channel)
        });
    if plan.abi_policy == AbiPolicy::Strict
        && !plan.abi_pending.is_empty()
        && !deferred_media_channel
    {
        return fail(
            5,
            "plano estrito/release exige ABI observada; há payload ainda não produzido ou auditado",
        );
    }
    Ok(())
}

fn hydrate_media_channel_abi(
    plan: &mut ResolvedPlan,
    producer_plans: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    if plan.purpose != PlanPurpose::Media || plan.abi_policy != AbiPolicy::Strict {
        return Ok(());
    }
    let runtime_packages: BTreeSet<String> = plan
        .nodes
        .values()
        .filter(|node| node.materiality == Materiality::Runtime && node.kind != Kind::Meta)
        .map(|node| node.name.clone())
        .collect();
    if runtime_packages.is_empty() {
        plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
        let _ = verify_canonical(&plan.canonical_bytes()?)?;
        return Ok(());
    }
    let mut runtime_authorities = BTreeSet::<(String, String, String, String, String)>::new();
    for package in &runtime_packages {
        let node = plan
            .nodes
            .get(package)
            .ok_or_else(|| anyhow::anyhow!("NODE material desapareceu"))?;
        if node.kind == Kind::Binary && node.action == PlanAction::Vendor {
            let producer = plan.artifacts.iter().find(|artifact| {
                artifact.package == *package
                    && artifact.origin_kind == "vendor-producer"
                    && artifact.materiality == Materiality::Runtime
                    && artifact.reprocorr == node.payload_sha256
            });
            let Some(producer) = producer else {
                return fail(
                    5,
                    format!("{package}: Vendor runtime não prende autoridade produtora v4"),
                );
            };
            let channel_name = producer
                .identifier
                .strip_prefix("producer:")
                .and_then(|value| value.strip_suffix(":record-vendor"))
                .ok_or_else(|| anyhow::anyhow!("vendor-producer sem channel canônico"))?;
            runtime_authorities.insert((
                channel_name.to_string(),
                producer.channel_index_sha256.clone(),
                producer.channel_lock_sha256.clone(),
                producer.producer_plan_lock_sha256.clone(),
                producer.channel_release_root.clone(),
            ));
            continue;
        }
        if node.action != PlanAction::Channel || node.kind != Kind::Source {
            return fail(
                5,
                format!("{package}: mídia runtime exige Channel source ou Vendor binary factual"),
            );
        }
        let selection = plan
            .channels
            .get(package)
            .ok_or_else(|| anyhow::anyhow!("{package}: seleção de canal desapareceu"))?;
        if selection.index_format != 4
            || !selection.release_root
            || selection.legacy_development
            || !canonical_sha256(
                selection
                    .producer_plan_lock_sha256
                    .as_deref()
                    .unwrap_or("-"),
            )
            || selection.index_reprocorr.as_deref() != Some(node.payload_sha256.as_str())
        {
            return fail(
                5,
                format!(
                    "{package}: mídia estrita exige canal v4 release e payload REPROCORR factual"
                ),
            );
        }
        runtime_authorities.insert((
            selection.channel.clone(),
            selection.index_sha256.clone(),
            selection.lock_sha256.clone(),
            selection
                .producer_plan_lock_sha256
                .clone()
                .expect("validado acima"),
            "yes".to_string(),
        ));
    }
    if runtime_authorities.len() != 1 {
        bail!("mídia runtime exige uma única autoridade producer PLAN/index/lock release");
    }
    let (channel_name, index_sha256, channel_lock_sha256, producer_sha256, release_root) =
        runtime_authorities.into_iter().next().unwrap();
    if release_root != "yes" {
        bail!("autoridade produtora runtime não é RELEASE_ROOT=yes");
    }
    let bytes = producer_plans.get(&producer_sha256).ok_or_else(|| {
        anyhow::anyhow!("PLAN_LOCK produtor {producer_sha256} não foi autenticado junto ao canal")
    })?;
    let verified = verify_canonical(bytes)?;
    if verified.lock_sha256 != producer_sha256
        || verified.purpose != PlanPurpose::ChannelEmit.as_str()
        || verified.abi_policy != AbiPolicy::Strict.as_str()
    {
        bail!("mídia recebeu PLAN_LOCK produtor com identidade/purpose/policy divergente");
    }
    for package in &runtime_packages {
        let local = plan.nodes.get(package).unwrap();
        let producer = verified
            .nodes
            .get(package)
            .ok_or_else(|| anyhow::anyhow!("produtor não contém NODE runtime {package}"))?;
        if producer.version != local.version
            || producer.kind != kind_str(local.kind)
            || producer.world != local.world
            || producer.action != "keep"
            || producer.role != "runtime"
            || producer.fingerprint != local.fingerprint
            || producer.payload != local.payload_sha256
            || producer.license != local.license
        {
            bail!("{package}: NODE da mídia diverge da identidade factual do produtor");
        }
        let local_inputs: BTreeSet<(String, String, String)> = plan
            .artifacts
            .iter()
            .filter(|artifact| artifact.package == *package)
            .filter_map(|artifact| {
                let kind = match artifact.origin_kind.as_str() {
                    "vendor-input" | "identity-source-input" => "input",
                    "signature-waiver"
                    | "signature-key"
                    | "signature-key-source"
                    | "signature"
                    | "checksums"
                    | "signature-evidence" => artifact.origin_kind.as_str(),
                    _ => return None,
                };
                Some((
                    kind.to_string(),
                    artifact.transport_sha256.clone(),
                    artifact.identifier.clone(),
                ))
            })
            .collect();
        let producer_facts = verified.artifact_facts(package)?;
        let producer_inputs: BTreeSet<(String, String, String)> = producer_facts
            .iter()
            .filter_map(|artifact| {
                let kind = match artifact.kind.as_str() {
                    "record-input" => "input",
                    "signature-waiver"
                    | "signature-key"
                    | "signature-key-source"
                    | "signature"
                    | "checksums"
                    | "signature-evidence" => artifact.kind.as_str(),
                    _ => return None,
                };
                Some((
                    kind.to_string(),
                    artifact.transport_sha256.clone(),
                    artifact.identifier.clone(),
                ))
            })
            .collect();
        if local_inputs != producer_inputs {
            bail!("{package}: inputs/assinaturas locais divergem do producer PLAN");
        }
        if local.kind == Kind::Binary {
            let local_producer = plan
                .artifacts
                .iter()
                .find(|artifact| {
                    artifact.package == *package && artifact.origin_kind == "vendor-producer"
                })
                .ok_or_else(|| anyhow::anyhow!("Vendor runtime sem ARTIFACT produtor"))?;
            let record_facts: Vec<&VerifiedArtifactFact> = producer_facts
                .iter()
                .filter(|artifact| artifact.kind == "record-vendor")
                .collect();
            if record_facts.len() != 1
                || record_facts[0].transport_sha256 != local_producer.transport_sha256
                || record_facts[0].reprocorr != local.payload_sha256
                || local_producer.channel_index_sha256 != index_sha256
                || local_producer.channel_lock_sha256 != channel_lock_sha256
                || local_producer.producer_plan_lock_sha256 != producer_sha256
                || local_producer.identifier != format!("producer:{channel_name}:record-vendor")
            {
                bail!("{package}: record-vendor local diverge da autoridade produtora");
            }
        }
    }
    let imported = verified.abi_projection(&runtime_packages)?;

    let mut requires: BTreeSet<_> = std::mem::take(&mut plan.abi_requires).into_iter().collect();
    let mut provides: BTreeSet<_> = std::mem::take(&mut plan.abi_provides).into_iter().collect();
    let mut static_objects: BTreeSet<_> =
        std::mem::take(&mut plan.abi_static).into_iter().collect();
    let mut none: BTreeSet<_> = std::mem::take(&mut plan.abi_none).into_iter().collect();
    requires.extend(imported.requires);
    provides.extend(imported.provides);
    static_objects.extend(imported.static_objects);
    none.extend(imported.none);
    plan.abi_requires = requires.into_iter().collect();
    plan.abi_provides = provides.into_iter().collect();
    plan.abi_static = static_objects.into_iter().collect();
    plan.abi_none = none.into_iter().collect();
    plan.abi_pending
        .retain(|pending| !runtime_packages.contains(&pending.package));
    if !plan.abi_pending.is_empty() {
        bail!("mídia estrita reteve ABI_PENDING após importar o produtor");
    }
    plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
    // O parser comum é a fronteira final: a ABI importada precisa fechar as
    // mesmas arestas, roles e versões do plano portátil, não apenas existir.
    let bytes = plan.canonical_bytes()?;
    let _ = verify_canonical(&bytes)?;
    Ok(())
}

pub fn resolve(
    ctx: &Ctx,
    roots: &[String],
    binary_policy: BinaryPolicy,
    abi_policy: AbiPolicy,
    mode: LoadMode,
) -> Result<ResolvedPlan> {
    let roots: Vec<PlanRoot> = roots
        .iter()
        .map(|name| PlanRoot {
            name: name.clone(),
            role: RootRole::Install,
        })
        .collect();
    resolve_for(
        ctx,
        &roots,
        PlanPurpose::Rectify,
        binary_policy,
        abi_policy,
        mode,
    )
}

fn open_anchored_leaf(path: &Path, flags: i32) -> Result<(fs::File, fs::File, CString)> {
    let mut directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(CString::new(name.as_bytes())?),
            Component::ParentDir | Component::Prefix(_) => {
                bail!("caminho ancorado contém componente de escape")
            }
        }
    }
    let leaf = names
        .pop()
        .ok_or_else(|| anyhow::anyhow!("caminho ancorado não possui folha"))?;
    for name in names {
        directory = openat_file(
            &directory,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
    }
    let file = openat_file(
        &directory,
        &leaf,
        flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    Ok((file, directory, leaf))
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == ErrorKind::NotFound)
    })
}

fn read_world_bytes_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    const MAX_WORLD_BYTES: u64 = 4 * 1024 * 1024;
    let (mut file, parent, leaf) = match open_anchored_leaf(path, libc::O_RDONLY | libc::O_NONBLOCK)
    {
        Ok(opened) => opened,
        Err(error) if error_is_not_found(&error) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("não pude abrir world {}", path.display()))
        }
    };
    let before = StableMetadata::from(&file.metadata()?);
    if before.mode & libc::S_IFMT != libc::S_IFREG
        || before.nlink != 1
        || before.len > MAX_WORLD_BYTES
    {
        bail!("world precisa ser regular nlink=1 dentro do limite");
    }
    let mut bytes = Vec::with_capacity(before.len as usize);
    Read::by_ref(&mut file)
        .take(MAX_WORLD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = StableMetadata::from(&file.metadata()?);
    let reopened = openat_file(
        &parent,
        &leaf,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let at_path = StableMetadata::from(&reopened.metadata()?);
    if before != after || after != at_path || bytes.len() as u64 != before.len {
        bail!("world mudou durante o snapshot");
    }
    Ok(Some(bytes))
}

fn read_world_bytes(path: &Path) -> Result<Vec<u8>> {
    read_world_bytes_optional(path)?
        .ok_or_else(|| anyhow::anyhow!("world não existe: {}", path.display()))
}

/// Lê um world sem seguir symlink na folha e devolve somente identidades
/// canônicas. O pathname jamais entra no lock; apenas os roots ordenados.
pub fn roots_from_world(path: &Path, role: RootRole) -> Result<Vec<PlanRoot>> {
    let bytes = read_world_bytes(path)?;
    roots_from_world_bytes(&bytes, role)
}

fn roots_from_world_bytes(bytes: &[u8], role: RootRole) -> Result<Vec<PlanRoot>> {
    if bytes.contains(&b'\r') {
        bail!("world contém CR não canônico");
    }
    let text = std::str::from_utf8(bytes).context("world não é UTF-8")?;
    let mut names = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let value = raw.split_once('#').map_or(raw, |(value, _)| value).trim();
        if value.is_empty() {
            continue;
        }
        if value.split_whitespace().count() != 1 {
            bail!("world linha {} não contém exatamente um pacote", index + 1);
        }
        recipe::validate_name(value)?;
        if !names.insert(value.to_string()) {
            bail!("world repete pacote {value}");
        }
    }
    Ok(names
        .into_iter()
        .map(|name| PlanRoot { name, role })
        .collect())
}

fn system_world_snapshot(ctx: &Ctx) -> Result<(Vec<u8>, Vec<PlanRoot>)> {
    let bytes = read_world_bytes_optional(&ctx.world_path())?.unwrap_or_default();
    let roots = roots_from_world_bytes(&bytes, RootRole::Install)?;
    Ok((bytes, roots))
}

pub fn roots_from_system_world(ctx: &Ctx) -> Result<Vec<PlanRoot>> {
    Ok(system_world_snapshot(ctx)?.1)
}

fn classify_sync_orphans(
    ctx: &Ctx,
    roots: &[PlanRoot],
    nodes: &BTreeMap<String, PlanNode>,
    edges: &[PlanEdge],
) -> Result<(Vec<PlanOrphan>, Vec<PlanPredictedResidue>)> {
    let mut runtime_adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in edges
        .iter()
        .filter(|edge| matches!(edge.kind, EdgeKind::Runtime | EdgeKind::Aggregation))
    {
        runtime_adjacency
            .entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
    }
    let mut runtime = BTreeSet::new();
    let mut stack: Vec<&str> = roots.iter().map(|root| root.name.as_str()).collect();
    while let Some(package) = stack.pop() {
        if !runtime.insert(package.to_string()) {
            continue;
        }
        if let Some(dependencies) = runtime_adjacency.get(package) {
            stack.extend(dependencies.iter().copied());
        }
    }

    let records = ctx.records_dir();
    install::ensure_real_directory_or_absent(&ctx.root, &records, "registros do minitrue")?;
    let entries = match fs::read_dir(&records) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let predicted = nodes
                .values()
                .filter(|node| {
                    node.materiality.is_material()
                        && !runtime.contains(&node.name)
                        && !matches!(node.action, PlanAction::Keep)
                })
                .map(|node| PlanPredictedResidue {
                    package: node.name.clone(),
                    kind: "build-residue".to_string(),
                    reason: "materializado-pela-operacao".to_string(),
                    expected_fingerprint: node.fingerprint.clone(),
                    action: node.action.as_str().to_string(),
                })
                .collect();
            return Ok((Vec::new(), predicted));
        }
        Err(error) => return Err(error.into()),
    };
    let mut orphans = BTreeSet::new();
    for entry in entries {
        let entry = entry?;
        let package = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("record com nome não UTF-8"))?;
        recipe::validate_name(&package)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_dir() {
            bail!("record de {package} não é diretório real");
        }
        let record_fact_sha256 = install::verify_historical_record(ctx, &entry.path(), &package)
            .with_context(|| format!("record instalado {package} não é íntegro"))?;
        if runtime.contains(&package) {
            continue;
        }
        let (kind, reason) = if nodes.contains_key(&package) {
            ("build-residue", "somente-build-toolchain-runner")
        } else {
            ("unreachable", "fora-da-closure-runtime")
        };
        orphans.insert(PlanOrphan {
            package,
            kind: kind.to_string(),
            reason: reason.to_string(),
            record_fact_sha256,
        });
    }
    let predicted = nodes
        .values()
        .filter(|node| {
            node.materiality.is_material()
                && !runtime.contains(&node.name)
                && !matches!(node.action, PlanAction::Keep)
        })
        .map(|node| PlanPredictedResidue {
            package: node.name.clone(),
            kind: "build-residue".to_string(),
            reason: "materializado-pela-operacao".to_string(),
            expected_fingerprint: node.fingerprint.clone(),
            action: node.action.as_str().to_string(),
        })
        .collect();
    Ok((orphans.into_iter().collect(), predicted))
}

pub fn resolve_for(
    ctx: &Ctx,
    roots: &[PlanRoot],
    purpose: PlanPurpose,
    binary_policy: BinaryPolicy,
    abi_policy: AbiPolicy,
    mode: LoadMode,
) -> Result<ResolvedPlan> {
    resolve_for_with_intermediate(
        ctx,
        roots,
        purpose,
        binary_policy,
        abi_policy,
        mode,
        &BTreeSet::new(),
    )
}

fn resolve_for_with_intermediate(
    ctx: &Ctx,
    roots: &[PlanRoot],
    purpose: PlanPurpose,
    binary_policy: BinaryPolicy,
    abi_policy: AbiPolicy,
    mode: LoadMode,
    intermediate_records: &BTreeSet<String>,
) -> Result<ResolvedPlan> {
    if roots.is_empty() {
        return fail(1, "plano exige ao menos um root");
    }
    let mut canonical_roots = roots.to_vec();
    canonical_roots.sort_by(|left, right| {
        left.role
            .as_str()
            .cmp(right.role.as_str())
            .then_with(|| left.name.cmp(&right.name))
    });
    if canonical_roots.windows(2).any(|pair| pair[0] == pair[1]) {
        return fail(1, "roots repetidos não são canônicos");
    }
    for root in &canonical_roots {
        recipe::validate_name(&root.name)?;
    }

    let (tree_sha256, all) = load_frozen_tree(ctx)?;
    let mut identity = Vec::new();
    let mut seen = HashSet::new();
    for root in &canonical_roots {
        identity_visit(&root.name, &all, &mut seen, &mut Vec::new(), &mut identity)?;
    }
    let fingerprints = recipe::build_fingerprints(&identity)?;
    let recipes: BTreeMap<String, Recipe> = identity
        .into_iter()
        .map(|recipe| (recipe.name.clone(), recipe))
        .collect();
    let force_materialization = purpose == PlanPurpose::CacheClosure;
    let mut nodes = BTreeMap::new();
    for recipe in recipes.values() {
        let fingerprint = fingerprints
            .get(&recipe.name)
            .ok_or_else(|| anyhow::anyhow!("sem fingerprint para {}", recipe.name))?;
        nodes.insert(
            recipe.name.clone(),
            initial_node(
                ctx,
                recipe,
                fingerprint,
                binary_policy,
                intermediate_records.contains(&recipe.name),
                force_materialization,
            )?,
        );
    }

    let mut catalog = None;
    let mut channel_keep_candidates = BTreeSet::new();
    let mut active_edges = HashMap::new();
    let mut done = HashMap::new();
    let mut order = Vec::new();
    let allow_legacy_channel =
        abi_policy == AbiPolicy::Development && purpose != PlanPurpose::Media;
    let strict_media = purpose == PlanPurpose::Media && abi_policy == AbiPolicy::Strict;
    for root in &canonical_roots {
        activate(
            ctx,
            &root.name,
            root.role.materiality(),
            purpose,
            binary_policy,
            mode,
            allow_legacy_channel,
            strict_media,
            intermediate_records,
            force_materialization,
            &recipes,
            &fingerprints,
            &mut nodes,
            &mut catalog,
            &mut channel_keep_candidates,
            &mut active_edges,
            &mut done,
            &mut Vec::new(),
            &mut order,
        )?;
    }
    let channels = match catalog {
        Some(catalog) => catalog.finish()?,
        None => channel::Resolution::empty(mode),
    };
    for package in channel_keep_candidates {
        let node = nodes
            .get_mut(&package)
            .ok_or_else(|| anyhow::anyhow!("candidato keep de canal perdeu NODE"))?;
        let recipe = recipes
            .get(&package)
            .ok_or_else(|| anyhow::anyhow!("candidato keep de canal perdeu receita"))?;
        let selection = channels
            .get(&package)
            .ok_or_else(|| anyhow::anyhow!("candidato keep de canal perdeu seleção"))?;
        let expected_payload = selection
            .index_reprocorr
            .as_deref()
            .or(recipe.reprocorr.as_deref());
        let installed = install::installed_plan_material(ctx, recipe)?;
        if installed.as_ref().is_some_and(|(origin, payload)| {
            origin == &format!("canal:{}", selection.channel)
                && expected_payload == Some(payload.as_str())
        }) {
            let (origin, payload) = installed.expect("testado imediatamente acima");
            node.action = PlanAction::Keep;
            node.origin = origin;
            node.payload_sha256 = payload;
        }
    }
    let mut artifacts = Vec::new();
    let mut runtime_vendor_facts = BTreeMap::new();
    for node in nodes.values_mut() {
        let recipe = recipes
            .get(&node.name)
            .ok_or_else(|| anyhow::anyhow!("nó sem receita"))?;
        match node.action {
            PlanAction::Channel => {
                artifacts.extend(input_artifacts(
                    recipe,
                    "identity-source-input",
                    Materiality::IdentityOnly,
                    UpstreamEvidence::Observed,
                )?);
                let selection = channels
                    .get(&node.name)
                    .ok_or_else(|| anyhow::anyhow!("nó de canal sem seleção"))?;
                if channels.lock_sha256() != Some(selection.lock_sha256.as_str()) {
                    bail!("seleção de canal não prende os bytes exatos do CHANNEL_LOCK em memória");
                }
                if strict_media
                    && (selection.index_format != 4
                        || !selection.release_root
                        || selection.legacy_development
                        || selection.producer_plan_lock_sha256.is_none())
                {
                    bail!(
                        "{}: mídia estrita exige seleção CHANNEL_INDEX_FORMAT=4 RELEASE_ROOT=yes com PLAN_LOCK produtor",
                        node.name
                    );
                }
                node.origin = format!("canal:{}", selection.channel);
                // SHA256 prende o transporte tar.zst; REPROCORR é a
                // identidade factual do payload descompactado que o produtor
                // reobservou. Legacy development conserva o transporte como
                // identidade apenas quando o índice não possui REPROCORR.
                node.payload_sha256 = selection
                    .index_reprocorr
                    .clone()
                    .unwrap_or_else(|| selection.artifact_sha256.clone());
                artifacts.push(PlanArtifact {
                    package: node.name.clone(),
                    origin_kind: "channel".to_string(),
                    materiality: node.materiality,
                    transport_sha256: selection.artifact_sha256.clone(),
                    reprocorr: selection
                        .index_reprocorr
                        .clone()
                        .or_else(|| recipe.reprocorr.clone())
                        .unwrap_or_else(|| "-".to_string()),
                    channel_index_sha256: selection.index_sha256.clone(),
                    channel_lock_sha256: selection.lock_sha256.clone(),
                    producer_plan_lock_sha256: selection
                        .producer_plan_lock_sha256
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                    channel_release_root: if selection.release_root {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    },
                    identifier: format!(
                        "channel:{}:url={}",
                        selection.channel, selection.artifact_url
                    ),
                });
            }
            PlanAction::Vendor => {
                artifacts.extend(input_artifacts(
                    recipe,
                    "vendor-input",
                    node.materiality,
                    UpstreamEvidence::Observed,
                )?);
                if strict_media && node.materiality == Materiality::Runtime {
                    let producer =
                        install::vendor_producer_record_fact(ctx, recipe, &node.fingerprint)?;
                    node.payload_sha256 = producer.payload_sha256.clone();
                    runtime_vendor_facts.insert(node.name.clone(), producer);
                }
            }
            PlanAction::Source => artifacts.extend(input_artifacts(
                recipe,
                "source-input",
                node.materiality,
                UpstreamEvidence::Observed,
            )?),
            PlanAction::Keep => {
                if recipe.kind != Kind::Meta {
                    artifacts.extend(input_artifacts(
                        recipe,
                        "record-input",
                        Materiality::IdentityOnly,
                        if node.origin.starts_with("canal:") {
                            UpstreamEvidence::FromChannel
                        } else {
                            UpstreamEvidence::Observed
                        },
                    )?);
                }
                if let Some(artifact) = factual_artifact(ctx, node)? {
                    artifacts.push(artifact);
                }
                if let Some(selection) = channels.get(&node.name) {
                    artifacts.push(PlanArtifact {
                        package: node.name.clone(),
                        origin_kind: "channel-selection".to_string(),
                        materiality: Materiality::IdentityOnly,
                        transport_sha256: selection.artifact_sha256.clone(),
                        reprocorr: selection
                            .index_reprocorr
                            .clone()
                            .or_else(|| recipe.reprocorr.clone())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "{}: keep selecionado por canal sem hash do payload",
                                    node.name
                                )
                            })?,
                        channel_index_sha256: selection.index_sha256.clone(),
                        channel_lock_sha256: selection.lock_sha256.clone(),
                        producer_plan_lock_sha256: selection
                            .producer_plan_lock_sha256
                            .clone()
                            .unwrap_or_else(|| "-".to_string()),
                        channel_release_root: if selection.release_root {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                        identifier: format!(
                            "channel:{}:url={}",
                            selection.channel, selection.artifact_url
                        ),
                    });
                }
            }
            PlanAction::Meta => {}
        }
    }
    if !runtime_vendor_facts.is_empty() {
        let authorities: BTreeSet<(String, String, String, String, String)> = artifacts
            .iter()
            .filter(|artifact| {
                artifact.origin_kind == "channel"
                    && artifact.materiality == Materiality::Runtime
                    && artifact.channel_release_root == "yes"
            })
            .map(|artifact| {
                let channel_name = artifact
                    .identifier
                    .strip_prefix("channel:")
                    .and_then(|value| value.split_once(":url=").map(|(name, _)| name))
                    .ok_or_else(|| anyhow::anyhow!("autoridade channel sem nome canônico"))?;
                Ok((
                    channel_name.to_string(),
                    artifact.channel_index_sha256.clone(),
                    artifact.channel_lock_sha256.clone(),
                    artifact.producer_plan_lock_sha256.clone(),
                    artifact.channel_release_root.clone(),
                ))
            })
            .collect::<Result<_>>()?;
        if authorities.len() != 1 {
            bail!("mídia runtime Vendor exige uma única autoridade Channel v4 release do target");
        }
        let (channel_name, index, channel_lock, producer_plan, release_root) =
            authorities.into_iter().next().unwrap();
        for (package, producer) in runtime_vendor_facts {
            artifacts.push(PlanArtifact {
                package,
                origin_kind: "vendor-producer".to_string(),
                materiality: Materiality::Runtime,
                transport_sha256: producer.record_fact_sha256,
                reprocorr: producer.payload_sha256,
                channel_index_sha256: index.clone(),
                channel_lock_sha256: channel_lock.clone(),
                producer_plan_lock_sha256: producer_plan.clone(),
                channel_release_root: release_root.clone(),
                identifier: format!("producer:{channel_name}:record-vendor"),
            });
        }
    }
    artifacts.sort();
    artifacts.dedup();
    let edges = edge_list(&recipes, &fingerprints, &active_edges)?;
    order = material_order(&nodes, &edges)?;
    let build_contract_sha256 = sha256(recipe::build_runner_material().as_bytes());
    let (orphans, predicted_residues) = if purpose == PlanPurpose::Sync {
        classify_sync_orphans(ctx, &canonical_roots, &nodes, &edges)?
    } else {
        (Vec::new(), Vec::new())
    };
    let mut plan = ResolvedPlan {
        roots: canonical_roots,
        recipes,
        fingerprints,
        nodes,
        edges,
        order,
        channels,
        tree_sha256,
        build_contract_sha256,
        binary_policy,
        purpose,
        abi_policy,
        artifacts,
        abi_requires: Vec::new(),
        abi_provides: Vec::new(),
        abi_static: Vec::new(),
        abi_none: Vec::new(),
        abi_pending: Vec::new(),
        abi_audit_sha256: "-".to_string(),
        orphans,
        predicted_residues,
        objects_authenticated: Cell::new(false),
        tree_revalidated: Cell::new(false),
    };
    finalize_media_cache_payloads(&mut plan)?;
    finalize_abi(&mut plan, ctx)?;
    // Todos os vetores são canônicos antes de qualquer consumidor vê-los.
    plan.edges.sort();
    plan.edges.dedup();
    Ok(plan)
}

/// Abrangência do fechamento pós-apply.
///
/// `Complete` é o fechamento de sempre: o mundo instalado INTEIRO precisa estar
/// `keep`, e o `APPLIED_PLAN_RECEIPT` que sai dele é a prova de que um plano foi
/// aplicado por completo. `Partial` existe para o caminho de FALHA: fecha só o
/// que a execução conseguiu terminar, tomando esses pacotes como raízes, e NÃO
/// emite receipt — porque nada ali prova um mundo completo, e emitir um seria
/// mentir sobre o estado.
///
/// Sem isto, uma cadeia interrompida deixava todos os seus registros em v3, e v3
/// não é elegível para `keep`: uma retomada reconstruiria tudo, inclusive um
/// superseder como o gawk, que não reconstrói depois de ter tomado o applet do
/// busybox. O custo disso eram horas por falha.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppliedClosure {
    Complete,
    Partial,
}

/// Fecha novamente o estado *depois* da aplicação. A primeira resolução
/// development pode declarar payload/ABI pendentes porque ainda vai produzi-los;
/// esta passagem exige que cada material já seja `keep`, reabre todos os inputs,
/// reaudita ABI, publica o novo lock e só então revincula os records.
pub(crate) fn finalize_applied(
    ctx: &Ctx,
    roots: &[String],
    purpose: PlanPurpose,
    binary_policy: BinaryPolicy,
    abi_policy: AbiPolicy,
    written_records: &BTreeSet<String>,
    closure: AppliedClosure,
) -> Result<FinalizedMaterials> {
    let roots: Vec<PlanRoot> =
        if purpose == PlanPurpose::Rectify && closure == AppliedClosure::Complete {
            // `applied-plans/current` is the authority for the complete installed
            // world, not merely for the package names of this invocation.
            roots_from_system_world(ctx)?
        } else {
            roots
                .iter()
                .map(|name| PlanRoot {
                    name: name.clone(),
                    role: RootRole::Install,
                })
                .collect()
        };
    let mut plan = resolve_for_with_intermediate(
        ctx,
        &roots,
        purpose,
        binary_policy,
        abi_policy,
        LoadMode::Mutating,
        written_records,
    )?;
    if plan.nodes.values().any(|node| {
        node.materiality.is_material()
            && !matches!(node.action, PlanAction::Keep | PlanAction::Meta)
    }) {
        return fail(
            5,
            "fechamento pós-apply encontrou payload material que ainda não é keep",
        );
    }
    plan.authenticate_objects(ctx, false)?;
    plan.revalidate_tree(ctx)?;
    // RECORD_FORMAT=4 nunca representa um estado pendente, mesmo quando o
    // plano foi pedido em modo development. Development permite produzir o
    // payload; esta segunda passagem já precisa prová-lo factualmente.
    //
    // A forma ESTRITA é do fechamento completo, e cobra mais que o vínculo de
    // record: ela recusa qualquer ABI_PENDING na seleção porque é o que
    // autoriza publicação oficial. Um fechamento parcial não publica nada — não
    // emite receipt, não vira autoridade de mundo — e cobrar dele a prova de um
    // mundo inteiro é justamente o que o impede de existir. A garantia que
    // importa aqui continua intacta e é do `bind_record`: só vira v4 o record
    // cujo nó é `keep`/`meta` com payload factual.
    let identities = plan.material_identities(closure == AppliedClosure::Complete)?;
    if closure == AppliedClosure::Partial && !plan.abi_pending.is_empty() {
        // Não é erro, e por isso não aborta: no meio de uma execução
        // interrompida há ABI que ninguém chegou a observar. Fica dito para que
        // a próxima investigação não precise adivinhar, que foi exatamente o
        // que esta precisou.
        eprintln!(
            "  fechamento parcial: {} pacote(s) sem ABI observada, não impedem o vínculo",
            plan.abi_pending.len()
        );
    }
    let lock_sha256 = plan.persist(ctx)?;
    // O que o v4 afirma é "este record é factual". Um pacote cuja ABI ninguém
    // observou não sustenta essa afirmação, e promovê-lo assim mesmo faria uma
    // retomada tratá-lo como `keep` sem que ele jamais tenha sido auditado —
    // trocaria a garantia pela conveniência, que é exatamente o que este
    // fechamento existe para NÃO fazer. Ele fica em v3 e a próxima execução o
    // reconstrói; os demais seguem promovidos.
    let pendentes: BTreeSet<&str> = plan
        .abi_pending
        .iter()
        .map(|pending| pending.package.as_str())
        .collect();
    for (package, node) in &plan.nodes {
        if written_records.contains(package)
            && !pendentes.contains(package.as_str())
            && node.materiality == Materiality::Runtime
            && matches!(node.action, PlanAction::Keep | PlanAction::Meta)
        {
            if !ctx.records_dir().join(package).is_dir() {
                bail!("{package}: fechamento factual perdeu o record material");
            }
            plan.bind_record(ctx, package, &lock_sha256)?;
        }
    }
    // O receipt afirma que ESTE plano é o mundo instalado. Um fechamento
    // parcial não pode afirmar isso: ele fecha o que deu certo até a falha, e o
    // resto da closure não foi construído. Emitir receipt aqui trocaria a
    // retomada barata por uma autoridade falsa.
    if purpose == PlanPurpose::Rectify && closure == AppliedClosure::Complete {
        let receipt = persist_applied_receipt(ctx, &plan, &lock_sha256)?;
        eprintln!("  receipt aplicado: {receipt}");
    }
    Ok(FinalizedMaterials {
        lock_sha256,
        identities,
    })
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let safe = byte.is_ascii_alphanumeric()
            || matches!(*byte, b'.' | b'_' | b':' | b'+' | b'/' | b'@' | b'=' | b'-');
        if safe && *byte != b'%' {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

fn push_line(body: &mut String, line: String) -> Result<()> {
    if body
        .len()
        .checked_add(line.len() + 1)
        .is_none_or(|size| size > MAX_PLAN_BYTES)
    {
        bail!("PLAN_LOCK excede {MAX_PLAN_BYTES} bytes");
    }
    body.push_str(&line);
    body.push('\n');
    Ok(())
}

fn artifact_record_line(artifact: &PlanArtifact) -> String {
    format!(
        "ARTIFACT\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        encode(&artifact.package),
        artifact.origin_kind,
        artifact.materiality.as_str(),
        artifact.transport_sha256,
        artifact.reprocorr,
        artifact.channel_index_sha256,
        artifact.channel_lock_sha256,
        artifact.producer_plan_lock_sha256,
        artifact.channel_release_root,
        encode(&artifact.identifier),
    )
}

fn provenance_sha256_from_lines<I>(lines: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let mut lines: Vec<String> = lines.into_iter().collect();
    lines.sort();
    let mut digest = Sha256::new();
    digest.update(b"MINITRUE-PROVENANCE-V1\0");
    for line in lines {
        digest.update(line.as_bytes());
        digest.update(b"\n");
    }
    hex::encode(digest.finalize())
}

fn material_id_from_node_base(base: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"MINITRUE-MATERIAL-V1\0");
    digest.update(base.as_bytes());
    digest.update(b"\n");
    hex::encode(digest.finalize())
}

fn node_base_line(node: &PlanNode, provenance_sha256: &str) -> String {
    format!(
        "NODE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        encode(&node.name),
        encode(&node.version),
        kind_str(node.kind),
        node.world,
        node.action.as_str(),
        encode(&node.origin),
        node.fingerprint,
        node.materiality.as_str(),
        node.payload_sha256,
        encode(&node.license),
        provenance_sha256,
    )
}

fn live_artifact_record_line(id: &str, artifact: &LiveArtifactIdentity) -> String {
    format!(
        "LIVE_ARTIFACT\t{}\t{}\t{}\t{}",
        encode(id),
        encode(&artifact.kind),
        encode(&artifact.identifier),
        artifact.sha256,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_live_material_identity(
    id: String,
    variant: String,
    status: LiveMaterialStatus,
    materiality: LiveMateriality,
    role: Materiality,
    artifact_kind: String,
    origin_kind: String,
    source_id: String,
    provenance_id: String,
    license: String,
    license_evidence_sha256: String,
    payload_sha256: String,
    mut artifacts: Vec<LiveArtifactIdentity>,
) -> LiveMaterialIdentity {
    artifacts.sort();
    let provenance_sha256 = provenance_sha256_from_lines(
        artifacts
            .iter()
            .map(|artifact| live_artifact_record_line(&id, artifact)),
    );
    let base = format!(
        "MATERIAL\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        encode(&id),
        encode(&variant),
        status.as_str(),
        materiality.as_str(),
        role.as_str(),
        encode(&artifact_kind),
        encode(&origin_kind),
        encode(&source_id),
        encode(&provenance_id),
        encode(&license),
        license_evidence_sha256,
        payload_sha256,
        provenance_sha256,
    );
    let material_id = material_id_from_node_base(&base);
    LiveMaterialIdentity {
        id,
        variant,
        status,
        materiality,
        role,
        artifact_kind,
        origin_kind,
        source_id,
        provenance_id,
        license,
        license_evidence_sha256,
        payload_sha256,
        material_id,
        provenance_sha256,
        artifacts,
    }
}

fn live_common_artifacts(
    authority_sha256: &str,
    runner_proof_sha256: &str,
    components_sha256: &str,
    entries_sha256: &str,
) -> Vec<LiveArtifactIdentity> {
    vec![
        LiveArtifactIdentity {
            kind: "authority".to_string(),
            identifier: "live-lock".to_string(),
            sha256: authority_sha256.to_string(),
        },
        LiveArtifactIdentity {
            kind: "runner-proof".to_string(),
            identifier: "live-efi".to_string(),
            sha256: runner_proof_sha256.to_string(),
        },
        LiveArtifactIdentity {
            kind: "components".to_string(),
            identifier: "live-efi".to_string(),
            sha256: components_sha256.to_string(),
        },
        LiveArtifactIdentity {
            kind: "entries".to_string(),
            identifier: "live-efi".to_string(),
            sha256: entries_sha256.to_string(),
        },
    ]
}

fn parse_live_media_documents(
    anchors: &LiveMediaAnchors<'_>,
    documents: LiveMediaDocuments<'_>,
) -> Result<LiveMaterialImport> {
    require_live_sha256(
        anchors.expected_authority_sha256,
        "âncora de autoridade LIVE_LOCK",
    )?;
    require_live_sha256(
        anchors.expected_runner_proof_sha256,
        "âncora externa do Runner Proof",
    )?;
    let authority_sha256 = sha256(documents.lock);
    let runner_proof_sha256 = sha256(documents.runner_proof);
    let components_sha256 = sha256(documents.components);
    if authority_sha256 != anchors.expected_authority_sha256 {
        bail!("LIVE_LOCK diverge da autoridade externa esperada");
    }
    if runner_proof_sha256 != anchors.expected_runner_proof_sha256 {
        bail!("Runner Proof diverge da âncora externa esperada");
    }
    let lock = parse_live_lock(documents.lock)?;
    let components = parse_live_components(documents.components)?;
    let runner = parse_live_runner_proof(documents.runner_proof)?;
    if lock.components_sha256 != components_sha256
        || lock.embedded_components_sha256 != components_sha256
        || lock.runner_proof_sha256 != runner_proof_sha256
        || components.runner_proof_sha256 != runner_proof_sha256
        || lock.entries_sha256 != components.entries_sha256
        || lock.build_contract_sha256 != components.build_contract_sha256
        || lock.mode != components.mode
        || lock.mode != runner.mode
        || lock.epoch != components.epoch
        || lock.epoch != runner.epoch
        || lock.source_snapshot_sha256 != runner.source_snapshot_sha256
        || lock.builder_lock_sha256 != runner.builder_lock_sha256
        || lock.builder_rootfs_tree_sha256 != runner.builder_rootfs_tree_sha256
        || lock.helper_binary_sha256 != runner.helper_binary_sha256
    {
        bail!("LIVE_LOCK/Components/Runner Proof não formam a mesma composição");
    }
    if lock.mode != "release"
        || lock.release_eligible != "yes"
        || components.release_inputs_complete != "yes"
        || runner.authenticated != "yes"
    {
        bail!("import Media Strict exige composição LIVE release autenticada e elegível");
    }
    for (value, label) in [
        (&lock.boot_efi_sha256, "BOOT_EFI_SHA256"),
        (&lock.embed_proof_sha256, "EMBED_PROOF_SHA256"),
        (&lock.initramfs_blob_sha256, "INITRAMFS_BLOB_SHA256"),
        (&lock.initramfs_cpio_sha256, "INITRAMFS_CPIO_SHA256"),
        (&lock.helper_binary_sha256, "LIVE_LOCK_HELPER_BINARY_SHA256"),
        (&lock.build_contract_sha256, "BUILD_CONTRACT_SHA256"),
        (&lock.source_snapshot_sha256, "SOURCE_SNAPSHOT_SHA256"),
        (&lock.builder_lock_sha256, "BUILDER_LOCK_SHA256"),
        (
            &lock.builder_rootfs_tree_sha256,
            "BUILDER_ROOTFS_TREE_SHA256",
        ),
    ] {
        if value == EMPTY_SHA256 {
            bail!("import Media Strict contém pin factual vazio em {label}");
        }
    }

    let mut identities = Vec::with_capacity(components.entries.len() + 1);
    for entry in components.entries {
        let mut artifacts = live_common_artifacts(
            &authority_sha256,
            &runner_proof_sha256,
            &components_sha256,
            &components.entries_sha256,
        );
        artifacts.extend([
            LiveArtifactIdentity {
                kind: "entry".to_string(),
                identifier: format!("{}:{}", entry.variant, entry.id),
                sha256: sha256(format!("{}\n", entry.raw_line).as_bytes()),
            },
            LiveArtifactIdentity {
                kind: "input".to_string(),
                identifier: entry.source_id.clone(),
                sha256: entry.input_sha256.clone(),
            },
            LiveArtifactIdentity {
                kind: "payload".to_string(),
                identifier: entry.provenance.clone(),
                sha256: entry.payload_sha256.clone(),
            },
            LiveArtifactIdentity {
                kind: "config".to_string(),
                identifier: format!("component:{}:config", entry.id),
                sha256: entry.config_sha256.clone(),
            },
            LiveArtifactIdentity {
                kind: "build-contract".to_string(),
                identifier: "live-efi".to_string(),
                sha256: entry.contract_sha256.clone(),
            },
            LiveArtifactIdentity {
                kind: "toolchain".to_string(),
                identifier: entry.toolchain_id.clone(),
                sha256: entry.toolchain_sha256.clone(),
            },
            LiveArtifactIdentity {
                kind: "license-evidence".to_string(),
                identifier: format!("component:{}:license", entry.id),
                sha256: entry.license_evidence_sha256.clone(),
            },
        ]);
        identities.push(build_live_material_identity(
            entry.id,
            entry.variant,
            entry.status,
            entry.materiality,
            entry.role,
            entry.artifact_kind,
            entry.origin_kind,
            entry.source_id,
            entry.provenance,
            entry.license,
            entry.license_evidence_sha256,
            entry.payload_sha256,
            artifacts,
        ));
    }

    let mut boot_artifacts = live_common_artifacts(
        &authority_sha256,
        &runner_proof_sha256,
        &components_sha256,
        &components.entries_sha256,
    );
    boot_artifacts.extend([
        LiveArtifactIdentity {
            kind: "runner-binary".to_string(),
            identifier: format!("{}@{}", runner.runner_id, runner.runner_path),
            sha256: runner.runner_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "builder-lock".to_string(),
            identifier: runner.builder_id.clone(),
            sha256: lock.builder_lock_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "builder-rootfs".to_string(),
            identifier: runner.builder_id,
            sha256: lock.builder_rootfs_tree_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "embed-proof".to_string(),
            identifier: "boot-efi".to_string(),
            sha256: lock.embed_proof_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "initramfs-blob".to_string(),
            identifier: "boot-efi".to_string(),
            sha256: lock.initramfs_blob_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "initramfs-cpio".to_string(),
            identifier: "boot-efi".to_string(),
            sha256: lock.initramfs_cpio_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "helper-binary".to_string(),
            identifier: "live-lock-helper".to_string(),
            sha256: lock.helper_binary_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "source-snapshot".to_string(),
            identifier: "live-efi".to_string(),
            sha256: lock.source_snapshot_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "build-contract".to_string(),
            identifier: "live-efi".to_string(),
            sha256: lock.build_contract_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "license-evidence".to_string(),
            identifier: "boot-efi".to_string(),
            sha256: lock.payload_license_evidence_sha256.clone(),
        },
        LiveArtifactIdentity {
            kind: "payload".to_string(),
            identifier: "boot-efi".to_string(),
            sha256: lock.payload_sha256.clone(),
        },
    ]);
    identities.push(build_live_material_identity(
        "boot-efi".to_string(),
        "live-efi".to_string(),
        LiveMaterialStatus::Produced,
        LiveMateriality::Material,
        Materiality::Runtime,
        "payload".to_string(),
        "built-from-source".to_string(),
        "generated:linux-efi-stub".to_string(),
        lock.payload_provenance,
        lock.payload_license,
        lock.payload_license_evidence_sha256,
        lock.payload_sha256,
        boot_artifacts,
    ));
    identities.sort_by(|left, right| {
        left.variant
            .cmp(&right.variant)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(LiveMaterialImport {
        authority_kind: "live-lock".to_string(),
        authority_sha256,
        runner_proof_sha256,
        components_sha256,
        build_contract_sha256: lock.build_contract_sha256,
        identities,
    })
}

impl ResolvedPlan {
    fn abi_record_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let mut group: Vec<String> = self
            .abi_provides
            .iter()
            .map(|provide| {
                format!(
                    "ABI_PROVIDE\t{}\t{}\t{}\t{}\t{}",
                    encode(&provide.package),
                    encode(&provide.object),
                    encode(&provide.namespace),
                    encode(&provide.name),
                    encode(&provide.versions),
                )
            })
            .collect();
        group.sort();
        lines.append(&mut group);
        let mut group: Vec<String> = self
            .abi_requires
            .iter()
            .map(|require| {
                format!(
                    "ABI_REQUIRE\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    encode(&require.package),
                    encode(&require.object),
                    encode(&require.namespace),
                    encode(&require.name),
                    encode(&require.versions),
                    encode(&require.provider_package),
                    encode(&require.provider_object),
                )
            })
            .collect();
        group.sort();
        lines.append(&mut group);
        let mut group: Vec<String> = self
            .abi_static
            .iter()
            .map(|fact| {
                format!(
                    "ABI_STATIC\t{}\t{}",
                    encode(&fact.package),
                    encode(&fact.object)
                )
            })
            .collect();
        group.sort();
        lines.append(&mut group);
        let mut group: Vec<String> = self
            .abi_none
            .iter()
            .map(|none| {
                format!(
                    "ABI_NONE\t{}\t{}",
                    encode(&none.package),
                    encode(&none.reason),
                )
            })
            .collect();
        group.sort();
        lines.append(&mut group);
        lines
    }

    fn recompute_abi_audit_sha256(&self) -> String {
        canonical_hash_material(
            b"minitrue-plan-abi-v1\0",
            self.abi_record_lines().into_iter().map(String::into_bytes),
        )
    }

    fn record_lines(&self) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        let mut start = lines.len();
        for root in &self.roots {
            lines.push(format!(
                "ROOT\t{}\t{}",
                root.role.as_str(),
                encode(&root.name)
            ));
        }
        lines[start..].sort();
        start = lines.len();
        for node in self.nodes.values() {
            let provenance_sha256 = provenance_sha256_from_lines(
                self.artifacts
                    .iter()
                    .filter(|artifact| artifact.package == node.name)
                    .map(artifact_record_line),
            );
            let base = node_base_line(node, &provenance_sha256);
            let material_id = material_id_from_node_base(&base);
            lines.push(format!("{base}\t{material_id}"));
        }
        lines[start..].sort();
        start = lines.len();
        for edge in &self.edges {
            lines.push(format!(
                "EDGE\t{}\t{}\t{}\t{}\t{}",
                encode(&edge.from),
                edge.kind.as_str(),
                encode(&edge.to),
                edge.expected_fingerprint,
                edge.materiality.as_str(),
            ));
        }
        lines[start..].sort();
        start = lines.len();
        for artifact in &self.artifacts {
            lines.push(artifact_record_line(artifact));
        }
        lines[start..].sort();
        lines.extend(self.abi_record_lines());
        start = lines.len();
        for pending in &self.abi_pending {
            lines.push(format!(
                "ABI_PENDING\t{}\t{}",
                encode(&pending.package),
                encode(&pending.reason),
            ));
        }
        lines[start..].sort();
        start = lines.len();
        for orphan in &self.orphans {
            lines.push(format!(
                "ORPHAN\t{}\t{}\t{}\t{}",
                encode(&orphan.package),
                orphan.kind,
                encode(&orphan.reason),
                orphan.record_fact_sha256,
            ));
        }
        lines[start..].sort();
        start = lines.len();
        for residue in &self.predicted_residues {
            lines.push(format!(
                "PREDICTED_RESIDUE\t{}\t{}\t{}\t{}\t{}",
                encode(&residue.package),
                residue.kind,
                encode(&residue.reason),
                residue.expected_fingerprint,
                residue.action,
            ));
        }
        lines[start..].sort();
        Ok(lines)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let recomputed_abi = self.recompute_abi_audit_sha256();
        if self.abi_audit_sha256 != recomputed_abi {
            bail!("ABI_AUDIT_SHA256 diverge dos records ABI tipados");
        }
        let total_entries = self.roots.len()
            + self.nodes.len()
            + self.edges.len()
            + self.artifacts.len()
            + self.abi_provides.len()
            + self.abi_requires.len()
            + self.abi_static.len()
            + self.abi_none.len()
            + self.abi_pending.len()
            + self.orphans.len()
            + self.predicted_residues.len();
        if total_entries > MAX_PLAN_ENTRIES {
            bail!("PLAN_LOCK excede {MAX_PLAN_ENTRIES} registros");
        }
        let mut body = String::new();
        push_line(&mut body, format!("PLAN_LOCK_FORMAT={PLAN_LOCK_FORMAT}"))?;
        push_line(&mut body, format!("TREE_SHA256={}", self.tree_sha256))?;
        push_line(
            &mut body,
            format!("BUILD_CONTRACT_SHA256={}", self.build_contract_sha256),
        )?;
        push_line(&mut body, format!("ARCH={ARCH}"))?;
        push_line(&mut body, format!("PURPOSE={}", self.purpose.as_str()))?;
        push_line(
            &mut body,
            format!("BINARY_POLICY={}", policy_str(self.binary_policy)),
        )?;
        push_line(
            &mut body,
            format!("ABI_POLICY={}", self.abi_policy.as_str()),
        )?;
        push_line(
            &mut body,
            format!("ABI_AUDIT_SHA256={}", self.abi_audit_sha256),
        )?;
        for (name, count) in [
            ("ROOT_COUNT", self.roots.len()),
            ("NODE_COUNT", self.nodes.len()),
            ("EDGE_COUNT", self.edges.len()),
            ("ARTIFACT_COUNT", self.artifacts.len()),
            ("ABI_PROVIDE_COUNT", self.abi_provides.len()),
            ("ABI_REQUIRE_COUNT", self.abi_requires.len()),
            ("ABI_STATIC_COUNT", self.abi_static.len()),
            ("ABI_NONE_COUNT", self.abi_none.len()),
            ("ABI_PENDING_COUNT", self.abi_pending.len()),
            ("ORPHAN_COUNT", self.orphans.len()),
            ("PREDICTED_RESIDUE_COUNT", self.predicted_residues.len()),
        ] {
            push_line(&mut body, format!("{name}={count}"))?;
        }
        for line in self.record_lines()? {
            push_line(&mut body, line)?;
        }
        let closure_sha256 = sha256(body.as_bytes());
        push_line(&mut body, format!("CLOSURE_SHA256={closure_sha256}"))?;
        Ok(body.into_bytes())
    }

    pub fn lock_sha256(&self) -> Result<String> {
        let bytes = self.canonical_bytes()?;
        Ok(verify_canonical(&bytes)?.lock_sha256)
    }

    /// Importa a composição do ambiente EFI somente a partir dos três
    /// documentos canônicos e de duas âncoras entregues pelo pipeline/perfil.
    /// `AUTHENTICATED=yes` é validado como estado, mas jamais usado como raiz
    /// de confiança autoportante.
    pub fn import_live_media(
        &self,
        anchors: &LiveMediaAnchors<'_>,
        documents: LiveMediaDocuments<'_>,
    ) -> Result<LiveMaterialImport> {
        if self.purpose != PlanPurpose::Media || self.abi_policy != AbiPolicy::Strict {
            return fail(
                5,
                "import LIVE exige ResolvedPlan PURPOSE=media/ABI_POLICY=strict",
            );
        }
        // O import externo complementa, e não substitui, o inventário factual
        // da mídia target. Assim um plano pending não pode autenticar o vivo.
        let _ = self.material_identities(true)?;
        parse_live_media_documents(anchors, documents)
    }

    pub fn material_identities(&self, strict: bool) -> Result<Vec<MaterialIdentity>> {
        let official_provenance = self.abi_policy == AbiPolicy::Strict;
        if strict
            && self.purpose == PlanPurpose::Media
            && self
                .nodes
                .values()
                .any(|node| node.materiality.is_material() && node.kind != Kind::Meta)
            && !self.objects_authenticated.get()
        {
            return fail(
                5,
                "mídia estrita exige autenticação offline dos objetos e PLAN_LOCKs produtores",
            );
        }
        if strict && !self.abi_pending.is_empty() {
            return fail(
                5,
                "seleção material estrita contém ABI_PENDING; publicação oficial recusada",
            );
        }
        if strict && self.abi_audit_sha256 != self.recompute_abi_audit_sha256() {
            return fail(
                5,
                "seleção material estrita diverge da auditoria ABI tipada",
            );
        }
        let mut identities = Vec::new();
        for node in self
            .nodes
            .values()
            .filter(|node| node.materiality.is_material())
        {
            if strict && node.payload_sha256 == "pending" {
                return fail(
                    5,
                    format!(
                        "{}: identidade material ainda tem payload pending",
                        node.name
                    ),
                );
            }
            let portable_media_channel = self.purpose == PlanPurpose::Media
                && self.abi_policy == AbiPolicy::Strict
                && node.action == PlanAction::Channel;
            if strict && self.purpose == PlanPurpose::Media && node.kind != Kind::Meta {
                let coherent = match node.materiality {
                    Materiality::Runtime => {
                        (node.kind == Kind::Source && node.action == PlanAction::Channel)
                            || (node.kind == Kind::Binary && node.action == PlanAction::Vendor)
                    }
                    Materiality::CacheOnly => match node.kind {
                        Kind::Source => {
                            matches!(node.action, PlanAction::Channel | PlanAction::Source)
                        }
                        Kind::Binary => node.action == PlanAction::Vendor,
                        Kind::Meta => false,
                    },
                    Materiality::IdentityOnly => false,
                };
                if !coherent {
                    return fail(
                        5,
                        format!(
                            "{}: mídia portátil contém ação incompatível com role/kind",
                            node.name
                        ),
                    );
                }
            }
            if strict
                && self.purpose != PlanPurpose::Media
                && !matches!(node.action, PlanAction::Keep | PlanAction::Meta)
                && !portable_media_channel
            {
                return fail(
                    5,
                    format!(
                        "{}: fechamento estrito exige payload aplicado e reobservado como keep",
                        node.name
                    ),
                );
            }
            let node_artifacts: Vec<&PlanArtifact> = self
                .artifacts
                .iter()
                .filter(|artifact| artifact.package == node.name)
                .collect();
            let provenance_sha256 = provenance_sha256_from_lines(
                node_artifacts
                    .iter()
                    .map(|artifact| artifact_record_line(artifact)),
            );
            let material_id = material_id_from_node_base(&node_base_line(node, &provenance_sha256));
            let verified_node = VerifiedNode {
                version: node.version.clone(),
                kind: kind_str(node.kind).to_string(),
                world: node.world.to_string(),
                action: node.action.as_str().to_string(),
                origin: node.origin.clone(),
                fingerprint: node.fingerprint.clone(),
                role: node.materiality.as_str().to_string(),
                payload: node.payload_sha256.clone(),
                license: node.license.clone(),
                provenance_sha256: provenance_sha256.clone(),
            };
            for artifact in &node_artifacts {
                validate_artifact_semantics(
                    &artifact.package,
                    &artifact.origin_kind,
                    artifact.materiality.as_str(),
                    &artifact.transport_sha256,
                    &artifact.reprocorr,
                    &artifact.channel_index_sha256,
                    &artifact.channel_lock_sha256,
                    &artifact.producer_plan_lock_sha256,
                    &artifact.channel_release_root,
                    &artifact.identifier,
                    &verified_node,
                    official_provenance,
                )?;
                if strict
                    && (artifact.transport_sha256 == "pending" || artifact.reprocorr == "pending")
                {
                    return fail(
                        5,
                        format!(
                            "{}: proveniência material ainda tem input pending",
                            node.name
                        ),
                    );
                }
                if strict
                    && portable_media_channel
                    && artifact.origin_kind == "channel"
                    && artifact.channel_release_root != "yes"
                {
                    return fail(
                        5,
                        format!("{}: mídia estrita exige RELEASE_ROOT=yes", node.name),
                    );
                }
            }
            let factual_kind = match (
                node.materiality,
                node.action,
                node.kind,
                node.origin.as_str(),
            ) {
                // Um meta não tem payload nem artefato factual, seja quando é
                // declarado agora (Meta), seja quando já está registrado e é
                // preservado (Keep). O parser canônico já o dispensa pelo KIND.
                (_, PlanAction::Meta | PlanAction::Keep, Kind::Meta, "meta") => None,
                (_, PlanAction::Channel, Kind::Source, origin) if origin.starts_with("canal:") => {
                    Some("channel")
                }
                (Materiality::Runtime, PlanAction::Vendor, Kind::Binary, "vendor") => {
                    Some("vendor-producer")
                }
                (Materiality::CacheOnly, PlanAction::Vendor, Kind::Binary, "vendor") => {
                    Some("vendor-input")
                }
                (Materiality::CacheOnly, PlanAction::Source, Kind::Source, "fonte") => {
                    Some("source-input")
                }
                (_, PlanAction::Keep, _, "vendor") => Some("record-vendor"),
                (_, PlanAction::Keep, _, "fonte") => Some("record-source"),
                (_, PlanAction::Keep, _, origin) if origin.starts_with("canal:") => {
                    Some("record-channel")
                }
                _ => return fail(5, format!("{}: origem material não factual", node.name)),
            };
            if strict
                && factual_kind.is_some_and(|factual_kind| {
                    !node_artifacts
                        .iter()
                        .any(|artifact| artifact.origin_kind == factual_kind)
                })
            {
                return fail(5, format!("{}: fechamento sem ARTIFACT factual", node.name));
            }
            let abi_covered =
                self.abi_provides
                    .iter()
                    .any(|fact| fact.package == node.name)
                    || self.abi_requires.iter().any(|fact| {
                        fact.package == node.name || fact.provider_package == node.name
                    })
                    || self.abi_static.iter().any(|fact| fact.package == node.name)
                    || self.abi_none.iter().any(|fact| fact.package == node.name);
            if strict && node.kind != Kind::Meta && !abi_covered {
                return fail(
                    5,
                    format!(
                        "{}: payload factual sem ABI_PROVIDE/ABI_REQUIRE/ABI_STATIC/ABI_NONE",
                        node.name
                    ),
                );
            }
            identities.push(MaterialIdentity {
                name: node.name.clone(),
                version: node.version.clone(),
                kind: kind_str(node.kind).to_string(),
                world: node.world.to_string(),
                role: node.materiality.as_str().to_string(),
                fingerprint: node.fingerprint.clone(),
                payload_sha256: node.payload_sha256.clone(),
                license: node.license.clone(),
                material_id,
                provenance_sha256,
                provenance_kind: match node.action {
                    PlanAction::Keep => factual_kind.unwrap_or("meta"),
                    PlanAction::Vendor => "vendor",
                    PlanAction::Channel => "channel",
                    PlanAction::Source => "source",
                    PlanAction::Meta => "meta",
                }
                .to_string(),
                provenance_id: node.origin.clone(),
                artifacts: self
                    .artifacts
                    .iter()
                    .filter(|artifact| artifact.package == node.name)
                    .map(|artifact| MaterialArtifactIdentity {
                        kind: artifact.origin_kind.clone(),
                        role: artifact.materiality.as_str().to_string(),
                        transport_sha256: artifact.transport_sha256.clone(),
                        reprocorr: artifact.reprocorr.clone(),
                        channel_index_sha256: artifact.channel_index_sha256.clone(),
                        channel_lock_sha256: artifact.channel_lock_sha256.clone(),
                        producer_plan_lock_sha256: artifact.producer_plan_lock_sha256.clone(),
                        channel_release_root: artifact.channel_release_root.clone(),
                        identifier: artifact.identifier.clone(),
                    })
                    .collect(),
            });
        }
        Ok(identities)
    }

    pub fn print(&self) -> Result<()> {
        let bytes = self.canonical_bytes()?;
        let _ = verify_canonical(&bytes)?;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
        Ok(())
    }

    pub fn revalidate_tree(&self, ctx: &Ctx) -> Result<()> {
        let (current, _) = newspeak_tree_hash(ctx)?;
        if current != self.tree_sha256 {
            return fail(
                2,
                "árvore Newspeak mudou depois da resolução; aplicação recusada",
            );
        }
        self.tree_revalidated.set(true);
        Ok(())
    }

    /// Valida todo o namespace de publicação antes de a aplicação escrever o
    /// primeiro payload/record. Nenhum diretório é criado aqui. Objetos
    /// content-addressed preexistentes precisam provar nome, bytes e formato;
    /// colisões, symlinks e tipos especiais falham antes da mutação.
    pub(crate) fn preflight_publication(&self, ctx: &Ctx) -> Result<()> {
        if self.purpose != PlanPurpose::Rectify {
            bail!("preflight de publicação só pertence a PURPOSE=rectify");
        }
        preflight_content_addressed_namespace(
            &ctx.root.join("var/lib/minitrue/plan-locks"),
            "lock",
            ContentAddressedKind::PlanLock,
        )?;
        preflight_applied_plan_namespace(&ctx.root.join("var/lib/minitrue/applied-plans"))?;

        // A enumeração ancorada recusa qualquer entrada não-diretório no
        // namespace de records, inclusive uma colisão fora dos nós do plano.
        if let Some(existing) = snapshot_record_directory(ctx)? {
            existing.revalidate()?;
        }
        for (package, node) in &self.nodes {
            if node.materiality != Materiality::Runtime {
                continue;
            }
            recipe::validate_name(package)?;
            let record = ctx.records_dir().join(package);
            if let Some(directory) =
                open_anchored_record_directory_optional(&record, "record alvo do plano")?
            {
                preflight_record_target_namespace(&directory)?;
                let meta = CString::new("meta")?;
                if let Some(bytes) = read_existing_record_meta_at(&directory, &meta)? {
                    let _ = parse_meta_lines(&bytes)?;
                }
            }
            preflight_content_addressed_namespace(
                &record.join("plan-slices"),
                "slice",
                ContentAddressedKind::Slice,
            )?;
        }
        if let Some(existing) = snapshot_record_directory(ctx)? {
            existing.revalidate()?;
        }
        Ok(())
    }

    /// Prova todos os objetos ativos segundo a origem escolhida. Em modo
    /// offline `ensure_artifacts` apenas reabre e revalida cache + assinaturas;
    /// o precheck do diretório impede que a própria prova crie estado vazio.
    pub fn authenticate_objects(&mut self, ctx: &Ctx, cache_only: bool) -> Result<()> {
        let effective = if cache_only {
            let needs_cache = self.order.iter().any(|name| {
                self.nodes
                    .get(name)
                    .is_some_and(|node| !matches!(node.action, PlanAction::Keep | PlanAction::Meta))
            });
            if needs_cache && !ctx.cache_dir().is_dir() {
                return fail(6, "cache verify --closure: cache ausente");
            }
            Ctx {
                root: ctx.root.clone(),
                offline: true,
                tofu: false,
                jobs: ctx.jobs,
            }
        } else {
            Ctx {
                root: ctx.root.clone(),
                offline: ctx.offline,
                tofu: false,
                jobs: ctx.jobs,
            }
        };
        let closing_applied = self.nodes.values().all(|node| {
            !node.materiality.is_material()
                || matches!(node.action, PlanAction::Keep | PlanAction::Meta)
        });
        let producer_plans = self.channels.authenticate_producer_plans(&effective)?;
        let mut observed_inputs = Vec::new();
        for name in &self.order {
            let node = self
                .nodes
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("ordem perdeu nó {name}"))?;
            if node.action == PlanAction::Meta {
                continue;
            }
            let recipe = self
                .recipes
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("ordem perdeu receita {name}"))?;
            match node.action {
                PlanAction::Channel => {
                    let selection = self
                        .channels
                        .get(name)
                        .ok_or_else(|| anyhow::anyhow!("seleção de canal ausente para {name}"))?;
                    install::preflight_channel_selection(&effective, recipe, selection)?;
                    if cache_only || self.abi_policy == AbiPolicy::Strict {
                        observed_inputs.extend(
                            crate::fetch::ensure_artifacts_authenticated(&effective, recipe)?
                                .inputs
                                .into_iter()
                                .map(|fact| (name.clone(), fact)),
                        );
                    }
                }
                PlanAction::Vendor | PlanAction::Source => {
                    observed_inputs.extend(
                        crate::fetch::ensure_artifacts_authenticated(&effective, recipe)?
                            .inputs
                            .into_iter()
                            .map(|fact| (name.clone(), fact)),
                    );
                    if self.purpose == PlanPurpose::Media
                        && self.abi_policy == AbiPolicy::Strict
                        && node.materiality == Materiality::Runtime
                    {
                        if node.action != PlanAction::Vendor || node.kind != Kind::Binary {
                            bail!("mídia runtime local só admite Vendor binary factual");
                        }
                        let producer = install::vendor_producer_record_fact(
                            &effective,
                            recipe,
                            &node.fingerprint,
                        )?;
                        if producer.payload_sha256 != node.payload_sha256
                            || !self.artifacts.iter().any(|artifact| {
                                artifact.package == *name
                                    && artifact.origin_kind == "vendor-producer"
                                    && artifact.transport_sha256 == producer.record_fact_sha256
                                    && artifact.reprocorr == producer.payload_sha256
                            })
                        {
                            bail!("{name}: snapshot vendor produtor mudou depois da resolução");
                        }
                    }
                }
                PlanAction::Keep => {
                    // A prova de um Keep é o artefato factual do seu record, e a
                    // matriz canônica o nomeia POR ORIGEM: `record-vendor` para
                    // vendor, `record-source` para fonte, `record-channel` para
                    // canal. Só as duas primeiras têm o objeto upstream como
                    // insumo. A terceira prende CHANNEL_SHA256 e ARTIFACT_HASH
                    // gravados no record — o tarball do upstream não participa
                    // da cadeia, e quem o autenticou foi o produtor do canal.
                    //
                    // Cobrá-lo aqui obrigaria toda máquina instalada por canal a
                    // carregar a fonte de cada pacote, o oposto do que um canal
                    // binário existe para fazer. O ramo Channel trata a MESMA
                    // receita assim: SRC vira `identity-source-input`,
                    // identidade sem objeto. Um Keep de canal é aquele mesmo nó
                    // depois de aplicado, e não pode passar a dever mais.
                    //
                    // Estrito continua cobrando tudo: ele recusa transporte
                    // `pending` e roda onde a mídia é emitida, com os objetos à
                    // mão.
                    let from_channel = node.origin.starts_with("canal:");
                    if (closing_applied && !from_channel) || self.abi_policy == AbiPolicy::Strict {
                        observed_inputs.extend(
                            crate::fetch::ensure_artifacts_authenticated(&effective, recipe)?
                                .inputs
                                .into_iter()
                                .map(|fact| (name.clone(), fact)),
                        );
                    }
                }
                PlanAction::Meta => unreachable!(),
            }
        }
        for (package, observed) in observed_inputs {
            let artifact = self
                .artifacts
                .iter_mut()
                .find(|artifact| {
                    artifact.package == package
                        && artifact.origin_kind == observed.origin_kind
                        && artifact.identifier == observed.identifier
                })
                .ok_or_else(|| anyhow::anyhow!("input autenticado não pertence ao plano"))?;
            artifact.transport_sha256 = observed.sha256;
        }
        finalize_media_cache_payloads(self)?;
        hydrate_media_channel_abi(self, &producer_plans)?;
        self.objects_authenticated.set(true);
        Ok(())
    }

    pub fn persist(&self, ctx: &Ctx) -> Result<String> {
        if !self.objects_authenticated.get() {
            bail!("PLAN_LOCK não pode ser persistido antes de autenticar todos os objetos");
        }
        self.revalidate_tree(ctx)?;
        if !self.tree_revalidated.get() {
            bail!("PLAN_LOCK não pode ser persistido antes de revalidar a árvore");
        }
        if self.purpose == PlanPurpose::Rectify {
            // Revalidação imediatamente antes da primeira publicação factual;
            // o preflight original ocorreu antes de qualquer payload/record.
            self.preflight_publication(ctx)?;
        }
        self.channels.persist(ctx)?;
        let bytes = self.canonical_bytes()?;
        let verified = verify_canonical(&bytes)?;
        let persisted = persist_plan_lock(ctx, &bytes)?;
        if persisted != verified.lock_sha256 {
            bail!("PLAN_LOCK persistido diverge da serialização verificada em memória");
        }
        Ok(persisted)
    }

    /// Publica somente os CHANNEL_LOCKs autenticados necessários à aplicação.
    /// O PLAN_LOCK permanece exclusivamente em memória até a reauditoria
    /// pós-apply fechar payload e ABI.
    pub(crate) fn persist_channels(&self, ctx: &Ctx) -> Result<()> {
        if !self.objects_authenticated.get() {
            bail!("CHANNEL_LOCK não pode ser persistido antes de autenticar todos os objetos");
        }
        self.revalidate_tree(ctx)?;
        if !self.tree_revalidated.get() {
            bail!("CHANNEL_LOCK não pode ser persistido antes de revalidar a árvore");
        }
        self.channels.persist(ctx)
    }

    /// Prende o record já aplicado ao lock inteiro e à sua fatia explicável.
    /// O slice é content-addressed e publicado antes da troca atômica de
    /// `meta`; portanto um crash deixa ou o vínculo antigo íntegro ou o novo.
    pub(crate) fn bind_record(&self, ctx: &Ctx, package: &str, lock_sha256: &str) -> Result<()> {
        let expected = self.lock_sha256()?;
        if expected != lock_sha256 {
            bail!("hash aplicado não corresponde ao PLAN_LOCK resolvido");
        }
        let node = self
            .nodes
            .get(package)
            .ok_or_else(|| anyhow::anyhow!("{package}: nó ausente no PLAN_LOCK"))?;
        if node.materiality != Materiality::Runtime {
            bail!("{package}: somente NODE runtime pode vincular record v4");
        }
        // Toda validação sem I/O vem antes de publicar a fatia.
        let payload_factual = match node.action {
            PlanAction::Keep => {
                canonical_sha256(&node.payload_sha256)
                    || (node.kind == Kind::Meta && node.payload_sha256 == "-")
            }
            PlanAction::Meta => node.kind == Kind::Meta && node.payload_sha256 == "-",
            _ => false,
        };
        if !payload_factual {
            bail!("{package}: RECORD_FORMAT=4 exige payload keep/meta factual");
        }
        let abi_factual = self.abi_provides.iter().any(|fact| fact.package == package)
            || self
                .abi_requires
                .iter()
                .any(|fact| fact.package == package || fact.provider_package == package)
            || self.abi_static.iter().any(|fact| fact.package == package)
            || self.abi_none.iter().any(|fact| fact.package == package);
        if (node.kind != Kind::Meta && !abi_factual)
            || self
                .abi_pending
                .iter()
                .any(|pending| pending.package == package)
        {
            bail!("{package}: RECORD_FORMAT=4 exige ABI factual");
        }
        let slice = self.slice_bytes(package)?;
        let slice_sha256 = persist_record_slice(ctx, package, &slice)?;
        bind_record_meta(
            ctx,
            package,
            lock_sha256,
            &slice_sha256,
            node.action.as_str(),
            &node.payload_sha256,
            &self.abi_audit_sha256,
        )?;
        let record = ctx.records_dir().join(package);
        let meta = install::read_meta_strict(&record)?
            .ok_or_else(|| anyhow::anyhow!("{package}: record sumiu após o vínculo de plano"))?;
        verify_record_binding(ctx, &record, &meta)
    }

    pub fn slice_bytes(&self, package: &str) -> Result<Vec<u8>> {
        let lock_sha = self.lock_sha256()?;
        let records = self.record_lines()?;
        let encoded = encode(package);
        let mut selected = Vec::new();
        for line in records {
            let fields: Vec<&str> = line.split('\t').collect();
            let relevant = match fields.first().copied() {
                Some("ROOT") => fields.get(2) == Some(&encoded.as_str()),
                Some("NODE") => fields.get(1) == Some(&encoded.as_str()),
                Some("EDGE") => {
                    fields.get(1) == Some(&encoded.as_str())
                        || fields.get(3) == Some(&encoded.as_str())
                }
                Some("ARTIFACT") | Some("ABI_PROVIDE") | Some("ABI_STATIC") | Some("ABI_NONE")
                | Some("ABI_PENDING") => fields.get(1) == Some(&encoded.as_str()),
                Some("ABI_REQUIRE") => {
                    fields.get(1) == Some(&encoded.as_str())
                        || fields.get(6) == Some(&encoded.as_str())
                }
                Some("PREDICTED_RESIDUE") => fields.get(1) == Some(&encoded.as_str()),
                _ => false,
            };
            if relevant {
                selected.push(line);
            }
        }
        selected.sort();
        let mut body = format!(
            "PLAN_SLICE_FORMAT={PLAN_SLICE_FORMAT}\nPLAN_LOCK_SHA256={lock_sha}\nTREE_SHA256={}\nBUILD_CONTRACT_SHA256={}\nARCH={ARCH}\nPURPOSE={}\nBINARY_POLICY={}\nABI_POLICY={}\nABI_AUDIT_SHA256={}\nPACKAGE={encoded}\nRECORD_COUNT={}\n",
            self.tree_sha256,
            self.build_contract_sha256,
            self.purpose.as_str(),
            policy_str(self.binary_policy),
            self.abi_policy.as_str(),
            self.abi_audit_sha256,
            selected.len()
        );
        for line in selected {
            push_line(&mut body, line)?;
        }
        Ok(body.into_bytes())
    }
}

fn openat_file(
    directory: &fs::File,
    name: &CString,
    flags: i32,
    mode: u32,
) -> std::io::Result<fs::File> {
    // SAFETY: `name` é C string viva, dirfd permanece aberto e o fd retornado
    // ganha dono único em File.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn lock_file_metadata_valid(metadata: &fs::Metadata, max_bytes: usize) -> bool {
    metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o644
        && metadata.len() <= max_bytes as u64
}

fn read_existing_regular_at(
    directory: &fs::File,
    name: &CString,
    max_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    let mut file = match openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let before = file.metadata()?;
    if !lock_file_metadata_valid(&before, max_bytes) {
        bail!("{label} existente tem tipo/owner/mode/nlink/limite inválido");
    }
    let snapshot = StableMetadata::from(&before);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = StableMetadata::from(&file.metadata()?);
    let reopened = openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let at_path = StableMetadata::from(&reopened.metadata()?);
    if snapshot != after || after != at_path || bytes.len() as u64 != before.len() {
        bail!("{label} existente mudou durante a leitura");
    }
    Ok(Some(bytes))
}

fn unlinkat_name(directory: &fs::File, name: &CString) {
    // SAFETY: tentativa best-effort sobre nome relativo validado e dirfd vivo.
    let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
}

#[derive(Clone, Copy)]
enum ContentAddressedKind {
    PlanLock,
    Slice,
    Receipt,
}

fn canonical_content_name<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let hash = name.strip_suffix(&format!(".{suffix}"))?;
    canonical_sha256(hash).then_some(hash)
}

fn recoverable_publication_temporary(name: &str, suffix: &str) -> bool {
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut fields = body.split('.');
    let Some(hash) = fields.next() else {
        return false;
    };
    let Some(observed_suffix) = fields.next() else {
        return false;
    };
    let Some(process_serial) = fields.next() else {
        return false;
    };
    fields.next().is_none()
        && canonical_sha256(hash)
        && observed_suffix == suffix
        && process_serial.split_once('-').is_some_and(|(pid, serial)| {
            !pid.is_empty()
                && !serial.is_empty()
                && pid.bytes().all(|byte| byte.is_ascii_digit())
                && serial.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn recover_publication_temporary(directory: &fs::File, name: &CString, label: &str) -> Result<()> {
    let file = openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        bail!("temporário órfão de {label} não é recuperável com segurança");
    }
    // SAFETY: nome relativo validado e dirfd vivo. O arquivo jamais foi
    // referenciado por um nome final/current, portanto removê-lo é rollback.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}

fn recoverable_record_meta_temporary(name: &str) -> bool {
    let Some(serial) = name
        .strip_prefix(".meta.plan-bind.")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    serial.split_once('-').is_some_and(|(pid, counter)| {
        !pid.is_empty()
            && !counter.is_empty()
            && pid.bytes().all(|byte| byte.is_ascii_digit())
            && counter.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn preflight_record_target_namespace(directory: &fs::File) -> Result<()> {
    for name in bounded_directory_names(directory, "record alvo")? {
        if recoverable_record_meta_temporary(&name) {
            recover_publication_temporary(directory, &CString::new(name.as_bytes())?, "meta v4")?;
        } else if name.starts_with(".meta.plan-bind.") {
            bail!("colisão estrangeira no alvo temporário de meta v4");
        }
    }
    Ok(())
}

fn validate_preflight_content(kind: ContentAddressedKind, bytes: &[u8], hash: &str) -> Result<()> {
    if sha256(bytes) != hash {
        bail!("objeto content-addressed diverge do hash no nome");
    }
    match kind {
        ContentAddressedKind::PlanLock => {
            if verify_canonical(bytes)?.lock_sha256 != hash {
                bail!("PLAN_LOCK preexistente não é canônico");
            }
        }
        ContentAddressedKind::Slice => {
            validate_plan_slice_framing(bytes)?;
        }
        ContentAddressedKind::Receipt => {
            let _ = parse_applied_receipt(bytes, hash)?;
        }
    }
    Ok(())
}

fn validate_plan_slice_framing(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > MAX_PLAN_BYTES
        || !bytes.ends_with(b"\n")
        || bytes.contains(&b'\r')
    {
        bail!("fatia preexistente não possui framing canônico");
    }
    let text = std::str::from_utf8(bytes).context("fatia preexistente não é UTF-8")?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 11
        || header_value(lines[0], "PLAN_SLICE_FORMAT")? != PLAN_SLICE_FORMAT
        || header_value(lines[4], "ARCH")? != ARCH
        || !matches!(
            header_value(lines[5], "PURPOSE")?,
            "rectify" | "sync" | "cache-closure" | "media" | "channel-emit"
        )
        || !matches!(
            header_value(lines[6], "BINARY_POLICY")?,
            "prefer-binary" | "source-only" | "only-binary"
        )
        || !matches!(
            header_value(lines[7], "ABI_POLICY")?,
            "development" | "strict"
        )
    {
        bail!("fatia preexistente contém headers/enums inválidos");
    }
    for (index, header) in ["PLAN_LOCK_SHA256", "TREE_SHA256", "BUILD_CONTRACT_SHA256"]
        .iter()
        .enumerate()
    {
        if !canonical_sha256(header_value(lines[index + 1], header)?) {
            bail!("fatia preexistente contém hash não canônico");
        }
    }
    if !canonical_sha256(header_value(lines[8], "ABI_AUDIT_SHA256")?) {
        bail!("fatia preexistente contém ABI_AUDIT_SHA256 inválido");
    }
    let package = decode(header_value(lines[9], "PACKAGE")?)?;
    recipe::validate_name(&package)?;
    let count = canonical_count(header_value(lines[10], "RECORD_COUNT")?, "RECORD_COUNT")?;
    if count > MAX_PLAN_ENTRIES || lines.len() != 11 + count {
        bail!("fatia preexistente diverge de RECORD_COUNT");
    }
    if lines[11..]
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        || lines[11..].iter().any(|line| {
            !matches!(
                line.split('\t').next(),
                Some(
                    "ROOT"
                        | "NODE"
                        | "EDGE"
                        | "ARTIFACT"
                        | "ABI_PROVIDE"
                        | "ABI_REQUIRE"
                        | "ABI_STATIC"
                        | "ABI_NONE"
                        | "ABI_PENDING"
                        | "PREDICTED_RESIDUE"
                )
            )
        })
    {
        bail!("fatia preexistente não possui records C-sort/tipados");
    }
    Ok(())
}

fn preflight_content_addressed_namespace(
    path: &Path,
    suffix: &str,
    kind: ContentAddressedKind,
) -> Result<()> {
    let (directory, parent, directory_name) = match open_anchored_leaf(
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(opened) => opened,
        Err(error) if error_is_not_found(&error) => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("preflight de {}", path.display()))
        }
    };
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        bail!("namespace content-addressed não é diretório real/confiável");
    }

    for name in bounded_directory_names(&directory, "namespace content-addressed")? {
        let encoded = CString::new(name.as_bytes())?;
        if recoverable_publication_temporary(&name, suffix) {
            recover_publication_temporary(&directory, &encoded, suffix)?;
            continue;
        }
        let hash = canonical_content_name(&name, suffix)
            .ok_or_else(|| anyhow::anyhow!("entrada estrangeira no namespace .{suffix}: {name}"))?;
        let bytes = read_existing_regular_at(
            &directory,
            &encoded,
            MAX_PLAN_BYTES,
            "objeto content-addressed no preflight",
        )?
        .ok_or_else(|| anyhow::anyhow!("objeto desapareceu durante o preflight"))?;
        validate_preflight_content(kind, &bytes, hash)?;
    }

    let stable = StableMetadata::from(&directory.metadata()?);
    for name in bounded_directory_names(&directory, "revalidação content-addressed")? {
        let hash = canonical_content_name(&name, suffix)
            .ok_or_else(|| anyhow::anyhow!("entrada estrangeira no namespace .{suffix}: {name}"))?;
        let encoded = CString::new(name.as_bytes())?;
        let bytes = read_existing_regular_at(
            &directory,
            &encoded,
            MAX_PLAN_BYTES,
            "objeto content-addressed na revalidação",
        )?
        .ok_or_else(|| anyhow::anyhow!("objeto desapareceu durante a revalidação"))?;
        validate_preflight_content(kind, &bytes, hash)?;
    }
    let reopened = openat_file(
        &parent,
        &directory_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    if StableMetadata::from(&directory.metadata()?) != stable
        || StableMetadata::from(&reopened.metadata()?) != stable
    {
        bail!("namespace content-addressed mudou durante o preflight");
    }
    Ok(())
}

fn recoverable_current_temporary(name: &str) -> bool {
    let Some(serial) = name
        .strip_prefix(".current.")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    serial.split_once('-').is_some_and(|(pid, counter)| {
        !pid.is_empty()
            && !counter.is_empty()
            && pid.bytes().all(|byte| byte.is_ascii_digit())
            && counter.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn preflight_applied_plan_namespace(path: &Path) -> Result<()> {
    let (directory, parent, directory_name) = match open_anchored_leaf(
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(opened) => opened,
        Err(error) if error_is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error).context("preflight do namespace applied-plans"),
    };
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        bail!("namespace applied-plans não é diretório real/confiável");
    }
    let mut current = None;
    let mut receipts = BTreeSet::new();
    for name in bounded_directory_names(&directory, "namespace applied-plans")? {
        let encoded = CString::new(name.as_bytes())?;
        if recoverable_current_temporary(&name) {
            recover_publication_temporary(&directory, &encoded, "current")?;
        } else if name == "current" {
            let bytes = read_existing_regular_at(&directory, &encoded, 1024, "current")?
                .ok_or_else(|| anyhow::anyhow!("current desapareceu durante preflight"))?;
            current = Some(parse_current_receipt_pointer(&bytes)?);
        } else {
            let hash = canonical_content_name(&name, "receipt").ok_or_else(|| {
                anyhow::anyhow!("entrada estrangeira no namespace applied-plans: {name}")
            })?;
            let bytes = read_existing_regular_at(
                &directory,
                &encoded,
                MAX_PLAN_BYTES,
                "receipt no preflight",
            )?
            .ok_or_else(|| anyhow::anyhow!("receipt desapareceu durante preflight"))?;
            validate_preflight_content(ContentAddressedKind::Receipt, &bytes, hash)?;
            receipts.insert(hash.to_string());
        }
    }
    if current
        .as_ref()
        .is_some_and(|(receipt, _)| !receipts.contains(receipt))
    {
        bail!("current referencia receipt ausente no preflight");
    }
    let stable = StableMetadata::from(&directory.metadata()?);
    let mut second_current = None;
    let mut second_receipts = BTreeSet::new();
    for name in bounded_directory_names(&directory, "revalidação applied-plans")? {
        let encoded = CString::new(name.as_bytes())?;
        if name == "current" {
            let bytes =
                read_existing_regular_at(&directory, &encoded, 1024, "current na revalidação")?
                    .ok_or_else(|| anyhow::anyhow!("current desapareceu na revalidação"))?;
            second_current = Some(parse_current_receipt_pointer(&bytes)?);
        } else {
            let hash = canonical_content_name(&name, "receipt").ok_or_else(|| {
                anyhow::anyhow!("entrada estrangeira no namespace applied-plans: {name}")
            })?;
            let bytes = read_existing_regular_at(
                &directory,
                &encoded,
                MAX_PLAN_BYTES,
                "receipt na revalidação",
            )?
            .ok_or_else(|| anyhow::anyhow!("receipt desapareceu na revalidação"))?;
            validate_preflight_content(ContentAddressedKind::Receipt, &bytes, hash)?;
            second_receipts.insert(hash.to_string());
        }
    }
    let reopened = openat_file(
        &parent,
        &directory_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    if second_current != current
        || second_receipts != receipts
        || StableMetadata::from(&directory.metadata()?) != stable
        || StableMetadata::from(&reopened.metadata()?) != stable
    {
        bail!("namespace applied-plans mudou durante o preflight");
    }
    Ok(())
}

fn persist_content_addressed(
    ctx: &Ctx,
    directory: &Path,
    suffix: &str,
    bytes: &[u8],
    max_bytes: usize,
    label: &str,
) -> Result<String> {
    if bytes.len() > max_bytes {
        bail!("{label} excede {max_bytes} bytes");
    }
    let hash = sha256(bytes);
    install::ensure_real_directory_or_absent(&ctx.root, directory, label)?;
    fs::create_dir_all(directory)?;
    install::ensure_real_directory_or_absent(&ctx.root, directory, label)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let directory_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let directory_metadata = directory_file.metadata()?;
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.uid() != unsafe { libc::geteuid() }
        || directory_metadata.mode() & 0o022 != 0
    {
        bail!("diretório de {label} não é privado/confiável");
    }
    let final_name = CString::new(format!("{hash}.{suffix}"))?;
    match read_existing_regular_at(&directory_file, &final_name, max_bytes, label)? {
        Some(existing) if existing == bytes => return Ok(hash),
        Some(_) => bail!("{label} existente diverge do próprio hash {hash}"),
        None => {}
    }
    for _ in 0..128 {
        let serial = PLAN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_name = CString::new(format!(
            ".{hash}.{suffix}.{}-{serial}.tmp",
            std::process::id()
        ))?;
        let mut file = match openat_file(
            &directory_file,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            let staged = file.metadata()?;
            if !lock_file_metadata_valid(&staged, max_bytes) || staged.len() != bytes.len() as u64 {
                bail!("temporário de {label} não preservou owner/mode/nlink/tamanho");
            }
            match crate::linux::renameat2(
                directory_file.as_raw_fd(),
                &temporary_name,
                directory_file.as_raw_fd(),
                &final_name,
                libc::RENAME_NOREPLACE,
            ) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if read_existing_regular_at(&directory_file, &final_name, max_bytes, label)?
                        .as_deref()
                        != Some(bytes)
                    {
                        bail!("{label} concorrente diverge do próprio hash {hash}");
                    }
                }
                Err(error) => return Err(error.into()),
            }
            directory_file.sync_all()?;
            Ok(())
        })();
        unlinkat_name(&directory_file, &temporary_name);
        result?;
        if read_existing_regular_at(&directory_file, &final_name, max_bytes, label)?.as_deref()
            != Some(bytes)
        {
            bail!("{label} publicado diverge do próprio hash {hash}");
        }
        return Ok(hash);
    }
    bail!("não reservei temporário para {label}")
}

fn persist_plan_lock(ctx: &Ctx, bytes: &[u8]) -> Result<String> {
    let directory = ctx.root.join("var/lib/minitrue/plan-locks");
    plan_publication_checkpoint("before_plan_persist")?;
    let hash =
        persist_content_addressed(ctx, &directory, "lock", bytes, MAX_PLAN_BYTES, "PLAN_LOCK")?;
    plan_publication_checkpoint("after_plan_persist")?;
    Ok(hash)
}

fn publish_current_receipt(
    directory: &Path,
    receipt_sha256: &str,
    plan_lock_sha256: &str,
) -> Result<()> {
    let body = format!(
        "APPLIED_PLAN_CURRENT_FORMAT=1\nRECEIPT_SHA256={receipt_sha256}\nPLAN_LOCK_SHA256={plan_lock_sha256}\n"
    );
    let directory_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let current = CString::new("current")?;
    for _ in 0..128 {
        let serial = PLAN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_name = CString::new(format!(".current.{}-{serial}.tmp", std::process::id()))?;
        let mut file = match openat_file(
            &directory_file,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<()> {
            file.write_all(body.as_bytes())?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            if !lock_file_metadata_valid(&file.metadata()?, 1024) {
                bail!("ponteiro de receipt temporário não é íntegro");
            }
            plan_publication_checkpoint("before_current_rename")?;
            // SAFETY: nomes relativos sem NUL e dirfd permanecem vivos.
            if unsafe {
                libc::renameat(
                    directory_file.as_raw_fd(),
                    temporary_name.as_ptr(),
                    directory_file.as_raw_fd(),
                    current.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            plan_publication_checkpoint("after_current_rename")?;
            directory_file.sync_all()?;
            plan_publication_checkpoint("after_current_parent_fsync")?;
            Ok(())
        })();
        unlinkat_name(&directory_file, &temporary_name);
        result?;
        if read_existing_regular_at(&directory_file, &current, 1024, "ponteiro de receipt")?
            .as_deref()
            != Some(body.as_bytes())
        {
            bail!("ponteiro de receipt publicado diverge dos bytes preparados");
        }
        return Ok(());
    }
    bail!("não reservei temporário para ponteiro de receipt")
}

fn persist_applied_receipt(
    ctx: &Ctx,
    plan: &ResolvedPlan,
    plan_lock_sha256: &str,
) -> Result<String> {
    let (world_bytes, world_roots) = system_world_snapshot(ctx)?;
    if plan.roots != world_roots {
        bail!("receipt global não corresponde exatamente aos roots do world");
    }
    let expected_records: BTreeSet<String> = plan
        .nodes
        .iter()
        .filter_map(|(package, node)| {
            (node.materiality == Materiality::Runtime).then_some(package.clone())
        })
        .collect();
    let record_snapshot = snapshot_record_directory(ctx)?
        .ok_or_else(|| anyhow::anyhow!("receipt global perdeu o diretório de records"))?;
    // DUAS ASSERÇÕES, e não uma igualdade. A igualdade exigia que o diretório de
    // records fosse EXATAMENTE o mundo runtime, e isso nunca pode valer: o
    // ferramental de build grava record como qualquer outro pacote, e ele é
    // identity-only por definição. Medido na primeira base que chegou a fechar
    // desde que esta checagem existe — 167 nós, 126 runtime e 41 identity-only,
    // com os 41 sobrando e nada faltando. gcc, bison, meson, ninja, python, zig,
    // os overlays -introspection: nenhum vai para a superfície, e todos deixam
    // record porque o record é quem responde de quem é cada arquivo.
    //
    // O que a igualdade queria garantir eram duas coisas distintas, e as duas
    // continuam garantidas separadamente: nenhum record órfão de pacote que saiu
    // do world, e nenhum participante do world sem record. O receipt segue
    // comprometendo só os runtime, que é o laço logo abaixo.
    let record_names = record_snapshot.names();
    let plan_names: BTreeSet<String> = plan.nodes.keys().cloned().collect();
    let mut orfaos = record_names.difference(&plan_names).peekable();
    if orfaos.peek().is_some() {
        let lista: Vec<&str> = orfaos.map(String::as_str).collect();
        bail!(
            "diretório de records tem pacote fora do world resolvido: {}",
            lista.join(" ")
        );
    }
    let mut ausentes = expected_records.difference(&record_names).peekable();
    if ausentes.peek().is_some() {
        let lista: Vec<&str> = ausentes.map(String::as_str).collect();
        bail!(
            "world resolvido tem participante sem record: {}",
            lista.join(" ")
        );
    }
    let mut facts = Vec::new();
    for package in &expected_records {
        let record = ctx.records_dir().join(package);
        let meta = install::read_meta_strict(&record)?
            .ok_or_else(|| anyhow::anyhow!("{package}: receipt perdeu record participante"))?;
        if meta.get("RECORD_FORMAT").map(String::as_str) != Some("4") {
            bail!("{package}: receipt só pode comprometer RECORD_FORMAT=4");
        }
        facts.push((
            package.clone(),
            install::verify_historical_record(ctx, &record, package)?,
        ));
    }
    facts.sort();
    record_snapshot.revalidate()?;
    let mut body = format!(
        "APPLIED_PLAN_RECEIPT_FORMAT=1\nPLAN_LOCK_SHA256={plan_lock_sha256}\nTREE_SHA256={}\nWORLD_SHA256={}\nRECORD_COUNT={}\n",
        plan.tree_sha256,
        sha256(&world_bytes),
        facts.len()
    );
    for (package, fact) in &facts {
        push_line(&mut body, format!("RECORD\t{}\t{fact}", encode(package)))?;
    }
    let directory = ctx.root.join("var/lib/minitrue/applied-plans");
    plan_publication_checkpoint("before_receipt_persist")?;
    let receipt_sha256 = persist_content_addressed(
        ctx,
        &directory,
        "receipt",
        body.as_bytes(),
        MAX_PLAN_BYTES,
        "receipt de plano aplicado",
    )?;
    plan_publication_checkpoint("after_receipt_persist")?;
    // Último write do commit multi-record: lock, records e receipt já estão
    // duráveis. Um crash anterior deixa o ponteiro antigo intacto.
    publish_current_receipt(&directory, &receipt_sha256, plan_lock_sha256)?;
    verify_applied_receipt(ctx)?;
    Ok(receipt_sha256)
}

#[derive(Debug)]
struct AppliedReceipt {
    plan_lock_sha256: String,
    tree_sha256: String,
    world_sha256: String,
    records: BTreeMap<String, String>,
}

fn parse_current_receipt_pointer(bytes: &[u8]) -> Result<(String, String)> {
    if bytes.len() > 1024 || bytes.contains(&b'\r') || !bytes.ends_with(b"\n") {
        bail!("ponteiro de receipt não é canônico");
    }
    let text = std::str::from_utf8(bytes).context("ponteiro de receipt não é UTF-8")?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() != 3 || header_value(lines[0], "APPLIED_PLAN_CURRENT_FORMAT")? != "1" {
        bail!("ponteiro de receipt possui formato desconhecido");
    }
    let receipt = header_value(lines[1], "RECEIPT_SHA256")?.to_string();
    let plan = header_value(lines[2], "PLAN_LOCK_SHA256")?.to_string();
    if !canonical_sha256(&receipt) || !canonical_sha256(&plan) {
        bail!("ponteiro de receipt contém hash não canônico");
    }
    Ok((receipt, plan))
}

fn parse_applied_receipt(bytes: &[u8], expected_sha256: &str) -> Result<AppliedReceipt> {
    if bytes.len() > MAX_PLAN_BYTES
        || bytes.contains(&b'\r')
        || !bytes.ends_with(b"\n")
        || !canonical_sha256(expected_sha256)
        || sha256(bytes) != expected_sha256
    {
        bail!("receipt aplicado não corresponde aos bytes canônicos esperados");
    }
    let text = std::str::from_utf8(bytes).context("receipt aplicado não é UTF-8")?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 5 || header_value(lines[0], "APPLIED_PLAN_RECEIPT_FORMAT")? != "1" {
        bail!("receipt aplicado possui formato desconhecido");
    }
    let plan_lock_sha256 = header_value(lines[1], "PLAN_LOCK_SHA256")?.to_string();
    let tree_sha256 = header_value(lines[2], "TREE_SHA256")?.to_string();
    let world_sha256 = header_value(lines[3], "WORLD_SHA256")?.to_string();
    let count = canonical_count(header_value(lines[4], "RECORD_COUNT")?, "RECORD_COUNT")?;
    if count > MAX_PLAN_ENTRIES || lines.len() != 5 + count {
        bail!("RECORD_COUNT do receipt não corresponde aos records");
    }
    if !canonical_sha256(&plan_lock_sha256)
        || !canonical_sha256(&tree_sha256)
        || !canonical_sha256(&world_sha256)
    {
        bail!("receipt aplicado contém hash não canônico");
    }
    if lines[5..]
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        bail!("records do receipt não estão C-sort/únicos");
    }
    let mut records = BTreeMap::new();
    for line in &lines[5..] {
        let fields = record_fields(line, "RECORD", 3)?;
        let package = decode(fields[1])?;
        recipe::validate_name(&package)?;
        if !canonical_sha256(fields[2]) || records.insert(package, fields[2].to_string()).is_some()
        {
            bail!("receipt contém record repetido ou hash factual inválido");
        }
    }
    Ok(AppliedReceipt {
        plan_lock_sha256,
        tree_sha256,
        world_sha256,
        records,
    })
}

fn open_anchored_directory_optional(path: &Path, label: &str) -> Result<Option<fs::File>> {
    open_anchored_directory_optional_with_mask(path, label, 0o022)
}

fn open_anchored_record_directory_optional(path: &Path, label: &str) -> Result<Option<fs::File>> {
    open_anchored_directory_optional_with_mask(path, label, 0o002)
}

fn open_anchored_directory_optional_with_mask(
    path: &Path,
    label: &str,
    forbidden_mode: u32,
) -> Result<Option<fs::File>> {
    let (directory, _, _) = match open_anchored_leaf(path, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(opened) => opened,
        Err(error) if error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("não pude abrir {label}")),
    };
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & forbidden_mode != 0
    {
        bail!("{label} não é diretório real/confiável");
    }
    Ok(Some(directory))
}

fn directory_has_entries(directory: &fs::File) -> Result<bool> {
    // O pathname em /proc referencia o descritor já aberto e validado acima;
    // portanto a enumeração não reabre ancestrais mutáveis do rootfs.
    let fd_path = Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string());
    Ok(fs::read_dir(fd_path)?.next().transpose()?.is_some())
}

fn bounded_directory_names(directory: &fs::File, label: &str) -> Result<Vec<String>> {
    let fd_path = Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string());
    let mut names = Vec::new();
    for entry in fs::read_dir(fd_path)? {
        if names.len() == MAX_PLAN_ENTRIES {
            bail!("{label} excede {MAX_PLAN_ENTRIES} entradas");
        }
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("{label} contém nome não UTF-8"))?;
        if name.is_empty() || name.len() > MAX_PUBLICATION_NAME_BYTES || name.contains('/') {
            bail!("{label} contém nome fora do limite/canonicidade");
        }
        names.push(name);
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{label} não possui nomes C-sort/únicos");
    }
    Ok(names)
}

struct RecordDirectorySnapshot {
    directory: fs::File,
    parent: fs::File,
    directory_name: CString,
    directory_metadata: StableMetadata,
    records: BTreeMap<String, StableMetadata>,
}

fn enumerate_record_entries(directory: &fs::File) -> Result<BTreeMap<String, StableMetadata>> {
    let mut records = BTreeMap::new();
    for name in bounded_directory_names(directory, "diretório de records")? {
        recipe::validate_name(&name)?;
        let encoded = CString::new(name.as_bytes())?;
        let record = openat_file(
            directory,
            &encoded,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| format!("abrindo record {name} pela enumeração ancorada"))?;
        let metadata = record.metadata()?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o002 != 0
        {
            bail!("record {name} não é diretório real/confiável");
        }
        if records
            .insert(name.clone(), StableMetadata::from(&metadata))
            .is_some()
        {
            bail!("record repetido durante enumeração: {name}");
        }
    }
    Ok(records)
}

fn snapshot_record_directory(ctx: &Ctx) -> Result<Option<RecordDirectorySnapshot>> {
    let path = ctx.records_dir();
    let (directory, parent, directory_name) = match open_anchored_leaf(
        &path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(opened) => opened,
        Err(error) if error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error).context("abrindo diretório de records ancorado"),
    };
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o002 != 0
    {
        bail!("diretório de records não é real/confiável");
    }
    let snapshot = RecordDirectorySnapshot {
        records: enumerate_record_entries(&directory)?,
        directory_metadata: StableMetadata::from(&metadata),
        directory,
        parent,
        directory_name,
    };
    snapshot.revalidate()?;
    Ok(Some(snapshot))
}

impl RecordDirectorySnapshot {
    fn revalidate(&self) -> Result<()> {
        let observed = enumerate_record_entries(&self.directory)?;
        let after = StableMetadata::from(&self.directory.metadata()?);
        let reopened = openat_file(
            &self.parent,
            &self.directory_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let at_path = StableMetadata::from(&reopened.metadata()?);
        if observed != self.records
            || after != self.directory_metadata
            || at_path != self.directory_metadata
        {
            bail!("diretório de records mudou durante o snapshot do receipt");
        }
        Ok(())
    }

    fn names(&self) -> BTreeSet<String> {
        self.records.keys().cloned().collect()
    }
}

fn records_exist_without_receipt(ctx: &Ctx) -> Result<bool> {
    Ok(
        match open_anchored_record_directory_optional(&ctx.records_dir(), "diretório de records")?
        {
            Some(directory) => directory_has_entries(&directory)?,
            None => false,
        },
    )
}

fn verified_root_map(roots: &[PlanRoot]) -> BTreeMap<String, BTreeSet<String>> {
    let mut map = BTreeMap::new();
    for root in roots {
        map.entry(root.name.clone())
            .or_insert_with(BTreeSet::new)
            .insert(root.role.as_str().to_string());
    }
    map
}

fn verify_receipt_record_identity(
    ctx: &Ctx,
    package: &str,
    node: &VerifiedNode,
    verified: &VerifiedPlan,
) -> Result<String> {
    if node.role != "runtime"
        || !matches!(node.action.as_str(), "keep" | "meta")
        || node.payload == "pending"
        || (node.kind != "meta" && !verified.abi_factual_packages.contains(package))
        || verified.abi_pending_packages.contains(package)
    {
        bail!("{package}: receipt referencia NODE material não factual");
    }
    let record = ctx.records_dir().join(package);
    let meta = install::read_meta_strict(&record)?
        .ok_or_else(|| anyhow::anyhow!("{package}: receipt referencia record ausente"))?;
    let expected_world = match node.world.as_str() {
        "A" => "A",
        "B" => "B",
        "META" => "M",
        _ => bail!("{package}: NODE do receipt possui WORLD inválido"),
    };
    if meta.get("RECORD_FORMAT").map(String::as_str) != Some("4")
        || meta.get("NAME").map(String::as_str) != Some(package)
        || meta.get("VERSION") != Some(&node.version)
        || meta.get("KIND") != Some(&node.kind)
        || meta.get("WORLD").map(String::as_str) != Some(expected_world)
        || meta.get("ORIGIN") != Some(&node.origin)
        || meta.get("FINGERPRINT") != Some(&node.fingerprint)
        || meta.get("LICENSE").map(String::as_str).unwrap_or("-") != node.license
    {
        bail!("{package}: identidade do record diverge do receipt/PLAN_LOCK corrente");
    }
    match node.kind.as_str() {
        "source" if meta.get("ARTIFACT_HASH") != Some(&node.payload) => {
            bail!("{package}: payload source diverge do receipt")
        }
        "binary"
            if record_payload_sha256(&record, package, record_is_provisional(&meta))?
                != node.payload =>
        {
            bail!("{package}: payload vendor diverge do receipt")
        }
        "meta" if node.payload != "-" => bail!("{package}: meta do receipt possui payload"),
        "source" | "binary" | "meta" => {}
        _ => bail!("{package}: KIND desconhecido no receipt"),
    }
    install::verify_historical_record(ctx, &record, package)
}

/// Verifica a autoridade global publicada em `applied-plans/current` sem
/// aceitar receipts órfãos ou um subconjunto da operação anterior.
pub(crate) fn verify_applied_receipt(ctx: &Ctx) -> Result<()> {
    let (world_bytes, world_roots) = system_world_snapshot(ctx)?;
    let directory_path = ctx.root.join("var/lib/minitrue/applied-plans");
    let Some(directory) =
        open_anchored_directory_optional(&directory_path, "diretório de receipts aplicados")?
    else {
        if !world_roots.is_empty() || records_exist_without_receipt(ctx)? {
            bail!("estado instalado não possui applied-plans/current");
        }
        return Ok(());
    };
    let current_name = CString::new("current")?;
    let Some(pointer_bytes) =
        read_existing_regular_at(&directory, &current_name, 1024, "ponteiro de receipt")?
    else {
        if directory_has_entries(&directory)?
            || !world_roots.is_empty()
            || records_exist_without_receipt(ctx)?
        {
            bail!("estado aplicado está incompleto: receipt existe sem ponteiro current");
        }
        return Ok(());
    };
    let (receipt_sha256, pointer_plan_sha256) = parse_current_receipt_pointer(&pointer_bytes)?;
    let receipt_name = CString::new(format!("{receipt_sha256}.receipt"))?;
    let receipt_bytes = read_existing_regular_at(
        &directory,
        &receipt_name,
        MAX_PLAN_BYTES,
        "receipt aplicado",
    )?
    .ok_or_else(|| anyhow::anyhow!("ponteiro current referencia receipt ausente"))?;
    let receipt = parse_applied_receipt(&receipt_bytes, &receipt_sha256)?;
    if pointer_plan_sha256 != receipt.plan_lock_sha256 {
        bail!("ponteiro current diverge do PLAN_LOCK preso no receipt");
    }
    let lock = persisted_lock_bytes(ctx, &receipt.plan_lock_sha256)?;
    let verified = verify_canonical(&lock)?;
    if verified.purpose != "rectify"
        || verified.roots != verified_root_map(&world_roots)
        || receipt.world_sha256 != sha256(&world_bytes)
        || receipt.tree_sha256 != verified.tree_sha256
    {
        bail!("receipt corrente diverge de purpose/world/roots/árvore do PLAN_LOCK");
    }
    let (current_tree_sha256, _) = load_frozen_tree(ctx)?;
    if current_tree_sha256 != receipt.tree_sha256 {
        bail!("árvore Newspeak corrente diverge do receipt aplicado");
    }
    let expected_packages: BTreeSet<String> = verified
        .nodes
        .iter()
        .filter_map(|(package, node)| (node.role == "runtime").then_some(package.clone()))
        .collect();
    if receipt.records.keys().cloned().collect::<BTreeSet<_>>() != expected_packages {
        bail!("receipt não contém exatamente todos os records runtime do PLAN_LOCK");
    }
    let record_snapshot = snapshot_record_directory(ctx)?.ok_or_else(|| {
        anyhow::anyhow!("receipt corrente referencia diretório de records ausente")
    })?;
    // MESMA CORREÇÃO DO persist_applied_receipt, e a irmã dela: o diretório de
    // records guarda também o ferramental identity-only — gcc, meson, ninja, os
    // overlays -introspection —, que não vai para a superfície e por isso não
    // entra no receipt. Exigir igualdade com os runtime era pedir um diretório
    // que nenhuma árvore tem.
    //
    // A comparação LOGO ACIMA, entre receipt.records e expected_packages, está
    // certa e fica: o receipt compromete exatamente os runtime. O que estava
    // errado era medir o DISCO com a régua do receipt.
    let record_names = record_snapshot.names();
    let lock_names: BTreeSet<String> = verified.nodes.keys().cloned().collect();
    let mut orfaos = record_names.difference(&lock_names).peekable();
    if orfaos.peek().is_some() {
        let lista: Vec<&str> = orfaos.map(String::as_str).collect();
        bail!(
            "diretório de records tem pacote fora do PLAN_LOCK do receipt: {}",
            lista.join(" ")
        );
    }
    let mut ausentes = expected_packages.difference(&record_names).peekable();
    if ausentes.peek().is_some() {
        let lista: Vec<&str> = ausentes.map(String::as_str).collect();
        bail!(
            "diretório de records perdeu participante do receipt: {}",
            lista.join(" ")
        );
    }
    for (package, expected_fact) in &receipt.records {
        let node = verified.nodes.get(package).unwrap();
        let observed = verify_receipt_record_identity(ctx, package, node, &verified)?;
        if &observed != expected_fact {
            bail!("{package}: RECORD_FACT_SHA256 diverge do receipt corrente");
        }
    }
    record_snapshot.revalidate()?;
    // Reabra o ponteiro no mesmo dirfd depois de todas as provas: um commit
    // concorrente nunca pode ser misturado com os records do snapshot anterior.
    if read_existing_regular_at(&directory, &current_name, 1024, "ponteiro de receipt")?.as_deref()
        != Some(pointer_bytes.as_slice())
    {
        bail!("ponteiro current mudou durante a verificação global");
    }
    Ok(())
}

pub(crate) fn persisted_lock_bytes(ctx: &Ctx, hash: &str) -> Result<Vec<u8>> {
    if !canonical_sha256(hash) {
        bail!("hash de PLAN_LOCK não canônico");
    }
    let directory = ctx.root.join("var/lib/minitrue/plan-locks");
    let bytes = read_content_addressed(&directory, &format!("{hash}.lock"), "PLAN_LOCK")?;
    if sha256(&bytes) != hash || verify_canonical(&bytes)?.lock_sha256 != hash {
        bail!("PLAN_LOCK persistido não corresponde ao hash/parser canônico");
    }
    Ok(bytes)
}

pub(crate) fn verify_lock_bytes(bytes: &[u8], expected_sha256: &str) -> Result<()> {
    if !canonical_sha256(expected_sha256)
        || sha256(bytes) != expected_sha256
        || verify_canonical(bytes)?.lock_sha256 != expected_sha256
    {
        bail!("PLAN_LOCK externo não corresponde ao hash/parser canônico");
    }
    Ok(())
}

pub(crate) fn verify_channel_producer_plan(
    bytes: &[u8],
    expected_sha256: &str,
    release_root: bool,
    expected: &[(String, String, String, String)],
) -> Result<()> {
    if !canonical_sha256(expected_sha256) || sha256(bytes) != expected_sha256 {
        bail!("PLAN_LOCK produtor diverge do hash assinado pelo índice");
    }
    let verified = verify_canonical(bytes)?;
    if verified.lock_sha256 != expected_sha256 || verified.purpose != "channel-emit" {
        bail!("PLAN_LOCK produtor não é o inventário canônico de channel-emit");
    }
    if release_root && verified.abi_policy != "strict" {
        bail!("RELEASE_ROOT=yes exige PLAN_LOCK produtor ABI_POLICY=strict");
    }
    let mut observed = Vec::new();
    for (name, node) in &verified.nodes {
        if node.role != "runtime" || node.kind != "source" {
            continue;
        }
        if node.action != "keep"
            || !canonical_sha256(&node.payload)
            || !verified.abi_factual_packages.contains(name)
            || verified.abi_pending_packages.contains(name)
        {
            bail!("PLAN_LOCK produtor contém material source não factual");
        }
        observed.push((
            name.clone(),
            node.version.clone(),
            node.fingerprint.clone(),
            node.payload.clone(),
        ));
    }
    observed.sort();
    if observed != expected {
        bail!("conjunto material do PLAN_LOCK produtor diverge do índice assinado");
    }
    Ok(())
}

/// Fixture criptográfica de canal: produz bytes pelo mesmo serializador e os
/// submete ao mesmo parser sem fabricar um caminho alternativo de aceitação.
#[cfg(test)]
pub(crate) fn synthetic_channel_emit_plan(
    recipe: &Recipe,
    fingerprint: &str,
    payload_sha256: &str,
) -> Result<Vec<u8>> {
    if recipe.kind != Kind::Source
        || !canonical_sha256(fingerprint)
        || !canonical_sha256(payload_sha256)
    {
        bail!("fixture produtora exige identidade source factual");
    }
    let mut artifacts = input_artifacts(
        recipe,
        "record-input",
        Materiality::IdentityOnly,
        UpstreamEvidence::Observed,
    )?;
    // O PRODUTOR baixou e conferiu a assinatura antes de emitir: nos bytes dele
    // esses inputs não são `pending`, e um lock estrito recusaria se fossem.
    // A fixture registra a observação em vez de suprimir o fato — suprimi-lo
    // faria a receita assinada e a não assinada gerarem o mesmo plano, que é
    // exatamente a confusão que a evidência tipada existe para impedir.
    for artifact in &mut artifacts {
        if artifact.transport_sha256 == "pending" {
            artifact.transport_sha256 = hex::encode(Sha256::digest(
                format!("fixture-produtor-observou:{}", artifact.identifier).as_bytes(),
            ));
        }
    }
    artifacts.push(PlanArtifact {
        package: recipe.name.clone(),
        origin_kind: "record-source".to_string(),
        materiality: Materiality::Runtime,
        transport_sha256: "-".to_string(),
        reprocorr: payload_sha256.to_string(),
        channel_index_sha256: "-".to_string(),
        channel_lock_sha256: "-".to_string(),
        producer_plan_lock_sha256: "-".to_string(),
        channel_release_root: "-".to_string(),
        identifier: "record:source-stage".to_string(),
    });
    artifacts.sort();
    let mut plan = ResolvedPlan {
        roots: vec![PlanRoot {
            name: recipe.name.clone(),
            role: RootRole::Install,
        }],
        recipes: BTreeMap::from([(recipe.name.clone(), recipe.clone())]),
        fingerprints: HashMap::from([(recipe.name.clone(), fingerprint.to_string())]),
        nodes: BTreeMap::from([(
            recipe.name.clone(),
            PlanNode {
                name: recipe.name.clone(),
                version: recipe.version.clone(),
                kind: Kind::Source,
                world: "B",
                action: PlanAction::Keep,
                origin: "fonte".to_string(),
                fingerprint: fingerprint.to_string(),
                materiality: Materiality::Runtime,
                payload_sha256: payload_sha256.to_string(),
                license: recipe
                    .license
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("fixture source sem LICENSE"))?,
            },
        )]),
        edges: Vec::new(),
        order: vec![recipe.name.clone()],
        channels: channel::Resolution::empty(LoadMode::ReadOnly),
        tree_sha256: sha256(&recipe.recipe_bytes),
        build_contract_sha256: sha256(recipe::build_runner_material().as_bytes()),
        binary_policy: BinaryPolicy::PreferBinary,
        purpose: PlanPurpose::ChannelEmit,
        abi_policy: AbiPolicy::Strict,
        artifacts,
        abi_requires: Vec::new(),
        abi_provides: Vec::new(),
        abi_static: Vec::new(),
        abi_none: vec![AbiNone {
            package: recipe.name.clone(),
            reason: "payload-sem-abi-observada".to_string(),
        }],
        abi_pending: Vec::new(),
        abi_audit_sha256: String::new(),
        orphans: Vec::new(),
        predicted_residues: Vec::new(),
        objects_authenticated: Cell::new(false),
        tree_revalidated: Cell::new(false),
    };
    plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
    let bytes = plan.canonical_bytes()?;
    let hash = sha256(&bytes);
    verify_channel_producer_plan(
        &bytes,
        &hash,
        false,
        &[(
            recipe.name.clone(),
            recipe.version.clone(),
            fingerprint.to_string(),
            payload_sha256.to_string(),
        )],
    )?;
    Ok(bytes)
}

fn persist_record_slice(ctx: &Ctx, package: &str, bytes: &[u8]) -> Result<String> {
    recipe::validate_name(package)?;
    let directory = ctx.records_dir().join(package).join("plan-slices");
    plan_publication_checkpoint("before_slice_persist")?;
    let hash = persist_content_addressed(
        ctx,
        &directory,
        "slice",
        bytes,
        MAX_PLAN_BYTES,
        "fatia de PLAN_LOCK",
    )?;
    plan_publication_checkpoint("after_slice_persist")?;
    Ok(hash)
}

const MAX_META_BYTES: usize = 64 * 1024 * 1024;

fn record_meta_metadata_valid(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o002 == 0
        && metadata.len() <= MAX_META_BYTES as u64
}

fn read_record_meta_at(directory: &fs::File, name: &CString) -> Result<Vec<u8>> {
    let mut file = openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let before = file.metadata()?;
    if !record_meta_metadata_valid(&before) {
        bail!("meta do record tem tipo/owner/mode/nlink/limite inválido");
    }
    let snapshot = StableMetadata::from(&before);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_META_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = StableMetadata::from(&file.metadata()?);
    let reopened = openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let at_path = StableMetadata::from(&reopened.metadata()?);
    if snapshot != after || after != at_path || bytes.len() as u64 != before.len() {
        bail!("meta do record mudou durante a leitura");
    }
    Ok(bytes)
}

fn read_existing_record_meta_at(directory: &fs::File, name: &CString) -> Result<Option<Vec<u8>>> {
    match read_record_meta_at(directory, name) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error_is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn parse_meta_lines(bytes: &[u8]) -> Result<(Vec<String>, HashMap<String, String>)> {
    if bytes.is_empty() || bytes.len() > MAX_META_BYTES || !bytes.ends_with(b"\n") {
        bail!("meta do record é vazio, excessivo ou não termina em LF");
    }
    let text = std::str::from_utf8(bytes).context("meta do record não é UTF-8")?;
    let mut lines = Vec::new();
    let mut fields = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("meta linha {} malformada", index + 1))?;
        let valid_key = !key.is_empty()
            && key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && key.as_bytes()[0].is_ascii_uppercase();
        if !valid_key || value.chars().any(char::is_control) {
            bail!("meta linha {} não é canônica", index + 1);
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            bail!("meta contém campo duplicado: {key}");
        }
        lines.push(line.to_string());
    }
    Ok((lines, fields))
}

fn bind_record_meta(
    ctx: &Ctx,
    package: &str,
    lock_sha256: &str,
    slice_sha256: &str,
    action: &str,
    payload_sha256: &str,
    abi_sha256: &str,
) -> Result<()> {
    recipe::validate_name(package)?;
    if !matches!(action, "keep" | "meta")
        || !canonical_sha256(lock_sha256)
        || !canonical_sha256(slice_sha256)
        || !(canonical_sha256(payload_sha256)
            || (matches!(action, "keep" | "meta") && payload_sha256 == "-"))
        || !canonical_sha256(abi_sha256)
    {
        bail!("vínculo de PLAN_LOCK recebeu hash não canônico");
    }
    let record = ctx.records_dir().join(package);
    install::ensure_real_directory_or_absent(&ctx.root, &record, "record para vínculo de plano")?;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&record)?;
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o002 != 0
    {
        bail!("diretório de record não é privado/confiável para vínculo de plano");
    }
    let meta_name = CString::new("meta")?;
    let original = read_record_meta_at(&directory, &meta_name)?;
    let (lines, fields) = parse_meta_lines(&original)?;
    if fields.get("NAME").map(String::as_str) != Some(package) {
        bail!("record não corresponde ao pacote vinculado {package}");
    }
    match fields.get("RECORD_FORMAT").map(String::as_str) {
        Some("3") => {}
        Some("4") => bail!("INSTALL_PLAN de RECORD_FORMAT=4 é imutável"),
        _ => bail!("somente record v3 pode receber primeiro fechamento factual"),
    }

    let mut body = String::new();
    let mut inserted = false;
    for line in lines {
        if line.starts_with("PLAN_LOCK_SHA256=")
            || line.starts_with("PLAN_SLICE_SHA256=")
            || line.starts_with("PLAN_ACTION=")
            || line.starts_with("PLAN_PAYLOAD_SHA256=")
            || line.starts_with("PLAN_ABI_SHA256=")
            || line.starts_with("INSTALL_PLAN_LOCK_SHA256=")
            || line.starts_with("INSTALL_PLAN_SLICE_SHA256=")
            || line.starts_with("INSTALL_PLAN_ACTION=")
            || line.starts_with("INSTALL_PLAN_PAYLOAD_SHA256=")
            || line.starts_with("INSTALL_PLAN_ABI_SHA256=")
        {
            continue;
        }
        if line.starts_with("RECORD_FORMAT=") {
            body.push_str("RECORD_FORMAT=4\n");
            continue;
        }
        if !inserted && line.starts_with("TRANSACTION_ID=") {
            body.push_str(&format!("INSTALL_PLAN_LOCK_SHA256={lock_sha256}\n"));
            body.push_str(&format!("INSTALL_PLAN_SLICE_SHA256={slice_sha256}\n"));
            body.push_str(&format!("INSTALL_PLAN_ACTION={action}\n"));
            body.push_str(&format!("INSTALL_PLAN_PAYLOAD_SHA256={payload_sha256}\n"));
            body.push_str(&format!("INSTALL_PLAN_ABI_SHA256={abi_sha256}\n"));
            inserted = true;
        }
        body.push_str(&line);
        body.push('\n');
    }
    if !inserted {
        body.push_str(&format!("INSTALL_PLAN_LOCK_SHA256={lock_sha256}\n"));
        body.push_str(&format!("INSTALL_PLAN_SLICE_SHA256={slice_sha256}\n"));
        body.push_str(&format!("INSTALL_PLAN_ACTION={action}\n"));
        body.push_str(&format!("INSTALL_PLAN_PAYLOAD_SHA256={payload_sha256}\n"));
        body.push_str(&format!("INSTALL_PLAN_ABI_SHA256={abi_sha256}\n"));
    }
    let bytes = body.as_bytes();
    let _ = parse_meta_lines(bytes)?;

    for _ in 0..128 {
        let serial = PLAN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_name = CString::new(format!(
            ".meta.plan-bind.{}-{serial}.tmp",
            std::process::id()
        ))?;
        let mut temporary = match openat_file(
            &directory,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<()> {
            temporary.write_all(bytes)?;
            temporary.set_permissions(fs::Permissions::from_mode(0o644))?;
            temporary.sync_all()?;
            let staged = temporary.metadata()?;
            if !record_meta_metadata_valid(&staged) || staged.len() != bytes.len() as u64 {
                bail!("meta temporário do vínculo não é regular/íntegro");
            }
            if read_record_meta_at(&directory, &meta_name)? != original {
                bail!("meta mudou enquanto o vínculo de plano era preparado");
            }
            plan_publication_checkpoint("before_record_v4_rename")?;
            // SAFETY: ambos os nomes são relativos, validados e os dirfds
            // permanecem vivos. renameat substitui `meta` atomicamente.
            let renamed = unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    directory.as_raw_fd(),
                    meta_name.as_ptr(),
                )
            };
            if renamed != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            plan_publication_checkpoint("after_record_v4_rename")?;
            directory.sync_all()?;
            plan_publication_checkpoint("after_record_v4_parent_fsync")?;
            Ok(())
        })();
        unlinkat_name(&directory, &temporary_name);
        result?;
        if read_record_meta_at(&directory, &meta_name)? != bytes {
            bail!("meta publicado não preservou o vínculo de PLAN_LOCK");
        }
        return Ok(());
    }
    bail!("não reservei temporário para vínculo do PLAN_LOCK no record")
}

#[derive(Clone, Debug)]
struct VerifiedNode {
    version: String,
    kind: String,
    world: String,
    action: String,
    origin: String,
    fingerprint: String,
    role: String,
    payload: String,
    license: String,
    provenance_sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedPlan {
    pub lock_sha256: String,
    tree_sha256: String,
    build_contract_sha256: String,
    purpose: String,
    binary_policy: String,
    abi_policy: String,
    abi_audit_sha256: String,
    records: Vec<String>,
    roots: BTreeMap<String, BTreeSet<String>>,
    nodes: BTreeMap<String, VerifiedNode>,
    abi_factual_packages: BTreeSet<String>,
    abi_pending_packages: BTreeSet<String>,
}

#[derive(Default)]
struct AbiProjection {
    requires: BTreeSet<AbiRequire>,
    provides: BTreeSet<AbiProvide>,
    static_objects: BTreeSet<AbiStatic>,
    none: BTreeSet<AbiNone>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct VerifiedArtifactFact {
    kind: String,
    role: String,
    transport_sha256: String,
    reprocorr: String,
    channel_index_sha256: String,
    channel_lock_sha256: String,
    producer_plan_lock_sha256: String,
    channel_release_root: String,
    identifier: String,
}

impl VerifiedPlan {
    fn artifact_facts(&self, package: &str) -> Result<Vec<VerifiedArtifactFact>> {
        let mut facts = Vec::new();
        for line in &self.records {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.first().copied() != Some("ARTIFACT") || decode(fields[1])? != package {
                continue;
            }
            let fields = record_fields(line, "ARTIFACT", 11)?;
            facts.push(VerifiedArtifactFact {
                kind: decode(fields[2])?,
                role: fields[3].to_string(),
                transport_sha256: fields[4].to_string(),
                reprocorr: fields[5].to_string(),
                channel_index_sha256: fields[6].to_string(),
                channel_lock_sha256: fields[7].to_string(),
                producer_plan_lock_sha256: fields[8].to_string(),
                channel_release_root: fields[9].to_string(),
                identifier: decode(fields[10])?,
            });
        }
        facts.sort();
        Ok(facts)
    }

    fn abi_projection(&self, packages: &BTreeSet<String>) -> Result<AbiProjection> {
        if packages.iter().any(|package| {
            !self.abi_factual_packages.contains(package)
                || self.abi_pending_packages.contains(package)
        }) {
            bail!("PLAN_LOCK produtor não possui ABI factual para toda a seleção");
        }
        let mut projection = AbiProjection::default();
        for line in &self.records {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.first().copied() {
                Some("ABI_PROVIDE") => {
                    let fields = record_fields(line, "ABI_PROVIDE", 6)?;
                    let package = decode(fields[1])?;
                    if packages.contains(&package) {
                        projection.provides.insert(AbiProvide {
                            package,
                            object: decode(fields[2])?,
                            namespace: decode(fields[3])?,
                            name: decode(fields[4])?,
                            versions: decode(fields[5])?,
                        });
                    }
                }
                Some("ABI_REQUIRE") => {
                    let fields = record_fields(line, "ABI_REQUIRE", 8)?;
                    let package = decode(fields[1])?;
                    if packages.contains(&package) {
                        let provider_package = decode(fields[6])?;
                        if !packages.contains(&provider_package) {
                            bail!(
                                "ABI do produtor referencia provider fora da closure material da mídia"
                            );
                        }
                        projection.requires.insert(AbiRequire {
                            package,
                            object: decode(fields[2])?,
                            namespace: decode(fields[3])?,
                            name: decode(fields[4])?,
                            versions: decode(fields[5])?,
                            provider_package,
                            provider_object: decode(fields[7])?,
                        });
                    }
                }
                Some("ABI_STATIC") => {
                    let fields = record_fields(line, "ABI_STATIC", 3)?;
                    let package = decode(fields[1])?;
                    if packages.contains(&package) {
                        projection.static_objects.insert(AbiStatic {
                            package,
                            object: decode(fields[2])?,
                        });
                    }
                }
                Some("ABI_NONE") => {
                    let fields = record_fields(line, "ABI_NONE", 3)?;
                    let package = decode(fields[1])?;
                    if packages.contains(&package) {
                        projection.none.insert(AbiNone {
                            package,
                            reason: decode(fields[2])?,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(projection)
    }
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
            || bytes[index + 1].is_ascii_lowercase()
            || bytes[index + 2].is_ascii_lowercase()
        {
            bail!("escape percentual não canônico em PLAN_LOCK");
        }
        let hex = std::str::from_utf8(&bytes[index + 1..index + 3])?;
        out.push(u8::from_str_radix(hex, 16)?);
        index += 3;
    }
    let out = String::from_utf8(out).context("campo percent-encoded não é UTF-8")?;
    if out.chars().any(char::is_control) {
        bail!("campo PLAN_LOCK decodifica para caractere de controle");
    }
    if encode(&out) != value {
        bail!("campo PLAN_LOCK não usa encoding canônico");
    }
    Ok(out)
}

fn header_value<'a>(line: &'a str, expected: &str) -> Result<&'a str> {
    if line.is_empty() || line.trim() != line || line.chars().any(char::is_control) {
        bail!("cabeçalho PLAN_LOCK não canônico");
    }
    let (name, value) = line
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("cabeçalho PLAN_LOCK sem ="))?;
    if name != expected || value.is_empty() {
        bail!("PLAN_LOCK esperava {expected}, encontrou {name}");
    }
    Ok(value)
}

fn canonical_count(value: &str, field: &str) -> Result<usize> {
    let count = value
        .parse::<usize>()
        .with_context(|| format!("{field} inválido"))?;
    if count.to_string() != value || count > MAX_PLAN_ENTRIES {
        bail!("{field} não canônico ou excessivo");
    }
    Ok(count)
}

fn record_fields<'a>(line: &'a str, tag: &str, arity: usize) -> Result<Vec<&'a str>> {
    if line.is_empty() || line.contains('\r') || line.chars().any(|c| c.is_control() && c != '\t') {
        bail!("registro {tag} contém controle/linha vazia");
    }
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != arity || fields.first().copied() != Some(tag) {
        bail!(
            "registro {tag} tem aridade/tag inválido: esperado {arity}, obtido {}",
            fields.len()
        );
    }
    Ok(fields)
}

fn validate_hash_or(value: &str, alternatives: &[&str], field: &str) -> Result<()> {
    if !canonical_sha256(value) && !alternatives.contains(&value) {
        bail!("{field} não é SHA-256/sentinela canônica");
    }
    Ok(())
}

fn validate_canonical_https(value: &str, label: &str) -> Result<()> {
    let parsed = url::Url::parse(value).with_context(|| format!("{label} inválida"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || value.contains(';')
        || parsed.as_str() != value
    {
        bail!("{label} não é URL de transporte canônica");
    }
    Ok(())
}

fn canonical_index(value: &str, label: &str) -> Result<usize> {
    let index = value
        .parse::<usize>()
        .with_context(|| format!("{label} inválido"))?;
    if index.to_string() != value {
        bail!("{label} não canônico");
    }
    Ok(index)
}

fn validate_abi_path(value: &str, label: &str) -> Result<()> {
    if !value.starts_with('/')
        || value == "/"
        || value.ends_with('/')
        || value.len() > 4096
        || value.contains("//")
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        bail!("{label} não é path virtual absoluto canônico");
    }
    Ok(())
}

fn validate_abi_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('/')
        || value.contains(',')
        || value.chars().any(char::is_whitespace)
    {
        bail!("{label} não é nome ABI canônico");
    }
    Ok(())
}

fn abi_version_set(value: &str) -> Result<BTreeSet<String>> {
    if value == "-" {
        return Ok(BTreeSet::new());
    }
    let values: Vec<&str> = value.split(',').collect();
    if values.is_empty()
        || values.iter().any(|version| {
            version.is_empty()
                || version.len() > 512
                || version
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control())
        })
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("conjunto de versões ABI não está C-sort/único");
    }
    Ok(values.into_iter().map(str::to_string).collect())
}

fn validate_source_identifier(identifier: &str) -> Result<()> {
    let rest = identifier
        .strip_prefix("recipe:SRC[")
        .ok_or_else(|| anyhow::anyhow!("input de receita sem prefixo SRC"))?;
    let (index, url) = rest
        .split_once("]=")
        .ok_or_else(|| anyhow::anyhow!("input SRC malformado"))?;
    if canonical_index(index, "índice SRC")? == 0 {
        bail!("SRC[0] não existe");
    }
    validate_canonical_https(url, "URL de SRC")
}

fn validate_files_transport(value: &str, exact_waiver: bool) -> Result<()> {
    if exact_waiver && value != "files/assinatura-insegura" {
        bail!("waiver não usa transporte canônico");
    }
    let Some(name) = value.strip_prefix("files/") else {
        bail!("chave/waiver não usa files/<basename>");
    };
    if name.is_empty()
        || name.contains('/')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        bail!("transporte files/ não canônico");
    }
    Ok(())
}

fn validate_epoch(value: &str) -> Result<()> {
    let epoch = value.parse::<u64>().context("epoch inválido")?;
    if epoch.to_string() != value || epoch > u32::MAX as u64 {
        bail!("epoch não canônico");
    }
    Ok(())
}

fn validate_upper_fingerprint(value: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        bail!("fingerprint OpenPGP não canônico");
    }
    Ok(())
}

fn split_signature_src_index(identifier: &str) -> Result<(&str, Option<usize>)> {
    let Some((base, index)) = identifier.rsplit_once(";SRC_INDEX=") else {
        return Ok((identifier, None));
    };
    let index = canonical_index(index, "SRC_INDEX")?;
    if index == 0 || base.contains(";SRC_INDEX=") {
        bail!("SRC_INDEX auxiliar não é decimal canônico positivo/final");
    }
    Ok((base, Some(index)))
}

fn validate_signature_identifier(kind: &str, identifier: &str, transport: &str) -> Result<()> {
    let (identifier, src_index) = split_signature_src_index(identifier)?;
    if src_index.is_some() && !identifier.starts_with("recipe:WAIVER_") {
        bail!("SRC_INDEX só pode qualificar fato auxiliar de waiver");
    }
    match kind {
        "signature-waiver" => {
            if src_index.is_some() {
                bail!("declaração de waiver não usa sufixo SRC_INDEX");
            }
            if let Some(value) = identifier.strip_prefix("recipe:SIG_UNSAFE_WAIVER=") {
                validate_files_transport(value, true)?;
            } else {
                let value = identifier
                    .strip_prefix("recipe:SIG_UNSAFE_WAIVER[")
                    .ok_or_else(|| anyhow::anyhow!("waiver sem identificador canônico"))?;
                let (index, transport) = value
                    .split_once("]=")
                    .ok_or_else(|| anyhow::anyhow!("waiver indexado malformado"))?;
                let index = canonical_index(index, "índice de waiver")?;
                if index == 0 || transport != format!("files/assinatura-insegura-{index}") {
                    bail!("waiver indexado não casa SRC/transporte canônico");
                }
                validate_files_transport(transport, false)?;
            }
        }
        "checksums" => {
            let value = identifier
                .strip_prefix("recipe:SIGSUMS=")
                .ok_or_else(|| anyhow::anyhow!("SIGSUMS sem identificador canônico"))?;
            let (url, epoch) = value
                .rsplit_once(";EPOCH=")
                .ok_or_else(|| anyhow::anyhow!("SIGSUMS sem epoch"))?;
            validate_canonical_https(url, "URL de SIGSUMS")?;
            validate_epoch(epoch)?;
        }
        "signature" => {
            if let Some(value) = identifier.strip_prefix("recipe:WAIVER_SIG_FILE=") {
                let (file, url_epoch) = value
                    .split_once(";URL=")
                    .ok_or_else(|| anyhow::anyhow!("assinatura de waiver sem URL"))?;
                let (url, epoch) = url_epoch
                    .rsplit_once(";EPOCH=")
                    .ok_or_else(|| anyhow::anyhow!("assinatura de waiver sem epoch"))?;
                validate_files_transport(file, false)?;
                validate_canonical_https(url, "URL de assinatura revisada")?;
                validate_epoch(epoch)?;
                return Ok(());
            }
            // Minisign tem forma própria porque tem semântica própria: chave
            // única para todas as fontes, assinatura Ed25519 crua sem validade
            // nem expiração. Não há instante de referência a declarar, e não há
            // SIGKEY[n] com que parear.
            if let Some(value) = identifier.strip_prefix("recipe:SIG_MINISIGN[") {
                let (index, url) = value
                    .split_once("]=")
                    .ok_or_else(|| anyhow::anyhow!("assinatura minisign indexada malformada"))?;
                if canonical_index(index, "índice SIG_MINISIGN")? == 0 {
                    bail!("assinatura minisign com índice zero");
                }
                validate_canonical_https(url, "URL de assinatura minisign")?;
                return Ok(());
            }
            let value = identifier
                .strip_prefix("recipe:")
                .ok_or_else(|| anyhow::anyhow!("assinatura sem prefixo recipe"))?;
            let (field, url_epoch) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("assinatura sem ="))?;
            let valid_field = if let Some(index) = field
                .strip_prefix("SIG[")
                .and_then(|value| value.strip_suffix(']'))
            {
                canonical_index(index, "índice SIG")? > 0
            } else {
                matches!(field, "SIGSUMS_SIG" | "WAIVER_SIG")
            };
            if !valid_field {
                bail!("campo de assinatura não canônico");
            }
            let (url, epoch) = match url_epoch.rsplit_once(";EPOCH=") {
                Some((url, epoch)) => {
                    validate_epoch(epoch)?;
                    (url, Some(epoch))
                }
                None => (url_epoch, None),
            };
            if (field.starts_with("SIG[") || matches!(field, "SIGSUMS_SIG" | "WAIVER_SIG"))
                && epoch.is_none()
            {
                bail!("assinatura exige epoch");
            }
            validate_canonical_https(url, "URL de assinatura")?;
        }
        "signature-key-source" => {
            if let Some(url) = identifier.strip_prefix("recipe:WAIVER_KEY_SOURCE=") {
                validate_canonical_https(url, "URL de fonte da chave revisada")?;
                return Ok(());
            }
            let value = identifier
                .strip_prefix("recipe:WAIVER_KEY_SOURCE_FILE=")
                .ok_or_else(|| anyhow::anyhow!("fonte da chave sem identificador tipado"))?;
            let (file, url) = value
                .split_once(";URL=")
                .ok_or_else(|| anyhow::anyhow!("fonte da chave sem URL"))?;
            validate_files_transport(file, false)?;
            validate_canonical_https(url, "URL de fonte da chave")?;
        }
        "signature-key" => {
            if let Some(hash) = identifier.strip_prefix("recipe:SIGKEY=minisign:") {
                if !canonical_sha256(hash) || hash != transport {
                    bail!("SIGKEY minisign não prende seus bytes");
                }
                return Ok(());
            }
            if let Some(value) = identifier.strip_prefix("recipe:SIGKEY[") {
                let (index, rest) = value
                    .split_once("]=")
                    .ok_or_else(|| anyhow::anyhow!("SIGKEY indexada malformada"))?;
                if canonical_index(index, "índice SIGKEY")? == 0 {
                    bail!("SIGKEY_0 não existe");
                }
                let (file, fingerprint) = rest
                    .rsplit_once(";FP=")
                    .ok_or_else(|| anyhow::anyhow!("SIGKEY sem fingerprint"))?;
                validate_files_transport(file, false)?;
                validate_upper_fingerprint(fingerprint)?;
                return Ok(());
            }
            let (file, value) =
                if let Some(value) = identifier.strip_prefix("recipe:WAIVER_KEY_CERT_FILE=") {
                    let (file, value) = value
                        .split_once(";FP=")
                        .ok_or_else(|| anyhow::anyhow!("certificado de waiver sem fingerprint"))?;
                    validate_files_transport(file, false)?;
                    (Some(file), value)
                } else {
                    let value = identifier
                        .strip_prefix("recipe:WAIVER_KEY_CERT=reviewed;FP=")
                        .ok_or_else(|| anyhow::anyhow!("chave sem identificador tipado"))?;
                    (None, value)
                };
            let (fingerprint, extraction) = value
                .rsplit_once(";EXTRACTION=")
                .ok_or_else(|| anyhow::anyhow!("waiver de chave sem extração"))?;
            if extraction.is_empty()
                || extraction.chars().any(char::is_control)
                || extraction.contains(';')
            {
                bail!("extração de chave não canônica");
            }
            validate_upper_fingerprint(fingerprint)?;
            if file.is_none() && transport == "pending" {
                bail!("certificado revisado não pode ser pending");
            }
        }
        "signature-evidence" => {
            let (value, date_marker) = if let Some(value) =
                identifier.strip_prefix("recipe:WAIVER_ENDORSEMENT_FILE=")
            {
                let (value, observed_epoch) = value
                    .rsplit_once(";OBSERVED_EPOCH=")
                    .ok_or_else(|| anyhow::anyhow!("evidência sem observed epoch"))?;
                let (value, expiry_epoch) = value
                    .rsplit_once(";EXPIRY_EPOCH=")
                    .ok_or_else(|| anyhow::anyhow!("evidência sem expiry epoch"))?;
                let (value, validation_epoch) = value
                    .rsplit_once(";VALIDATION_EPOCH=")
                    .ok_or_else(|| anyhow::anyhow!("evidência sem validation epoch"))?;
                validate_epoch(validation_epoch)?;
                validate_epoch(expiry_epoch)?;
                validate_epoch(observed_epoch)?;
                (value, ";PAGE_DATE=")
            } else if let Some(value) = identifier.strip_prefix("recipe:WAIVER_RELEASE_PAGE_FILE=")
            {
                (value, ";LAST_MODIFIED=")
            } else if let Some(value) =
                identifier.strip_prefix("recipe:WAIVER_FINGERPRINT_PAGE_FILE=")
            {
                (value, ";LAST_MODIFIED=")
            } else {
                bail!("evidência de waiver sem prefixo tipado");
            };
            let (value, extraction) = value
                .rsplit_once(";EXTRACTION=")
                .ok_or_else(|| anyhow::anyhow!("evidência sem extração"))?;
            let (file_url, last_modified) = value
                .rsplit_once(date_marker)
                .ok_or_else(|| anyhow::anyhow!("evidência sem last-modified"))?;
            let (file, url) = file_url
                .split_once(";URL=")
                .ok_or_else(|| anyhow::anyhow!("evidência sem URL"))?;
            validate_files_transport(file, false)?;
            validate_canonical_https(url, "URL de endorsement")?;
            for (field, label) in [
                (last_modified, "last-modified"),
                (extraction, "extração de endorsement"),
            ] {
                if field.is_empty() || field.contains(';') || field.chars().any(char::is_control) {
                    bail!("{label} não canônico");
                }
            }
        }
        _ => bail!("tipo auxiliar de assinatura desconhecido"),
    }
    Ok(())
}

#[derive(Default)]
struct WaiverFactCounts {
    declarations: usize,
    signature: usize,
    key_source: usize,
    key: usize,
    evidence: usize,
    indexed: bool,
}

fn bracketed_index(identifier: &str, prefix: &str, label: &str) -> Result<Option<usize>> {
    let Some(value) = identifier.strip_prefix(prefix) else {
        return Ok(None);
    };
    let (index, _) = value
        .split_once("]=")
        .ok_or_else(|| anyhow::anyhow!("{label} indexado malformado"))?;
    let index = canonical_index(index, label)?;
    if index == 0 {
        bail!("{label} não aceita índice zero");
    }
    Ok(Some(index))
}

fn validate_package_artifact_correlation(
    package: &str,
    node: &VerifiedNode,
    facts: &[(String, String)],
) -> Result<()> {
    let source_kinds = [
        "identity-source-input",
        "vendor-input",
        "source-input",
        "record-input",
    ];
    let mut source_counts = BTreeMap::<usize, usize>::new();
    let empty_source_count = facts
        .iter()
        .filter(|(kind, identifier)| kind == "source-empty" && identifier == "recipe:SRC=none")
        .count();
    for (kind, identifier) in facts {
        if source_kinds.contains(&kind.as_str()) {
            let rest = identifier
                .strip_prefix("recipe:SRC[")
                .ok_or_else(|| anyhow::anyhow!("{package}: input SRC sem índice"))?;
            let (index, _) = rest
                .split_once("]=")
                .ok_or_else(|| anyhow::anyhow!("{package}: input SRC malformado"))?;
            let index = canonical_index(index, "índice SRC")?;
            *source_counts.entry(index).or_default() += 1;
        }
    }
    if node.kind != "meta"
        && node.role != "identity-only"
        && source_counts.is_empty()
        && empty_source_count != 1
    {
        bail!("{package}: NODE material Vendor/Source não possui input SRC factual");
    }
    if empty_source_count > 1 || (empty_source_count != 0 && !source_counts.is_empty()) {
        bail!("{package}: declaração SRC vazia conflita com slots indexados");
    }
    if source_counts
        .iter()
        .any(|(index, count)| *index == 0 || *count != 1)
        || source_counts.keys().copied().ne(1..=source_counts.len())
    {
        bail!("{package}: slots SRC não são contíguos, únicos e iniciados em 1");
    }

    let mut waivers = BTreeMap::<usize, WaiverFactCounts>::new();
    let mut normal_signatures = BTreeSet::new();
    let mut normal_keys = BTreeSet::new();
    for (kind, raw_identifier) in facts {
        if kind == "signature-waiver" {
            let (index, indexed) = if raw_identifier.starts_with("recipe:SIG_UNSAFE_WAIVER[") {
                (
                    bracketed_index(raw_identifier, "recipe:SIG_UNSAFE_WAIVER[", "índice waiver")?
                        .unwrap(),
                    true,
                )
            } else if raw_identifier.starts_with("recipe:SIG_UNSAFE_WAIVER=") {
                (1, false)
            } else {
                bail!("{package}: declaração de waiver não canônica");
            };
            let counts = waivers.entry(index).or_default();
            counts.declarations += 1;
            counts.indexed |= indexed;
            continue;
        }
        let (identifier, suffix) = split_signature_src_index(raw_identifier)?;
        if identifier.starts_with("recipe:WAIVER_") {
            let index = suffix.unwrap_or(1);
            let counts = waivers.entry(index).or_default();
            match kind.as_str() {
                "signature" => counts.signature += 1,
                "signature-key-source" => counts.key_source += 1,
                "signature-key" => counts.key += 1,
                "signature-evidence" => counts.evidence += 1,
                _ => bail!("{package}: tipo auxiliar de waiver desconhecido"),
            }
            continue;
        }
        if kind == "signature" {
            if let Some(index) = bracketed_index(identifier, "recipe:SIG[", "índice SIG")? {
                if !normal_signatures.insert(index) {
                    bail!("{package}: SIG repete slot {index}");
                }
            }
        } else if kind == "signature-key" {
            if let Some(index) = bracketed_index(identifier, "recipe:SIGKEY[", "índice SIGKEY")? {
                if !normal_keys.insert(index) {
                    bail!("{package}: SIGKEY repete slot {index}");
                }
            }
        }
    }
    for (index, counts) in &waivers {
        if !source_counts.contains_key(index)
            || counts.declarations != 1
            || counts.signature != 1
            || counts.key_source != 1
            || counts.key != 1
            || counts.evidence > 2
            || (counts.indexed && !matches!(counts.evidence, 1 | 2))
        {
            bail!("{package}: fatos de waiver não fecham exatamente o slot SRC[{index}]");
        }
        if counts.indexed {
            let indexed_aux = facts.iter().filter(|(kind, identifier)| {
                kind != "signature-waiver"
                    && identifier.starts_with("recipe:WAIVER_")
                    && split_signature_src_index(identifier)
                        .is_ok_and(|(_, suffix)| suffix == Some(*index))
            });
            if indexed_aux.count()
                != counts.signature + counts.key_source + counts.key + counts.evidence
            {
                bail!("{package}: auxiliar de waiver perdeu SRC_INDEX final");
            }
        }
        if normal_signatures.contains(index) || normal_keys.contains(index) {
            bail!("{package}: slot SRC[{index}] mistura waiver e assinatura normal");
        }
    }
    // Minisign não entra na bijeção acima: são N assinaturas para UMA chave.
    // Mas isso não pode virar ausência de correlação — sem esta conferência,
    // uma assinatura minisign existiria sem chave que a julgue, ou apontaria
    // para um SRC que a receita não declara.
    let minisign_signatures: BTreeSet<usize> = facts
        .iter()
        .filter(|(kind, _)| kind == "signature")
        .filter_map(|(_, identifier)| {
            bracketed_index(identifier, "recipe:SIG_MINISIGN[", "índice SIG_MINISIGN").transpose()
        })
        .collect::<Result<_>>()?;
    let minisign_keys = facts
        .iter()
        .filter(|(kind, identifier)| {
            kind == "signature-key" && identifier.starts_with("recipe:SIGKEY=minisign:")
        })
        .count();
    if !minisign_signatures.is_empty() {
        if minisign_keys != 1 {
            bail!("{package}: assinatura minisign exige exatamente uma SIGKEY minisign");
        }
        if minisign_signatures
            .iter()
            .any(|index| !source_counts.contains_key(index))
        {
            bail!("{package}: assinatura minisign aponta para SRC inexistente");
        }
        if !normal_signatures.is_empty() || !normal_keys.is_empty() {
            bail!("{package}: mistura assinatura minisign com assinatura indexada OpenPGP");
        }
    } else if minisign_keys > 0 {
        bail!("{package}: SIGKEY minisign sem assinatura que ela julgue");
    }
    // SIGSUMS também não entra na bijeção, e por um motivo próprio: um único
    // manifesto assinado cobre TODOS os SRC da receita — o fetch confere o
    // basename de cada artefato contra ele —, e a única chave declarada é a que
    // julga esse manifesto. Ela sai emitida como `SIGKEY[1]`, onde o índice não
    // aponta para SRC nenhum: é só o slot canônico da chave. A bijeção a via
    // como chave órfã e recusava o plano.
    //
    // Era assimetria emissor/validador da pior espécie: o próprio `minitrue
    // plan` produzia um PLAN_LOCK que o `verify_canonical` dele mesmo
    // rejeitava. E não era caso de nicho — só o kernel usa SIGSUMS, mas o
    // linux-headers entrou nas DEPS da glibc, então a closure inteira do Mundo
    // B passava por ele: `plan zlib` já falhava. O `rectify` escapava por
    // acidente, porque não reanalisa o lock que emite.
    //
    // A conferência que substitui a bijeção é a mesma em espírito: manifesto e
    // chave existem em par, a assinatura destacada é opcional e única, e nada
    // disso convive com assinatura indexada nem com waiver — o SignaturePlan
    // da receita é uma variante só. Minisign já foi recusado acima, porque
    // àquela altura a chave do manifesto ainda contava em `normal_keys`.
    let checksum_manifests = facts
        .iter()
        .filter(|(kind, identifier)| {
            kind == "checksums" && identifier.starts_with("recipe:SIGSUMS=")
        })
        .count();
    if checksum_manifests > 0 {
        if checksum_manifests != 1 {
            bail!("{package}: SIGSUMS exige exatamente um manifesto");
        }
        if facts
            .iter()
            .filter(|(kind, identifier)| {
                kind == "signature" && identifier.starts_with("recipe:SIGSUMS_SIG=")
            })
            .count()
            > 1
        {
            bail!("{package}: SIGSUMS declara mais de uma assinatura destacada");
        }
        if !waivers.is_empty() {
            bail!("{package}: SIGSUMS não convive com waiver de assinatura");
        }
        if !normal_signatures.is_empty() {
            bail!("{package}: SIGSUMS não convive com assinatura indexada OpenPGP");
        }
        if normal_keys.len() != 1 || !normal_keys.contains(&1) {
            bail!("{package}: SIGSUMS exige exatamente a SIGKEY[1] que julga o manifesto");
        }
        normal_keys.clear();
    }
    if normal_signatures != normal_keys {
        bail!("{package}: SIG[n] e SIGKEY[n] não são bijetivos");
    }
    if normal_signatures
        .iter()
        .any(|index| !source_counts.contains_key(index))
    {
        bail!("{package}: assinatura normal referencia SRC ausente");
    }
    if !waivers.is_empty() || !normal_signatures.is_empty() {
        for index in 1..=source_counts.len() {
            let waiver = waivers.contains_key(&index);
            let normal = normal_signatures.contains(&index) && normal_keys.contains(&index);
            if waiver == normal {
                bail!("{package}: SRC[{index}] exige XOR exato entre assinatura normal e waiver");
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_artifact_semantics(
    package: &str,
    kind: &str,
    role: &str,
    transport: &str,
    reprocorr: &str,
    index: &str,
    channel_lock: &str,
    producer_plan_lock: &str,
    channel_release_root: &str,
    identifier: &str,
    node: &VerifiedNode,
    strict: bool,
) -> Result<()> {
    let all_dash = reprocorr == "-"
        && index == "-"
        && channel_lock == "-"
        && producer_plan_lock == "-"
        && channel_release_root == "-";
    match kind {
        "source-empty" => {
            if node.kind != "source"
                || identifier != "recipe:SRC=none"
                || transport != "-"
                || !all_dash
            {
                bail!("ARTIFACT source-empty não é declaração vazia canônica");
            }
        }
        "identity-source-input" | "vendor-input" | "source-input" | "record-input" => {
            if !canonical_sha256(transport) || !all_dash {
                bail!("ARTIFACT {kind} não prende exatamente SRC/SHA256");
            }
            validate_source_identifier(identifier)?;
            let expected_role = match kind {
                "identity-source-input" | "record-input" => "identity-only",
                _ => node.role.as_str(),
            };
            if role != expected_role {
                bail!("ARTIFACT {kind} tem papel incoerente");
            }
            let coherent = match kind {
                "identity-source-input" => node.kind == "source" && node.action == "channel",
                "vendor-input" => node.kind == "binary" && node.action == "vendor",
                "source-input" => node.kind == "source" && node.action == "source",
                "record-input" => node.action == "keep" && node.kind != "meta",
                _ => false,
            };
            if !coherent {
                bail!("ARTIFACT {kind} não corresponde a KIND/ACTION");
            }
        }
        "vendor-producer" => {
            if role != "runtime"
                || node.role != "runtime"
                || node.kind != "binary"
                || node.action != "vendor"
                || node.origin != "vendor"
                || !canonical_sha256(transport)
                || reprocorr != node.payload
                || !canonical_sha256(reprocorr)
                || !canonical_sha256(index)
                || !canonical_sha256(channel_lock)
                || !canonical_sha256(producer_plan_lock)
                || channel_release_root != "yes"
            {
                bail!("ARTIFACT vendor-producer não prende o Vendor runtime factual");
            }
            let channel_name = identifier
                .strip_prefix("producer:")
                .and_then(|value| value.strip_suffix(":record-vendor"))
                .ok_or_else(|| anyhow::anyhow!("vendor-producer sem autoridade tipada"))?;
            recipe::validate_name(channel_name)?;
        }
        "signature-waiver"
        | "signature-key"
        | "signature-key-source"
        | "signature"
        | "checksums"
        | "signature-evidence" => {
            validate_hash_or(transport, &["pending"], "hash de input autenticado")?;
            if role != "identity-only" || !all_dash {
                bail!("input auxiliar precisa ser identity-only e não possui campos de canal");
            }
            if strict && transport == "pending" {
                bail!("PLAN_LOCK estrito contém input auxiliar pending");
            }
            validate_signature_identifier(kind, identifier, transport)?;
        }
        "channel" => {
            let expected_payload = if canonical_sha256(reprocorr) {
                reprocorr
            } else {
                transport
            };
            if role != node.role
                || node.action != "channel"
                || !node.origin.starts_with("canal:")
                || !canonical_sha256(transport)
                || expected_payload != node.payload
                || !canonical_sha256(index)
                || !canonical_sha256(channel_lock)
                || !(canonical_sha256(producer_plan_lock) || (!strict && producer_plan_lock == "-"))
                || !matches!(channel_release_root, "yes" | "no")
                || !(canonical_sha256(reprocorr) || (!strict && reprocorr == "-"))
            {
                bail!("ARTIFACT channel não corresponde ao NODE/CHANNEL_LOCK");
            }
            let value = identifier
                .strip_prefix("channel:")
                .ok_or_else(|| anyhow::anyhow!("identificador de canal inválido"))?;
            let (channel_name, url) = value
                .split_once(":url=")
                .ok_or_else(|| anyhow::anyhow!("identificador de canal sem URL"))?;
            recipe::validate_name(channel_name)?;
            if node.origin != format!("canal:{channel_name}") {
                bail!("identificador de canal diverge da origem do NODE");
            }
            validate_canonical_https(url, "URL de artefato de canal")?;
        }
        "channel-selection" => {
            if role != "identity-only"
                || node.kind != "source"
                || node.action != "keep"
                || !node.origin.starts_with("canal:")
                || !canonical_sha256(transport)
                || reprocorr != node.payload
                || !canonical_sha256(reprocorr)
                || !canonical_sha256(index)
                || !canonical_sha256(channel_lock)
                || !(canonical_sha256(producer_plan_lock) || (!strict && producer_plan_lock == "-"))
                || !matches!(channel_release_root, "yes" | "no")
            {
                bail!("ARTIFACT channel-selection não corresponde ao Keep desejado");
            }
            let value = identifier
                .strip_prefix("channel:")
                .ok_or_else(|| anyhow::anyhow!("identificador de seleção de canal inválido"))?;
            let (channel_name, url) = value
                .split_once(":url=")
                .ok_or_else(|| anyhow::anyhow!("seleção de canal sem URL"))?;
            recipe::validate_name(channel_name)?;
            if node.origin != format!("canal:{channel_name}") {
                bail!("seleção de canal diverge da origem factual do NODE");
            }
            validate_canonical_https(url, "URL de artefato selecionado")?;
        }
        "record-channel" => {
            if role != node.role
                || node.action != "keep"
                || !node.origin.starts_with("canal:")
                || !canonical_sha256(transport)
                || reprocorr != node.payload
                || !canonical_sha256(reprocorr)
                || !canonical_sha256(index)
                || !canonical_sha256(channel_lock)
                || !(canonical_sha256(producer_plan_lock) || (!strict && producer_plan_lock == "-"))
                || !matches!(channel_release_root, "yes" | "no")
            {
                bail!("ARTIFACT record-channel não corresponde ao record factual");
            }
            let value = identifier
                .strip_prefix("record:channel:")
                .ok_or_else(|| anyhow::anyhow!("record-channel sem prefixo"))?;
            let (channel_name, path) = value
                .split_once(":path=")
                .ok_or_else(|| anyhow::anyhow!("record-channel sem path tipado"))?;
            recipe::validate_name(channel_name)?;
            if node.origin != format!("canal:{channel_name}") {
                bail!("record-channel diverge da origem do NODE");
            }
            channel::validate_artifact_path(channel_name, path)?;
        }
        "record-source" => {
            if role != node.role
                || node.kind != "source"
                || node.action != "keep"
                || node.origin != "fonte"
                || identifier != "record:source-stage"
                || transport != "-"
                || reprocorr != node.payload
                || !canonical_sha256(reprocorr)
                || index != "-"
                || channel_lock != "-"
                || producer_plan_lock != "-"
                || channel_release_root != "-"
            {
                bail!("ARTIFACT record-source não corresponde ao record factual");
            }
        }
        "record-vendor" => {
            if role != node.role
                || node.kind != "binary"
                || node.action != "keep"
                || node.origin != "vendor"
                || identifier != "record:vendor-manifest"
                || !canonical_sha256(transport)
                || reprocorr != node.payload
                || !canonical_sha256(reprocorr)
                || index != "-"
                || channel_lock != "-"
                || producer_plan_lock != "-"
                || channel_release_root != "-"
            {
                bail!("ARTIFACT record-vendor não corresponde ao record factual");
            }
        }
        _ => bail!("ARTIFACT contém origem tipada desconhecida"),
    }
    if package.is_empty() {
        bail!("ARTIFACT sem pacote");
    }
    Ok(())
}

fn verify_graph_closure(
    roots: &BTreeMap<String, BTreeSet<String>>,
    nodes: &BTreeMap<String, VerifiedNode>,
    adjacency: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    fn visit(
        name: &str,
        adjacency: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<()> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_string()) {
            bail!("PLAN_LOCK contém ciclo de identidade");
        }
        if let Some(dependencies) = adjacency.get(name) {
            for dependency in dependencies {
                visit(dependency, adjacency, visiting, visited)?;
            }
        }
        visiting.remove(name);
        visited.insert(name.to_string());
        Ok(())
    }

    let mut visited = BTreeSet::new();
    for root in roots.keys() {
        visit(root, adjacency, &mut BTreeSet::new(), &mut visited)?;
    }
    if visited.len() != nodes.len() || nodes.keys().any(|name| !visited.contains(name)) {
        bail!("PLAN_LOCK contém NODE fora da closure exata dos ROOT");
    }
    Ok(())
}

pub(crate) fn verify_canonical(bytes: &[u8]) -> Result<VerifiedPlan> {
    if bytes.len() > MAX_PLAN_BYTES || bytes.contains(&b'\r') || !bytes.ends_with(b"\n") {
        bail!("PLAN_LOCK excede limite, contém CR ou não termina em LF");
    }
    let text = std::str::from_utf8(bytes).context("PLAN_LOCK não é UTF-8")?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 18 {
        bail!("PLAN_LOCK truncado");
    }
    let mut cursor = 0usize;
    let mut take_header = |expected: &str| -> Result<&str> {
        let line = lines
            .get(cursor)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("PLAN_LOCK truncado em {expected}"))?;
        cursor += 1;
        header_value(line, expected)
    };
    if take_header("PLAN_LOCK_FORMAT")? != PLAN_LOCK_FORMAT {
        bail!("PLAN_LOCK_FORMAT desconhecido");
    }
    let tree_sha256 = take_header("TREE_SHA256")?.to_string();
    let build_contract_sha256 = take_header("BUILD_CONTRACT_SHA256")?.to_string();
    if !canonical_sha256(&tree_sha256) || !canonical_sha256(&build_contract_sha256) {
        bail!("hash de árvore/contrato inválido");
    }
    if take_header("ARCH")? != ARCH {
        bail!("arquitetura do PLAN_LOCK é incompatível");
    }
    let purpose = take_header("PURPOSE")?.to_string();
    let parsed_purpose = PlanPurpose::parse(&purpose)?;
    let binary_policy = take_header("BINARY_POLICY")?.to_string();
    if !matches!(
        binary_policy.as_str(),
        "prefer-binary" | "source-only" | "only-binary"
    ) {
        bail!("BINARY_POLICY inválida");
    }
    let abi_policy = take_header("ABI_POLICY")?.to_string();
    if !matches!(abi_policy.as_str(), "development" | "strict") {
        bail!("ABI_POLICY inválida");
    }
    let abi_audit_sha256 = take_header("ABI_AUDIT_SHA256")?.to_string();
    if !canonical_sha256(&abi_audit_sha256) {
        bail!("ABI_AUDIT_SHA256 não é SHA-256 canônico");
    }
    let counts = [
        "ROOT_COUNT",
        "NODE_COUNT",
        "EDGE_COUNT",
        "ARTIFACT_COUNT",
        "ABI_PROVIDE_COUNT",
        "ABI_REQUIRE_COUNT",
        "ABI_STATIC_COUNT",
        "ABI_NONE_COUNT",
        "ABI_PENDING_COUNT",
        "ORPHAN_COUNT",
        "PREDICTED_RESIDUE_COUNT",
    ];
    let mut parsed_counts = Vec::with_capacity(counts.len());
    for field in counts {
        parsed_counts.push(canonical_count(take_header(field)?, field)?);
    }
    let total = parsed_counts
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(*value))
        .ok_or_else(|| anyhow::anyhow!("contagens PLAN_LOCK excedem usize"))?;
    if total > MAX_PLAN_ENTRIES || lines.len() != cursor + total + 1 {
        bail!("contagens PLAN_LOCK não correspondem aos registros");
    }

    let tags = [
        ("ROOT", 3usize),
        ("NODE", 13),
        ("EDGE", 6),
        ("ARTIFACT", 11),
        ("ABI_PROVIDE", 6),
        ("ABI_REQUIRE", 8),
        ("ABI_STATIC", 3),
        ("ABI_NONE", 3),
        ("ABI_PENDING", 3),
        ("ORPHAN", 5),
        ("PREDICTED_RESIDUE", 6),
    ];
    let mut groups: Vec<Vec<&str>> = Vec::new();
    let mut records = Vec::with_capacity(total);
    for ((tag, arity), count) in tags.into_iter().zip(parsed_counts.iter().copied()) {
        let group = lines[cursor..cursor + count].to_vec();
        if group
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            bail!("grupo {tag} não está C-sort/único");
        }
        for line in &group {
            record_fields(line, tag, arity)?;
            records.push((*line).to_string());
        }
        cursor += count;
        groups.push(group);
    }
    let closure = header_value(lines[cursor], "CLOSURE_SHA256")?;
    if !canonical_sha256(closure) {
        bail!("CLOSURE_SHA256 inválido");
    }
    let closure_line_len = lines[cursor].len() + 1;
    let body_len = bytes
        .len()
        .checked_sub(closure_line_len)
        .ok_or_else(|| anyhow::anyhow!("PLAN_LOCK truncado no closure"))?;
    if sha256(&bytes[..body_len]) != closure {
        bail!("CLOSURE_SHA256 não corresponde aos bytes canônicos");
    }

    let mut roots: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in &groups[0] {
        let fields = record_fields(line, "ROOT", 3)?;
        if !matches!(fields[1], "install" | "availability") {
            bail!("ROOT tem papel inválido");
        }
        let name = decode(fields[2])?;
        recipe::validate_name(&name)?;
        if !roots
            .entry(name.clone())
            .or_default()
            .insert(fields[1].to_string())
        {
            bail!("ROOT repete pacote {name}");
        }
    }
    if roots.is_empty() {
        bail!("PLAN_LOCK exige ROOT_COUNT positivo");
    }
    if matches!(purpose.as_str(), "rectify" | "sync" | "channel-emit")
        && roots.values().flatten().any(|role| role != "install")
    {
        bail!("PURPOSE de instalação só aceita ROOT install");
    }
    if purpose == "cache-closure" && roots.values().flatten().any(|role| role != "availability") {
        bail!("PURPOSE=cache-closure só aceita ROOT availability");
    }
    // Media representa simultaneamente o target instalável (`install`) e os
    // materiais apenas disponíveis no cache (`availability`).
    let mut nodes = BTreeMap::new();
    let mut material_ids = BTreeSet::new();
    for line in &groups[1] {
        let fields = record_fields(line, "NODE", 13)?;
        let name = decode(fields[1])?;
        let version = decode(fields[2])?;
        recipe::validate_name(&name)?;
        recipe::validate_version(&name, &version)?;
        if !matches!(fields[3], "binary" | "source" | "meta")
            || !matches!(fields[4], "A" | "B" | "META")
            || !matches!(fields[5], "keep" | "meta" | "vendor" | "channel" | "source")
            || !matches!(fields[8], "runtime" | "cache-only" | "identity-only")
        {
            bail!("NODE {name} contém enum inválido");
        }
        if !matches!(
            (fields[3], fields[4]),
            ("binary", "A") | ("source", "B") | ("meta", "META")
        ) {
            bail!("NODE {name} tem KIND/WORLD incoerente");
        }
        let origin = decode(fields[6])?;
        let action = fields[5];
        let role = fields[8];
        let payload = fields[9];
        let channel_origin = origin.strip_prefix("canal:");
        if let Some(channel) = channel_origin {
            recipe::validate_name(channel)?;
        }
        let coherent_action = match (fields[3], action) {
            ("binary", "vendor") => {
                origin == "vendor"
                    && (payload == "pending"
                        || (parsed_purpose == PlanPurpose::Media
                            && abi_policy == "strict"
                            && role != "identity-only"
                            && canonical_sha256(payload)))
            }
            ("binary", "keep") => origin == "vendor" && canonical_sha256(payload),
            ("source", "source") => {
                origin == "fonte"
                    && (payload == "pending"
                        || (parsed_purpose == PlanPurpose::Media
                            && abi_policy == "strict"
                            && role == "cache-only"
                            && canonical_sha256(payload)))
            }
            ("source", "channel") => channel_origin.is_some() && canonical_sha256(payload),
            ("source", "keep") => {
                (origin == "fonte" || channel_origin.is_some()) && canonical_sha256(payload)
            }
            ("meta", "meta" | "keep") => origin == "meta" && payload == "-",
            _ => false,
        };
        if !coherent_action {
            bail!("NODE {name} tem KIND/ACTION/ORIGIN/payload incoerente");
        }
        if !canonical_sha256(fields[7]) {
            bail!("NODE {name} tem fingerprint inválido");
        }
        validate_hash_or(fields[9], &["pending", "-"], "NODE payload")?;
        let license = decode(fields[10])?;
        if (fields[3] == "meta" && license != "-")
            || (fields[3] != "meta" && (license.is_empty() || license == "-"))
            || !canonical_sha256(fields[11])
            || !canonical_sha256(fields[12])
        {
            bail!("NODE {name} não prende LICENSE/proveniência/material canônicos");
        }
        let node_base = line
            .rsplit_once('\t')
            .map(|(base, _)| base)
            .ok_or_else(|| anyhow::anyhow!("NODE sem MATERIAL_ID"))?;
        if material_id_from_node_base(node_base) != fields[12] {
            bail!("NODE {name} contém MATERIAL_ID divergente da linha sem id");
        }
        if !material_ids.insert(fields[12].to_string()) {
            bail!("NODE repete MATERIAL_ID");
        }
        if abi_policy == "strict" && role != "identity-only" && payload == "pending" {
            bail!("PLAN_LOCK estrito contém payload pending");
        }
        if nodes
            .insert(
                name.clone(),
                VerifiedNode {
                    version,
                    kind: fields[3].to_string(),
                    world: fields[4].to_string(),
                    action: action.to_string(),
                    origin,
                    fingerprint: fields[7].to_string(),
                    role: role.to_string(),
                    payload: payload.to_string(),
                    license,
                    provenance_sha256: fields[11].to_string(),
                },
            )
            .is_some()
        {
            bail!("NODE repetido: {name}");
        }
    }
    for (name, roles) in &roots {
        let node = nodes
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("ROOT {name} não possui NODE"))?;
        for role in roles {
            let coherent = match role.as_str() {
                "install" => node.role == "runtime",
                "availability" => matches!(node.role.as_str(), "cache-only" | "runtime"),
                _ => false,
            };
            if !coherent {
                bail!("ROOT {name} não materializa com o papel esperado");
            }
        }
    }
    for (name, node) in &nodes {
        if node.role == "identity-only" {
            continue;
        }
        match binary_policy.as_str() {
            "source-only"
                if node.kind == "source"
                    && !(node.origin == "fonte"
                        && matches!(node.action.as_str(), "source" | "keep")) =>
            {
                bail!("BINARY_POLICY=source-only contradiz NODE {name}");
            }
            "only-binary"
                if node.kind == "source"
                    && !(node.origin.starts_with("canal:")
                        && matches!(node.action.as_str(), "channel" | "keep")) =>
            {
                bail!("BINARY_POLICY=only-binary contradiz NODE {name}");
            }
            _ => {}
        }
        let coherent_role = match parsed_purpose {
            PlanPurpose::Rectify | PlanPurpose::Sync | PlanPurpose::ChannelEmit => {
                node.role == "runtime"
            }
            PlanPurpose::CacheClosure => node.role == "cache-only",
            PlanPurpose::Media => matches!(node.role.as_str(), "runtime" | "cache-only"),
        };
        if !coherent_role {
            bail!("PURPOSE contradiz papel material do NODE {name}");
        }
        if parsed_purpose == PlanPurpose::Media && abi_policy == "strict" && node.kind != "meta" {
            let coherent_media_action = match node.role.as_str() {
                "runtime" => {
                    (node.kind == "source"
                        && node.action == "channel"
                        && node.origin.starts_with("canal:"))
                        || (node.kind == "binary"
                            && node.action == "vendor"
                            && node.origin == "vendor")
                }
                "cache-only" => {
                    (node.kind == "source"
                        && ((node.action == "channel" && node.origin.starts_with("canal:"))
                            || (node.action == "source" && node.origin == "fonte")))
                        || (node.kind == "binary"
                            && node.action == "vendor"
                            && node.origin == "vendor")
                }
                _ => false,
            };
            if !coherent_media_action {
                bail!("PURPOSE=media/strict contém ação incompatível com role/kind");
            }
        }
        if parsed_purpose == PlanPurpose::ChannelEmit
            && !matches!(node.action.as_str(), "keep" | "meta")
        {
            bail!("PURPOSE=channel-emit exige NODE material factual keep/meta");
        }
    }
    let role_covers = |node: &str, edge: &str| {
        edge == "identity-only" || node == edge || (node == "runtime" && edge == "cache-only")
    };
    let mut edge_keys = BTreeSet::new();
    let mut direct_runtime_edges = BTreeSet::new();
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut runtime_adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in &groups[2] {
        let fields = record_fields(line, "EDGE", 6)?;
        let from = decode(fields[1])?;
        let to = decode(fields[3])?;
        if !matches!(
            fields[2],
            "runtime" | "aggregation" | "build" | "toolchain" | "runner"
        ) || !matches!(fields[5], "runtime" | "cache-only" | "identity-only")
        {
            bail!("EDGE contém enum inválido");
        }
        let consumer = nodes
            .get(&from)
            .ok_or_else(|| anyhow::anyhow!("EDGE referencia consumer ausente {from}"))?;
        let provider = nodes
            .get(&to)
            .ok_or_else(|| anyhow::anyhow!("EDGE referencia provider ausente {to}"))?;
        if (consumer.kind == "meta") != (fields[2] == "aggregation") {
            bail!("EDGE aggregation deve existir se e somente se o consumer é meta");
        }
        if fields[4] != provider.fingerprint
            || !role_covers(&consumer.role, fields[5])
            || !role_covers(&provider.role, fields[5])
        {
            bail!("EDGE {from}->{to} não prende NODE/fingerprint exato");
        }
        if !edge_keys.insert((from.clone(), fields[2].to_string(), to.clone())) {
            bail!("EDGE repete identidade semântica");
        }
        adjacency
            .entry(decode(fields[1])?)
            .or_default()
            .push(decode(fields[3])?);
        if fields[2] == "runtime" {
            direct_runtime_edges.insert((from.clone(), to.clone()));
        }
        if matches!(fields[2], "runtime" | "aggregation") {
            runtime_adjacency.entry(from).or_default().push(to);
        }
    }
    verify_graph_closure(&roots, &nodes, &adjacency)?;
    let mut runtime_reachable = BTreeSet::new();
    let mut runtime_stack: Vec<String> = roots.keys().cloned().collect();
    while let Some(package) = runtime_stack.pop() {
        if !runtime_reachable.insert(package.clone()) {
            continue;
        }
        if let Some(dependencies) = runtime_adjacency.get(&package) {
            runtime_stack.extend(dependencies.iter().cloned());
        }
    }
    let mut artifact_keys = BTreeSet::new();
    let mut artifact_kinds: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut artifact_facts: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut artifact_lines_by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut pending_artifact_packages = BTreeSet::new();
    for line in &groups[3] {
        let fields = record_fields(line, "ARTIFACT", 11)?;
        let package = decode(fields[1])?;
        let node = nodes
            .get(&package)
            .ok_or_else(|| anyhow::anyhow!("ARTIFACT referencia pacote ausente"))?;
        if !matches!(fields[3], "runtime" | "cache-only" | "identity-only")
            || !role_covers(&node.role, fields[3])
        {
            bail!("ARTIFACT referencia pacote/papel inválido");
        }
        let kind = decode(fields[2])?;
        validate_hash_or(fields[4], &["-", "pending"], "ARTIFACT transport")?;
        validate_hash_or(fields[5], &["-", "pending"], "ARTIFACT reprocorr")?;
        validate_hash_or(fields[6], &["-"], "ARTIFACT index")?;
        validate_hash_or(fields[7], &["-"], "ARTIFACT channel lock")?;
        validate_hash_or(fields[8], &["-"], "ARTIFACT producer plan")?;
        if !matches!(fields[9], "-" | "yes" | "no") {
            bail!("ARTIFACT CHANNEL_RELEASE_ROOT inválido");
        }
        let identifier = decode(fields[10])?;
        validate_artifact_semantics(
            &package,
            &kind,
            fields[3],
            fields[4],
            fields[5],
            fields[6],
            fields[7],
            fields[8],
            fields[9],
            &identifier,
            node,
            abi_policy == "strict",
        )?;
        if parsed_purpose == PlanPurpose::Media
            && abi_policy == "strict"
            && node.role != "identity-only"
            && kind == "channel"
            && fields[9] != "yes"
        {
            bail!("mídia estrita exige ARTIFACT channel RELEASE_ROOT=yes");
        }
        artifact_kinds
            .entry(package.clone())
            .or_default()
            .insert(kind.clone());
        artifact_facts
            .entry(package.clone())
            .or_default()
            .push((kind.clone(), identifier.clone()));
        artifact_lines_by_package
            .entry(package.clone())
            .or_default()
            .push((*line).to_string());
        if fields[4] == "pending" || fields[5] == "pending" {
            pending_artifact_packages.insert(package.clone());
        }
        if !artifact_keys.insert((package, kind, identifier)) {
            bail!("ARTIFACT repete identidade semântica");
        }
    }
    for (package, node) in &nodes {
        let observed_provenance = provenance_sha256_from_lines(
            artifact_lines_by_package
                .get(package)
                .cloned()
                .unwrap_or_default(),
        );
        if node.provenance_sha256 != observed_provenance {
            bail!("NODE {package} não prende exatamente seus ARTIFACTs C-sort");
        }
        validate_package_artifact_correlation(
            package,
            node,
            artifact_facts
                .get(package)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        )?;
        if node.role == "identity-only" || node.kind == "meta" {
            continue;
        }
        if parsed_purpose == PlanPurpose::Media
            && abi_policy == "strict"
            && node.role == "cache-only"
            && matches!(node.action.as_str(), "vendor" | "source")
        {
            let mut material_lines: Vec<Vec<u8>> = artifact_lines_by_package
                .get(package)
                .into_iter()
                .flatten()
                .filter(|line| line.split('\t').nth(3) == Some("cache-only"))
                .map(|line| line.as_bytes().to_vec())
                .collect();
            material_lines.sort();
            if material_lines.is_empty()
                || canonical_hash_material(b"MINITRUE-CACHE-INPUT-SET-V1\0", material_lines)
                    != node.payload
            {
                bail!("NODE cache-only não prende o conjunto C-sort exato de inputs");
            }
        }
        let kinds = artifact_kinds.get(package);
        // O ARTIFACT vendor-producer só nasce onde o emissor o produz: mídia com
        // ABI estrita, única situação em que existe uma autoridade Channel v4
        // release para ancorá-lo. Exigi-lo fora daí faria o parser recusar um
        // PLAN_LOCK que o próprio Minitrue acabou de emitir — um `plan` de
        // leitura sobre raiz limpa não tem produtor a citar.
        let strict_media = parsed_purpose == PlanPurpose::Media && abi_policy == "strict";
        let required = match (node.action.as_str(), node.origin.as_str()) {
            ("keep", "vendor") => Some("record-vendor"),
            ("keep", "fonte") => Some("record-source"),
            ("keep", origin) if origin.starts_with("canal:") => Some("record-channel"),
            ("vendor", "vendor") if strict_media && node.role == "runtime" => {
                Some("vendor-producer")
            }
            ("vendor", "vendor") | ("source", "fonte") => None,
            ("channel", origin) if origin.starts_with("canal:") => Some("channel"),
            _ => bail!("NODE material não possui matriz de proveniência fechada"),
        };
        if let Some(required) = required {
            if !kinds.is_some_and(|kinds| kinds.contains(required)) {
                bail!("NODE material {package} não possui ARTIFACT factual {required}");
            }
        }
        if abi_policy == "strict" && pending_artifact_packages.contains(package) {
            bail!("PLAN_LOCK estrito contém ARTIFACT pending");
        }
    }
    let material_factual = |package: &str| {
        nodes.get(package).is_some_and(|node| {
            node.role != "identity-only"
                && node.kind != "meta"
                && (node.action == "keep"
                    || (parsed_purpose == PlanPurpose::Media
                        && abi_policy == "strict"
                        && matches!(node.action.as_str(), "channel" | "vendor" | "source")))
        })
    };
    // O conjunto de pendentes é lido ANTES dos fatos ABI, e não depois, porque
    // as regras de correlação precisam dele. Um pacote em ABI_PENDING não
    // emitiu ABI_PROVIDE nenhum — é o que "sem ABI observada" significa —, e
    // sem essa informação em mãos o laço de requisitos conclui que o provedor
    // não existe. Foi assim que o fechamento parcial da v42 morreu.
    let mut pending_packages = BTreeSet::new();
    for line in &groups[8] {
        let fields = record_fields(line, "ABI_PENDING", 3)?;
        let package = decode(fields[1])?;
        let reason = decode(fields[2])?;
        let node = nodes
            .get(&package)
            .ok_or_else(|| anyhow::anyhow!("ABI_PENDING referencia pacote ausente"))?;
        if node.role == "identity-only"
            || node.kind == "meta"
            || !matches!(
                reason.as_str(),
                "payload-nao-observado" | "auditoria-incompleta" | "auditoria-indisponivel"
            )
        {
            bail!("ABI_PENDING referencia pacote ausente");
        }
        if !pending_packages.insert(package) {
            bail!("ABI_PENDING repete pacote");
        }
    }
    // A política estrita continua não admitindo pendência alguma, e é ela que
    // autoriza publicação. Toda a tolerância abaixo vive em development, onde o
    // formato JÁ aceita provider "?" — integralmente desconhecido.
    if abi_policy == "strict" && !groups[8].is_empty() {
        bail!("PLAN_LOCK estrito contém ABI_PENDING");
    }
    let mut abi_covered = BTreeSet::new();
    let mut abi_providers: BTreeMap<(String, String, String, String), BTreeSet<String>> =
        BTreeMap::new();
    for line in &groups[4] {
        let fields = record_fields(line, "ABI_PROVIDE", 6)?;
        let package = decode(fields[1])?;
        let object = decode(fields[2])?;
        let namespace = decode(fields[3])?;
        let name = decode(fields[4])?;
        let versions = decode(fields[5])?;
        if !material_factual(&package) {
            bail!("ABI_PROVIDE referencia pacote ausente");
        }
        validate_abi_path(&object, "objeto ABI_PROVIDE")?;
        let versions = abi_version_set(&versions)?;
        match namespace.as_str() {
            "path" if name == object && versions.is_empty() => {}
            "soname" => validate_abi_name(&name, "SONAME fornecido")?,
            _ => bail!("ABI_PROVIDE contém namespace/nome/versões incoerente"),
        }
        if abi_providers
            .insert((package.clone(), object, namespace, name), versions)
            .is_some()
        {
            bail!("ABI_PROVIDE repete identidade com versões divergentes");
        }
        abi_covered.insert(package);
    }
    #[derive(Debug)]
    struct ParsedRequire {
        package: String,
        namespace: String,
        name: String,
        versions: BTreeSet<String>,
        provider_package: String,
        provider_object: String,
    }
    let mut abi_requirements = Vec::new();
    for line in &groups[5] {
        let fields = record_fields(line, "ABI_REQUIRE", 8)?;
        let package = decode(fields[1])?;
        let object = decode(fields[2])?;
        let namespace = decode(fields[3])?;
        let name = decode(fields[4])?;
        let versions = abi_version_set(&decode(fields[5])?)?;
        let provider_package = decode(fields[6])?;
        let provider_object = decode(fields[7])?;
        if !material_factual(&package) {
            bail!("ABI_REQUIRE referencia consumidor ausente/não factual");
        }
        validate_abi_path(&object, "objeto consumidor ABI_REQUIRE")?;
        match namespace.as_str() {
            "needed" => validate_abi_name(&name, "DT_NEEDED")?,
            "interp" | "shebang" => {
                validate_abi_path(&name, "path requerido")?;
                if !versions.is_empty() {
                    bail!("interp/shebang não pode exigir symbol versions");
                }
            }
            _ => bail!("ABI_REQUIRE contém namespace desconhecido"),
        }
        let unknown = provider_package == "?" || provider_object == "?";
        if unknown {
            if provider_package != "?" || provider_object != "?" || abi_policy == "strict" {
                bail!("provider ABI desconhecido só é permitido integralmente em development");
            }
        } else {
            recipe::validate_name(&provider_package)?;
            validate_abi_path(&provider_object, "objeto provider ABI_REQUIRE")?;
            if !material_factual(&provider_package) {
                bail!("ABI_REQUIRE referencia provider não material/factual");
            }
        }
        abi_covered.insert(package.clone());
        // Ser NOMEADO como provedor por outro pacote não é fato ABI próprio, e
        // por isso não cobre um pendente: a asserção é do consumidor, não do
        // provedor. Marcá-lo aqui fazia o pendente colidir com a checagem de
        // coerência mais abaixo — a segunda parede do mesmo defeito.
        if !unknown && !pending_packages.contains(&provider_package) {
            abi_covered.insert(provider_package.clone());
        }
        abi_requirements.push(ParsedRequire {
            package,
            namespace,
            name,
            versions,
            provider_package,
            provider_object,
        });
    }
    for requirement in &abi_requirements {
        if requirement.provider_package == "?" {
            continue;
        }
        // Provedor DECLARADO PENDENTE: o plano diz, nos próprios bytes, que a
        // ABI dele não foi observada, então cobrar-lhe um ABI_PROVIDE exato é
        // cobrar prova que ele já assumiu não ter.
        //
        // O argumento de que isto não afrouxa nada: logo acima, o formato
        // aceita provider "?" — desconhecido POR INTEIRO — em development.
        // "icu, pendente" carrega estritamente MAIS informação que "?".
        // Recusar o mais informativo enquanto se aceita o menos era a
        // incoerência, e é o que impedia o fechamento parcial de existir.
        //
        // Em strict nada disso é alcançável: groups[8] tem de estar vazio.
        if pending_packages.contains(&requirement.provider_package) {
            continue;
        }
        if abi_policy == "strict" {
            let consumer = nodes.get(&requirement.package).unwrap();
            let provider = nodes.get(&requirement.provider_package).unwrap();
            let role_is_coherent = match parsed_purpose {
                PlanPurpose::Rectify | PlanPurpose::Sync | PlanPurpose::ChannelEmit => {
                    consumer.role == "runtime" && provider.role == "runtime"
                }
                PlanPurpose::CacheClosure => {
                    consumer.role == "cache-only" && provider.role == "cache-only"
                }
                PlanPurpose::Media => {
                    matches!(consumer.role.as_str(), "runtime" | "cache-only")
                        && (provider.role == consumer.role || provider.role == "runtime")
                }
            };
            if !role_is_coherent
                || (requirement.package != requirement.provider_package
                    && !direct_runtime_edges.contains(&(
                        requirement.package.clone(),
                        requirement.provider_package.clone(),
                    )))
            {
                bail!("ABI_REQUIRE estrito não aponta para provider runtime em DEPS direto");
            }
        }
        let expected_namespace = if requirement.namespace == "needed" {
            "soname"
        } else {
            "path"
        };
        let matches: Vec<&BTreeSet<String>> = abi_providers
            .iter()
            .filter_map(|((package, object, namespace, name), versions)| {
                (package == &requirement.provider_package
                    && object == &requirement.provider_object
                    && namespace == expected_namespace
                    && (expected_namespace == "path" || name == &requirement.name))
                    .then_some(versions)
            })
            .collect();
        if matches.len() != 1 {
            bail!("ABI_REQUIRE não corresponde a exatamente um ABI_PROVIDE factual");
        }
        if !requirement.versions.is_subset(matches[0]) {
            bail!("ABI_REQUIRE exige versões ausentes do ABI_PROVIDE exato");
        }
    }

    let mut static_keys = BTreeSet::new();
    for line in &groups[6] {
        let fields = record_fields(line, "ABI_STATIC", 3)?;
        let package = decode(fields[1])?;
        let object = decode(fields[2])?;
        if !material_factual(&package) {
            bail!("ABI_STATIC referencia pacote ausente/não factual");
        }
        validate_abi_path(&object, "objeto ABI_STATIC")?;
        if !static_keys.insert((package.clone(), object)) {
            bail!("ABI_STATIC repete objeto");
        }
        abi_covered.insert(package);
    }
    let mut none_packages = BTreeSet::new();
    for line in &groups[7] {
        let fields = record_fields(line, "ABI_NONE", 3)?;
        let package = decode(fields[1])?;
        let reason = decode(fields[2])?;
        let is_media_cache = parsed_purpose == PlanPurpose::Media
            && abi_policy == "strict"
            && nodes
                .get(&package)
                .is_some_and(|node| node.role == "cache-only");
        let canonical_reason = if is_media_cache {
            reason == "cache-only-nao-aplicavel"
        } else {
            reason == "payload-sem-abi-observada"
        };
        if !canonical_reason
            || !material_factual(&package)
            || !none_packages.insert(package.clone())
        {
            bail!("ABI_NONE não é prova canônica para pacote factual");
        }
        abi_covered.insert(package);
    }
    for package in &none_packages {
        if abi_providers
            .keys()
            .any(|(provider, _, _, _)| provider == package)
            || static_keys.iter().any(|(owner, _)| owner == package)
            || abi_requirements
                .iter()
                .any(|requirement| requirement.package == *package)
        {
            bail!("ABI_NONE conflita com fatos ABI do mesmo payload");
        }
    }
    let abi_lines = groups[4..=7]
        .iter()
        .flat_map(|group| group.iter())
        .map(|line| line.as_bytes().to_vec());
    if canonical_hash_material(b"minitrue-plan-abi-v1\0", abi_lines) != abi_audit_sha256 {
        bail!("ABI_AUDIT_SHA256 não corresponde aos records ABI tipados");
    }
    if pending_packages
        .iter()
        .any(|package| abi_covered.contains(package))
    {
        bail!("ABI_PENDING conflita com ABI_STATIC/NONE/REQUIRE/PROVIDE factual");
    }
    for (package, node) in &nodes {
        let factual_action = node.action == "keep"
            || (parsed_purpose == PlanPurpose::Media
                && abi_policy == "strict"
                && matches!(node.action.as_str(), "channel" | "vendor" | "source"));
        if node.role != "identity-only"
            && !matches!(node.kind.as_str(), "meta")
            && !factual_action
            && !pending_packages.contains(package)
        {
            bail!("NODE material sem payload observado não possui ABI_PENDING");
        }
        if node.role != "identity-only"
            && node.kind != "meta"
            && factual_action
            && !abi_covered.contains(package)
            && !pending_packages.contains(package)
        {
            bail!("NODE material factual não possui fatos ABI nem ABI_NONE");
        }
    }
    let mut orphan_keys = BTreeSet::new();
    if purpose != "sync" && !groups[9].is_empty() {
        bail!("ORPHAN só é permitido em PURPOSE=sync");
    }
    for line in &groups[9] {
        let fields = record_fields(line, "ORPHAN", 5)?;
        let package = decode(fields[1])?;
        recipe::validate_name(&package)?;
        let reason = decode(fields[3])?;
        if !canonical_sha256(fields[4]) {
            bail!("ORPHAN não prende RECORD_FACT_SHA256 canônico");
        }
        let coherent = match fields[2] {
            "unreachable" => reason == "fora-da-closure-runtime" && !nodes.contains_key(&package),
            "build-residue" => {
                reason == "somente-build-toolchain-runner"
                    && nodes.contains_key(&package)
                    && !runtime_reachable.contains(&package)
            }
            _ => false,
        };
        if !coherent {
            bail!("ORPHAN contém espécie/reason/closure incoerente");
        }
        if !orphan_keys.insert((package, fields[2].to_string())) {
            bail!("ORPHAN repete pacote/espécie");
        }
    }
    let mut predicted_keys = BTreeSet::new();
    if purpose != "sync" && !groups[10].is_empty() {
        bail!("PREDICTED_RESIDUE só é permitido em PURPOSE=sync");
    }
    for line in &groups[10] {
        let fields = record_fields(line, "PREDICTED_RESIDUE", 6)?;
        let package = decode(fields[1])?;
        let reason = decode(fields[3])?;
        let node = nodes
            .get(&package)
            .ok_or_else(|| anyhow::anyhow!("PREDICTED_RESIDUE referencia NODE ausente"))?;
        if fields[2] != "build-residue"
            || reason != "materializado-pela-operacao"
            || fields[4] != node.fingerprint
            || fields[5] != node.action
            || node.role == "identity-only"
            || node.action == "keep"
            || runtime_reachable.contains(&package)
        {
            bail!("PREDICTED_RESIDUE não corresponde à operação/closure tipada");
        }
        if !predicted_keys.insert(package) {
            bail!("PREDICTED_RESIDUE repete pacote");
        }
    }
    let expected_predicted: BTreeSet<String> = if purpose == "sync" {
        nodes
            .iter()
            .filter_map(|(package, node)| {
                (node.role != "identity-only"
                    && node.action != "keep"
                    && !runtime_reachable.contains(package))
                .then_some(package.clone())
            })
            .collect()
    } else {
        BTreeSet::new()
    };
    if predicted_keys != expected_predicted {
        bail!("PREDICTED_RESIDUE não é o conjunto exato de resíduos futuros");
    }

    Ok(VerifiedPlan {
        lock_sha256: sha256(bytes),
        tree_sha256,
        build_contract_sha256,
        purpose,
        binary_policy,
        abi_policy,
        abi_audit_sha256,
        records,
        roots,
        nodes,
        abi_factual_packages: abi_covered,
        abi_pending_packages: pending_packages,
    })
}

impl VerifiedPlan {
    fn slice_bytes(&self, package: &str) -> Result<Vec<u8>> {
        let encoded = encode(package);
        let mut selected = Vec::new();
        for line in &self.records {
            let fields: Vec<&str> = line.split('\t').collect();
            let relevant = match fields.first().copied() {
                Some("ROOT") => fields.get(2) == Some(&encoded.as_str()),
                Some("NODE") => fields.get(1) == Some(&encoded.as_str()),
                Some("EDGE") => {
                    fields.get(1) == Some(&encoded.as_str())
                        || fields.get(3) == Some(&encoded.as_str())
                }
                Some("ARTIFACT") | Some("ABI_PROVIDE") | Some("ABI_STATIC") | Some("ABI_NONE")
                | Some("ABI_PENDING") => fields.get(1) == Some(&encoded.as_str()),
                Some("ABI_REQUIRE") => {
                    fields.get(1) == Some(&encoded.as_str())
                        || fields.get(6) == Some(&encoded.as_str())
                }
                Some("PREDICTED_RESIDUE") => fields.get(1) == Some(&encoded.as_str()),
                _ => false,
            };
            if relevant {
                selected.push(line.clone());
            }
        }
        selected.sort();
        let mut body = format!(
            "PLAN_SLICE_FORMAT={PLAN_SLICE_FORMAT}\nPLAN_LOCK_SHA256={}\nTREE_SHA256={}\nBUILD_CONTRACT_SHA256={}\nARCH={ARCH}\nPURPOSE={}\nBINARY_POLICY={}\nABI_POLICY={}\nABI_AUDIT_SHA256={}\nPACKAGE={encoded}\nRECORD_COUNT={}\n",
            self.lock_sha256,
            self.tree_sha256,
            self.build_contract_sha256,
            self.purpose,
            self.binary_policy,
            self.abi_policy,
            self.abi_audit_sha256,
            selected.len()
        );
        for line in selected {
            push_line(&mut body, line)?;
        }
        Ok(body.into_bytes())
    }
}

fn read_content_addressed(directory: &Path, name: &str, label: &str) -> Result<Vec<u8>> {
    let (directory_file, _, _) = open_anchored_leaf(directory, libc::O_RDONLY | libc::O_DIRECTORY)
        .with_context(|| format!("não pude abrir diretório ancorado de {label}"))?;
    let metadata = directory_file.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        bail!("diretório de {label} não é privado/confiável");
    }
    let name = CString::new(name)?;
    read_existing_regular_at(&directory_file, &name, MAX_PLAN_BYTES, label)?
        .ok_or_else(|| anyhow::anyhow!("{label} referenciado não existe"))
}

/// Payload factual de um registro Mundo A, do jeito que o PLAN_LOCK o prende.
///
/// Um registro PROVISIONAL existe para se dissolver: seus applets cedem lugar
/// às ferramentas reais conforme o sistema materializa, e
/// `adopt_provisional_path` transfere cada caminho para quem o instala e o
/// declara em SUPERSEDES. Prender o manifesto inteiro era prender um valor que
/// o próprio design promete mudar — e mudava DENTRO do plano que causava a
/// mudança: instalar binutils tirava `/usr/bin/ar` e `/usr/bin/strings` do
/// busybox, e o vínculo do PLAN_LOCK do busybox quebrava no meio da execução.
///
/// Saber de antemão QUAIS caminhos serão cedidos exigiria construir antes de
/// resolver, porque quem supersede costuma ser Mundo B. Mas a cessão não
/// alcança o payload: um pacote Mundo A vive em `/opt/<nome>/`, e ninguém
/// supersede um caminho de lá. É essa árvore que identifica o pacote, e é ela
/// que fica presa; a integridade do manifesto inteiro continua conferida pelo
/// `verify`, por outro caminho.
///
/// Registro não-provisional não cede nada, e continua preso por inteiro. A
/// leitura é ancorada em descritor como a de qualquer outro payload de record.
/// Um registro provisional é o que declara, no próprio meta, que veio para
/// ceder lugar.
pub(crate) fn record_is_provisional(meta: &HashMap<String, String>) -> bool {
    meta.get("PROVISIONAL").map(String::as_str) == Some("1")
}

pub(crate) fn record_payload_sha256(
    record: &Path,
    name: &str,
    provisional: bool,
) -> Result<String> {
    let manifest = read_record_payload(record, "manifest")?;
    if !provisional {
        return Ok(sha256(&manifest));
    }
    let prefix = format!("/opt/{name}/").into_bytes();
    let mut retained: Vec<u8> = Vec::new();
    for line in manifest.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let separator = line
            .windows(2)
            .position(|window| window == b"  ")
            .ok_or_else(|| anyhow::anyhow!("{name}: manifesto tem linha sem caminho"))?;
        if line[separator + 2..].starts_with(&prefix) {
            retained.extend_from_slice(line);
            retained.push(b'\n');
        }
    }
    if retained.is_empty() {
        bail!("{name}: registro provisional não reivindica payload em /opt/{name}/");
    }
    Ok(sha256(&retained))
}

fn read_record_payload(record: &Path, name: &str) -> Result<Vec<u8>> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(record)?;
    let name = CString::new(name)?;
    let mut file = openat_file(
        &directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > MAX_META_BYTES as u64
    {
        bail!("arquivo factual do record não é regular nlink=1 dentro do limite");
    }
    let snapshot = StableMetadata::from(&before);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_META_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = StableMetadata::from(&file.metadata()?);
    let reopened = openat_file(
        &directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let at_path = StableMetadata::from(&reopened.metadata()?);
    if snapshot != after || after != at_path || bytes.len() as u64 != before.len() {
        bail!("arquivo factual do record mudou durante a leitura");
    }
    Ok(bytes)
}

/// Verifica vínculos históricos opcionais de v3 e o fechamento obrigatório de
/// v4. V3 permanece legível/migrável, mas só v4 declara ação, payload e ABI
/// factuais junto do lock+slice em uma única troca de `meta`.
pub(crate) fn verify_record_binding(
    ctx: &Ctx,
    record: &Path,
    meta: &HashMap<String, String>,
) -> Result<()> {
    let format = meta.get("RECORD_FORMAT").map(String::as_str);
    let install_action = meta.get("INSTALL_PLAN_ACTION").map(String::as_str);
    let install_payload = meta.get("INSTALL_PLAN_PAYLOAD_SHA256").map(String::as_str);
    let install_abi = meta.get("INSTALL_PLAN_ABI_SHA256").map(String::as_str);
    let legacy_plan_fields_present = ["PLAN_ACTION", "PLAN_PAYLOAD_SHA256", "PLAN_ABI_SHA256"]
        .iter()
        .any(|field| meta.contains_key(*field));
    let (lock_sha256, slice_sha256) = match (
        format,
        meta.get("INSTALL_PLAN_LOCK_SHA256"),
        meta.get("INSTALL_PLAN_SLICE_SHA256"),
        install_action,
        install_payload,
        install_abi,
    ) {
        (Some("4"), Some(lock), Some(slice), Some(action), Some(payload), Some(abi))
            if matches!(action, "keep" | "meta")
                && (canonical_sha256(payload)
                    || (meta.get("KIND").map(String::as_str) == Some("meta")
                        && matches!(action, "keep" | "meta")
                        && payload == "-"))
                && canonical_sha256(abi)
                && !legacy_plan_fields_present
                && !meta.contains_key("PLAN_LOCK_SHA256")
                && !meta.contains_key("PLAN_SLICE_SHA256") =>
        {
            (lock.as_str(), slice.as_str())
        }
        (Some("4"), ..) => bail!("RECORD_FORMAT=4 contém fechamento INSTALL_PLAN parcial/inválido"),
        (_, None, None, None, None, None) => {
            if legacy_plan_fields_present {
                bail!("record contém vínculo parcial de PLAN_LOCK");
            }
            match (meta.get("PLAN_LOCK_SHA256"), meta.get("PLAN_SLICE_SHA256")) {
                (None, None) => return Ok(()),
                (Some(lock), Some(slice)) if format == Some("3") => (lock.as_str(), slice.as_str()),
                _ => bail!("record contém vínculo parcial de PLAN_LOCK"),
            }
        }
        _ => bail!("record contém vínculo parcial de INSTALL_PLAN"),
    };
    if !canonical_sha256(lock_sha256) || !canonical_sha256(slice_sha256) {
        bail!("record contém hash de PLAN_LOCK/slice não canônico");
    }
    let package = meta
        .get("NAME")
        .ok_or_else(|| anyhow::anyhow!("record vinculado não declara NAME"))?;
    recipe::validate_name(package)?;
    if record.file_name().and_then(|name| name.to_str()) != Some(package.as_str()) {
        bail!("record vinculado não corresponde ao próprio NAME");
    }

    let lock_directory = ctx.root.join("var/lib/minitrue/plan-locks");
    let lock =
        read_content_addressed(&lock_directory, &format!("{lock_sha256}.lock"), "PLAN_LOCK")?;
    if sha256(&lock) != lock_sha256 {
        bail!("PLAN_LOCK referenciado não corresponde ao próprio hash");
    }
    let verified = verify_canonical(&lock)?;
    if verified.lock_sha256 != lock_sha256 {
        bail!("parser do PLAN_LOCK divergiu do hash do record");
    }
    let node = verified
        .nodes
        .get(package)
        .ok_or_else(|| anyhow::anyhow!("PLAN_LOCK não contém NODE para {package}"))?;
    if format == Some("4")
        && (install_action != Some(node.action.as_str())
            || install_payload != Some(node.payload.as_str())
            || install_abi != Some(verified.abi_audit_sha256.as_str())
            || node.payload == "pending"
            || node.role != "runtime"
            || (node.kind != "meta" && !verified.abi_factual_packages.contains(package))
            || verified.abi_pending_packages.contains(package))
    {
        bail!("RECORD_FORMAT=4 não prende ação/payload/ABI factual do NODE exato");
    }
    let record_world = match node.world.as_str() {
        "A" => "A",
        "B" => "B",
        "META" => "M",
        _ => bail!("NODE contém WORLD desconhecido"),
    };
    if !matches!(
        verified.purpose.as_str(),
        "rectify" | "sync" | "channel-emit"
    ) || !matches!(node.role.as_str(), "runtime" | "identity-only")
        || meta.get("VERSION") != Some(&node.version)
        || meta.get("KIND") != Some(&node.kind)
        || meta.get("WORLD").map(String::as_str) != Some(record_world)
        || meta.get("FINGERPRINT") != Some(&node.fingerprint)
        || meta.get("ORIGIN") != Some(&node.origin)
    {
        bail!("record não corresponde à identidade runtime do PLAN_LOCK");
    }
    match node.payload.as_str() {
        "pending" if verified.abi_policy == "development" => {}
        "pending" => bail!("record estrito referencia payload pending"),
        "-" if node.kind == "meta" => {}
        "-" => bail!("NODE com payload usa sentinela de metapacote"),
        payload if node.action == "channel" => {
            if meta.get("CHANNEL_SHA256").map(String::as_str) != Some(payload) {
                bail!("record de canal diverge do payload preso no PLAN_LOCK");
            }
        }
        payload if node.kind == "source" => {
            if meta.get("ARTIFACT_HASH").map(String::as_str) != Some(payload) {
                bail!("record B diverge do payload factual preso no PLAN_LOCK");
            }
        }
        payload if node.kind == "binary" => {
            if record_payload_sha256(record, package, record_is_provisional(meta))? != payload {
                bail!("record A diverge do payload preso no PLAN_LOCK");
            }
        }
        _ => bail!("payload do NODE é incompatível com KIND/ACTION"),
    }

    let slice_directory = record.join("plan-slices");
    let slice = read_content_addressed(
        &slice_directory,
        &format!("{slice_sha256}.slice"),
        "fatia de PLAN_LOCK",
    )?;
    if sha256(&slice) != slice_sha256 {
        bail!("fatia referenciada não corresponde ao próprio hash");
    }
    let expected_slice = verified.slice_bytes(package)?;
    if slice != expected_slice {
        bail!("fatia do record não deriva exatamente do PLAN_LOCK verificado");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNT: AtomicU64 = AtomicU64::new(0);

    struct LiveFixture {
        lock: Vec<u8>,
        components: Vec<u8>,
        runner_proof: Vec<u8>,
        authority_sha256: String,
        runner_proof_sha256: String,
    }

    fn test_pin(label: &str) -> String {
        sha256(label.as_bytes())
    }

    fn live_fixture(mode: &str, runner_id: &str, identity_input: &str) -> LiveFixture {
        let authenticated = if mode == "release" { "yes" } else { "no" };
        let eligible = if mode == "release" { "yes" } else { "no" };
        let complete = if mode == "release" { "yes" } else { "no" };
        let runner_path = if mode == "release" {
            "/usr/bin/bwrap"
        } else {
            "development-host"
        };
        let runner_pin = test_pin("runner-binary");
        let builder_lock = test_pin("builder-lock");
        let builder_root = test_pin("builder-root");
        let source_snapshot = test_pin("source-snapshot");
        let runner_proof = format!(
            "LIVE_RUNNER_PROOF_FORMAT=1\n\
             VARIANT=live-efi\n\
             BUILD_MODE={mode}\n\
             AUTHENTICATED={authenticated}\n\
             RUNNER_ID={runner_id}\n\
             RUNNER_PATH={runner_path}\n\
             RUNNER_SHA256={runner_pin}\n\
             BUILDER_ID=builder-fixture\n\
             BUILDER_LOCK_SHA256={builder_lock}\n\
             BUILDER_ROOTFS_TREE_SHA256={builder_root}\n\
             SOURCE_SNAPSHOT_SHA256={source_snapshot}\n\
             BUILD_EFI_SOURCE_SHA256={}\n\
             LIVE_LOCK_SOURCE_SHA256={}\n\
             LIVE_LOCK_HELPER_SOURCE_SHA256={}\n\
             LIVE_LOCK_HELPER_BINARY_SHA256={}\n\
             BUSYBOX_CONFIG_SHA256={}\n\
             LINUX_TAR_SHA256={}\n\
             BUSYBOX_TAR_SHA256={}\n\
             E2FSPROGS_TAR_SHA256={}\n\
             NCURSES_TAR_SHA256={}\n\
             UTIL_LINUX_TAR_SHA256={}\n\
             MINIPAX_BINARY_SHA256={}\n\
             MINITRUE_BINARY_SHA256={}\n\
             ZIG_TAR_SHA256={}\n\
             ZIG_BINARY_SHA256={}\n\
             MUSL_TREE_SHA256={}\n\
             SOURCE_DATE_EPOCH=1704067200\n",
            test_pin("build-efi-source"),
            test_pin("live-lock-source"),
            test_pin("helper-source"),
            test_pin("helper-binary"),
            test_pin("busybox-config"),
            test_pin("linux-tar"),
            test_pin("busybox-tar"),
            test_pin("e2fs-tar"),
            test_pin("ncurses-tar"),
            test_pin("util-linux-tar"),
            test_pin("minipax"),
            test_pin("minitrue"),
            test_pin("zig-tar"),
            test_pin("zig-binary"),
            test_pin("musl-tree"),
        )
        .into_bytes();
        let runner_proof_sha256 = sha256(&runner_proof);
        let contract = test_pin("live-build-contract");
        let material_evidence = test_pin("material-license-evidence");
        let identity_input = test_pin(identity_input);
        let entries = format!(
            "ENTRY=config-a|live-efi|measured|identity-only|identity-only|config|repo|repo:config-a|config:fixture|-|{EMPTY_SHA256}|{identity_input}|{identity_input}|{identity_input}|{contract}|toolchain:fixture|{}\n\
             ENTRY=payload-a|live-efi|produced|material|runtime|payload|built-from-source|initramfs:/bin/payload-a|source:payload-a|MIT|{material_evidence}|{}|{}|{}|{contract}|toolchain:fixture|{}\n",
            test_pin("identity-toolchain"),
            test_pin("material-input"),
            test_pin("material-payload"),
            test_pin("material-config"),
            test_pin("material-toolchain"),
        );
        let entries_sha256 = sha256(entries.as_bytes());
        let components = format!(
            "LIVE_COMPONENTS_FORMAT=1\n\
             VARIANT=live-efi\n\
             BUILD_MODE={mode}\n\
             RELEASE_INPUTS_COMPLETE={complete}\n\
             RELEASE_ELIGIBLE=no\n\
             SOURCE_DATE_EPOCH=1704067200\n\
             RUNNER_PROOF_SHA256={runner_proof_sha256}\n\
             ENTRIES_SHA256={entries_sha256}\n\
             BUILD_CONTRACT_SHA256={contract}\n\
             ENTRY_COUNT=2\n\
             {LIVE_COMPONENT_ENTRY_SCHEMA}\n\
             {entries}"
        )
        .into_bytes();
        let components_sha256 = sha256(&components);
        let boot = test_pin("boot-efi");
        let embed = test_pin("embed-proof");
        let boot_evidence = test_pin("boot-license-evidence");
        let lock = format!(
            "LIVE_LOCK_FORMAT=1\n\
             VARIANT=live-efi\n\
             BUILD_MODE={mode}\n\
             RELEASE_ELIGIBLE={eligible}\n\
             AUTHORITY_KIND=live-lock\n\
             BOOT_EFI_SHA256={boot}\n\
             COMPONENTS_SHA256={components_sha256}\n\
             RUNNER_PROOF_SHA256={runner_proof_sha256}\n\
             EMBED_PROOF_SHA256={embed}\n\
             ENTRIES_SHA256={entries_sha256}\n\
             BUILD_CONTRACT_SHA256={contract}\n\
             SOURCE_DATE_EPOCH=1704067200\n\
             INITRAMFS_BLOB_SHA256={}\n\
             INITRAMFS_CPIO_SHA256={}\n\
             EMBEDDED_COMPONENTS_SHA256={components_sha256}\n\
             LIVE_LOCK_HELPER_BINARY_SHA256={}\n\
             SOURCE_SNAPSHOT_SHA256={source_snapshot}\n\
             BUILDER_LOCK_SHA256={builder_lock}\n\
             BUILDER_ROOTFS_TREE_SHA256={builder_root}\n\
             {LIVE_PAYLOAD_SCHEMA}\n\
             PAYLOAD=boot-efi|live-efi|material|runtime|payload|built-from-source|generated:linux-efi-stub|embed-proof:{embed}|MIT|{boot_evidence}|{boot}\n",
            test_pin("initramfs-cpio"),
            test_pin("initramfs-cpio"),
            test_pin("helper-binary"),
        )
        .into_bytes();
        let authority_sha256 = sha256(&lock);
        LiveFixture {
            lock,
            components,
            runner_proof,
            authority_sha256,
            runner_proof_sha256,
        }
    }

    fn live_plan(purpose: PlanPurpose, abi_policy: AbiPolicy) -> ResolvedPlan {
        let node = PlanNode {
            name: "media-root".to_string(),
            version: "1".to_string(),
            kind: Kind::Meta,
            world: "META",
            action: PlanAction::Meta,
            origin: "meta".to_string(),
            fingerprint: test_pin("media-root-fingerprint"),
            materiality: Materiality::Runtime,
            payload_sha256: "-".to_string(),
            license: "-".to_string(),
        };
        let mut plan = ResolvedPlan {
            roots: vec![PlanRoot {
                name: node.name.clone(),
                role: RootRole::Install,
            }],
            recipes: BTreeMap::new(),
            fingerprints: HashMap::new(),
            nodes: BTreeMap::from([(node.name.clone(), node)]),
            edges: Vec::new(),
            order: vec!["media-root".to_string()],
            channels: channel::Resolution::empty(LoadMode::ReadOnly),
            tree_sha256: test_pin("media-tree"),
            build_contract_sha256: test_pin("media-contract"),
            binary_policy: BinaryPolicy::PreferBinary,
            purpose,
            abi_policy,
            artifacts: Vec::new(),
            abi_requires: Vec::new(),
            abi_provides: Vec::new(),
            abi_static: Vec::new(),
            abi_none: Vec::new(),
            abi_pending: Vec::new(),
            abi_audit_sha256: String::new(),
            orphans: Vec::new(),
            predicted_residues: Vec::new(),
            objects_authenticated: Cell::new(false),
            tree_revalidated: Cell::new(false),
        };
        plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
        plan
    }

    fn refresh_live_entries_hash(text: &str) -> Vec<u8> {
        let entry_offset = text.find("ENTRY=").unwrap();
        let entries = &text.as_bytes()[entry_offset..];
        let old = text
            .lines()
            .find(|line| line.starts_with("ENTRIES_SHA256="))
            .unwrap();
        let head =
            text[..entry_offset].replacen(old, &format!("ENTRIES_SHA256={}", sha256(entries)), 1);
        [head.as_bytes(), entries].concat()
    }

    fn rebind_live_components(fixture: &LiveFixture, from: &str, to: &str) -> LiveFixture {
        let old_components_sha256 = sha256(&fixture.components);
        let old = std::str::from_utf8(&fixture.components).unwrap();
        let replaced = old.replacen(from, to, 1);
        assert_ne!(old, replaced);
        let components = refresh_live_entries_hash(&replaced);
        let parsed = parse_live_components(&components).unwrap();
        let components_sha256 = sha256(&components);
        let lock_text = std::str::from_utf8(&fixture.lock)
            .unwrap()
            .replace(&old_components_sha256, &components_sha256)
            .replacen(
                fixture
                    .lock
                    .split(|byte| *byte == b'\n')
                    .find_map(|line| {
                        std::str::from_utf8(line)
                            .ok()?
                            .strip_prefix("ENTRIES_SHA256=")
                    })
                    .unwrap(),
                &parsed.entries_sha256,
                1,
            );
        let lock = lock_text.into_bytes();
        LiveFixture {
            authority_sha256: sha256(&lock),
            runner_proof_sha256: fixture.runner_proof_sha256.clone(),
            lock,
            components,
            runner_proof: fixture.runner_proof.clone(),
        }
    }

    fn rebind_live_runner_proof(fixture: &LiveFixture, from: &str, to: &str) -> LiveFixture {
        let old_proof = std::str::from_utf8(&fixture.runner_proof).unwrap();
        let replaced = old_proof.replacen(from, to, 1);
        assert_ne!(old_proof, replaced);
        let runner_proof = replaced.into_bytes();
        parse_live_runner_proof(&runner_proof).unwrap();
        let runner_proof_sha256 = sha256(&runner_proof);
        let components_text = std::str::from_utf8(&fixture.components)
            .unwrap()
            .replace(&fixture.runner_proof_sha256, &runner_proof_sha256);
        let components = components_text.into_bytes();
        parse_live_components(&components).unwrap();
        let old_components_sha256 = sha256(&fixture.components);
        let components_sha256 = sha256(&components);
        let lock_text = std::str::from_utf8(&fixture.lock)
            .unwrap()
            .replace(&fixture.runner_proof_sha256, &runner_proof_sha256)
            .replace(&old_components_sha256, &components_sha256);
        let lock = lock_text.into_bytes();
        LiveFixture {
            authority_sha256: sha256(&lock),
            runner_proof_sha256,
            lock,
            components,
            runner_proof,
        }
    }

    fn import_live(plan: &ResolvedPlan, fixture: &LiveFixture) -> Result<LiveMaterialImport> {
        plan.import_live_media(
            &LiveMediaAnchors {
                expected_authority_sha256: &fixture.authority_sha256,
                expected_runner_proof_sha256: &fixture.runner_proof_sha256,
            },
            LiveMediaDocuments {
                lock: &fixture.lock,
                components: &fixture.components,
                runner_proof: &fixture.runner_proof,
            },
        )
    }

    #[test]
    fn live_media_importa_manifesto_dinamico_e_boot_efi() {
        let plan = live_plan(PlanPurpose::Media, AbiPolicy::Strict);
        let fixture = live_fixture("release", "runner-fixture", "identity-input-a");
        let first = import_live(&plan, &fixture).unwrap();
        let second = import_live(&plan, &fixture).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.authority_kind, "live-lock");
        assert_eq!(first.identities.len(), 3);
        assert_eq!(first.material_identities().len(), 3);
        assert_eq!(first.materials().count(), 2);
        assert_eq!(first.identity_only_facts().count(), 1);
        assert!(first.identities.iter().any(|identity| {
            identity.id == "boot-efi"
                && identity.materiality == LiveMateriality::Material
                && identity.license == "MIT"
        }));
        assert!(first.identities.iter().any(|identity| {
            identity.id == "config-a"
                && identity.materiality == LiveMateriality::IdentityOnly
                && identity.license == "-"
        }));
        assert!(first.identities.iter().all(|identity| {
            canonical_sha256(&identity.material_id)
                && canonical_sha256(&identity.provenance_sha256)
                && identity.artifacts.windows(2).all(|pair| pair[0] < pair[1])
        }));
    }

    #[test]
    fn media_preserva_roots_runtime_e_cache_only_no_mesmo_lock() {
        let mut plan = live_plan(PlanPurpose::Media, AbiPolicy::Strict);
        let availability = PlanNode {
            name: "media-cache".to_string(),
            version: "1".to_string(),
            kind: Kind::Meta,
            world: "META",
            action: PlanAction::Meta,
            origin: "meta".to_string(),
            fingerprint: test_pin("media-cache-fingerprint"),
            materiality: Materiality::CacheOnly,
            payload_sha256: "-".to_string(),
            license: "-".to_string(),
        };
        plan.roots.push(PlanRoot {
            name: availability.name.clone(),
            role: RootRole::Availability,
        });
        plan.order.push(availability.name.clone());
        plan.nodes.insert(availability.name.clone(), availability);
        let bytes = plan.canonical_bytes().unwrap();
        verify_canonical(&bytes).unwrap();
        let identities = plan.material_identities(true).unwrap();
        assert!(identities.iter().any(|identity| identity.role == "runtime"));
        assert!(identities
            .iter()
            .any(|identity| identity.role == "cache-only"));
    }

    #[test]
    fn live_media_exige_plano_strict_e_ancoras_externas() {
        let fixture = live_fixture("release", "runner-fixture", "identity-input-a");
        assert!(import_live(
            &live_plan(PlanPurpose::Rectify, AbiPolicy::Strict),
            &fixture
        )
        .is_err());
        assert!(import_live(
            &live_plan(PlanPurpose::Media, AbiPolicy::Development),
            &fixture
        )
        .is_err());
        let plan = live_plan(PlanPurpose::Media, AbiPolicy::Strict);
        assert!(plan
            .import_live_media(
                &LiveMediaAnchors {
                    expected_authority_sha256: &test_pin("outra-autoridade"),
                    expected_runner_proof_sha256: &fixture.runner_proof_sha256,
                },
                LiveMediaDocuments {
                    lock: &fixture.lock,
                    components: &fixture.components,
                    runner_proof: &fixture.runner_proof,
                },
            )
            .is_err());
        assert!(plan
            .import_live_media(
                &LiveMediaAnchors {
                    expected_authority_sha256: &fixture.authority_sha256,
                    expected_runner_proof_sha256: &test_pin("outro-proof"),
                },
                LiveMediaDocuments {
                    lock: &fixture.lock,
                    components: &fixture.components,
                    runner_proof: &fixture.runner_proof,
                },
            )
            .is_err());
        let development = live_fixture("development", "development-runner", "identity-input-a");
        assert!(import_live(&plan, &development).is_err());
    }

    #[test]
    fn live_components_recusa_texto_count_schema_ordem_e_identidade_invalidos() {
        let fixture = live_fixture("release", "runner-fixture", "identity-input-a");
        let text = std::str::from_utf8(&fixture.components).unwrap();
        assert!(
            parse_live_components(&fixture.components[..fixture.components.len() - 1]).is_err()
        );
        assert!(parse_live_components(&text.replacen('\n', "\r\n", 1).into_bytes()).is_err());
        let mut non_ascii = fixture.components.clone();
        non_ascii[0] = 0xff;
        assert!(parse_live_components(&non_ascii).is_err());
        assert!(parse_live_components(
            &text
                .replacen("ENTRY_COUNT=2", "ENTRY_COUNT=02", 1)
                .into_bytes()
        )
        .is_err());
        assert!(parse_live_components(
            &text
                .replacen("ENTRY_COUNT=2", "ENTRY_COUNT=0", 1)
                .into_bytes()
        )
        .is_err());
        assert!(parse_live_components(
            &text
                .replacen(LIVE_COMPONENT_ENTRY_SCHEMA, "ENTRY_SCHEMA=id", 1)
                .into_bytes()
        )
        .is_err());
        assert!(
            parse_live_components(&text.replacen("origin_kind", "origin", 1).into_bytes()).is_err()
        );

        let missing = &text.as_bytes()[..text.find("ENTRY=payload-a").unwrap()];
        assert!(parse_live_components(missing).is_err());
        let extra = format!("{text}EXTRA=forbidden\n");
        assert!(parse_live_components(extra.as_bytes()).is_err());
        let config_line = text
            .lines()
            .find(|line| line.starts_with("ENTRY=config-a"))
            .unwrap();
        let duplicate = text.replacen(
            text.lines()
                .find(|line| line.starts_with("ENTRY=payload-a"))
                .unwrap(),
            config_line,
            1,
        );
        assert!(parse_live_components(&refresh_live_entries_hash(&duplicate)).is_err());
        let wrong_entries_hash = text.replacen(
            text.lines()
                .find(|line| line.starts_with("ENTRIES_SHA256="))
                .unwrap(),
            &format!("ENTRIES_SHA256={}", test_pin("wrong-entries")),
            1,
        );
        assert!(parse_live_components(wrong_entries_hash.as_bytes()).is_err());

        let first = text.find("ENTRY=config-a").unwrap();
        let second = text.find("ENTRY=payload-a").unwrap();
        let prefix = &text[..first];
        let config = &text[first..second];
        let payload = &text[second..];
        let swapped_entries = format!("{payload}{config}");
        let swapped_hash = sha256(swapped_entries.as_bytes());
        let swapped = format!(
            "{}{}",
            prefix.replacen(
                text.lines()
                    .find(|line| line.starts_with("ENTRIES_SHA256="))
                    .unwrap(),
                &format!("ENTRIES_SHA256={swapped_hash}"),
                1,
            ),
            swapped_entries
        );
        assert!(parse_live_components(swapped.as_bytes()).is_err());

        for (from, to) in [
            ("|built-from-source|", "|fixture|"),
            ("|config|repo|", "|config|development-prebuilt|"),
            ("|payload|built-from-source|", "|unknown|built-from-source|"),
            ("|produced|material|runtime|", "|measured|material|runtime|"),
            ("|material|runtime|", "|material|identity-only|"),
            (
                "|built-from-source|initramfs:/bin/payload-a|",
                "|built-from-source|-|",
            ),
            (
                "|initramfs:/bin/payload-a|source:payload-a|",
                "|initramfs:/bin/payload-a|-|",
            ),
            ("|source:payload-a|MIT|", "|source:payload-a|-|"),
            (
                &format!("|MIT|{}|", test_pin("material-license-evidence")),
                &format!("|MIT|{EMPTY_SHA256}|"),
            ),
            (
                &format!(
                    "|{}|{}|",
                    test_pin("material-input"),
                    test_pin("material-payload")
                ),
                &format!("|{EMPTY_SHA256}|{}|", test_pin("material-payload")),
            ),
            (
                &format!(
                    "|{}|{}|",
                    test_pin("material-payload"),
                    test_pin("material-config")
                ),
                &format!("|{EMPTY_SHA256}|{}|", test_pin("material-config")),
            ),
            (
                &format!("|config:fixture|-|{EMPTY_SHA256}|"),
                &format!("|config:fixture|MIT|{EMPTY_SHA256}|"),
            ),
        ] {
            let tampered = text.replacen(from, to, 1);
            assert!(parse_live_components(&refresh_live_entries_hash(&tampered)).is_err());
        }
        let license_ref = text.replacen(
            "|source:payload-a|MIT|",
            "|source:payload-a|LicenseRef-NONE-compatible|",
            1,
        );
        parse_live_components(&refresh_live_entries_hash(&license_ref)).unwrap();
    }

    #[test]
    fn live_runner_e_lock_recusam_linha_extra_ordem_e_payload_incoerente() {
        let fixture = live_fixture("release", "runner-fixture", "identity-input-a");
        let proof = std::str::from_utf8(&fixture.runner_proof).unwrap();
        assert!(parse_live_runner_proof(proof.trim_end().as_bytes()).is_err());
        assert!(parse_live_runner_proof(format!("{proof}EXTRA=no\n").as_bytes()).is_err());
        assert!(parse_live_runner_proof(
            proof
                .replacen("RUNNER_ID=runner-fixture", "RUNNER_ID=bad runner", 1)
                .as_bytes()
        )
        .is_err());
        assert!(parse_live_runner_proof(
            proof
                .replacen("BUILD_MODE=release", "BUILD_MODE=development", 1)
                .as_bytes()
        )
        .is_err());

        let lock = std::str::from_utf8(&fixture.lock).unwrap();
        assert!(parse_live_lock(lock.trim_end().as_bytes()).is_err());
        assert!(parse_live_lock(format!("{lock}EXTRA=no\n").as_bytes()).is_err());
        assert!(parse_live_lock(
            lock.replacen("AUTHORITY_KIND=live-lock", "AUTHORITY_KIND=self", 1)
                .as_bytes()
        )
        .is_err());
        assert!(parse_live_lock(
            lock.replacen(LIVE_PAYLOAD_SCHEMA, "PAYLOAD_SCHEMA=id", 1)
                .as_bytes()
        )
        .is_err());
        assert!(parse_live_lock(
            lock.replacen("|embed-proof:", "|other-proof:", 1)
                .as_bytes()
        )
        .is_err());
        assert!(parse_live_lock(
            lock.replacen(
                &format!("INITRAMFS_BLOB_SHA256={}", test_pin("initramfs-cpio")),
                &format!("INITRAMFS_BLOB_SHA256={}", test_pin("other-blob")),
                1,
            )
            .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn live_import_recusa_cross_hash_e_boot_adulterados_e_ids_prendem_proveniencia() {
        let plan = live_plan(PlanPurpose::Media, AbiPolicy::Strict);
        let fixture = live_fixture("release", "runner-fixture", "identity-input-a");
        let original = import_live(&plan, &fixture).unwrap();

        let lock_text = std::str::from_utf8(&fixture.lock).unwrap();
        let boot = test_pin("boot-efi");
        let tampered_lock = lock_text
            .replacen(
                &format!("|{}\n", boot),
                &format!("|{}\n", test_pin("different-boot")),
                1,
            )
            .into_bytes();
        assert!(plan
            .import_live_media(
                &LiveMediaAnchors {
                    expected_authority_sha256: &sha256(&tampered_lock),
                    expected_runner_proof_sha256: &fixture.runner_proof_sha256,
                },
                LiveMediaDocuments {
                    lock: &tampered_lock,
                    components: &fixture.components,
                    runner_proof: &fixture.runner_proof,
                },
            )
            .is_err());

        let wrong_components = lock_text
            .replacen(
                &format!("COMPONENTS_SHA256={}", sha256(&fixture.components)),
                &format!("COMPONENTS_SHA256={}", test_pin("other-components")),
                1,
            )
            .into_bytes();
        assert!(plan
            .import_live_media(
                &LiveMediaAnchors {
                    expected_authority_sha256: &sha256(&wrong_components),
                    expected_runner_proof_sha256: &fixture.runner_proof_sha256,
                },
                LiveMediaDocuments {
                    lock: &wrong_components,
                    components: &fixture.components,
                    runner_proof: &fixture.runner_proof,
                },
            )
            .is_err());

        let helper_mismatch = rebind_live_runner_proof(
            &fixture,
            &format!(
                "LIVE_LOCK_HELPER_BINARY_SHA256={}",
                test_pin("helper-binary")
            ),
            &format!(
                "LIVE_LOCK_HELPER_BINARY_SHA256={}",
                test_pin("other-helper-binary")
            ),
        );
        assert!(import_live(&plan, &helper_mismatch).is_err());

        let changed_runner = live_fixture("release", "runner-other", "identity-input-a");
        let changed_identity = live_fixture("release", "runner-fixture", "identity-input-b");
        let changed_material = rebind_live_components(
            &fixture,
            &test_pin("material-input"),
            &test_pin("material-input-b"),
        );
        let runner_import = import_live(&plan, &changed_runner).unwrap();
        let identity_import = import_live(&plan, &changed_identity).unwrap();
        let material_import = import_live(&plan, &changed_material).unwrap();
        let original_boot = original
            .identities
            .iter()
            .find(|identity| identity.id == "boot-efi")
            .unwrap();
        let runner_boot = runner_import
            .identities
            .iter()
            .find(|identity| identity.id == "boot-efi")
            .unwrap();
        let identity_boot = identity_import
            .identities
            .iter()
            .find(|identity| identity.id == "boot-efi")
            .unwrap();
        assert_ne!(original_boot.material_id, runner_boot.material_id);
        assert_ne!(
            original_boot.provenance_sha256,
            runner_boot.provenance_sha256
        );
        assert_ne!(original_boot.material_id, identity_boot.material_id);
        assert_ne!(
            original_boot.provenance_sha256,
            identity_boot.provenance_sha256
        );
        let original_config = original
            .identities
            .iter()
            .find(|identity| identity.id == "config-a")
            .unwrap();
        let changed_config = identity_import
            .identities
            .iter()
            .find(|identity| identity.id == "config-a")
            .unwrap();
        assert_ne!(original_config.material_id, changed_config.material_id);
        assert_ne!(
            original_config.provenance_sha256,
            changed_config.provenance_sha256
        );
        let original_payload = original
            .identities
            .iter()
            .find(|identity| identity.id == "payload-a")
            .unwrap();
        let changed_payload = material_import
            .identities
            .iter()
            .find(|identity| identity.id == "payload-a")
            .unwrap();
        assert_ne!(original_payload.material_id, changed_payload.material_id);
        assert_ne!(
            original_payload.provenance_sha256,
            changed_payload.provenance_sha256
        );
    }

    fn fixture(name: &str) -> (PathBuf, Ctx) {
        let serial = COUNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "minitrue-plan-{name}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("var/lib/minitrue/newspeak")).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        (root, ctx)
    }

    fn recipe_file(root: &Path, name: &str, body: &str) {
        let dir = root.join("var/lib/minitrue/newspeak").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("recipe"), body).unwrap();
    }

    fn with_fresh_closure(text: &str) -> Vec<u8> {
        let marker = "CLOSURE_SHA256=";
        let offset = text.rfind(marker).unwrap();
        let body = &text.as_bytes()[..offset];
        let mut out = body.to_vec();
        out.extend_from_slice(format!("{marker}{}\n", sha256(body)).as_bytes());
        out
    }

    #[test]
    fn lock_tipado_distingue_material_de_identity_only() {
        let (root, ctx) = fixture("typed");
        recipe_file(
            &root,
            "busybox",
            &format!(
                "NAME=busybox\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/busybox.tar\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                "a".repeat(64)
            ),
        );
        recipe_file(
            &root,
            "compiler",
            "NAME=compiler\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nbuild() { :; }\n",
        );
        recipe_file(
            &root,
            "app",
            "NAME=app\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nDEPS=busybox\nBUILD_DEPS=compiler\nbuild() { :; }\n",
        );
        let plan = resolve(
            &ctx,
            &["app".to_string()],
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        assert_eq!(plan.nodes["app"].materiality, Materiality::Runtime);
        assert_eq!(plan.nodes["compiler"].materiality, Materiality::Runtime);
        assert!(plan.edges.iter().any(|edge| {
            edge.from == "app"
                && edge.to == "compiler"
                && edge.kind == EdgeKind::Build
                && edge.materiality == Materiality::Runtime
        }));
        let bytes = plan.canonical_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("PLAN_LOCK_FORMAT=1\nTREE_SHA256="));
        assert!(text.contains("BUILD_CONTRACT_SHA256="));
        assert!(text.contains("ORPHAN_COUNT=0\n"));
        assert!(text.ends_with('\n'));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn meta_emite_somente_aresta_aggregation_e_parser_fecha_a_relacao() {
        let (root, ctx) = fixture("meta-aggregation");
        recipe_file(
            &root,
            "leaf",
            &format!(
                "NAME=leaf\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/leaf\nSHA256={}\ninstall_pkg() {{ :; }}\n",
                "a".repeat(64)
            ),
        );
        recipe_file(
            &root,
            "bundle",
            "NAME=bundle\nVERSION=1\nKIND=meta\nDEPS=leaf\n",
        );
        let plan = resolve(
            &ctx,
            &["bundle".to_string()],
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(plan.edges.iter().any(|edge| {
            edge.from == "bundle" && edge.to == "leaf" && edge.kind == EdgeKind::Aggregation
        }));
        let bytes = plan.canonical_bytes().unwrap();
        verify_canonical(&bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let tampered = with_fresh_closure(&text.replacen(
            "EDGE\tbundle\taggregation\tleaf",
            "EDGE\tbundle\truntime\tleaf",
            1,
        ));
        assert!(verify_canonical(&tampered).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parser_recusa_plano_sem_root() {
        let (root, ctx) = fixture("empty-root");
        assert!(resolve_for(
            &ctx,
            &[],
            PlanPurpose::Sync,
            BinaryPolicy::PreferBinary,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn abi_none_e_decidido_por_payload_nao_pela_closure_agregada() {
        let snapshot = audit::PlanAbiSnapshot {
            facts: Vec::new(),
            providers: vec![audit::PlanAbiProvideFact {
                package: "lib".to_string(),
                object: "/usr/lib/libx.so".to_string(),
                namespace: "soname".to_string(),
                name: "libx.so".to_string(),
                versions: "-".to_string(),
            }],
            static_objects: Vec::new(),
            complete: true,
            error_count: 0,
            missing_count: 0,
        };
        assert!(abi_snapshot_covers_package(&snapshot, "lib"));
        assert!(!abi_snapshot_covers_package(&snapshot, "app"));
    }

    #[test]
    fn abi_do_produtor_nao_pode_projetar_provider_fora_da_closure_da_midia() {
        let pkg_payload = test_pin("producer-pkg-payload");
        let lib_payload = test_pin("producer-lib-payload");
        let pkg_fingerprint = test_pin("producer-pkg-fingerprint");
        let lib_fingerprint = test_pin("producer-lib-fingerprint");
        let nodes = BTreeMap::from([
            (
                "lib".to_string(),
                PlanNode {
                    name: "lib".to_string(),
                    version: "1".to_string(),
                    kind: Kind::Source,
                    world: "B",
                    action: PlanAction::Keep,
                    origin: "fonte".to_string(),
                    fingerprint: lib_fingerprint.clone(),
                    materiality: Materiality::Runtime,
                    payload_sha256: lib_payload.clone(),
                    license: "MIT".to_string(),
                },
            ),
            (
                "pkg".to_string(),
                PlanNode {
                    name: "pkg".to_string(),
                    version: "1".to_string(),
                    kind: Kind::Source,
                    world: "B",
                    action: PlanAction::Keep,
                    origin: "fonte".to_string(),
                    fingerprint: pkg_fingerprint.clone(),
                    materiality: Materiality::Runtime,
                    payload_sha256: pkg_payload.clone(),
                    license: "MIT".to_string(),
                },
            ),
        ]);
        let mut artifacts = Vec::new();
        for (package, payload) in [("lib", &lib_payload), ("pkg", &pkg_payload)] {
            artifacts.push(PlanArtifact {
                package: package.to_string(),
                origin_kind: "source-empty".to_string(),
                materiality: Materiality::IdentityOnly,
                transport_sha256: "-".to_string(),
                reprocorr: "-".to_string(),
                channel_index_sha256: "-".to_string(),
                channel_lock_sha256: "-".to_string(),
                producer_plan_lock_sha256: "-".to_string(),
                channel_release_root: "-".to_string(),
                identifier: "recipe:SRC=none".to_string(),
            });
            artifacts.push(PlanArtifact {
                package: package.to_string(),
                origin_kind: "record-source".to_string(),
                materiality: Materiality::Runtime,
                transport_sha256: "-".to_string(),
                reprocorr: payload.clone(),
                channel_index_sha256: "-".to_string(),
                channel_lock_sha256: "-".to_string(),
                producer_plan_lock_sha256: "-".to_string(),
                channel_release_root: "-".to_string(),
                identifier: "record:source-stage".to_string(),
            });
        }
        artifacts.sort();
        let mut producer = ResolvedPlan {
            roots: vec![PlanRoot {
                name: "pkg".to_string(),
                role: RootRole::Install,
            }],
            recipes: BTreeMap::new(),
            fingerprints: HashMap::from([
                ("pkg".to_string(), pkg_fingerprint),
                ("lib".to_string(), lib_fingerprint.clone()),
            ]),
            nodes,
            edges: vec![PlanEdge {
                from: "pkg".to_string(),
                kind: EdgeKind::Runtime,
                to: "lib".to_string(),
                expected_fingerprint: lib_fingerprint,
                materiality: Materiality::Runtime,
            }],
            order: vec!["lib".to_string(), "pkg".to_string()],
            channels: channel::Resolution::empty(LoadMode::ReadOnly),
            tree_sha256: test_pin("producer-tree"),
            build_contract_sha256: test_pin("producer-contract"),
            binary_policy: BinaryPolicy::PreferBinary,
            purpose: PlanPurpose::ChannelEmit,
            abi_policy: AbiPolicy::Strict,
            artifacts,
            abi_requires: vec![AbiRequire {
                package: "pkg".to_string(),
                object: "/usr/bin/pkg".to_string(),
                namespace: "needed".to_string(),
                name: "libfixture.so.1".to_string(),
                versions: "-".to_string(),
                provider_package: "lib".to_string(),
                provider_object: "/usr/lib/libfixture.so.1".to_string(),
            }],
            abi_provides: vec![AbiProvide {
                package: "lib".to_string(),
                object: "/usr/lib/libfixture.so.1".to_string(),
                namespace: "soname".to_string(),
                name: "libfixture.so.1".to_string(),
                versions: "-".to_string(),
            }],
            abi_static: Vec::new(),
            abi_none: Vec::new(),
            abi_pending: Vec::new(),
            abi_audit_sha256: String::new(),
            orphans: Vec::new(),
            predicted_residues: Vec::new(),
            objects_authenticated: Cell::new(false),
            tree_revalidated: Cell::new(false),
        };
        producer.abi_audit_sha256 = producer.recompute_abi_audit_sha256();
        let verified = verify_canonical(&producer.canonical_bytes().unwrap()).unwrap();
        assert!(verified
            .abi_projection(&BTreeSet::from(["pkg".to_string()]))
            .is_err());
    }

    /// Um nó qualquer, material e de mundo A, só para dar contexto às
    /// conferências de assinatura.
    fn no_de_vendor() -> VerifiedNode {
        VerifiedNode {
            version: "1".into(),
            kind: "binary".into(),
            world: "A".into(),
            action: "vendor".into(),
            origin: "vendor".into(),
            fingerprint: "a".repeat(64),
            role: "runtime".into(),
            payload: "b".repeat(64),
            license: "MIT".into(),
            provenance_sha256: "c".repeat(64),
        }
    }

    fn fatos(pares: &[(&str, &str)]) -> Vec<(String, String)> {
        pares
            .iter()
            .map(|(kind, identifier)| (kind.to_string(), identifier.to_string()))
            .collect()
    }

    fn no_de_fonte() -> VerifiedNode {
        VerifiedNode {
            kind: "source".into(),
            world: "B".into(),
            action: "source".into(),
            origin: "source".into(),
            ..no_de_vendor()
        }
    }

    const SRC_1: (&str, &str) = ("vendor-input", "recipe:SRC[1]=https://e.invalid/a.tar");
    const SRC_2: (&str, &str) = ("vendor-input", "recipe:SRC[2]=https://e.invalid/b.tar");
    const FONTE_1: (&str, &str) = ("source-input", "recipe:SRC[1]=https://e.invalid/a.tar.xz");
    const FONTE_2: (&str, &str) = ("source-input", "recipe:SRC[2]=https://e.invalid/b.tar.xz");
    const SIGSUMS: (&str, &str) = (
        "checksums",
        "recipe:SIGSUMS=https://e.invalid/sha256sums.asc;EPOCH=10",
    );
    const SIGSUMS_SIG: (&str, &str) = (
        "signature",
        "recipe:SIGSUMS_SIG=https://e.invalid/sha256sums.txt.asc;EPOCH=10",
    );
    const SIGKEY_1: (&str, &str) = ("signature-key", "recipe:SIGKEY[1]=files/k.asc;FP=AA");
    const MINISIG_1: (&str, &str) = (
        "signature",
        "recipe:SIG_MINISIGN[1]=https://e.invalid/a.sig",
    );
    const MINISIG_2: (&str, &str) = (
        "signature",
        "recipe:SIG_MINISIGN[2]=https://e.invalid/b.sig",
    );
    const MINIKEY: (&str, &str) = ("signature-key", "recipe:SIGKEY=minisign:aaaa");

    #[test]
    fn cessao_de_applet_nao_move_o_payload_do_provisional() {
        let (root, _ctx) = fixture("provisional");
        let record = root.join("var/lib/minitrue/records/busybox");
        fs::create_dir_all(&record).unwrap();
        let escreve = |linhas: &str| fs::write(record.join("manifest"), linhas).unwrap();

        // O retrato do busybox recém-instalado: a árvore em /opt é o payload,
        // e os applets em /usr/bin são a superfície que cede.
        let antes = "d:aa  /opt/busybox/1.35.0\n\
                     l:bb  /opt/busybox/current\n\
                     l:cc  /usr/bin/ar\n\
                     l:dd  /usr/bin/strings\n";
        escreve(antes);
        let payload = record_payload_sha256(&record, "busybox", true).unwrap();

        // Instalar binutils tira /usr/bin/ar e /usr/bin/strings. Era isso que
        // invalidava o PLAN_LOCK no meio do plano que causava a cessão.
        escreve("d:aa  /opt/busybox/1.35.0\nl:bb  /opt/busybox/current\n");
        assert_eq!(
            record_payload_sha256(&record, "busybox", true).unwrap(),
            payload,
            "ceder applet não pode mover o payload de um provisional"
        );

        // Mexer no payload em si continua movendo o valor preso.
        escreve("d:ff  /opt/busybox/1.35.0\nl:bb  /opt/busybox/current\n");
        assert_ne!(
            record_payload_sha256(&record, "busybox", true).unwrap(),
            payload
        );

        // Registro não-provisional não cede nada, e continua preso por inteiro:
        // ali o mesmo par de linhas a menos MUDA o valor.
        escreve(antes);
        let inteiro = record_payload_sha256(&record, "busybox", false).unwrap();
        escreve("d:aa  /opt/busybox/1.35.0\nl:bb  /opt/busybox/current\n");
        assert_ne!(
            record_payload_sha256(&record, "busybox", false).unwrap(),
            inteiro
        );

        // Um provisional sem payload em /opt não tem o que prender, e dizer
        // isso é melhor que prender o hash do vazio.
        escreve("l:cc  /usr/bin/ar\n");
        assert!(record_payload_sha256(&record, "busybox", true).is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn minisign_tem_n_assinaturas_para_uma_chave_e_nenhum_epoch() {
        let no = no_de_vendor();
        // A regressão que travou o rebuild: minisign emitia `SIG[n]`, e o
        // validador cobrava dele o EPOCH e a bijeção com `SIGKEY[n]` — regras
        // que só existem no OpenPGP. Uma assinatura Ed25519 crua não tem
        // validade nem expiração, então não há instante de referência a citar.
        validate_package_artifact_correlation("zig", &no, &fatos(&[SRC_1, MINISIG_1, MINIKEY]))
            .unwrap();
        // Uma chave para duas fontes é o caso normal do minisign, e seria
        // recusado por qualquer regra de bijeção.
        validate_package_artifact_correlation(
            "zig",
            &no,
            &fatos(&[SRC_1, SRC_2, MINISIG_1, MINISIG_2, MINIKEY]),
        )
        .unwrap();
    }

    #[test]
    fn minisign_sem_correlacao_e_recusado() {
        let no = no_de_vendor();
        let recusa = |pares: &[(&str, &str)], porque: &str| {
            assert!(
                validate_package_artifact_correlation("zig", &no, &fatos(pares)).is_err(),
                "{porque}"
            );
        };
        recusa(
            &[SRC_1, MINISIG_1],
            "assinatura sem chave não tem quem a julgue",
        );
        recusa(&[SRC_1, MINIKEY], "chave sem assinatura que ela julgue");
        recusa(
            &[SRC_1, MINISIG_2, MINIKEY],
            "assinatura apontando para SRC[2] inexistente",
        );
        // Misturar os dois esquemas deixaria ambíguo qual chave julga qual
        // assinatura.
        recusa(
            &[
                SRC_1,
                MINISIG_1,
                MINIKEY,
                (
                    "signature",
                    "recipe:SIG[1]=https://e.invalid/a.asc;EPOCH=10",
                ),
                ("signature-key", "recipe:SIGKEY[1]=files/k.asc;FP=AA"),
            ],
            "minisign misturado com OpenPGP indexado",
        );
    }

    #[test]
    fn sigsums_e_um_manifesto_para_todos_os_src() {
        let no = no_de_fonte();
        // O caso do kernel: um sha256sums.asc clearsigned cobre o tarball, e a
        // SIGKEY[1] julga o manifesto — não um SRC. A bijeção SIG[n]/SIGKEY[n]
        // lia isso como chave órfã, e o `plan` recusava o próprio PLAN_LOCK que
        // acabara de emitir. Como o linux-headers está nas DEPS da glibc, a
        // recusa alcançava o Mundo B inteiro.
        validate_package_artifact_correlation("linux", &no, &fatos(&[FONTE_1, SIGSUMS, SIGKEY_1]))
            .unwrap();
        // Um manifesto só, cobrindo as duas fontes: é assim que o fetch confere
        // (basename por artefato contra o mesmo manifesto), e a bijeção jamais
        // aceitaria.
        validate_package_artifact_correlation(
            "linux",
            &no,
            &fatos(&[FONTE_1, FONTE_2, SIGSUMS, SIGKEY_1]),
        )
        .unwrap();
        // Manifesto destacado é a outra forma suportada, e é única.
        validate_package_artifact_correlation(
            "linux",
            &no,
            &fatos(&[FONTE_1, SIGSUMS, SIGSUMS_SIG, SIGKEY_1]),
        )
        .unwrap();
    }

    #[test]
    fn sigsums_sem_correlacao_e_recusado() {
        let no = no_de_fonte();
        let recusa = |pares: &[(&str, &str)], porque: &str| {
            assert!(
                validate_package_artifact_correlation("linux", &no, &fatos(pares)).is_err(),
                "{porque}"
            );
        };
        recusa(
            &[FONTE_1, SIGSUMS],
            "manifesto sem chave não tem quem o julgue",
        );
        recusa(
            &[
                FONTE_1,
                SIGSUMS,
                SIGKEY_1,
                ("signature-key", "recipe:SIGKEY[2]=files/k.asc;FP=BB"),
            ],
            "segunda chave não julga manifesto nenhum",
        );
        recusa(
            &[
                FONTE_1,
                SIGSUMS,
                SIGKEY_1,
                (
                    "signature",
                    "recipe:SIG[1]=https://e.invalid/a.asc;EPOCH=10",
                ),
            ],
            "SIGSUMS misturado com assinatura indexada",
        );
        recusa(
            &[FONTE_1, SIGSUMS, SIGKEY_1, MINIKEY, MINISIG_1],
            "SIGSUMS misturado com minisign",
        );
        recusa(
            &[
                FONTE_1,
                SIGSUMS,
                SIGSUMS_SIG,
                SIGKEY_1,
                (
                    "signature",
                    "recipe:SIGSUMS_SIG=https://e.invalid/outro.asc;EPOCH=10",
                ),
            ],
            "duas assinaturas destacadas para um manifesto",
        );
        // A chave continua obrigatória mesmo quando o manifesto não existe: um
        // SIGKEY[1] sozinho é a chave órfã que a bijeção sempre recusou, e
        // afrouxá-la para o SIGSUMS não podia abrir essa porta.
        recusa(
            &[FONTE_1, SIGKEY_1],
            "chave indexada sem nada que ela julgue",
        );
    }

    #[test]
    fn plan_readonly_nao_cria_estado() {
        let (root, ctx) = fixture("readonly");
        recipe_file(
            &root,
            "tool",
            &format!(
                "NAME=tool\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/tool.tar\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                "b".repeat(64)
            ),
        );
        let plan = resolve(
            &ctx,
            &["tool".to_string()],
            BinaryPolicy::PreferBinary,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        plan.print().unwrap();
        assert!(!root.join("var/lib/minitrue/plan-locks").exists());
        assert!(!root.join("var/lib/minitrue/channel-locks").exists());
        assert!(!ctx.world_path().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parser_recusa_contagem_ordem_e_reason_semanticos() {
        let (root, ctx) = fixture("canonical");
        recipe_file(
            &root,
            "busybox",
            &format!(
                "NAME=busybox\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/busybox.tar\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                "a".repeat(64)
            ),
        );
        recipe_file(
            &root,
            "app",
            "NAME=app\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nbuild() { :; }\n",
        );
        let plan = resolve(
            &ctx,
            &["app".to_string()],
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        let bytes = plan.canonical_bytes().unwrap();
        verify_canonical(&bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();

        let wrong_count = with_fresh_closure(&text.replacen("NODE_COUNT=2", "NODE_COUNT=3", 1));
        assert!(verify_canonical(&wrong_count).is_err());

        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let nodes: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| line.starts_with("NODE\t").then_some(index))
            .collect();
        lines.swap(nodes[0], nodes[1]);
        let reordered = with_fresh_closure(&(lines.join("\n") + "\n"));
        assert!(verify_canonical(&reordered).is_err());

        let invalid_reason =
            with_fresh_closure(&text.replacen("payload-nao-observado", "erro-/tmp/host", 1));
        assert!(verify_canonical(&invalid_reason).is_err());

        let local_identifier = with_fresh_closure(&text.replacen(
            "https://e.invalid/busybox.tar",
            "file:/tmp/host.tar",
            1,
        ));
        assert!(verify_canonical(&local_identifier).is_err());

        let zero_source_index = with_fresh_closure(&text.replacen("SRC%5B1%5D", "SRC%5B0%5D", 1));
        assert!(verify_canonical(&zero_source_index).is_err());

        let insecure_source = with_fresh_closure(&text.replacen(
            "https://e.invalid/busybox.tar",
            "http://e.invalid/busybox.tar",
            1,
        ));
        assert!(verify_canonical(&insecure_source).is_err());

        let incoherent_artifact =
            with_fresh_closure(&text.replacen("vendor-input", "record-source", 1));
        assert!(verify_canonical(&incoherent_artifact).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_closure_usa_availability_e_nao_persiste() {
        let (root, ctx) = fixture("availability");
        let payload = b"runner fechado";
        let payload_hash = sha256(payload);
        recipe_file(
            &root,
            "busybox",
            &format!(
                "NAME=busybox\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/busybox.tar\nSHA256={payload_hash}\ninstall_pkg(){{ :; }}\n"
            ),
        );
        recipe_file(
            &root,
            "app",
            "NAME=app\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nbuild() { :; }\n",
        );
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(ctx.cache_dir().join(&payload_hash), payload).unwrap();
        let mut plan = resolve_for(
            &ctx,
            &[PlanRoot {
                name: "app".to_string(),
                role: RootRole::Availability,
            }],
            PlanPurpose::CacheClosure,
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(plan
            .nodes
            .values()
            .all(|node| node.materiality == Materiality::CacheOnly));
        assert!(plan.edges.iter().any(|edge| {
            edge.from == "app"
                && edge.to == "busybox"
                && edge.kind == EdgeKind::Runner
                && edge.materiality == Materiality::CacheOnly
        }));
        plan.authenticate_objects(&ctx, true).unwrap();
        plan.revalidate_tree(&ctx).unwrap();
        let bytes = plan.canonical_bytes().unwrap();
        verify_canonical(&bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("PURPOSE=cache-closure\n"));
        assert!(text.contains("ROOT\tavailability\tapp\n"));
        assert!(!root.join("var/lib/minitrue/plan-locks").exists());
        assert!(!root.join("var/lib/minitrue/channel-locks").exists());
        assert!(!ctx.records_dir().exists());
        assert!(!ctx.world_path().exists());
        assert_eq!(
            fs::read(ctx.cache_dir().join(&payload_hash)).unwrap(),
            payload
        );

        // ReadOnly/offline não corrige permissões por efeito colateral. Um
        // cache inseguro é recusado e permanece exatamente como foi entregue.
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o775)).unwrap();
        let mode_before = fs::metadata(ctx.cache_dir()).unwrap().permissions().mode() & 0o777;
        let mut insecure = resolve_for(
            &ctx,
            &[PlanRoot {
                name: "app".to_string(),
                role: RootRole::Availability,
            }],
            PlanPurpose::CacheClosure,
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(insecure.authenticate_objects(&ctx, true).is_err());
        assert_eq!(
            fs::metadata(ctx.cache_dir()).unwrap().permissions().mode() & 0o777,
            mode_before
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn strict_recusa_payload_e_abi_pending() {
        let (root, ctx) = fixture("strict");
        recipe_file(
            &root,
            "tool",
            &format!(
                "NAME=tool\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/tool.tar\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                "c".repeat(64)
            ),
        );
        assert!(resolve(
            &ctx,
            &["tool".to_string()],
            BinaryPolicy::SourceOnly,
            AbiPolicy::Strict,
            LoadMode::ReadOnly,
        )
        .is_err());
        let development = resolve(
            &ctx,
            &["tool".to_string()],
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(development.material_identities(true).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_readonly_classifica_unreachable_e_build_residue() {
        let (root, ctx) = fixture("sync-orphans");
        let mut requested = Vec::new();
        for name in ["tool", "anchor", "old"] {
            let payload = format!("payload de {name}\n");
            let payload_hash = sha256(payload.as_bytes());
            recipe_file(
                &root,
                name,
                &format!(
                    "NAME={name}\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/{name}\nSHA256={payload_hash}\nLINKS={name}=bin/{name}\ninstall_pkg() {{\n  mkdir -p \"$PREFIX/bin\"\n  cp \"$DL\" \"$PREFIX/bin/{name}\"\n  chmod 755 \"$PREFIX/bin/{name}\"\n}}\n"
                ),
            );
            fs::create_dir_all(ctx.cache_dir()).unwrap();
            fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(ctx.cache_dir().join(payload_hash), payload).unwrap();
            requested.push(name.to_string());
        }
        recipe_file(
            &root,
            "busybox",
            &format!(
                "NAME=busybox\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/busybox\nSHA256={}\ninstall_pkg() {{ :; }}\n",
                "d".repeat(64)
            ),
        );
        recipe_file(
            &root,
            "app",
            "NAME=app\nVERSION=1\nKIND=source\nLICENSE=MIT\nTOOLCHAIN=none\nDEPS=anchor\nBUILD_DEPS=tool\nbuild() { :; }\n",
        );
        install::rectify(&ctx, &requested, BinaryPolicy::SourceOnly).unwrap();
        let tool_meta = install::read_meta_strict(&ctx.records_dir().join("tool"))
            .unwrap()
            .unwrap();
        let applied_lock = fs::read(
            root.join("var/lib/minitrue/plan-locks")
                .join(format!("{}.lock", tool_meta["INSTALL_PLAN_LOCK_SHA256"])),
        )
        .unwrap();
        let applied_text = std::str::from_utf8(&applied_lock).unwrap();
        assert!(applied_text.contains("ABI_NONE\ttool\tpayload-sem-abi-observada\n"));
        fs::remove_dir_all(root.join("var/lib/minitrue/newspeak/old")).unwrap();
        fs::write(ctx.world_path(), b"app\n").unwrap();
        let world_before = fs::read(ctx.world_path()).unwrap();
        let locks_before = fs::read_dir(root.join("var/lib/minitrue/plan-locks"))
            .unwrap()
            .count();

        let roots = roots_from_system_world(&ctx).unwrap();
        let plan = resolve_for(
            &ctx,
            &roots,
            PlanPurpose::Sync,
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .unwrap();
        assert!(plan.orphans.iter().any(|orphan| {
            orphan.package == "tool"
                && orphan.kind == "build-residue"
                && orphan.reason == "somente-build-toolchain-runner"
                && canonical_sha256(&orphan.record_fact_sha256)
        }));
        assert!(plan.predicted_residues.iter().any(|residue| {
            residue.package == "busybox"
                && residue.kind == "build-residue"
                && residue.reason == "materializado-pela-operacao"
                && residue.action == "vendor"
                && canonical_sha256(&residue.expected_fingerprint)
        }));
        assert!(plan.orphans.iter().any(|orphan| {
            orphan.package == "old"
                && orphan.kind == "unreachable"
                && orphan.reason == "fora-da-closure-runtime"
                && canonical_sha256(&orphan.record_fact_sha256)
        }));
        verify_canonical(&plan.canonical_bytes().unwrap()).unwrap();
        assert_eq!(fs::read(ctx.world_path()).unwrap(), world_before);
        assert_eq!(
            fs::read_dir(root.join("var/lib/minitrue/plan-locks"))
                .unwrap()
                .count(),
            locks_before
        );
        let old_meta_path = ctx.records_dir().join("old/meta");
        let old_meta = fs::read_to_string(&old_meta_path).unwrap();
        fs::write(
            &old_meta_path,
            old_meta.replacen("FINGERPRINT=", "FINGERPRINT=x", 1),
        )
        .unwrap();
        assert!(resolve_for(
            &ctx,
            &roots,
            PlanPurpose::Sync,
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::ReadOnly,
        )
        .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn persistencia_e_record_prendem_lock_e_slice_exatos() {
        let (root, ctx) = fixture("binding");
        let payload = b"vendor autenticado";
        let payload_hash = sha256(payload);
        recipe_file(
            &root,
            "tool",
            &format!(
                "NAME=tool\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://e.invalid/tool.tar\nSHA256={payload_hash}\ninstall_pkg(){{ :; }}\n"
            ),
        );
        fs::create_dir_all(ctx.cache_dir()).unwrap();
        fs::set_permissions(ctx.cache_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(ctx.cache_dir().join(&payload_hash), payload).unwrap();
        let mut plan = resolve(
            &ctx,
            &["tool".to_string()],
            BinaryPolicy::SourceOnly,
            AbiPolicy::Development,
            LoadMode::Mutating,
        )
        .unwrap();
        assert!(plan.persist(&ctx).is_err());
        assert!(!root.join("var/lib/minitrue/plan-locks").exists());
        plan.authenticate_objects(&ctx, false).unwrap();
        plan.revalidate_tree(&ctx).unwrap();
        let development_lock = plan.persist(&ctx).unwrap();
        let record = ctx.records_dir().join("tool");
        fs::create_dir_all(&record).unwrap();
        let manifest = b"f:fixture  /usr/bin/tool\n";
        fs::write(record.join("manifest"), manifest).unwrap();
        fs::write(
            record.join("meta"),
            format!(
                "RECORD_FORMAT=3\nNAME=tool\nVERSION=1\nKIND=binary\nWORLD=A\nORIGIN=vendor\nFINGERPRINT={}\n",
                plan.fingerprints["tool"]
            ),
        )
        .unwrap();
        assert!(plan.bind_record(&ctx, "tool", &development_lock).is_err());
        let factual_payload = sha256(manifest);
        let node = plan.nodes.get_mut("tool").unwrap();
        node.action = PlanAction::Keep;
        node.payload_sha256.clone_from(&factual_payload);
        for artifact in &mut plan.artifacts {
            artifact.origin_kind = "record-input".into();
            artifact.materiality = Materiality::IdentityOnly;
        }
        plan.artifacts.push(PlanArtifact {
            package: "tool".into(),
            origin_kind: "record-vendor".into(),
            materiality: Materiality::Runtime,
            // Diferente do record-source, um vendor tem transporte: o objeto
            // pinado por SHA256 na receita. REPROCORR continua sendo o payload
            // factual reobservado do manifesto.
            transport_sha256: payload_hash.clone(),
            reprocorr: factual_payload.clone(),
            channel_index_sha256: "-".into(),
            channel_lock_sha256: "-".into(),
            producer_plan_lock_sha256: "-".into(),
            channel_release_root: "-".into(),
            identifier: "record:vendor-manifest".into(),
        });
        plan.artifacts.sort();
        plan.abi_pending.clear();
        plan.abi_none.push(AbiNone {
            package: "tool".into(),
            reason: "payload-sem-abi-observada".into(),
        });
        plan.abi_audit_sha256 = plan.recompute_abi_audit_sha256();
        let lock_sha256 = plan.persist(&ctx).unwrap();
        plan.bind_record(&ctx, "tool", &lock_sha256).unwrap();
        let meta = install::read_meta_strict(&record).unwrap().unwrap();
        assert_eq!(meta["RECORD_FORMAT"], "4");
        assert_eq!(meta["INSTALL_PLAN_ACTION"], "keep");
        assert_eq!(meta["INSTALL_PLAN_PAYLOAD_SHA256"], factual_payload);
        assert_eq!(meta["INSTALL_PLAN_ABI_SHA256"], plan.abi_audit_sha256);
        verify_record_binding(&ctx, &record, &meta).unwrap();

        let lock_path = root
            .join("var/lib/minitrue/plan-locks")
            .join(format!("{lock_sha256}.lock"));
        let alias = root.join("var/lib/minitrue/plan-locks/alias.lock");
        fs::hard_link(&lock_path, &alias).unwrap();
        assert!(verify_record_binding(&ctx, &record, &meta).is_err());
        fs::remove_file(alias).unwrap();
        verify_record_binding(&ctx, &record, &meta).unwrap();

        let slice_sha256 = meta["INSTALL_PLAN_SLICE_SHA256"].clone();
        let slice_path = record
            .join("plan-slices")
            .join(format!("{slice_sha256}.slice"));
        fs::write(&slice_path, b"adulterado\n").unwrap();
        assert!(verify_record_binding(&ctx, &record, &meta).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
