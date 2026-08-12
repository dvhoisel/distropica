#[path = "../src/openpgp.rs"]
mod openpgp;
#[path = "../src/openpgp_schema.rs"]
mod openpgp_schema;

use openpgp::{
    cache_object_name, inspect_rejected_dsa_sha1, pinned_cert_from_keyring_subset,
    pinned_primary_cert_subset, require_checksum_line, verify_clearsigned_checksums,
    verify_detached, verify_detached_checksums, verify_legacy_dsa_waiver, CacheObjectKind,
    PinnedCert, SignatureClock,
};
use openpgp_schema::{
    collect_literal_openpgp_fields, parse_signature_plan, parse_unsafe_signature_waiver,
    DetachedArtifactSpec, IndexedArtifactSignature, SignaturePlan, UnsafeSignatureWaiver,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::types::{HashAlgorithm, SignatureType};
use sequoia_openpgp::{Packet, PacketPile};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek};

const PRIMARY: &str = "AA1CF9EC4AE71CA1BF646C3AFCC8AE079B1EAEC6";
const SIGNING_SUBKEY: &str = "6196D38547D6033D170AF510370148E8A0CE16A9";
const ARTIFACT_SHA256: &str = "76f06b835e1cfcfb00c69194f3d74a74d89ee85fb845e4a4ee0a3e7689b1aa19";
const SIGNATURE_EPOCH: u64 = 1_767_225_720;

const PUBLIC: &[u8] = include_bytes!("fixtures/openpgp/public.asc");
const ARTIFACT: &[u8] = include_bytes!("fixtures/openpgp/artifact-1.0.tar.xz");
const ARTIFACT_SIGNATURE: &[u8] = include_bytes!("fixtures/openpgp/artifact-1.0.tar.xz.asc");
const CHECKSUMS: &[u8] = include_bytes!("fixtures/openpgp/sha256sums.txt");
const CHECKSUMS_SIGNATURE: &[u8] = include_bytes!("fixtures/openpgp/sha256sums.txt.asc");
const CLEARSIGNED_CHECKSUMS: &[u8] = include_bytes!("fixtures/openpgp/sha256sums.asc");
const SHA1_BINDING_PRIMARY: &str = "E6214EF69D1DB4D8F5C7FB1970BB76A86804CD69";
const SHA1_BINDING_CERT: &[u8] = include_bytes!("fixtures/openpgp/public-sha1-binding.asc");
const SHA1_POLICY_ARTIFACT: &[u8] = include_bytes!("fixtures/openpgp/artifact-sha1-policy.txt");
const SHA256_DATA_SIGNATURE_UNDER_SHA1_BINDING: &[u8] =
    include_bytes!("fixtures/openpgp/artifact-sha256-under-sha1-binding.asc");
const SHA1_DATA_SIGNATURE: &[u8] = include_bytes!("fixtures/openpgp/artifact-sha1.asc");
const DSA_BINDING_PRIMARY: &str = "CE98D0CCE710B1A8DCBE36BCA25316CF65A66698";
const RSA_SIGNER_UNDER_DSA: &str = "98B31D3C4F2DE0CD0A771A073510F978923F6F38";
const DSA_BINDING_CERT: &[u8] =
    include_bytes!("fixtures/openpgp/public-dsa-binding-rsa-signer.asc");
const RSA_SHA256_DATA_UNDER_DSA_BINDING: &[u8] =
    include_bytes!("fixtures/openpgp/artifact-rsa-sha256-under-dsa-binding.asc");
const DSA_SHA256_DATA_SIGNATURE: &[u8] = include_bytes!("fixtures/openpgp/artifact-dsa-sha256.asc");
const TEXT_SIGNATURE_PRIMARY: &str = "B425E7CDDFE98E4B6125579DBB5D8F5D028F4D1B";
const TEXT_SIGNATURE_CERT: &[u8] = include_bytes!("fixtures/openpgp/public-text-signature.asc");
const TEXT_SIGNATURE_ARTIFACT_LF: &[u8] = include_bytes!("fixtures/openpgp/artifact-text-lf.txt");
const TEXT_SIGNATURE: &[u8] = include_bytes!("fixtures/openpgp/artifact-text.asc");
const GLIBC_PRIMARY: &str = "35B17DF5752577CA0C541CEB94BFDF4484AD142F";
const GLIBC_SIGNER: &str = "FD19E6D31B192EE4DC63EAD3DC2B16215ED5412A";
const GLIBC_WKD_CERT: &[u8] = include_bytes!("../../newspeak/glibc/files/upstream-release.asc");
const GCC_PRIMARY: &str = "13975A70E63C361C73AE69EF6EEB81F8981C74C7";
const GCC_SIGNER: &str = "7F74F97C103468EE5D750B583AB00996FC26A641";
const GCC_CERT: &[u8] = include_bytes!("../../newspeak/gcc/files/upstream-release.asc");
const ZLIB_UNSAFE_WAIVER: &[u8] = include_bytes!("../../newspeak/zlib/files/assinatura-insegura");
const BISON_UNSAFE_WAIVER: &[u8] = include_bytes!("../../newspeak/bison/files/assinatura-insegura");
const BISON_PRIMARY: &str = "7DF84374B1EE1F9764BBE25D0DDCAA3278D5264E";
const BISON_OFFICIAL_KEY: &[u8] = include_bytes!("../../newspeak/bison/files/upstream-release.asc");
const BISON_OFFICIAL_KEYRING: &[u8] =
    include_bytes!("../../newspeak/bison/files/public-key-source.gpg");
const BISON_3_8_2_SIGNATURE: &[u8] =
    include_bytes!("../../newspeak/bison/files/upstream-signature.sig");
const ZLIB_PRIMARY: &str = "5ED46A6721D365587791E2AA783FCD8E58BCAFBA";
const ZLIB_OFFICIAL_KEY_PAGE: &[u8] =
    include_bytes!("../../newspeak/zlib/files/public-key-source.html");
const ZLIB_OFFICIAL_KEY: &[u8] = include_bytes!("../../newspeak/zlib/files/upstream-release.asc");
const ZLIB_1_3_2_SIGNATURE: &[u8] =
    include_bytes!("../../newspeak/zlib/files/upstream-signature.sig");
const GMP_UNSAFE_WAIVER: &[u8] = include_bytes!("../../newspeak/gmp/files/assinatura-insegura");
const GMP_PRIMARY: &str = "343C2FF0FBEE5EC2EDBEF399F3599FF828C67298";
const GMP_6_3_0: &[u8] = include_bytes!("fixtures/openpgp/gmp-6.3.0.tar.xz");
const GMP_6_3_0_SIGNATURE: &[u8] =
    include_bytes!("../../newspeak/gmp/files/upstream-signature.sig");
const GMP_VALIDATION_CERT_SOURCE: &[u8] =
    include_bytes!("../../newspeak/gmp/files/validation-cert-source.asc");
const GMP_VALIDATION_CERT: &[u8] =
    include_bytes!("../../newspeak/gmp/files/validation-at-signature.asc");
const GMP_STALE_OFFICIAL_CERT: &[u8] =
    include_bytes!("../../newspeak/gmp/files/upstream-release.asc");
const GMP_OFFICIAL_ENDORSEMENT: &[u8] =
    include_bytes!("../../newspeak/gmp/files/official-endorsement.html");
const MPC_UNSAFE_WAIVER: &[u8] = include_bytes!("../../newspeak/mpc/files/assinatura-insegura");
const MPC_PRIMARY: &str = "AD17A21EF8AED8F1CC02DBD9F7D5C9BF765C61E3";
const MPC_1_4_1: &[u8] = include_bytes!("fixtures/openpgp/mpc-1.4.1.tar.xz");
const MPC_1_4_1_SIGNATURE: &[u8] =
    include_bytes!("../../newspeak/mpc/files/upstream-signature.sig");
const MPC_CERT_SOURCE: &[u8] = include_bytes!("../../newspeak/mpc/files/cert-transport-source.gpg");
const MPC_EXTRACTED_CERT: &[u8] = include_bytes!("../../newspeak/mpc/files/upstream-release.asc");
const MPC_RELEASE_PAGE: &[u8] =
    include_bytes!("../../newspeak/mpc/files/official-release-page.html");
const MPC_FINGERPRINT_PAGE: &[u8] =
    include_bytes!("../../newspeak/mpc/files/official-fingerprint-page.html");
const FUTURE_SELFSIG_ONLY_CERT: &[u8] =
    include_bytes!("fixtures/openpgp/public-future-selfsig.asc");
const FLEX_PRIMARY: &str = "56C67868E93390AA1039AD1CE4B29C8D64885307";
const FLEX_2_6_4: &[u8] = include_bytes!("fixtures/openpgp/flex-2.6.4.tar.gz");
const FLEX_SIGNATURE: &[u8] = include_bytes!("../../newspeak/flex/files/upstream-signature.sig");
const FLEX_CERT: &[u8] = include_bytes!("../../newspeak/flex/files/upstream-release.asc");
const FLEX_TAG_JSON: &[u8] = include_bytes!("../../newspeak/flex/files/identity-tag.json");
const FLEX_RELEASE_JSON: &[u8] = include_bytes!("../../newspeak/flex/files/identity-release.json");
const FLEX_TAG_SIGNATURE: &[u8] =
    include_bytes!("../../newspeak/flex/files/identity-tag-signature.asc");
const FLEX_TAG_PAYLOAD: &[u8] =
    include_bytes!("../../newspeak/flex/files/identity-tag-payload.txt");
const MATHLIBS_GLIBC_RECIPE: &[u8] = include_bytes!("../../newspeak/mathlibs-glibc/recipe");

fn clock() -> SignatureClock {
    SignatureClock::from_sig_epoch(&(SIGNATURE_EPOCH + 1).to_string()).unwrap()
}

fn cert_with_subkey_pin() -> PinnedCert {
    PinnedCert::from_bytes(PUBLIC, PRIMARY, &[SIGNING_SUBKEY.to_string()]).unwrap()
}

fn fields(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn first_ascii_armored_public_key(source: &[u8]) -> &[u8] {
    const BEGIN: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
    const END: &[u8] = b"-----END PGP PUBLIC KEY BLOCK-----\n";
    let starts: Vec<_> = source
        .windows(BEGIN.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == BEGIN).then_some(index))
        .collect();
    assert_eq!(starts.len(), 1);
    let start = starts[0];
    let tail = &source[start..];
    let ends: Vec<_> = tail
        .windows(END.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == END).then_some(index + END.len()))
        .collect();
    assert_eq!(ends.len(), 1);
    &tail[..ends[0]]
}

fn json_escape_string(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for byte in bytes {
        match byte {
            b'"' => escaped.push_str("\\\""),
            b'\\' => escaped.push_str("\\\\"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            0x20..=0x7e => escaped.push(*byte as char),
            _ => escaped.push_str(&format!("\\u00{byte:02x}")),
        }
    }
    escaped
}

#[test]
fn detached_validates_primary_and_actual_signing_subkey() {
    let report = verify_detached(
        Cursor::new(ARTIFACT),
        ARTIFACT_SIGNATURE,
        &cert_with_subkey_pin(),
        clock(),
    )
    .unwrap();
    assert_eq!(report.primary_fingerprint, PRIMARY);
    assert_eq!(report.signing_fingerprint, SIGNING_SUBKEY);
    assert_eq!(report.signature_creation_epoch, SIGNATURE_EPOCH);
    assert_eq!(report.verification_epoch, SIGNATURE_EPOCH + 1);
}

/// Prova reproduzível sobre o tarball upstream real sem versionar 20 MiB no
/// repositório. O teste normal fica hermético; esta probe é executada na
/// revisão apontando para o blob já pinado no cache e o sidecar HTTPS exato.
#[test]
#[ignore = "exige GLIBC_REAL_ARTIFACT e GLIBC_REAL_SIGNATURE"]
fn glibc_wkd_integral_verifica_blob_real_com_subkey_esperada() {
    let artifact_path = std::env::var_os("GLIBC_REAL_ARTIFACT")
        .expect("GLIBC_REAL_ARTIFACT deve apontar para glibc-2.44.tar.xz");
    let signature_path = std::env::var_os("GLIBC_REAL_SIGNATURE")
        .expect("GLIBC_REAL_SIGNATURE deve apontar para glibc-2.44.tar.xz.sig");
    let mut artifact = File::open(artifact_path).unwrap();
    let mut artifact_hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = artifact.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        artifact_hasher.update(&buffer[..read]);
    }
    assert_eq!(
        hex::encode(artifact_hasher.finalize()),
        "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667"
    );
    artifact.rewind().unwrap();

    let mut signature = Vec::new();
    File::open(signature_path)
        .unwrap()
        .read_to_end(&mut signature)
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&signature)),
        "44aabe605a02a56959bab51b92d985945db66dbd0117debe3d741252b2133ec6"
    );
    assert_eq!(
        hex::encode(Sha256::digest(GLIBC_WKD_CERT)),
        "41c9d83a195695194d1bbffa86d7761f3f9a6cb2c60d2629bd256272c163e6f8"
    );
    let cert = PinnedCert::from_bytes(GLIBC_WKD_CERT, GLIBC_PRIMARY, &[]).unwrap();
    let report = verify_detached(
        &mut artifact,
        &signature,
        &cert,
        SignatureClock::from_unix_seconds(1_786_460_504).unwrap(),
    )
    .unwrap();
    assert_eq!(report.primary_fingerprint, GLIBC_PRIMARY);
    assert_eq!(report.signing_fingerprint, GLIBC_SIGNER);
    assert_eq!(report.signature_creation_epoch, 1_784_937_664);
    assert_eq!(report.verification_epoch, 1_786_460_504);
    assert_eq!(report.signature_type, SignatureType::Binary);
    assert_eq!(report.signing_pk_algorithm, 1);
    assert_eq!(report.signing_key_bits, Some(4096));
    assert_eq!(report.hash_algorithm, 8);
    eprintln!("glibc real report: {report:?}");
}

/// Probe real do caso que motivou a exceção estreita de DSA somente no
/// binding: a assinatura de dados do GCC usa a subkey RSA e SHA-256.
#[test]
#[ignore = "exige GCC_REAL_ARTIFACT e GCC_REAL_SIGNATURE"]
fn gcc_dsa_binding_verifica_blob_real_com_rsa_sha256_data() {
    let artifact_path = std::env::var_os("GCC_REAL_ARTIFACT")
        .expect("GCC_REAL_ARTIFACT deve apontar para gcc-15.3.0.tar.xz");
    let signature_path = std::env::var_os("GCC_REAL_SIGNATURE")
        .expect("GCC_REAL_SIGNATURE deve apontar para gcc-15.3.0.tar.xz.sig");
    let mut artifact = File::open(artifact_path).unwrap();
    let mut artifact_hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = artifact.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        artifact_hasher.update(&buffer[..read]);
    }
    assert_eq!(
        hex::encode(artifact_hasher.finalize()),
        "fa59c1beef8995f27c4d71c1df227587189315d3e6faff1bb4306e61b0c530eb"
    );
    artifact.rewind().unwrap();

    let mut signature = Vec::new();
    File::open(signature_path)
        .unwrap()
        .read_to_end(&mut signature)
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&signature)),
        "cf2ccaff74e643059b0509a902b413c0bdb0d000b956af3538f48e645f72fef5"
    );
    assert_eq!(
        hex::encode(Sha256::digest(GCC_CERT)),
        "c77d48ac0197075cc624ffc42101ffeb297aeffc446fb3fdda7f98c2aa26e871"
    );
    let cert = PinnedCert::from_bytes(GCC_CERT, GCC_PRIMARY, &[]).unwrap();
    let report = verify_detached(
        &mut artifact,
        &signature,
        &cert,
        SignatureClock::from_unix_seconds(1_786_460_504).unwrap(),
    )
    .unwrap();
    assert_eq!(report.primary_fingerprint, GCC_PRIMARY);
    assert_eq!(report.signing_fingerprint, GCC_SIGNER);
    assert_eq!(report.signature_creation_epoch, 1_781_246_552);
    assert_eq!(report.verification_epoch, 1_786_460_504);
    assert_eq!(report.signature_type, SignatureType::Binary);
    assert_eq!(report.signing_pk_algorithm, 1);
    assert_eq!(report.signing_key_bits, Some(2048));
    assert_eq!(report.hash_algorithm, 8);
    eprintln!("gcc real report: {report:?}");
}

#[test]
fn detached_rejects_tampering_wrong_subkey_and_future_signature() {
    let mut tampered = ARTIFACT.to_vec();
    tampered[0] ^= 1;
    assert!(verify_detached(
        Cursor::new(tampered),
        ARTIFACT_SIGNATURE,
        &cert_with_subkey_pin(),
        clock(),
    )
    .is_err());

    // A primária pertence ao certificado, mas não foi quem emitiu esta
    // assinatura: o pino estreito da subchave não pode virar pino do keyring.
    let primary_only = PinnedCert::from_bytes(PUBLIC, PRIMARY, &[PRIMARY.to_string()]).unwrap();
    assert!(verify_detached(
        Cursor::new(ARTIFACT),
        ARTIFACT_SIGNATURE,
        &primary_only,
        clock(),
    )
    .is_err());

    let before_signature =
        SignatureClock::from_sig_epoch(&(SIGNATURE_EPOCH - 1).to_string()).unwrap();
    assert!(verify_detached(
        Cursor::new(ARTIFACT),
        ARTIFACT_SIGNATURE,
        &cert_with_subkey_pin(),
        before_signature,
    )
    .is_err());
}

#[test]
fn detached_artifact_rejects_text_signature_and_eol_equivalence() {
    let cert = PinnedCert::from_bytes(TEXT_SIGNATURE_CERT, TEXT_SIGNATURE_PRIMARY, &[]).unwrap();
    let clock = SignatureClock::from_unix_seconds(1_767_225_721).unwrap();
    let error = verify_detached(
        Cursor::new(TEXT_SIGNATURE_ARTIFACT_LF),
        TEXT_SIGNATURE,
        &cert,
        clock,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("tipo de assinatura OpenPGP inesperado"));

    // OpenPGP Text canonicaliza EOL. O motor de SRC exige Binary, portanto a
    // variante CRLF também é recusada em vez de virar o mesmo documento.
    let crlf = TEXT_SIGNATURE_ARTIFACT_LF
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .flat_map(|line| line.iter().copied().chain([b'\r', b'\n']))
        .collect::<Vec<_>>();
    let error = verify_detached(Cursor::new(crlf), TEXT_SIGNATURE, &cert, clock).unwrap_err();
    assert!(format!("{error:#}").contains("tipo de assinatura OpenPGP inesperado"));
}

#[test]
fn legacy_sha1_is_limited_to_certificate_binding_not_signed_data() {
    let cert = PinnedCert::from_bytes(SHA1_BINDING_CERT, SHA1_BINDING_PRIMARY, &[]).unwrap();
    let clock = SignatureClock::from_unix_seconds(1_767_225_603).unwrap();

    // A selfsig SHA-1 só autentica a ligação do UID ao certificado. O mesmo
    // certificado assina o artefato com SHA-256 e deve ser aceito.
    let accepted = verify_detached(
        Cursor::new(SHA1_POLICY_ARTIFACT),
        SHA256_DATA_SIGNATURE_UNDER_SHA1_BINDING,
        &cert,
        clock,
    )
    .unwrap();
    assert_eq!(accepted.primary_fingerprint, SHA1_BINDING_PRIMARY);

    // SHA-1 sobre bytes do artefato continua proibido: esse contexto exige
    // resistência a colisão, que a exceção estreita não concede.
    assert!(verify_detached(
        Cursor::new(SHA1_POLICY_ARTIFACT),
        SHA1_DATA_SIGNATURE,
        &cert,
        clock,
    )
    .is_err());
}

#[test]
fn legacy_dsa_is_limited_to_certificate_binding_not_signed_data() {
    let clock = SignatureClock::from_unix_seconds(1_786_460_504).unwrap();
    let cert = PinnedCert::from_bytes(
        DSA_BINDING_CERT,
        DSA_BINDING_PRIMARY,
        &[RSA_SIGNER_UNDER_DSA.to_string()],
    )
    .unwrap();

    let accepted = verify_detached(
        Cursor::new(SHA1_POLICY_ARTIFACT),
        RSA_SHA256_DATA_UNDER_DSA_BINDING,
        &cert,
        clock,
    )
    .unwrap();
    assert_eq!(accepted.primary_fingerprint, DSA_BINDING_PRIMARY);
    assert_eq!(accepted.signing_fingerprint, RSA_SIGNER_UNDER_DSA);

    let cert_without_signer_pin =
        PinnedCert::from_bytes(DSA_BINDING_CERT, DSA_BINDING_PRIMARY, &[]).unwrap();
    let error = verify_detached(
        Cursor::new(SHA1_POLICY_ARTIFACT),
        DSA_SHA256_DATA_SIGNATURE,
        &cert_without_signer_pin,
        clock,
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("assinatura OpenPGP de dados usa DSA"),
        "{error:#}"
    );
}

#[test]
fn certificate_transport_is_exactly_one_public_cert_with_canonical_pin() {
    assert!(PinnedCert::from_bytes(PUBLIC, &PRIMARY.to_ascii_lowercase(), &[]).is_err());
    assert!(
        PinnedCert::from_bytes(PUBLIC, "BB1CF9EC4AE71CA1BF646C3AFCC8AE079B1EAEC6", &[],).is_err()
    );

    let mut keyring = PUBLIC.to_vec();
    keyring.extend_from_slice(PUBLIC);
    assert!(PinnedCert::from_bytes(&keyring, PRIMARY, &[]).is_err());
}

#[test]
fn both_signed_checksum_mechanisms_require_exact_artifact_line() {
    let cert = cert_with_subkey_pin();
    let clear = verify_clearsigned_checksums(
        CLEARSIGNED_CHECKSUMS,
        &cert,
        clock(),
        "artifact-1.0.tar.xz",
        ARTIFACT_SHA256,
    )
    .unwrap();
    assert_eq!(clear.signing_fingerprint, SIGNING_SUBKEY);

    let detached = verify_detached_checksums(
        CHECKSUMS,
        CHECKSUMS_SIGNATURE,
        &cert,
        clock(),
        "artifact-1.0.tar.xz",
        ARTIFACT_SHA256,
    )
    .unwrap();
    assert_eq!(detached.primary_fingerprint, PRIMARY);

    assert!(verify_clearsigned_checksums(
        CLEARSIGNED_CHECKSUMS,
        &cert,
        clock(),
        "artifact-1.0.tar.xz",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .is_err());
    assert!(verify_clearsigned_checksums(
        ARTIFACT_SIGNATURE,
        &cert,
        clock(),
        "artifact-1.0.tar.xz",
        ARTIFACT_SHA256,
    )
    .is_err());
}

#[test]
fn checksum_parser_rejects_ambiguity_paths_and_malformed_unrelated_lines() {
    let valid = format!("{ARTIFACT_SHA256}  artifact-1.0.tar.xz\n");
    require_checksum_line(valid.as_bytes(), "artifact-1.0.tar.xz", ARTIFACT_SHA256).unwrap();

    let duplicate = format!("{valid}{valid}");
    assert!(
        require_checksum_line(duplicate.as_bytes(), "artifact-1.0.tar.xz", ARTIFACT_SHA256,)
            .is_err()
    );
    let unrelated_duplicate =
        format!("{ARTIFACT_SHA256}  outro.tar.xz\n{ARTIFACT_SHA256}  outro.tar.xz\n{valid}");
    assert!(require_checksum_line(
        unrelated_duplicate.as_bytes(),
        "artifact-1.0.tar.xz",
        ARTIFACT_SHA256,
    )
    .is_err());
    let path = format!("{ARTIFACT_SHA256}  ./artifact-1.0.tar.xz\n");
    assert!(
        require_checksum_line(path.as_bytes(), "artifact-1.0.tar.xz", ARTIFACT_SHA256,).is_err()
    );
    let junk = format!("isto não é checksum\n{valid}");
    assert!(
        require_checksum_line(junk.as_bytes(), "artifact-1.0.tar.xz", ARTIFACT_SHA256,).is_err()
    );
}

#[test]
fn cache_namespace_binds_kind_url_key_artifact_and_explicit_time() {
    let cert = cert_with_subkey_pin();
    let base = cache_object_name(
        CacheObjectKind::DetachedSignature,
        ARTIFACT_SHA256,
        "https://upstream.invalid/artifact.asc",
        &cert,
        clock(),
    )
    .unwrap();
    assert!(base.ends_with(".openpgp-sig"));
    assert_ne!(
        base,
        cache_object_name(
            CacheObjectKind::SignedChecksums,
            ARTIFACT_SHA256,
            "https://upstream.invalid/artifact.asc",
            &cert,
            clock(),
        )
        .unwrap()
    );
    assert_ne!(
        base,
        cache_object_name(
            CacheObjectKind::ChecksumsSignature,
            ARTIFACT_SHA256,
            "https://upstream.invalid/artifact.asc",
            &cert,
            clock(),
        )
        .unwrap()
    );
    let primary_pin_only = PinnedCert::from_bytes(PUBLIC, PRIMARY, &[]).unwrap();
    assert_ne!(
        base,
        cache_object_name(
            CacheObjectKind::DetachedSignature,
            ARTIFACT_SHA256,
            "https://upstream.invalid/artifact.asc",
            &primary_pin_only,
            clock(),
        )
        .unwrap()
    );
    assert_ne!(
        base,
        cache_object_name(
            CacheObjectKind::DetachedSignature,
            ARTIFACT_SHA256,
            "https://upstream.invalid/other.asc",
            &cert,
            clock(),
        )
        .unwrap()
    );
    assert_ne!(
        base,
        cache_object_name(
            CacheObjectKind::DetachedSignature,
            ARTIFACT_SHA256,
            "https://upstream.invalid/artifact.asc",
            &cert,
            SignatureClock::from_sig_epoch(&(SIGNATURE_EPOCH + 2).to_string()).unwrap(),
        )
        .unwrap()
    );
    assert!(cache_object_name(
        CacheObjectKind::DetachedSignature,
        ARTIFACT_SHA256,
        "http://upstream.invalid/artifact.asc",
        &cert,
        clock(),
    )
    .is_err());
}

#[test]
fn signature_epoch_is_mandatory_canonical_and_bounded() {
    assert_eq!(
        SignatureClock::from_sig_epoch("1767225721")
            .unwrap()
            .signature_epoch(),
        1_767_225_721
    );
    assert!(SignatureClock::from_sig_epoch("").is_err());
    assert!(SignatureClock::from_sig_epoch("+1").is_err());
    assert!(SignatureClock::from_sig_epoch(" 1").is_err());
    assert!(SignatureClock::from_sig_epoch("01").is_err());
    assert!(SignatureClock::from_unix_seconds(u32::MAX as u64 + 1).is_err());
}

#[test]
fn unsafe_signature_waiver_is_versioned_exact_and_mutually_exclusive() {
    let parsed = parse_unsafe_signature_waiver(ZLIB_UNSAFE_WAIVER).unwrap();
    assert_eq!(parsed.common().package, "zlib");
    let UnsafeSignatureWaiver::InsecureData(waiver) = parsed else {
        panic!("zlib deve usar o waiver v1")
    };
    assert_eq!(waiver.common.package, "zlib");
    assert_eq!(waiver.common.version, "1.3.2");
    assert_eq!(waiver.common.signature_algorithm, "DSA-1024");
    assert_eq!(waiver.common.signature_hash, "SHA1");
    assert_eq!(waiver.common.reason, "SHA1_DATA_REJECTED");
    assert_eq!(
        waiver.public_key_source_sha256,
        "939bc34e71648cb70793c711d86a58c302a624f84c8600cfa62f2fdd3c925022"
    );
    assert_eq!(
        waiver.public_key_extraction,
        "HTML_FIRST_ASCII_ARMOR_PUBLIC_KEY_BLOCK"
    );
    assert_eq!(
        waiver.public_key_cert_sha256,
        "27f818fd93326e4531c6b094f0edc4c331a1c77ec6449675a3929ae3274d85ac"
    );

    let map = fields(&[("SIG_UNSAFE_WAIVER", "files/assinatura-insegura")]);
    assert!(matches!(
        parse_signature_plan(1, &map).unwrap(),
        SignaturePlan::UnsafeUpstreamWaiver { .. }
    ));
    assert!(parse_signature_plan(2, &map).is_err());

    let mixed = fields(&[
        ("SIG_UNSAFE_WAIVER", "files/assinatura-insegura"),
        ("SIG_1", "https://up.invalid/zlib.sig"),
    ]);
    assert!(parse_signature_plan(1, &mixed).is_err());

    let duplicate = String::from_utf8(ZLIB_UNSAFE_WAIVER.to_vec())
        .unwrap()
        .replace(
            "REASON=SHA1_DATA_REJECTED\n",
            "REASON=SHA1_DATA_REJECTED\nREASON=SHA1_DATA_REJECTED\n",
        );
    assert!(parse_unsafe_signature_waiver(duplicate.as_bytes()).is_err());
    let broadened = String::from_utf8(ZLIB_UNSAFE_WAIVER.to_vec())
        .unwrap()
        .replace("SIGNATURE_HASH=SHA1", "SIGNATURE_HASH=SHA256");
    assert!(parse_unsafe_signature_waiver(broadened.as_bytes()).is_err());
    let mismatched_date = String::from_utf8(ZLIB_UNSAFE_WAIVER.to_vec())
        .unwrap()
        .replace("REVIEW_DATE=2026-08-11", "REVIEW_DATE=2026-08-10");
    assert!(parse_unsafe_signature_waiver(mismatched_date.as_bytes()).is_err());

    let UnsafeSignatureWaiver::InsecureData(bison) =
        parse_unsafe_signature_waiver(BISON_UNSAFE_WAIVER).unwrap()
    else {
        panic!("bison deve usar o waiver v1")
    };
    assert_eq!(bison.common.package, "bison");
    assert_eq!(
        bison.public_key_extraction,
        "OPENPGP_CERT_BY_PRIMARY_FINGERPRINT"
    );
    assert_eq!(
        bison.public_key_cert_sha256,
        hex::encode(Sha256::digest(BISON_OFFICIAL_KEY))
    );
}

#[test]
fn gmp_v2_is_exact_real_and_never_retrodates_the_normal_engine() {
    let UnsafeSignatureWaiver::ExpiredSigner(waiver) =
        parse_unsafe_signature_waiver(GMP_UNSAFE_WAIVER).unwrap()
    else {
        panic!("GMP deve usar o waiver v2")
    };
    assert_eq!(waiver.common.package, "gmp");
    assert_eq!(waiver.common.signature_epoch, 1_690_719_513);
    assert_eq!(waiver.validation_epoch, waiver.common.signature_epoch);
    assert_eq!(waiver.validation_cert_expiry_epoch, 1_736_961_163);
    assert!(waiver.validation_cert_expiry_epoch < waiver.common.review_epoch);
    assert_eq!(
        hex::encode(Sha256::digest(GMP_6_3_0)),
        waiver.common.artifact_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(GMP_6_3_0_SIGNATURE)),
        waiver.common.signature_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(GMP_VALIDATION_CERT_SOURCE)),
        waiver.validation_cert_source_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(GMP_VALIDATION_CERT)),
        waiver.validation_cert_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(GMP_OFFICIAL_ENDORSEMENT)),
        waiver.official_endorsement_sha256
    );
    let endorsement = std::str::from_utf8(GMP_OFFICIAL_ENDORSEMENT).unwrap();
    assert!(endorsement.contains("Last modified: 2025-08-24"));
    assert!(endorsement.contains("Fingerprint: 343C 2FF0 FBEE 5EC2 EDBE  F399 F359 9FF8 28C6 7298"));

    let packets = PacketPile::from_bytes(GMP_6_3_0_SIGNATURE).unwrap();
    let signature = packets
        .descendants()
        .find_map(|packet| match packet {
            Packet::Signature(signature) => Some(signature),
            _ => None,
        })
        .unwrap();
    assert_eq!(u8::from(signature.pk_algo()), 1); // RSA Encrypt or Sign.
    assert_eq!(signature.hash_algo(), HashAlgorithm::SHA512);
    assert_eq!(
        signature
            .signature_creation_time()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        waiver.validation_epoch
    );

    // A exportação mínima é comprovadamente subconjunto packet-a-packet
    // da resposta transportada. Ela valida os bytes reais somente no instante
    // autenticado da assinatura; no REVIEW_EPOCH o motor segue fail-closed.
    let cert =
        pinned_primary_cert_subset(GMP_VALIDATION_CERT_SOURCE, GMP_VALIDATION_CERT, GMP_PRIMARY)
            .unwrap();
    let report = verify_detached(
        Cursor::new(GMP_6_3_0),
        GMP_6_3_0_SIGNATURE,
        &cert,
        SignatureClock::from_unix_seconds(waiver.validation_epoch).unwrap(),
    )
    .unwrap();
    assert_eq!(report.primary_fingerprint, GMP_PRIMARY);
    assert_eq!(report.signature_creation_epoch, waiver.validation_epoch);
    assert!(verify_detached(
        Cursor::new(GMP_6_3_0),
        GMP_6_3_0_SIGNATURE,
        &cert,
        SignatureClock::from_unix_seconds(waiver.common.review_epoch).unwrap(),
    )
    .is_err());

    // Sem a selfsig histórica transportada (o cert oficial stale termina
    // antes da release), nem sequer a validação no creation time passa.
    let stale = PinnedCert::from_bytes(GMP_STALE_OFFICIAL_CERT, GMP_PRIMARY, &[]).unwrap();
    assert!(verify_detached(
        Cursor::new(GMP_6_3_0),
        GMP_6_3_0_SIGNATURE,
        &stale,
        SignatureClock::from_unix_seconds(waiver.validation_epoch).unwrap(),
    )
    .is_err());

    let wrong_epoch = String::from_utf8(GMP_UNSAFE_WAIVER.to_vec())
        .unwrap()
        .replace("VALIDATION_EPOCH=1690719513", "VALIDATION_EPOCH=1690719514");
    assert!(parse_unsafe_signature_waiver(wrong_epoch.as_bytes()).is_err());
    let future_endorsement = String::from_utf8(GMP_UNSAFE_WAIVER.to_vec())
        .unwrap()
        .replace(
            "OFFICIAL_ENDORSEMENT_PAGE_DATE=2025-08-24",
            "OFFICIAL_ENDORSEMENT_PAGE_DATE=2026-08-12",
        );
    assert!(parse_unsafe_signature_waiver(future_endorsement.as_bytes()).is_err());
}

#[test]
fn mpc_v3_confines_real_dsa_math_and_normal_engine_still_refuses_it() {
    let UnsafeSignatureWaiver::LegacyDsaData(waiver) =
        parse_unsafe_signature_waiver(MPC_UNSAFE_WAIVER).unwrap()
    else {
        panic!("MPC deve usar o waiver v3")
    };
    assert_eq!(waiver.common.package, "mpc");
    assert_eq!(waiver.common.signature_epoch, 1_776_343_261);
    assert_eq!(waiver.common.signature_algorithm, "DSA-2048-Q256");
    assert_eq!(waiver.common.signature_hash, "SHA256");
    assert_eq!(
        hex::encode(Sha256::digest(MPC_1_4_1)),
        waiver.common.artifact_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(MPC_1_4_1_SIGNATURE)),
        waiver.common.signature_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(MPC_CERT_SOURCE)),
        waiver.cert_transport_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(MPC_EXTRACTED_CERT)),
        waiver.cert_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(MPC_RELEASE_PAGE)),
        waiver.official_release_page_sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(MPC_FINGERPRINT_PAGE)),
        waiver.official_fingerprint_page_sha256
    );
    let release_page = std::str::from_utf8(MPC_RELEASE_PAGE).unwrap();
    assert!(release_page.contains("mpc-1.4.1.tar.xz"));
    assert!(release_page.contains("mpc-1.4.1.tar.xz.sig"));
    assert!(release_page.contains("/downloads/enge.gpg"));
    assert!(release_page.contains("andreas.enge@inria.fr"));
    assert!(release_page.contains("Last modifications on 2026-04-16"));
    let fingerprint_page = std::str::from_utf8(MPC_FINGERPRINT_PAGE).unwrap();
    assert!(fingerprint_page.contains("AD17 A21E F8AE D8F1 CC02  DBD9 F7D5 C9BF 765C 61E3"));
    assert!(fingerprint_page.contains("andreas.enge@inria.fr"));
    assert!(fingerprint_page.contains("Last modifications on 2024-04-10"));

    let cert = pinned_primary_cert_subset(MPC_CERT_SOURCE, MPC_EXTRACTED_CERT, MPC_PRIMARY)
        .expect("cert reduzido deve ser subconjunto packet-a-packet da fonte oficial");
    let report = verify_legacy_dsa_waiver(
        Cursor::new(MPC_1_4_1),
        MPC_1_4_1_SIGNATURE,
        &cert,
        waiver.common.signature_epoch,
    )
    .unwrap();
    assert_eq!(report.primary_fingerprint, MPC_PRIMARY);
    assert_eq!(report.signing_fingerprint, MPC_PRIMARY);
    assert_eq!(
        report.signature_creation_epoch,
        waiver.common.signature_epoch
    );

    // A exceção é uma API separada: o caminho normal permanece em
    // ENGINE_FORMAT=3 e recusa DSA nos dados mesmo sobre o artefato real.
    assert!(verify_detached(
        Cursor::new(MPC_1_4_1),
        MPC_1_4_1_SIGNATURE,
        &cert,
        SignatureClock::from_unix_seconds(waiver.common.review_epoch).unwrap(),
    )
    .is_err());
    let mut tampered = MPC_1_4_1.to_vec();
    tampered[0] ^= 1;
    assert!(verify_legacy_dsa_waiver(
        Cursor::new(tampered),
        MPC_1_4_1_SIGNATURE,
        &cert,
        waiver.common.signature_epoch,
    )
    .is_err());
    assert!(verify_legacy_dsa_waiver(
        Cursor::new(MPC_1_4_1),
        MPC_1_4_1_SIGNATURE,
        &cert,
        waiver.common.signature_epoch + 1,
    )
    .is_err());
}

#[test]
fn future_selfsig_cannot_retroactively_validate_an_earlier_epoch() {
    let cert = pinned_primary_cert_subset(
        FUTURE_SELFSIG_ONLY_CERT,
        FUTURE_SELFSIG_ONLY_CERT,
        MPC_PRIMARY,
    )
    .unwrap();
    // A única selfsig foi criada em 1783180387; o creation time factual da
    // assinatura MPC é 1776343261. A política explícita não pode usar o
    // pacote futuro para conceder validade retroativa.
    assert!(cert
        .primary_expiration_epoch_at(SignatureClock::from_unix_seconds(1_776_343_261).unwrap())
        .is_err());
}

#[test]
fn flex_normal_signature_is_anchored_by_the_official_signed_tag_and_release() {
    assert_eq!(
        hex::encode(Sha256::digest(FLEX_2_6_4)),
        "e87aae032bf07c26f85ac0ed3250998c37621d95f8bd748b31f15b33c45ee995"
    );
    assert_eq!(
        hex::encode(Sha256::digest(FLEX_SIGNATURE)),
        "c61ccc11286e1eb2ceeb0f0a8f8437e86f1e41840991566351f438de7eb5a9a2"
    );
    assert_eq!(
        hex::encode(Sha256::digest(FLEX_CERT)),
        "41dd311dd998581a981e96fe6bc24907d447c150a4b30c07ef41bb1cb5535f1b"
    );
    assert_eq!(
        hex::encode(Sha256::digest(FLEX_TAG_JSON)),
        "65ac5b6f55ce751205fb9e1be0a65bc6376aebc699e5616a1242b4551d3970d4"
    );
    assert_eq!(
        hex::encode(Sha256::digest(FLEX_RELEASE_JSON)),
        "f36291f9ef96cfe86e447c2131d4008d0e9861bd9a3f9b06f5b29bbf8f9323c3"
    );

    let tag = std::str::from_utf8(FLEX_TAG_JSON).unwrap();
    assert!(tag.contains("\"sha\": \"d69a58075169410324fe49666f6641ba6a9d1f91\""));
    assert!(tag.contains("\"name\": \"Will Estes\""));
    assert!(tag.contains("\"email\": \"westes575@gmail.com\""));
    assert!(tag.contains("\"tag\": \"v2.6.4\""));
    let embedded_signature = format!(
        "\"signature\": \"{}\"",
        json_escape_string(FLEX_TAG_SIGNATURE)
    );
    let embedded_payload = format!("\"payload\": \"{}\"", json_escape_string(FLEX_TAG_PAYLOAD));
    assert_eq!(tag.matches(&embedded_signature).count(), 1);
    assert_eq!(tag.matches(&embedded_payload).count(), 1);

    let release = std::str::from_utf8(FLEX_RELEASE_JSON).unwrap();
    assert!(release.contains("\"tag_name\": \"v2.6.4\""));
    assert!(release.contains("\"author\": {\n    \"login\": \"westes\""));
    for (name, content_type, size) in [
        ("flex-2.6.4.tar.gz", "application/gzip", 1_419_096),
        ("flex-2.6.4.tar.gz.sig", "application/pgp-signature", 473),
    ] {
        assert!(release.contains(&format!("\"name\": \"{name}\"")));
        assert!(release.contains(&format!("\"content_type\": \"{content_type}\"")));
        assert!(release.contains(&format!("\"size\": {size}")));
    }
    assert!(release.matches("\"login\": \"westes\"").count() >= 3);

    let parsed_cert = sequoia_openpgp::Cert::from_bytes(FLEX_CERT).unwrap();
    assert!(parsed_cert
        .userids()
        .any(|userid| { userid.userid().value() == b"Will Estes <westes575@gmail.com>" }));
    let cert = PinnedCert::from_bytes(FLEX_CERT, FLEX_PRIMARY, &[]).unwrap();
    let review_clock = SignatureClock::from_unix_seconds(1_786_460_504).unwrap();
    let tag_report = verify_detached(
        Cursor::new(FLEX_TAG_PAYLOAD),
        FLEX_TAG_SIGNATURE,
        &cert,
        review_clock,
    )
    .unwrap();
    assert_eq!(tag_report.primary_fingerprint, FLEX_PRIMARY);
    assert_eq!(tag_report.signing_fingerprint, FLEX_PRIMARY);
    assert_eq!(tag_report.signature_creation_epoch, 1_494_102_986);

    let artifact_report =
        verify_detached(Cursor::new(FLEX_2_6_4), FLEX_SIGNATURE, &cert, review_clock).unwrap();
    assert_eq!(artifact_report.primary_fingerprint, FLEX_PRIMARY);
    assert_eq!(artifact_report.signing_fingerprint, FLEX_PRIMARY);
    assert_eq!(artifact_report.signature_creation_epoch, 1_494_103_229);
    assert_eq!(artifact_report.signing_pk_algorithm, 1);
    assert_eq!(artifact_report.signing_key_bits, Some(2048));
    assert_eq!(artifact_report.hash_algorithm, 8);
}

#[test]
fn actual_zlib_dsa_sha1_signature_matches_the_waiver_and_is_refused() {
    assert_eq!(
        hex::encode(Sha256::digest(ZLIB_OFFICIAL_KEY_PAGE)),
        "939bc34e71648cb70793c711d86a58c302a624f84c8600cfa62f2fdd3c925022"
    );
    assert_eq!(
        first_ascii_armored_public_key(ZLIB_OFFICIAL_KEY_PAGE),
        ZLIB_OFFICIAL_KEY
    );
    assert_eq!(
        hex::encode(Sha256::digest(ZLIB_OFFICIAL_KEY)),
        "27f818fd93326e4531c6b094f0edc4c331a1c77ec6449675a3929ae3274d85ac"
    );
    assert_eq!(
        hex::encode(Sha256::digest(ZLIB_1_3_2_SIGNATURE)),
        "977472e4d306906adbe34f8b1fdbf58c46fe8b4ade1c92117816b8281c5ee096"
    );
    let packets = PacketPile::from_bytes(ZLIB_1_3_2_SIGNATURE).unwrap();
    let signatures: Vec<_> = packets
        .descendants()
        .filter_map(|packet| match packet {
            Packet::Signature(signature) => Some(signature),
            _ => None,
        })
        .collect();
    assert_eq!(signatures.len(), 1);
    assert_eq!(u8::from(signatures[0].pk_algo()), 17); // OpenPGP DSA.
    assert_eq!(signatures[0].hash_algo(), HashAlgorithm::SHA1);
    assert_eq!(
        signatures[0]
            .signature_creation_time()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_771_337_860
    );

    let cert = PinnedCert::from_bytes(ZLIB_OFFICIAL_KEY, ZLIB_PRIMARY, &[]).unwrap();
    let metadata = inspect_rejected_dsa_sha1(ZLIB_1_3_2_SIGNATURE, &cert, 1_771_337_860).unwrap();
    assert_eq!(metadata.signing_key_bits, 1024);
    assert_eq!(metadata.dsa_q_bits, 160);
    assert_eq!(metadata.hash_algorithm, 2);
    // O artefato real é exercitado pela focal de receita; aqui os packets
    // oficiais acima ficam presos e a API normal jamais os aceita como prova
    // para bytes diferentes. O negativo DSA/SHA-256 independente prova que a
    // recusa não depende de SHA-1 nem de mismatch do payload.
    assert!(verify_detached(
        Cursor::new(b"the policy must reject before this payload can matter"),
        ZLIB_1_3_2_SIGNATURE,
        &cert,
        SignatureClock::from_unix_seconds(1_786_460_504).unwrap(),
    )
    .is_err());
}

#[test]
fn actual_bison_dsa_sha1_signature_matches_the_waiver_and_is_refused() {
    assert_eq!(
        hex::encode(Sha256::digest(BISON_3_8_2_SIGNATURE)),
        "aeff6fd7d7d7cad905ba3bc5228a2ccb95500c0f51fb4483e229c47c7c50f835"
    );
    let packets = PacketPile::from_bytes(BISON_3_8_2_SIGNATURE).unwrap();
    let signatures: Vec<_> = packets
        .descendants()
        .filter_map(|packet| match packet {
            Packet::Signature(signature) => Some(signature),
            _ => None,
        })
        .collect();
    assert_eq!(signatures.len(), 1);
    assert_eq!(u8::from(signatures[0].pk_algo()), 17); // OpenPGP DSA.
    assert_eq!(signatures[0].hash_algo(), HashAlgorithm::SHA1);
    assert_eq!(
        signatures[0]
            .signature_creation_time()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_632_562_233
    );

    let cert =
        pinned_cert_from_keyring_subset(BISON_OFFICIAL_KEYRING, BISON_OFFICIAL_KEY, BISON_PRIMARY)
            .unwrap();
    let metadata = inspect_rejected_dsa_sha1(BISON_3_8_2_SIGNATURE, &cert, 1_632_562_233).unwrap();
    assert_eq!(metadata.signing_key_bits, 1024);
    assert_eq!(metadata.dsa_q_bits, 160);
    assert!(verify_detached(
        Cursor::new(b"the policy must reject before this payload can matter"),
        BISON_3_8_2_SIGNATURE,
        &cert,
        SignatureClock::from_unix_seconds(1_786_460_504).unwrap(),
    )
    .is_err());
}

#[test]
fn schema_represents_mathlibs_three_distinct_keys() {
    let map = fields(&[
        ("SIG_1", "https://up.invalid/gmp.tar.xz.sig"),
        ("SIG_EPOCH_1", "1767225721"),
        ("SIGKEY_1", "files/gmp.asc"),
        ("SIGKEY_FP_1", "343C2FF0FBEE5EC2EDBEF399F3599FF828C67298"),
        ("SIG_2", "https://up.invalid/mpfr.tar.xz.sig"),
        ("SIG_EPOCH_2", "1767225721"),
        ("SIGKEY_2", "files/mpfr.asc"),
        ("SIGKEY_FP_2", "A534BE3F83E241D918280AEB5831D11A0D4DB02A"),
        ("SIG_3", "https://up.invalid/mpc.tar.gz.sig"),
        ("SIG_EPOCH_3", "1767225721"),
        ("SIGKEY_3", "files/mpc.asc"),
        ("SIGKEY_FP_3", "AD17A21EF8AED8F1CC02DBD9F7D5C9BF765C61E3"),
    ]);
    let SignaturePlan::OpenPgpDetached { artifacts } = parse_signature_plan(3, &map).unwrap()
    else {
        panic!("plano errado")
    };
    assert_eq!(artifacts.len(), 3);
    assert_eq!(artifacts[0].src_index, 1);
    assert_eq!(artifacts[0].signature_epoch, 1_767_225_721);
    assert_ne!(
        artifacts[0].key.primary_fingerprint,
        artifacts[1].key.primary_fingerprint
    );
}

#[test]
fn schema_misto_indexado_cobre_cada_src_uma_vez_e_recusa_ambiguidades() {
    assert!(parse_signature_plan(
        1,
        &fields(&[("SIG_UNSAFE_WAIVER_1", "files/assinatura-insegura-1")])
    )
    .is_err());

    let valid = fields(&[
        ("SIG_UNSAFE_WAIVER_1", "files/assinatura-insegura-1"),
        ("SIG_2", "https://up.invalid/mpfr.tar.xz.sig"),
        ("SIG_EPOCH_2", "1767225721"),
        ("SIGKEY_2", "files/mpfr.asc"),
        ("SIGKEY_FP_2", "A534BE3F83E241D918280AEB5831D11A0D4DB02A"),
        ("SIG_UNSAFE_WAIVER_3", "files/assinatura-insegura-3"),
    ]);
    let SignaturePlan::IndexedArtifacts { artifacts } = parse_signature_plan(3, &valid).unwrap()
    else {
        panic!("plano misto indexado esperado")
    };
    assert_eq!(artifacts.len(), 3);
    assert!(matches!(
        artifacts[0],
        IndexedArtifactSignature::UnsafeUpstreamWaiver { src_index: 1, .. }
    ));
    assert!(matches!(
        artifacts[1],
        IndexedArtifactSignature::OpenPgpDetached(ref spec) if spec.src_index == 2
    ));
    assert!(matches!(
        artifacts[2],
        IndexedArtifactSignature::UnsafeUpstreamWaiver { src_index: 3, .. }
    ));

    let without = |name: &str| {
        valid
            .iter()
            .filter(|(field, _)| field.as_str() != name)
            .map(|(field, value)| (field.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert!(parse_signature_plan(3, &without("SIG_2")).is_err());

    let mut overlap = valid.clone();
    overlap.insert("SIG_1".into(), "https://up.invalid/gmp.sig".into());
    assert!(parse_signature_plan(3, &overlap).is_err());

    let mut extra = valid.clone();
    extra.insert(
        "SIG_UNSAFE_WAIVER_4".into(),
        "files/assinatura-insegura-4".into(),
    );
    assert!(parse_signature_plan(3, &extra).is_err());

    let mut legacy = valid.clone();
    legacy.insert("SIG".into(), "https://up.invalid/minisig".into());
    legacy.insert("SIGKEY".into(), "RWQ0123456789".into());
    assert!(parse_signature_plan(3, &legacy).is_err());

    let mut sums = valid.clone();
    sums.insert("SIGSUMS".into(), "https://up.invalid/sums.asc".into());
    sums.insert("SIGSUMS_EPOCH".into(), "1767225721".into());
    assert!(parse_signature_plan(3, &sums).is_err());

    let mut wrong_transport = valid;
    wrong_transport.insert(
        "SIG_UNSAFE_WAIVER_1".into(),
        "files/assinatura-insegura-3".into(),
    );
    assert!(parse_signature_plan(3, &wrong_transport).is_err());

    assert!(collect_literal_openpgp_fields(
        b"SIG_UNSAFE_WAIVER_1=files/assinatura-insegura-1\nSIG_UNSAFE_WAIVER_1=files/assinatura-insegura-1\n"
    )
    .is_err());
}

#[test]
fn schema_mathlibs_real_fecha_slots_mistos_sem_relaxar_tuple_normal() {
    let source = std::str::from_utf8(MATHLIBS_GLIBC_RECIPE).unwrap();
    let parse = |recipe: &str| {
        let fields = collect_literal_openpgp_fields(recipe.as_bytes())?;
        parse_signature_plan(3, &fields)
    };
    let SignaturePlan::IndexedArtifacts { artifacts } = parse(source).unwrap() else {
        panic!("mathlibs real deve produzir plano misto indexado")
    };
    assert!(matches!(
        artifacts.as_slice(),
        [
            IndexedArtifactSignature::UnsafeUpstreamWaiver { src_index: 1, .. },
            IndexedArtifactSignature::OpenPgpDetached(DetachedArtifactSpec { src_index: 2, .. }),
            IndexedArtifactSignature::UnsafeUpstreamWaiver { src_index: 3, .. }
        ]
    ));

    // Qualquer membro ausente deixa a tuple normal do SRC_2 incompleta,
    // mesmo com waivers válidos nos slots vizinhos.
    for prefix in ["SIG_2=", "SIG_EPOCH_2=", "SIGKEY_2=", "SIGKEY_FP_2="] {
        let line = source
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap();
        let mutated = source.replacen(&format!("{line}\n"), "", 1);
        let error = parse(&mutated).unwrap_err();
        assert!(
            format!("{error:#}").contains("SRC_2 exige tuple OpenPGP normal completa"),
            "remoção de {prefix} falhou pelo motivo errado: {error:#}"
        );
    }

    // Buraco, índice externo, índice não canônico e campo deslocado para um
    // slot waiver são recusados antes de qualquer verificação criptográfica.
    let hole = source.replacen(
        "SIG_UNSAFE_WAIVER_3=\"files/assinatura-insegura-3\"\n",
        "",
        1,
    );
    assert!(format!("{:#}", parse(&hole).unwrap_err()).contains("SRC_3 exige tuple"));

    let extra = source.replacen("SIG_UNSAFE_WAIVER_3=", "SIG_UNSAFE_WAIVER_4=", 1);
    assert!(format!("{:#}", parse(&extra).unwrap_err()).contains("nenhum SRC"));

    let noncanonical = source.replacen("SIG_2=", "SIG_02=", 1);
    assert!(format!("{:#}", parse(&noncanonical).unwrap_err()).contains("não canônico"));

    let cross_slot = source.replacen("SIGKEY_2=", "SIGKEY_1=", 1);
    assert!(format!("{:#}", parse(&cross_slot).unwrap_err()).contains("misturar waiver"));

    // Cada família normal sobreposta ao waiver do SRC_1 deve falhar; não é
    // suficiente procurar apenas SIG_n e pular SIGKEY/SIG_EPOCH.
    let insert_before_build =
        |line: &str| source.replacen("\nbuild() {", &format!("\n{line}\nbuild() {{"), 1);
    for line in [
        "SIG_1=https://up.invalid/gmp.tar.xz.sig",
        "SIG_EPOCH_1=1767225721",
        "SIGKEY_1=files/gmp.asc",
        "SIGKEY_FP_1=343C2FF0FBEE5EC2EDBEF399F3599FF828C67298",
    ] {
        let error = parse(&insert_before_build(line)).unwrap_err();
        assert!(
            format!("{error:#}").contains("SRC_1 não pode misturar waiver"),
            "overlap {line} falhou pelo motivo errado: {error:#}"
        );
    }

    let sig_line = source
        .lines()
        .find(|line| line.starts_with("SIG_2="))
        .unwrap();
    let duplicate = source.replacen(
        &format!("{sig_line}\n"),
        &format!("{sig_line}\n{sig_line}\n"),
        1,
    );
    assert!(format!("{:#}", parse(&duplicate).unwrap_err()).contains("mais de uma vez"));
}

#[test]
fn schema_represents_kernel_clearsigned_and_cmake_detached_sums() {
    let kernel = fields(&[
        ("SIGSUMS", "https://cdn.kernel.org/v7.x/sha256sums.asc"),
        ("SIGSUMS_EPOCH", "1767225721"),
        ("SIGKEY_1", "files/kernel-autosigner.asc"),
        ("SIGKEY_FP_1", "B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"),
    ]);
    let SignaturePlan::OpenPgpChecksums {
        detached_signature_url,
        signature_epoch,
        ..
    } = parse_signature_plan(1, &kernel).unwrap()
    else {
        panic!("plano errado")
    };
    assert_eq!(detached_signature_url, None);
    assert_eq!(signature_epoch, 1_767_225_721);

    let cmake = fields(&[
        ("SIGSUMS", "https://up.invalid/cmake-SHA-256.txt"),
        ("SIGSUMS_SIG", "https://up.invalid/cmake-SHA-256.txt.asc"),
        ("SIGSUMS_EPOCH", "1767225721"),
        ("SIGKEY_1", "files/cmake.asc"),
        ("SIGKEY_FP_1", "C6C265324BBEBDC350B513D02D2CEF1034921684"),
    ]);
    let SignaturePlan::OpenPgpChecksums {
        detached_signature_url,
        ..
    } = parse_signature_plan(1, &cmake).unwrap()
    else {
        panic!("plano errado")
    };
    assert_eq!(
        detached_signature_url.as_deref(),
        Some("https://up.invalid/cmake-SHA-256.txt.asc")
    );
}

#[test]
fn schema_keeps_zig_minisign_and_rejects_holes_mixing_and_missing_keys() {
    let zig = fields(&[
        ("SIG", "https://ziglang.org/zig.tar.xz.minisig"),
        (
            "SIGKEY",
            "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U",
        ),
    ]);
    assert!(matches!(
        parse_signature_plan(1, &zig).unwrap(),
        SignaturePlan::LegacyMinisign { .. }
    ));

    for name in [
        "SIG",
        "SIGKEY",
        "SIGSUMS",
        "SIGSUMS_SIG",
        "SIGSUMS_EPOCH",
        "SIG_1",
        "SIGKEY_1",
        "SIGKEY_FP_1",
        "SIG_EPOCH_1",
    ] {
        let empty = fields(&[(name, "")]);
        assert!(
            parse_signature_plan(1, &empty).is_err(),
            "{name} vazio não pode desligar assinatura"
        );
    }

    let hole = fields(&[
        ("SIG_2", "https://up.invalid/two.sig"),
        ("SIG_EPOCH_2", "1767225721"),
        ("SIGKEY_2", "files/two.asc"),
        ("SIGKEY_FP_2", PRIMARY),
    ]);
    assert!(parse_signature_plan(2, &hole).is_err());

    let extra = fields(&[
        ("SIG_1", "https://up.invalid/one.sig"),
        ("SIG_EPOCH_1", "1767225721"),
        ("SIGKEY_1", "files/one.asc"),
        ("SIGKEY_FP_1", PRIMARY),
        ("SIG_2", "https://up.invalid/two.sig"),
        ("SIG_EPOCH_2", "1767225721"),
        ("SIGKEY_2", "files/two.asc"),
        ("SIGKEY_FP_2", PRIMARY),
    ]);
    assert!(parse_signature_plan(1, &extra).is_err());

    let mixed = fields(&[
        ("SIGSUMS", "https://up.invalid/sums.asc"),
        ("SIG_1", "https://up.invalid/one.sig"),
        ("SIG_EPOCH_1", "1767225721"),
        ("SIGKEY_1", "files/one.asc"),
        ("SIGKEY_FP_1", PRIMARY),
    ]);
    assert!(parse_signature_plan(1, &mixed).is_err());

    // Os 13 casos sem transporte de chave primário continuam bloqueados: uma
    // URL de assinatura e um fingerprint, sozinhos, não formam um plano.
    let unresolved_key = fields(&[
        ("SIG_1", "https://up.invalid/one.sig"),
        ("SIG_EPOCH_1", "1767225721"),
        ("SIGKEY_FP_1", PRIMARY),
    ]);
    assert!(parse_signature_plan(1, &unresolved_key).is_err());

    let no_detached_epoch = fields(&[
        ("SIG_1", "https://up.invalid/one.sig"),
        ("SIGKEY_1", "files/one.asc"),
        ("SIGKEY_FP_1", PRIMARY),
    ]);
    assert!(parse_signature_plan(1, &no_detached_epoch).is_err());
    let no_sums_epoch = fields(&[
        ("SIGSUMS", "https://up.invalid/sums.asc"),
        ("SIGKEY_1", "files/one.asc"),
        ("SIGKEY_FP_1", PRIMARY),
    ]);
    assert!(parse_signature_plan(1, &no_sums_epoch).is_err());
    let noncanonical_epoch = fields(&[
        ("SIG_1", "https://up.invalid/one.sig"),
        ("SIG_EPOCH_1", "01767225721"),
        ("SIGKEY_1", "files/one.asc"),
        ("SIGKEY_FP_1", PRIMARY),
    ]);
    assert!(parse_signature_plan(1, &noncanonical_epoch).is_err());
}

#[test]
fn literal_collector_never_sources_expansion_or_command_substitution() {
    let recipe = format!(
        "NAME=x\n# SIG_1 permanece dado literal.\nSIG_1=https://up.invalid/x.sig\nSIG_EPOCH_1=1767225721\nSIGKEY_1=files/x.asc\nSIGKEY_FP_1={PRIMARY}\nbuild() {{ :; }}\n"
    );
    let collected = collect_literal_openpgp_fields(recipe.as_bytes()).unwrap();
    assert!(matches!(
        parse_signature_plan(1, &collected).unwrap(),
        SignaturePlan::OpenPgpDetached { .. }
    ));

    assert!(collect_literal_openpgp_fields(b"SIG_1=$(curl https://attacker.invalid/x)\n").is_err());
    assert!(collect_literal_openpgp_fields(b"SIG_1=$SRC.sig\n").is_err());
    assert!(collect_literal_openpgp_fields(b"export SIG_1=https://up.invalid/x.sig\n").is_err());
    assert!(collect_literal_openpgp_fields(b" SIG_1=https://up.invalid/x.sig\n").is_err());
    assert!(
        collect_literal_openpgp_fields(b"build() { :; }\nSIG_1=https://up.invalid/x.sig\n")
            .is_err()
    );
    for function in [
        "build () { :; }",
        "function build { :; }",
        "helper() { :; }",
    ] {
        let recipe = format!("{function}\nSIG_1=https://up.invalid/x.sig\n");
        assert!(collect_literal_openpgp_fields(recipe.as_bytes()).is_err());
    }
    assert!(collect_literal_openpgp_fields(
        b"SIG_1=https://up.invalid/a.sig\nSIG_1=https://up.invalid/b.sig\n"
    )
    .is_err());
}

#[test]
fn literal_collector_covers_legacy_sig_names_fail_closed() {
    let legacy = collect_literal_openpgp_fields(
        b"SIG=https://ziglang.org/zig.tar.xz.minisig\nSIGKEY=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U\n",
    )
    .unwrap();
    assert!(matches!(
        parse_signature_plan(1, &legacy).unwrap(),
        SignaturePlan::LegacyMinisign { .. }
    ));

    for recipe in [
        b"SIG=$(curl https://attacker.invalid/x)\n".as_slice(),
        b"SIGKEY=$(cat /tmp/attacker-key)\n".as_slice(),
        b"SIGKEY_FP=$(cat /tmp/attacker-fingerprint)\n".as_slice(),
        b"SIG_UNKNOWN=$(touch /tmp/never)\n".as_slice(),
        b"SIG=https://up.invalid/a.minisig\nSIG=https://up.invalid/b.minisig\n".as_slice(),
        b"SIGKEY=first\nSIGKEY=second\n".as_slice(),
    ] {
        assert!(collect_literal_openpgp_fields(recipe).is_err());
    }

    let plain_fingerprint =
        collect_literal_openpgp_fields(format!("SIGKEY_FP={PRIMARY}\n").as_bytes()).unwrap();
    assert!(parse_signature_plan(1, &plain_fingerprint).is_err());

    let unknown = collect_literal_openpgp_fields(b"SIG_UNKNOWN=literal\n").unwrap();
    assert!(parse_signature_plan(1, &unknown).is_err());
}
