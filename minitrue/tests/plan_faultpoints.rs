use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

static SERIAL: AtomicU64 = AtomicU64::new(0);

const CHECKPOINTS: &[&str] = &[
    "before_plan_persist",
    "after_plan_persist",
    "before_slice_persist",
    "after_slice_persist",
    "before_record_v4_rename",
    "after_record_v4_rename",
    "after_record_v4_parent_fsync",
    "before_receipt_persist",
    "after_receipt_persist",
    "before_current_rename",
    "after_current_rename",
    "after_current_parent_fsync",
];

fn fixture(label: &str) -> PathBuf {
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "minitrue-plan-fault-{label}-{}-{serial}",
        std::process::id()
    ));
    let tree = root.join("var/lib/minitrue/newspeak");
    let cache = root.join("var/cache/minitrue");
    fs::create_dir_all(tree.join("leaf")).unwrap();
    fs::create_dir_all(tree.join("bundle")).unwrap();
    fs::create_dir_all(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let payload = b"payload factual\n";
    let payload_sha256 = hex::encode(Sha256::digest(payload));
    fs::write(cache.join(&payload_sha256), payload).unwrap();
    fs::write(
        tree.join("leaf/recipe"),
        format!(
            "NAME=leaf\nVERSION=1\nKIND=binary\nLICENSE=MIT\nSRC=https://invalid.example/leaf\nSHA256={payload_sha256}\ninstall_pkg() {{ mkdir -p \"$PREFIX/share\"; cp \"$DL\" \"$PREFIX/share/leaf\"; }}\n"
        ),
    )
    .unwrap();
    fs::write(
        tree.join("bundle/recipe"),
        "NAME=bundle\nVERSION=1\nKIND=meta\nDEPS=leaf\nABOUT='closure factual'\n",
    )
    .unwrap();
    root
}

fn minitrue(root: &Path, command: &str, fault: Option<(&str, &str)>) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_minitrue"));
    process
        .arg("--root")
        .arg(root)
        .arg("--offline")
        .arg(command);
    if command == "rectify" {
        process.arg("bundle");
    }
    if let Some((variable, checkpoint)) = fault {
        process.env(variable, checkpoint);
    }
    process.output().expect("executar minitrue focal")
}

fn assert_retry_contract(variable: &str, checkpoint: &str) {
    let root = fixture(checkpoint);
    let interrupted = minitrue(&root, "rectify", Some((variable, checkpoint)));
    assert!(
        !interrupted.status.success(),
        "{variable}={checkpoint} deveria interromper a publicação"
    );
    if variable == "MINITRUE_PLAN_KILLPOINT" {
        assert_eq!(
            interrupted.status.signal(),
            Some(libc::SIGKILL),
            "killpoint precisa exercitar morte real"
        );
    }

    let committed = matches!(
        checkpoint,
        "after_current_rename" | "after_current_parent_fsync"
    );
    let first_verify = minitrue(&root, "verify", None);
    assert_eq!(
        first_verify.status.success(),
        committed,
        "estado intermediário incorreto em {variable}={checkpoint}: {}",
        String::from_utf8_lossy(&first_verify.stderr)
    );

    // Retry é a recuperação normativa. Objetos content-addressed órfãos são
    // reutilizados, temporários são revertidos e v4 já fechado não é
    // re-promovido; o novo current só aparece depois de todo o world factual.
    let retry = minitrue(&root, "rectify", None);
    assert!(
        retry.status.success(),
        "retry falhou em {variable}={checkpoint}: {}",
        String::from_utf8_lossy(&retry.stderr)
    );
    let final_verify = minitrue(&root, "verify", None);
    assert!(
        final_verify.status.success(),
        "retry não fechou estado global em {variable}={checkpoint}: {}",
        String::from_utf8_lossy(&final_verify.stderr)
    );
    let records = root.join("var/lib/minitrue/records");
    assert!(records.join("leaf/meta").exists());
    assert!(records.join("bundle/meta").exists());
    fs::remove_dir_all(root).unwrap();
}

fn assert_preflight_rejects_before_payload(label: &str, sabotage: impl FnOnce(&Path)) {
    let root = fixture(label);
    sabotage(&root);
    let rejected = minitrue(&root, "rectify", None);
    assert!(
        !rejected.status.success(),
        "preflight deveria recusar {label}"
    );
    assert!(
        !root.join("opt/leaf").exists(),
        "{label}: payload foi escrito antes do preflight"
    );
    assert!(
        !root.join("var/lib/minitrue/records/leaf/meta").exists(),
        "{label}: record foi escrito antes do preflight"
    );
    assert!(
        !root.join("etc/minitrue/world").exists(),
        "{label}: world foi alterado antes do preflight"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn todos_faultpoints_falham_fechado_e_retry_fecha_multi_record() {
    for checkpoint in CHECKPOINTS {
        assert_retry_contract("MINITRUE_PLAN_FAULTPOINT", checkpoint);
    }
}

#[test]
fn todos_killpoints_falham_fechado_e_retry_fecha_multi_record() {
    for checkpoint in CHECKPOINTS {
        assert_retry_contract("MINITRUE_PLAN_KILLPOINT", checkpoint);
    }
}

#[test]
fn preflight_recusa_symlink_tipo_especial_e_colisao_antes_do_payload() {
    assert_preflight_rejects_before_payload("plan-lock-symlink", |root| {
        let state = root.join("var/lib/minitrue");
        fs::create_dir_all(state.join("foreign")).unwrap();
        symlink("foreign", state.join("plan-locks")).unwrap();
    });
    assert_preflight_rejects_before_payload("record-target-symlink", |root| {
        let records = root.join("var/lib/minitrue/records");
        fs::create_dir_all(&records).unwrap();
        symlink("../foreign-record", records.join("leaf")).unwrap();
    });
    assert_preflight_rejects_before_payload("slice-target-symlink", |root| {
        let record = root.join("var/lib/minitrue/records/leaf");
        fs::create_dir_all(&record).unwrap();
        symlink("../foreign-slices", record.join("plan-slices")).unwrap();
    });
    assert_preflight_rejects_before_payload("foreign-lock-collision", |root| {
        let locks = root.join("var/lib/minitrue/plan-locks");
        fs::create_dir_all(&locks).unwrap();
        fs::set_permissions(&locks, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(locks.join("foreign.lock"), b"foreign\n").unwrap();
    });
    assert_preflight_rejects_before_payload("current-symlink", |root| {
        let applied = root.join("var/lib/minitrue/applied-plans");
        fs::create_dir_all(&applied).unwrap();
        fs::set_permissions(&applied, fs::Permissions::from_mode(0o700)).unwrap();
        symlink("missing", applied.join("current")).unwrap();
    });
}

#[test]
fn receipt_enumera_exatamente_records_e_prende_hash_factual() {
    let root = fixture("receipt-exact-records");
    let applied = minitrue(&root, "rectify", None);
    assert!(
        applied.status.success(),
        "fixture não aplicou: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(minitrue(&root, "verify", None).status.success());

    let records = root.join("var/lib/minitrue/records");
    fs::create_dir(records.join("extra")).unwrap();
    assert!(
        !minitrue(&root, "verify", None).status.success(),
        "record extra precisa invalidar o receipt global"
    );
    fs::remove_dir(records.join("extra")).unwrap();

    fs::rename(records.join("bundle"), root.join("bundle.hidden")).unwrap();
    assert!(
        !minitrue(&root, "verify", None).status.success(),
        "record ausente precisa invalidar o receipt global"
    );
    fs::rename(root.join("bundle.hidden"), records.join("bundle")).unwrap();

    let meta = records.join("leaf/meta");
    let original = fs::read(&meta).unwrap();
    let mut tampered = original.clone();
    tampered.extend_from_slice(b"EXTRA_FACT=tamper\n");
    fs::write(&meta, tampered).unwrap();
    assert!(
        !minitrue(&root, "verify", None).status.success(),
        "hash factual divergente precisa invalidar o receipt"
    );
    fs::write(&meta, original).unwrap();
    assert!(minitrue(&root, "verify", None).status.success());
    fs::remove_dir_all(root).unwrap();
}
