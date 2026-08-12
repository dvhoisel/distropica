use std::process::{Command, Output};

fn minitrue(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_minitrue"))
        .args(args)
        .output()
        .expect("executar o minitrue construído pelo próprio cargo test")
}

#[cfg(not(feature = "tofu-authoring"))]
#[test]
fn build_distribuivel_nao_expoe_nem_aceita_tofu() {
    let help = minitrue(&["--help"]);
    assert!(help.status.success());
    assert!(!String::from_utf8_lossy(&help.stdout).contains("--tofu"));

    // `--help` depois da opção impediria um falso positivo em que o parser
    // tratasse a flag desconhecida como comando e terminasse com sucesso.
    let rejected = minitrue(&["--tofu", "--help"]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("opção desconhecida"));
}

#[cfg(feature = "tofu-authoring")]
#[test]
fn build_de_autoria_expoe_e_aceita_tofu_explicitamente() {
    let help = minitrue(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--tofu"));

    let accepted = minitrue(&["--tofu", "--help"]);
    assert!(accepted.status.success());
    assert!(String::from_utf8_lossy(&accepted.stdout).contains("--tofu"));
}
