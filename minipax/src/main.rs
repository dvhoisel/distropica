use anyhow::{bail, Result};
use minipax::install::{self, InstallOptions};
use minipax::media::{self, MediaFormat, MediaMode, MediaOptions};
use minipax::media_install::{self, MediaInstallOptions};
use minipax::profile::{ProfileOverrides, ResolvedProfile};
use std::collections::HashSet;
use std::path::PathBuf;

const USAGE: &str = r#"minipax — o Ministério da Paz

uso:
  minipax install --target DIR --profile DIR [opções]
  minipax install-media --source DIR --target DIR [opções]
  minipax partition --disk DISPOSITIVO [--esp-mib N] [--logical-sector N]
  minipax media build --profile DIR --mode online|offline \
      --format img|iso --boot-efi ARQ --output ARQ [opções]
  minipax lock --profile DIR [opções]

opções de perfil:
  --world ARQ       substitui target.world e torna o perfil custom
  --live-world ARQ  substitui live.world e torna o perfil custom
  --overlay DIR     substitui overlay/ e torna o perfil custom
  --newspeak DIR    árvore de receitas (ou DISTROPICA_NEWSPEAK)
  --cache DIR       offline: cache fechado; online: config+índice de canal

opções de instalação:
  --minitrue ARQ    binário minitrue (ou MINITRUE)
  --offline         proíbe rede durante fetch
  --from-source     não aceita binários de canal
  --only-binary     exige canal para todo pacote-fonte
  --resume          permite continuar apenas um target marcado pelo minipax
  --export-boot-efi ARQ  install-media: exporta o EFI do snapshot validado

`--target` nunca particiona. A escrita destrutiva em disco pertence ao
instalador da mídia viva e exige alvo resolvido e confirmação explícita."#;

#[derive(Default)]
struct Common {
    profile: Option<PathBuf>,
    overrides: ProfileOverrides,
}

struct ParsedArgs {
    common: Common,
    valued: Vec<(String, String)>,
    flags: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("minipax: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.remove(0);
    match command.as_str() {
        "install" => run_install(args),
        "install-media" => run_install_media(args),
        "media" => {
            if args.first().map(String::as_str) != Some("build") {
                bail!("media exige o subcomando build\n\n{USAGE}");
            }
            args.remove(0);
            run_media(args)
        }
        "lock" => run_lock(args),
        // Particionamento GPT do alvo (SPEC-0008): o caminho destrutivo fica
        // no Rust auditado, não num script guiando o fdisk do busybox.
        "partition" => run_partition(args),
        other => bail!("comando desconhecido {other:?}\n\n{USAGE}"),
    }
}

fn run_install_media(args: Vec<String>) -> Result<()> {
    let mut source = None;
    let mut target = None;
    let mut minitrue = None;
    let mut offline = false;
    let mut from_source = false;
    let mut only_binary = false;
    let mut resume = false;
    let mut export_boot_efi = None;
    let mut seen = HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if !seen.insert(option.to_string()) {
            bail!("opção repetida {option:?}");
        }
        match option {
            "--source" => source = Some(take_value(&args, &mut index, option)?.into()),
            "--target" => target = Some(take_value(&args, &mut index, option)?.into()),
            "--minitrue" => minitrue = Some(take_value(&args, &mut index, option)?.into()),
            "--offline" => offline = true,
            "--from-source" => from_source = true,
            "--only-binary" => only_binary = true,
            "--resume" => resume = true,
            "--export-boot-efi" => {
                export_boot_efi = Some(take_value(&args, &mut index, option)?.into())
            }
            other => bail!("opção desconhecida {other:?}"),
        }
        index += 1;
    }
    let source = source.ok_or_else(|| anyhow::anyhow!("--source é obrigatório"))?;
    let target = target.ok_or_else(|| anyhow::anyhow!("--target é obrigatório"))?;
    let minitrue = minitrue.or_else(|| std::env::var_os("MINITRUE").map(PathBuf::from));
    if from_source && only_binary {
        bail!("--from-source e --only-binary são mutuamente exclusivos");
    }
    media_install::install_media(&MediaInstallOptions {
        source,
        target,
        minitrue,
        offline,
        from_source,
        only_binary,
        resume,
        export_boot_efi,
    })
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{option} exige valor"))
}

fn parse_common(args: &[String], accepted: &[&str]) -> Result<ParsedArgs> {
    let mut common = Common::default();
    let mut valued = Vec::new();
    let mut flags = Vec::new();
    let mut seen = HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if !seen.insert(option.to_string()) {
            bail!("opção repetida {option:?}");
        }
        match option {
            "--profile" => common.profile = Some(take_value(args, &mut index, option)?.into()),
            "--world" => {
                common.overrides.target_world = Some(take_value(args, &mut index, option)?.into())
            }
            "--live-world" => {
                common.overrides.live_world = Some(take_value(args, &mut index, option)?.into())
            }
            "--overlay" => {
                common.overrides.overlay = Some(take_value(args, &mut index, option)?.into())
            }
            "--newspeak" => {
                common.overrides.newspeak = Some(take_value(args, &mut index, option)?.into())
            }
            "--cache" => {
                common.overrides.cache = Some(take_value(args, &mut index, option)?.into())
            }
            value if accepted.contains(&value) => {
                if matches!(
                    value,
                    "--offline" | "--from-source" | "--only-binary" | "--resume"
                ) {
                    flags.push(value.to_string());
                } else {
                    let argument = take_value(args, &mut index, value)?;
                    valued.push((value.to_string(), argument));
                }
            }
            other => bail!("opção desconhecida {other:?}"),
        }
        index += 1;
    }
    Ok(ParsedArgs {
        common,
        valued,
        flags,
    })
}

fn resolve(common: Common) -> Result<ResolvedProfile> {
    let profile = common
        .profile
        .ok_or_else(|| anyhow::anyhow!("--profile é obrigatório"))?;
    ResolvedProfile::load(&profile, common.overrides)
}

fn run_lock(args: Vec<String>) -> Result<()> {
    let ParsedArgs {
        common,
        valued,
        flags,
    } = parse_common(&args, &["--output"])?;
    if !flags.is_empty() {
        bail!("flags inesperadas em lock");
    }
    let profile = resolve(common)?;
    let lock = profile.lock()?;
    if let Some((_, output)) = valued.into_iter().find(|(name, _)| name == "--output") {
        minipax::profile::write_new(PathBuf::from(output).as_path(), lock.as_bytes())?;
    } else {
        print!("{lock}");
    }
    Ok(())
}

fn run_install(args: Vec<String>) -> Result<()> {
    let accepted = [
        "--target",
        "--minitrue",
        "--offline",
        "--from-source",
        "--only-binary",
        "--resume",
    ];
    let ParsedArgs {
        common,
        valued,
        flags,
    } = parse_common(&args, &accepted)?;
    let profile = resolve(common)?;
    let value = |name: &str| {
        valued
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| PathBuf::from(value))
    };
    let target = value("--target").ok_or_else(|| anyhow::anyhow!("--target é obrigatório"))?;
    let minitrue = value("--minitrue").or_else(|| std::env::var_os("MINITRUE").map(PathBuf::from));
    let from_source = flags.iter().any(|flag| flag == "--from-source");
    let only_binary = flags.iter().any(|flag| flag == "--only-binary");
    if from_source && only_binary {
        bail!("--from-source e --only-binary são mutuamente exclusivos");
    }
    install::install(
        &profile,
        &InstallOptions {
            target,
            minitrue,
            offline: flags.iter().any(|flag| flag == "--offline"),
            from_source,
            only_binary,
            resume: flags.iter().any(|flag| flag == "--resume"),
        },
    )
}

fn run_media(args: Vec<String>) -> Result<()> {
    let accepted = ["--mode", "--format", "--boot-efi", "--output"];
    let ParsedArgs {
        common,
        valued,
        flags,
    } = parse_common(&args, &accepted)?;
    if !flags.is_empty() {
        bail!("flags inesperadas em media build");
    }
    let profile = resolve(common)?;
    let text = |name: &str| {
        valued
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let mode = text("--mode")
        .ok_or_else(|| anyhow::anyhow!("--mode é obrigatório"))?
        .parse::<MediaMode>()?;
    let format = text("--format")
        .ok_or_else(|| anyhow::anyhow!("--format é obrigatório"))?
        .parse::<MediaFormat>()?;
    let boot_efi = text("--boot-efi")
        .ok_or_else(|| anyhow::anyhow!("--boot-efi é obrigatório"))?
        .into();
    let output = text("--output")
        .ok_or_else(|| anyhow::anyhow!("--output é obrigatório"))?
        .into();
    media::build(
        &profile,
        &MediaOptions {
            mode,
            format,
            boot_efi,
            output,
        },
    )
}

/// `minipax partition --disk /dev/sda [--esp-mib 64]`
fn run_partition(args: Vec<String>) -> Result<()> {
    let mut disk: Option<PathBuf> = None;
    let mut esp_mib: u64 = 64;
    let mut sector: u64 = minipax::partition::DEFAULT_SECTOR;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].clone();
        match option.as_str() {
            "--disk" => disk = Some(take_value(&args, &mut index, &option)?.into()),
            "--esp-mib" => {
                esp_mib = take_value(&args, &mut index, &option)?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--esp-mib exige número"))?
            }
            // O chamador conhece o setor lógico do disco (sysfs); presumir 512
            // num 4Kn escreveria a tabela no endereço errado.
            "--logical-sector" => {
                sector = take_value(&args, &mut index, &option)?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--logical-sector exige número"))?
            }
            other => bail!("opção desconhecida {other:?}"),
        }
        index += 1;
    }
    let disk = disk.ok_or_else(|| anyhow::anyhow!("partition exige --disk"))?;
    let ((esp_first, esp_last), (root_first, root_last)) =
        minipax::partition::write_layout(&disk, esp_mib, sector)?;
    // Saída legível por script: o instalador confere os setores que pediu.
    println!("ESP_FIRST_LBA={esp_first}");
    println!("ESP_LAST_LBA={esp_last}");
    println!("ROOT_FIRST_LBA={root_first}");
    println!("ROOT_LAST_LBA={root_last}");
    Ok(())
}
