use anyhow::{bail, Context, Result};
use minipax::install::{self, InstallOptions};
use minipax::install_disk::{self, Exigencias};
use minipax::media::{self, MediaFormat, MediaMode, MediaOptions};
use minipax::media_install::{self, MediaInstallOptions};
use minipax::profile::{ProfileOverrides, ResolvedProfile};
use minipax::tui::Terminal;
use std::collections::HashSet;
use std::path::PathBuf;

const USAGE: &str = r#"minipax — o Ministério da Paz

uso:
  minipax install --target DIR --profile DIR [opções]
  minipax install-media --source DIR --target DIR [opções]
  minipax partition --disk DISPOSITIVO [--esp-mib N] [--swap-mib N]
      [--logical-sector N]
  minipax efi-boot --esp DISPOSITIVO [--rotulo TEXTO] [--carregador CAMINHO]
      [--sysfs DIR] [--efivars DIR]
  minipax install-disk --saida ARQ [--sysfs DIR] [--midia DISPOSITIVO]
      [--efi-bytes N] [--esp-mib N] [--raiz-minima-bytes N] [--cfdisk ARQ]
  minipax media build --profile DIR --mode online|offline \
      --format img|iso --boot-efi ARQ --output ARQ [opções]
  minipax lock --profile DIR [opções]

opções de perfil:
  --world ARQ       substitui target.world e torna o perfil custom
  --live-world ARQ  substitui live.world e torna o perfil custom
  --overlay DIR     substitui overlay/ e torna o perfil custom
  --newspeak DIR    árvore de receitas (ou DISTROPICA_NEWSPEAK)
  --cache DIR       cache fechado para instalação/mídia offline

opção de saída da mídia:
  --output ARQ      o diretório pai deve pertencer ao UID efetivo e não ser
                    gravável por grupo/outros (crie-o antes com modo 0700)

opções de install-disk (o instalador de texto da mídia viva):
  --saida ARQ       onde gravar a decisão; precisa não existir
  --sysfs DIR       default: /sys/class/block
  --midia DISP      disco da própria mídia, que nunca é oferecido; repetível
  --efi-bytes N     tamanho do BOOTX64.EFI, para dimensionar a ESP mínima
  --esp-mib N       ESP que a rota automática cria (default: 64)
  --raiz-minima-bytes N  raiz mínima estimada pelo instalador
  --cfdisk ARQ      default: /bin/cfdisk

Sai 0 com a decisão gravada, 2 quando o operador desiste, 1 em erro.

opções de efi-boot (registra o arranque na NVRAM do firmware):
  --esp DISPOSITIVO  partição ESP já instalada, ex.: /dev/sda1
  --rotulo TEXTO     nome da entrada no menu do firmware (default: Distrópica)
  --carregador CAM   caminho DENTRO da ESP, com barra invertida
                     (default: \EFI\BOOT\BOOTX64.EFI)
  --sysfs DIR        default: /sys/class/block
  --efivars DIR      default: /sys/firmware/efi/efivars

O caminho de reserva EFI/BOOT/BOOTX64.EFI continua obrigatório e é gravado
pelo instalador; esta entrada existe porque firmware de disco fixo não é
obrigado a procurar por ele.

opções de instalação:
  --minitrue ARQ    binário minitrue (ou MINITRUE)
  --offline         proíbe rede durante fetch
  --from-source     não aceita binários de canal
  --only-binary     exige canal para todo pacote-fonte
  --resume          permite continuar apenas um target marcado pelo minipax
  --export-boot-efi ARQ  install-media: exporta o EFI do snapshot validado
  --check           install-media: só valida a mídia; não escreve nada

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
        // O instalador de texto. Ele NÃO escreve em disco: decide e grava a
        // decisão num arquivo, e quem apaga continua sendo o caminho auditado.
        "install-disk" => run_install_disk(args),
        "efi-boot" => run_efi_boot(args),
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
    let mut check_only = false;
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
            "--check" => check_only = true,
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
        check_only,
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
    let accepted = ["--mode", "--format", "--boot-efi", "--output", "--minitrue"];
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
            minitrue: text("--minitrue").map(PathBuf::from),
        },
    )
}

/// `minipax efi-boot --esp /dev/sda1`
///
/// Registra a entrada de arranque UEFI na NVRAM. Sai 1 quando não consegue —
/// e o chamador (o `bootstrap/live/init`) trata isso como AVISO, não como
/// falha de instalação: o caminho de reserva já está no disco, e há máquina
/// em que ele basta. Abortar uma instalação inteira por causa da NVRAM seria
/// pior que avisar.
fn run_efi_boot(args: Vec<String>) -> Result<()> {
    let mut esp: Option<PathBuf> = None;
    let mut rotulo = "Distrópica".to_string();
    let mut carregador = "\\EFI\\BOOT\\BOOTX64.EFI".to_string();
    let mut sysfs = PathBuf::from("/sys/class/block");
    let mut efivars = PathBuf::from(minipax::efi_boot::EFIVARS);
    let mut index = 0;
    while index < args.len() {
        let option = args[index].clone();
        match option.as_str() {
            "--esp" => esp = Some(take_value(&args, &mut index, &option)?.into()),
            "--rotulo" => rotulo = take_value(&args, &mut index, &option)?,
            "--carregador" => carregador = take_value(&args, &mut index, &option)?,
            "--sysfs" => sysfs = take_value(&args, &mut index, &option)?.into(),
            "--efivars" => efivars = take_value(&args, &mut index, &option)?.into(),
            other => bail!("opção desconhecida {other:?}"),
        }
        index += 1;
    }
    let esp = esp.ok_or_else(|| anyhow::anyhow!("efi-boot exige --esp"))?;
    // A barra do UEFI é a invertida. Aceitar a normal e converter em silêncio
    // esconderia o erro de quem chama; recusar diz onde consertar.
    if carregador.contains('/') {
        bail!("--carregador usa barra invertida: \\EFI\\BOOT\\BOOTX64.EFI");
    }
    let (disco, numero) = minipax::efi_boot::disco_da_particao(&sysfs, &esp)?;
    let setor = minipax::efi_boot::setor_logico(&sysfs, &disco);
    let alvo = minipax::efi_boot::le_esp(&disco, numero, setor)?;
    let registro = minipax::efi_boot::registra(&efivars, &rotulo, &alvo, &carregador)?;
    // Saída legível por script, no mesmo estilo do `partition`.
    println!("BOOT_ENTRY={}", registro.nome());
    println!("BOOT_ENTRY_REUSED={}", registro.reaproveitada);
    println!("ESP_DISK={}", disco.display());
    println!("ESP_PARTITION={numero}");
    Ok(())
}

/// `minipax partition --disk /dev/sda [--esp-mib 64]`
fn run_partition(args: Vec<String>) -> Result<()> {
    let mut disk: Option<PathBuf> = None;
    let mut esp_mib: u64 = 64;
    // ZERO por default, e o default é deliberado: quem sabe quanta swap fazer é
    // quem conhece a RAM da máquina, e isso é o instalador — que roda NELA e lê
    // o /proc/meminfo. Um número fixo aqui seria chute para toda máquina.
    let mut swap_mib: u64 = 0;
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
            // Zero desliga a swap. É opção e não default porque quem instala
            // numa máquina com muita RAM e disco apertado tem motivo legítimo
            // para não querer uma.
            "--swap-mib" => {
                swap_mib = take_value(&args, &mut index, &option)?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--swap-mib exige número"))?
            }
            other => bail!("opção desconhecida {other:?}"),
        }
        index += 1;
    }
    let disk = disk.ok_or_else(|| anyhow::anyhow!("partition exige --disk"))?;
    let ((esp_first, esp_last), (root_first, root_last), swap) =
        minipax::partition::write_layout(&disk, esp_mib, swap_mib, sector)?;
    // Saída legível por script: o instalador confere os setores que pediu.
    println!("ESP_FIRST_LBA={esp_first}");
    println!("ESP_LAST_LBA={esp_last}");
    println!("ROOT_FIRST_LBA={root_first}");
    println!("ROOT_LAST_LBA={root_last}");
    // A swap SEMPRE sai, mesmo ausente: um script que lê estas linhas precisa
    // distinguir "não pedi" de "pedi e não coube", e uma linha faltando é
    // indistinguível de uma versão antiga do minipax.
    match swap {
        Some((first, last)) => {
            println!("SWAP_FIRST_LBA={first}");
            println!("SWAP_LAST_LBA={last}");
        }
        None => {
            println!("SWAP_FIRST_LBA=");
            println!("SWAP_LAST_LBA=");
        }
    }
    Ok(())
}

/// `minipax install-disk --saida /run/decisao --efi-bytes N --raiz-minima-bytes N`
///
/// O instalador de texto. Ele decide QUAL disco e COMO, grava a decisão e sai;
/// quem apaga é o init, pelo caminho que já era auditado.
///
/// A SAÍDA VAI PARA ARQUIVO, e não para o stdout, porque o stdout aqui é a
/// TELA: a TUI desenha nele. Um comando que escrevesse a decisão em stdout
/// obrigaria quem chama a capturá-lo — e capturar o stdout apagaria a interface
/// do console, deixando o operador diante de uma tela preta esperando teclas.
fn run_install_disk(args: Vec<String>) -> Result<()> {
    let mut saida: Option<PathBuf> = None;
    let mut sysfs = PathBuf::from("/sys/class/block");
    let mut cfdisk = PathBuf::from("/bin/cfdisk");
    let mut midias: Vec<PathBuf> = Vec::new();
    let mut efi_bytes: Option<u64> = None;
    let mut raiz_minima: Option<u64> = None;
    let mut esp_mib: u64 = 64;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].clone();
        let numero = |v: String, quem: &str| -> Result<u64> {
            v.parse()
                .map_err(|_| anyhow::anyhow!("{quem} exige número em bytes"))
        };
        match option.as_str() {
            "--saida" => saida = Some(take_value(&args, &mut index, &option)?.into()),
            "--sysfs" => sysfs = take_value(&args, &mut index, &option)?.into(),
            "--cfdisk" => cfdisk = take_value(&args, &mut index, &option)?.into(),
            // Repetível: uma mídia pode aparecer por mais de um caminho, e
            // oferecer o disco da própria mídia como alvo destruiria a
            // instalação em curso.
            "--midia" => midias.push(take_value(&args, &mut index, &option)?.into()),
            "--efi-bytes" => {
                efi_bytes = Some(numero(
                    take_value(&args, &mut index, &option)?,
                    "--efi-bytes",
                )?)
            }
            "--raiz-minima-bytes" => {
                raiz_minima = Some(numero(
                    take_value(&args, &mut index, &option)?,
                    "--raiz-minima-bytes",
                )?)
            }
            "--esp-mib" => {
                esp_mib = take_value(&args, &mut index, &option)?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--esp-mib exige número"))?
            }
            other => bail!("opção desconhecida {other:?}"),
        }
        index += 1;
    }
    let saida = saida.ok_or_else(|| anyhow::anyhow!("install-disk exige --saida"))?;
    // OS DOIS MÍNIMOS SÃO OBRIGATÓRIOS, e não têm default. Eles são os números
    // que decidem se uma partição serve; um default aqui seria um palpite
    // fingindo ser medição, e envelheceria em silêncio conforme o EFI e o
    // payload crescessem. Quem chama sabe os dois — o init os mede na mídia.
    let exig = Exigencias {
        efi_bytes: efi_bytes
            .ok_or_else(|| anyhow::anyhow!("install-disk exige --efi-bytes (tamanho do EFI)"))?,
        esp_automatica_bytes: esp_mib * 1024 * 1024,
        raiz_minima_bytes: raiz_minima.ok_or_else(|| {
            anyhow::anyhow!("install-disk exige --raiz-minima-bytes (raiz mínima estimada)")
        })?,
    };

    // O terminal vive num escopo próprio para ser LARGADO antes do
    // `process::exit`: o Drop dele é quem devolve o console ao modo normal, e
    // `exit` não roda destrutores. Sair daqui com o console em modo cru deixaria
    // o shell de resgate sem eco, que é justamente onde alguém iria procurar
    // socorro.
    let decisao = {
        let mut term = Terminal::abrir()?;
        install_disk::executar(&mut term, &sysfs, &midias, &exig, &cfdisk)?
    };

    let Some(decisao) = decisao else {
        eprintln!("minipax: instalação cancelada pelo operador");
        std::process::exit(2);
    };
    // create_new: recusa sobrescrever e recusa seguir link. O caminho vem de
    // quem chama, e um link plantado ali faria a decisão ser escrita noutro
    // lugar — em /run, num initramfs, isso é paranoia barata.
    let mut arquivo = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&saida)
        .with_context(|| format!("gravando a decisão em {}", saida.display()))?;
    use std::io::Write as _;
    arquivo
        .write_all(decisao.serializa().as_bytes())
        .with_context(|| format!("gravando a decisão em {}", saida.display()))?;
    arquivo
        .sync_all()
        .with_context(|| format!("sincronizando {}", saida.display()))?;
    Ok(())
}
