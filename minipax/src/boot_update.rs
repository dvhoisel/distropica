//! A atualização do EFI de boot do sistema INSTALADO, com o anterior de
//! reserva (SPEC-0008 §4, SPEC-0011 §6).
//!
//! Até a 0.16 quem escrevia na ESP era só o instalador: o `BOOTX64.EFI` da
//! mídia ia para `EFI/BOOT/` e ficava lá para sempre. O kernel de todo sistema
//! instalado era o da ISO de onde ele nasceu, e a única forma de receber outro
//! era reinstalar — foi o que o beta tester fez para ganhar o driver r600, e
//! era o que faria para receber qualquer correção de segurança do kernel. Numa
//! distro que se declara rolling e edge, o componente mais exposto era o único
//! que não rolava.
//!
//! O desenho é o que a SPEC-0008 já pedia:
//!
//!   EFI/BOOT/BOOTX64.EFI          o atual — também o caminho de reserva que o
//!                                 firmware procura sem NVRAM
//!   EFI/distropica/anterior.efi   o último que arrancou antes dele
//!
//! e duas entradas na NVRAM, "Distrópica" e "Distrópica (anterior)", nessa
//! ordem na `BootOrder`. Kernel novo que não arranca → escolher a anterior no
//! menu do firmware. É a rede que torna aceitável acompanhar o stable mais
//! novo do kernel.org em vez de um LTS.
//!
//! A REGRA QUE NÃO SE QUEBRA: nunca apagar o EFI que está rodando. Quem diz
//! qual está rodando é o firmware, pela `BootCurrent`; quando ela não decide,
//! a string de versão embutida no cabeçalho do bzImage é comparada com a do
//! kernel em execução. Se a máquina arrancou pela reserva porque o atual não
//! arrancava, o atual é substituído e a reserva fica onde está.
//!
//! QUAL ESP. A da entrada "Distrópica" da NVRAM, que é de onde o firmware
//! arranca. Mas há sistema instalado sem ela, e não por defeito: o instalador
//! trata a falha de registrá-la como AVISO, porque o caminho de reserva basta
//! em muita máquina, e toda instalação sem firmware UEFI de verdade (a de
//! aceite, que arranca o kernel direto) termina assim. Recusar esse sistema
//! era deixá-lo para sempre no kernel da ISO de onde nasceu — o defeito que
//! este módulo existe para acabar. Sem a entrada, a ESP é reconhecida pelo
//! conteúdo: a ÚNICA cujo EFI atual ou anterior traz, no cabeçalho, a string
//! de versão do kernel desta sessão. Não é palpite — aquele arquivo é o kernel
//! que está rodando. Nenhuma ou mais de uma, e nada se escreve.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::efi_boot;

/// O atual, relativo à raiz da ESP. É também o caminho de reserva da norma.
pub const ATUAL: &str = "EFI/BOOT/BOOTX64.EFI";
/// O anterior, relativo à raiz da ESP.
pub const ANTERIOR: &str = "EFI/distropica/anterior.efi";
pub const ROTULO_ATUAL: &str = "Distrópica";
pub const ROTULO_ANTERIOR: &str = "Distrópica (anterior)";
pub const CARREGADOR_ATUAL: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
pub const CARREGADOR_ANTERIOR: &str = "\\EFI\\distropica\\anterior.efi";
/// Onde o pacote `distropica-efi` deixa o EFI que deve ser o atual.
pub const EFI_DO_PACOTE: &str = "/opt/distropica-efi/current/BOOTX64.EFI";

/// Qual dos dois EFIs da ESP arrancou esta sessão.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rodando {
    Atual,
    Anterior,
    /// A máquina não disse (sem NVRAM, arranque por mídia, kernel que não
    /// bate com nenhum dos dois). Trata-se como o caso comum — o atual
    /// arrancou —, que é a leitura que preserva o que provavelmente roda.
    Desconhecido,
}

/// O que a rotação fez, para o chamador dizer ao operador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acao {
    /// O atual já é byte a byte o EFI pedido: nada foi escrito.
    JaAtual,
    /// O atual virou o anterior e o novo virou o atual.
    Rotacionou,
    /// A máquina rodava o ANTERIOR (o atual não arrancou, ou alguém escolheu
    /// a reserva): o atual foi trocado e a reserva ficou onde estava.
    TrocouAtual,
}

impl Acao {
    pub fn rotulo(self) -> &'static str {
        match self {
            Acao::JaAtual => "ja-atual",
            Acao::Rotacionou => "rotacionado",
            Acao::TrocouAtual => "atual-trocado",
        }
    }
}

fn sincroniza_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("sincronizando {}", dir.display()))
}

/// Escreve `bytes` num temporário ao lado de `destino`, sincroniza, e só então
/// troca pelo nome final. Queda de energia no meio deixa o nome antigo
/// intacto ou o novo inteiro — nunca um EFI pela metade no caminho que o
/// firmware lê.
fn escreve_trocando(destino: &Path, bytes: &[u8]) -> Result<()> {
    let pai = destino.parent().context("destino sem diretório pai")?;
    fs::create_dir_all(pai).with_context(|| format!("criando {}", pai.display()))?;
    let temporario = pai.join(".distropica-efi.novo");
    let _ = fs::remove_file(&temporario);
    {
        let mut arquivo = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporario)
            .with_context(|| format!("criando {}", temporario.display()))?;
        arquivo
            .write_all(bytes)
            .with_context(|| format!("gravando {}", temporario.display()))?;
        arquivo
            .sync_all()
            .with_context(|| format!("sincronizando {}", temporario.display()))?;
    }
    fs::rename(&temporario, destino).with_context(|| {
        format!(
            "trocando {} por {}",
            destino.display(),
            temporario.display()
        )
    })?;
    sincroniza_dir(pai)
}

/// Bytes livres para usuário comum na ESP montada em `raiz`.
fn livres(raiz: &Path) -> Result<u64> {
    let estado = rustix::fs::statvfs(raiz)
        .with_context(|| format!("medindo o espaço livre de {}", raiz.display()))?;
    Ok(estado.f_bavail.saturating_mul(estado.f_frsize))
}

fn tamanho(caminho: &Path) -> u64 {
    fs::symlink_metadata(caminho).map(|m| m.len()).unwrap_or(0)
}

/// Folga para o FAT: cluster parcial do arquivo novo e as entradas de
/// diretório. 1 MiB cobre com sobra qualquer tamanho de cluster que o FAT32
/// usa numa ESP.
const FOLGA: u64 = 1024 * 1024;

/// Põe `novo` como o EFI atual da ESP montada em `raiz`, guardando o que
/// arrancou como anterior. É a única função que escreve na ESP, e a ordem dos
/// passos é o conteúdo dela:
///
/// 1. confere o espaço ANTES de mexer em qualquer coisa: faltou, nada muda;
/// 2. remove o anterior velho, que não é o que roda (é dois arranques atrás);
/// 3. RENOMEIA o atual para anterior — renomear não copia, então o pico de
///    ocupação é de dois EFIs, que é o que cabe na ESP de 64 MiB;
/// 4. escreve o novo num temporário, sincroniza e troca pelo nome do atual.
///
/// Queda de energia entre 3 e 4 deixa a ESP sem o caminho de reserva, mas com
/// o anterior íntegro e a entrada "Distrópica (anterior)" já registrada, que o
/// firmware tenta em seguida na `BootOrder`.
pub fn rotaciona(raiz: &Path, novo: &[u8], rodando: Rodando) -> Result<Acao> {
    if novo.is_empty() {
        bail!("EFI novo vazio: recusado antes de tocar a ESP");
    }
    let atual = raiz.join(ATUAL);
    let anterior = raiz.join(ANTERIOR);
    let atual_existe = fs::symlink_metadata(&atual)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false);
    if atual_existe
        && fs::read(&atual).with_context(|| format!("lendo {}", atual.display()))? == novo
    {
        return Ok(Acao::JaAtual);
    }

    let novo_len = novo.len() as u64;
    let disponivel = livres(raiz)?;
    if rodando == Rodando::Anterior || !atual_existe {
        // O atual sai por troca de nome sobre ele: o espaço dele só volta
        // depois, então o novo precisa caber inteiro no que já está livre.
        if disponivel < novo_len + FOLGA {
            bail!(
                "a ESP tem {disponivel} bytes livres e o EFI novo precisa de {}; nada foi alterado",
                novo_len + FOLGA
            );
        }
        escreve_trocando(&atual, novo)?;
        return Ok(if atual_existe {
            Acao::TrocouAtual
        } else {
            Acao::Rotacionou
        });
    }

    // Caso comum: o atual é quem roda (ou a máquina não disse). O anterior
    // velho sai e devolve o espaço dele.
    let recuperavel = tamanho(&anterior);
    if disponivel + recuperavel < novo_len + FOLGA {
        bail!(
            "a ESP não comporta o EFI novo ao lado do que roda: {} bytes livres \
             (contando o anterior que sairia) para {} necessários; nada foi alterado",
            disponivel + recuperavel,
            novo_len + FOLGA
        );
    }
    if recuperavel > 0 {
        fs::remove_file(&anterior)
            .with_context(|| format!("removendo o anterior velho {}", anterior.display()))?;
    }
    let pai_anterior = anterior.parent().context("anterior sem pai")?;
    fs::create_dir_all(pai_anterior)
        .with_context(|| format!("criando {}", pai_anterior.display()))?;
    fs::rename(&atual, &anterior)
        .with_context(|| format!("guardando {} como {}", atual.display(), anterior.display()))?;
    sincroniza_dir(pai_anterior)?;
    sincroniza_dir(atual.parent().context("atual sem pai")?)?;
    escreve_trocando(&atual, novo)?;
    Ok(Acao::Rotacionou)
}

/// A string de versão que o setup header do bzImage aponta (`kernel_version`,
/// deslocamento 0x20E): `7.1.8-distropica-live (user@host) #1 SMP ...`. O
/// mesmo texto que o kernel em execução publica em /proc/version, e por isso a
/// segunda testemunha de qual EFI arrancou.
pub fn versao_do_bzimage(efi: &[u8]) -> Option<String> {
    if efi.get(0x202..0x206)? != b"HdrS" {
        return None;
    }
    let ponteiro = u16::from_le_bytes([*efi.get(0x20E)?, *efi.get(0x20F)?]) as usize;
    let inicio = ponteiro.checked_add(0x200)?;
    let resto = efi.get(inicio..)?;
    let fim = resto.iter().position(|b| *b == 0)?;
    String::from_utf8(resto[..fim].to_vec()).ok()
}

/// O miolo comparável: `UTS_RELEASE` e `UTS_VERSION`. O bzImage traz
/// "R (quem@onde) V" e o /proc/version traz "Linux version R (quem@onde)
/// (compilador) V"; o compilador só aparece no segundo.
fn release_e_versao(texto: &str) -> Option<(String, String)> {
    let texto = texto
        .trim()
        .strip_prefix("Linux version ")
        .unwrap_or(texto.trim());
    let release = texto.split_whitespace().next()?.to_string();
    let versao = texto.find('#').map(|i| texto[i..].trim().to_string())?;
    Some((release, versao))
}

/// Decide qual EFI roda. Primeiro o firmware, pela `BootCurrent`; se ela não
/// aponta um dos dois caminhos desta ESP, o kernel em execução contra o
/// cabeçalho de cada arquivo.
pub fn qual_rodando(
    corrente: Option<&efi_boot::OpcaoLida>,
    guid_esp: Option<&[u8; 16]>,
    proc_version: Option<&str>,
    atual: Option<&[u8]>,
    anterior: Option<&[u8]>,
) -> Rodando {
    if let (Some(opcao), Some(guid)) = (corrente, guid_esp) {
        if opcao.guid.as_ref() == Some(guid) {
            // O FAT não distingue caixa, e firmware grava o caminho como bem
            // entende; compara-se sem ela.
            match opcao.arquivo.as_deref().map(str::to_ascii_lowercase) {
                Some(arquivo) if arquivo == CARREGADOR_ANTERIOR.to_ascii_lowercase() => {
                    return Rodando::Anterior
                }
                // Sem nó File() o firmware usou o caminho de reserva, que é
                // o atual.
                None => return Rodando::Atual,
                Some(arquivo) if arquivo == CARREGADOR_ATUAL.to_ascii_lowercase() => {
                    return Rodando::Atual
                }
                _ => {}
            }
        }
    }
    let rodando = proc_version.and_then(release_e_versao);
    let de = |bytes: Option<&[u8]>| {
        bytes
            .and_then(versao_do_bzimage)
            .and_then(|texto| release_e_versao(&texto))
    };
    match (rodando, de(atual), de(anterior)) {
        (Some(r), Some(a), Some(b)) if r == b && r != a => Rodando::Anterior,
        (Some(r), Some(a), _) if r == a => Rodando::Atual,
        _ => Rodando::Desconhecido,
    }
}

/// Registra as duas entradas na NVRAM: primeiro a reserva, depois a atual —
/// o `registra` põe cada uma na frente, então a ordem final é atual,
/// anterior, e o resto da máquina como estava.
pub fn registra_entradas(efivars: &Path, esp: &efi_boot::Esp, tem_anterior: bool) -> Result<()> {
    if tem_anterior {
        efi_boot::registra(efivars, ROTULO_ANTERIOR, esp, CARREGADOR_ANTERIOR)?;
    }
    efi_boot::registra(efivars, ROTULO_ATUAL, esp, CARREGADOR_ATUAL)?;
    Ok(())
}

/// Toda partição do sysfs que o GPT do disco dela diz ser uma ESP, com o nó de
/// dispositivo e a entrada lida.
fn esps(sysfs: &Path, dev: &Path) -> Result<Vec<(PathBuf, efi_boot::Esp)>> {
    let mut entradas: Vec<String> = fs::read_dir(sysfs)
        .with_context(|| format!("listando {}", sysfs.display()))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|nome| sysfs.join(nome).join("partition").is_file())
        .collect();
    entradas.sort();
    let mut saida = Vec::new();
    for nome in entradas {
        let particao = dev.join(&nome);
        let Ok((disco, numero)) = efi_boot::disco_da_particao(sysfs, &particao) else {
            continue;
        };
        let setor = efi_boot::setor_logico(sysfs, &disco);
        if let Ok(esp) = efi_boot::le_esp(&disco, numero, setor) {
            saida.push((particao, esp));
        }
    }
    Ok(saida)
}

/// Acha, entre as partições do sysfs, a ESP cujo GUID único é `guid`. É o GUID
/// que a entrada "Distrópica" da NVRAM carrega — a ESP de onde o firmware de
/// fato arranca, e não a primeira que tiver o rótulo certo: numa rota manual a
/// ESP pode ser a do Windows, com outro rótulo.
pub fn particao_com_guid(
    sysfs: &Path,
    dev: &Path,
    guid: &[u8; 16],
) -> Result<(PathBuf, efi_boot::Esp)> {
    esps(sysfs, dev)?
        .into_iter()
        .find(|(_, esp)| &esp.guid == guid)
        .context("nenhuma partição do sysfs tem o GUID da ESP registrada na NVRAM")
}

/// `efi` traz, no cabeçalho do bzImage, exatamente o kernel `rodando` —
/// release e versão de build, que carrega a data da compilação.
fn traz_o_kernel(rodando: &(String, String), efi: Option<&[u8]>) -> bool {
    efi.and_then(versao_do_bzimage)
        .and_then(|texto| release_e_versao(&texto))
        .as_ref()
        == Some(rodando)
}

/// Das ESPs que trazem o kernel desta sessão, a única. Separada da sondagem
/// para o teste cobrar a decisão sem montar nada.
fn unica_com_o_kernel(
    mut achadas: Vec<(PathBuf, efi_boot::Esp)>,
) -> Result<(PathBuf, efi_boot::Esp)> {
    match achadas.len() {
        1 => Ok(achadas.remove(0)),
        0 => bail!(
            "a NVRAM não tem a entrada \"{ROTULO_ATUAL}\" que diz qual é a ESP, e nenhuma \
             ESP desta máquina traz o EFI do kernel que está rodando; registre-a com \
             `minipax efi-boot --esp <partição>` e repita"
        ),
        _ => bail!(
            "a NVRAM não tem a entrada \"{ROTULO_ATUAL}\", e {} ESPs trazem o EFI do kernel \
             que está rodando ({}) — uma mídia de instalação conectada faz isso; remova-a, \
             ou registre a certa com `minipax efi-boot --esp <partição>`, e repita",
            achadas.len(),
            achadas
                .iter()
                .map(|(particao, _)| particao.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// A ESP reconhecida pelo conteúdo, para o sistema sem a entrada na NVRAM (ver
/// o cabeçalho do módulo). Cada ESP é montada SÓ PARA LEITURA durante a
/// sondagem: uma ESP alheia não ganha nem o bit de sujo do FAT por ter sido
/// olhada.
fn esp_do_kernel(
    sysfs: &Path,
    dev: &Path,
    proc_version: Option<&str>,
) -> Result<(PathBuf, efi_boot::Esp)> {
    let rodando = proc_version.and_then(release_e_versao).context(
        "sem a entrada da NVRAM e sem /proc/version legível, não há como reconhecer a ESP",
    )?;
    let mut achadas = Vec::new();
    for (particao, esp) in esps(sysfs, dev)? {
        let Ok(montagem) = Montagem::abre(&particao, true) else {
            continue;
        };
        let casa = [ATUAL, ANTERIOR].iter().any(|relativo| {
            traz_o_kernel(
                &rodando,
                fs::read(montagem.raiz.join(relativo)).ok().as_deref(),
            )
        });
        drop(montagem);
        if casa {
            achadas.push((particao, esp));
        }
    }
    unica_com_o_kernel(achadas)
}

/// Onde a partição já está montada, se estiver, pelo `maj:min` do
/// /proc/self/mountinfo — nome de dispositivo pode ser link, número não.
fn ja_montada(particao: &Path) -> Option<PathBuf> {
    let rdev = fs::metadata(particao).ok()?.rdev();
    let alvo = format!("{}:{}", rustix::fs::major(rdev), rustix::fs::minor(rdev));
    let texto = fs::read_to_string("/proc/self/mountinfo").ok()?;
    texto.lines().find_map(|linha| {
        let campos: Vec<&str> = linha.split(' ').collect();
        (campos.get(2) == Some(&alvo.as_str()))
            .then(|| {
                campos
                    .get(4)
                    .map(|p| PathBuf::from(p.replace("\\040", " ")))
            })
            .flatten()
    })
}

/// A ESP montada durante a rotação: por nós, num diretório privado, e
/// desmontada ao sair — ou a montagem que já existia, que não é nossa para
/// desfazer.
struct Montagem {
    raiz: PathBuf,
    nossa: bool,
}

impl Montagem {
    fn abre(particao: &Path, somente_leitura: bool) -> Result<Self> {
        if let Some(raiz) = ja_montada(particao) {
            return Ok(Montagem { raiz, nossa: false });
        }
        let raiz = PathBuf::from("/run/minipax-esp");
        fs::create_dir_all(&raiz).with_context(|| format!("criando {}", raiz.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&raiz, fs::Permissions::from_mode(0o700))?;
        let mut flags = rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOEXEC;
        if somente_leitura {
            flags |= rustix::mount::MountFlags::RDONLY;
        }
        rustix::mount::mount(particao, &raiz, "vfat", flags, None::<&std::ffi::CStr>)
            .with_context(|| format!("montando {} em {}", particao.display(), raiz.display()))?;
        Ok(Montagem { raiz, nossa: true })
    }
}

impl Drop for Montagem {
    fn drop(&mut self) {
        if self.nossa {
            let _ = rustix::mount::unmount(&self.raiz, rustix::mount::UnmountFlags::empty());
        }
    }
}

/// O efivarfs montado durante a operação, quando o sistema não o monta — o
/// rcS do base não monta, e no sistema instalado o diretório existe vazio.
/// Diretório com entradas é montagem de alguém (ou o diretório dos testes) e
/// não se toca.
struct Efivars {
    dir: PathBuf,
    nossa: bool,
}

impl Efivars {
    fn abre(dir: &Path) -> Self {
        let vazio = fs::read_dir(dir)
            .map(|mut entradas| entradas.next().is_none())
            .unwrap_or(false);
        let nossa = vazio
            && Path::new("/sys/firmware/efi").is_dir()
            && rustix::mount::mount(
                "efivarfs",
                dir,
                "efivarfs",
                rustix::mount::MountFlags::NOSUID
                    | rustix::mount::MountFlags::NODEV
                    | rustix::mount::MountFlags::NOEXEC,
                None::<&std::ffi::CStr>,
            )
            .is_ok();
        Efivars {
            dir: dir.to_path_buf(),
            nossa,
        }
    }
}

impl Drop for Efivars {
    fn drop(&mut self) {
        if self.nossa {
            let _ = rustix::mount::unmount(&self.dir, rustix::mount::UnmountFlags::empty());
        }
    }
}

/// Opções de `minipax boot-update`.
pub struct Opcoes {
    pub efi: PathBuf,
    pub efivars: PathBuf,
    pub sysfs: PathBuf,
    pub dev: PathBuf,
    /// Opera sobre este diretório como se fosse a ESP montada, sem descobrir
    /// nem montar nada e sem tocar a NVRAM. É o modo dos testes e o de quem
    /// monta a ESP à mão.
    pub esp_dir: Option<PathBuf>,
}

/// O resultado, legível por script.
pub struct Relatorio {
    pub acao: Acao,
    pub rodando: Rodando,
    pub esp: String,
    pub nvram: Option<String>,
}

/// Leva o EFI do pacote `distropica-efi` para a ESP do sistema instalado.
pub fn executa(opcoes: &Opcoes) -> Result<Relatorio> {
    crate::ensure_real_file(&opcoes.efi, "EFI de boot")?;
    let novo = fs::read(&opcoes.efi).with_context(|| format!("lendo {}", opcoes.efi.display()))?;
    let proc_version = fs::read_to_string("/proc/version").ok();

    if let Some(dir) = &opcoes.esp_dir {
        let rodando = qual_rodando(
            None,
            None,
            proc_version.as_deref(),
            fs::read(dir.join(ATUAL)).ok().as_deref(),
            fs::read(dir.join(ANTERIOR)).ok().as_deref(),
        );
        let acao = rotaciona(dir, &novo, rodando)?;
        return Ok(Relatorio {
            acao,
            rodando,
            esp: dir.display().to_string(),
            nvram: None,
        });
    }

    let _efivars = Efivars::abre(&opcoes.efivars);
    // A ESP é a da entrada "Distrópica" da NVRAM: é dela que o firmware
    // arranca. Sem a entrada — ou com uma que não aponta partição desta
    // máquina, ou com a NVRAM ilegível —, nada ali descreve de onde esta
    // sessão arrancou, e a ESP é reconhecida pelo kernel que traz (ver o
    // cabeçalho do módulo). Adivinhar partição para escrever kernel continua
    // sem se fazer.
    let pela_nvram = efi_boot::opcao_com_rotulo(&opcoes.efivars, ROTULO_ATUAL)
        .ok()
        .flatten()
        .and_then(|nossa| nossa.guid)
        .and_then(|guid| particao_com_guid(&opcoes.sysfs, &opcoes.dev, &guid).ok());
    let (particao, esp) = match pela_nvram {
        Some(achada) => achada,
        None => esp_do_kernel(&opcoes.sysfs, &opcoes.dev, proc_version.as_deref())?,
    };
    let guid = esp.guid;
    let montagem = Montagem::abre(&particao, false)?;
    let corrente = efi_boot::opcao_corrente(&opcoes.efivars);
    let rodando = qual_rodando(
        corrente.as_ref(),
        Some(&guid),
        proc_version.as_deref(),
        fs::read(montagem.raiz.join(ATUAL)).ok().as_deref(),
        fs::read(montagem.raiz.join(ANTERIOR)).ok().as_deref(),
    );
    let acao = rotaciona(&montagem.raiz, &novo, rodando)?;
    let tem_anterior = montagem.raiz.join(ANTERIOR).is_file();
    drop(montagem);
    // A NVRAM é conferida mesmo quando nada mudou na ESP: uma entrada de
    // reserva que se perdeu (firmware que zera a NVRAM numa atualização de
    // BIOS) volta aqui. Falhar nela não desfaz a ESP, que está correta.
    let nvram = match registra_entradas(&opcoes.efivars, &esp, tem_anterior) {
        Ok(()) => None,
        Err(erro) => Some(format!("{erro:#}")),
    };
    Ok(Relatorio {
        acao,
        rodando,
        esp: particao.display().to_string(),
        nvram,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esp_de_teste() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn escreve(raiz: &Path, relativo: &str, bytes: &[u8]) {
        let caminho = raiz.join(relativo);
        fs::create_dir_all(caminho.parent().unwrap()).unwrap();
        fs::write(caminho, bytes).unwrap();
    }

    /// Um bzImage mínimo: o cabeçalho "HdrS" e o ponteiro de versão.
    fn bzimage(versao: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        let ponteiro: u16 = 0x100; // aponta para 0x300 no arquivo
        bytes[0x20E..0x210].copy_from_slice(&ponteiro.to_le_bytes());
        bytes[0x300..0x300 + versao.len()].copy_from_slice(versao.as_bytes());
        bytes
    }

    #[test]
    fn rotacao_comum_guarda_o_que_roda_como_anterior() {
        let esp = esp_de_teste();
        escreve(esp.path(), ATUAL, b"efi-2");
        escreve(esp.path(), ANTERIOR, b"efi-1");
        let acao = rotaciona(esp.path(), b"efi-3", Rodando::Atual).unwrap();
        assert_eq!(acao, Acao::Rotacionou);
        assert_eq!(fs::read(esp.path().join(ATUAL)).unwrap(), b"efi-3");
        assert_eq!(fs::read(esp.path().join(ANTERIOR)).unwrap(), b"efi-2");
        // O temporário não fica para trás.
        assert!(!esp.path().join("EFI/BOOT/.distropica-efi.novo").exists());
    }

    #[test]
    fn rodando_a_reserva_so_o_atual_e_trocado() {
        // O atual (efi-2) não arrancou; a máquina subiu pelo anterior
        // (efi-1). A atualização seguinte troca o atual e NÃO toca a reserva,
        // que é o que está rodando.
        let esp = esp_de_teste();
        escreve(esp.path(), ATUAL, b"efi-2");
        escreve(esp.path(), ANTERIOR, b"efi-1");
        let acao = rotaciona(esp.path(), b"efi-3", Rodando::Anterior).unwrap();
        assert_eq!(acao, Acao::TrocouAtual);
        assert_eq!(fs::read(esp.path().join(ATUAL)).unwrap(), b"efi-3");
        assert_eq!(fs::read(esp.path().join(ANTERIOR)).unwrap(), b"efi-1");
    }

    #[test]
    fn mesmo_efi_nao_escreve_nada() {
        let esp = esp_de_teste();
        escreve(esp.path(), ATUAL, b"efi-2");
        escreve(esp.path(), ANTERIOR, b"efi-1");
        let acao = rotaciona(esp.path(), b"efi-2", Rodando::Atual).unwrap();
        assert_eq!(acao, Acao::JaAtual);
        assert_eq!(fs::read(esp.path().join(ANTERIOR)).unwrap(), b"efi-1");
    }

    #[test]
    fn primeira_rotacao_de_uma_instalacao_antiga_cria_a_reserva() {
        // Instalação até a 0.16: só o atual existe, sem EFI/distropica/.
        let esp = esp_de_teste();
        escreve(esp.path(), ATUAL, b"efi-016");
        let acao = rotaciona(esp.path(), b"efi-017", Rodando::Desconhecido).unwrap();
        assert_eq!(acao, Acao::Rotacionou);
        assert_eq!(fs::read(esp.path().join(ANTERIOR)).unwrap(), b"efi-016");
        assert_eq!(fs::read(esp.path().join(ATUAL)).unwrap(), b"efi-017");
    }

    #[test]
    fn efi_vazio_e_recusado_sem_tocar_a_esp() {
        let esp = esp_de_teste();
        escreve(esp.path(), ATUAL, b"efi-2");
        assert!(rotaciona(esp.path(), b"", Rodando::Atual).is_err());
        assert_eq!(fs::read(esp.path().join(ATUAL)).unwrap(), b"efi-2");
    }

    #[test]
    fn versao_do_bzimage_le_o_ponteiro_do_setup_header() {
        let efi = bzimage(
            "7.2.7-distropica-live (d@h) #1 SMP PREEMPT_DYNAMIC Thu Jan  1 00:00:00 UTC 2024",
        );
        assert_eq!(
            versao_do_bzimage(&efi).as_deref(),
            Some("7.2.7-distropica-live (d@h) #1 SMP PREEMPT_DYNAMIC Thu Jan  1 00:00:00 UTC 2024")
        );
        assert_eq!(versao_do_bzimage(b"nao e um bzimage"), None);
    }

    #[test]
    fn bootcurrent_decide_antes_da_versao_do_kernel() {
        let guid = [7u8; 16];
        let reserva = efi_boot::OpcaoLida {
            rotulo: ROTULO_ANTERIOR.into(),
            guid: Some(guid),
            arquivo: Some("\\EFI\\DISTROPICA\\ANTERIOR.EFI".into()),
        };
        assert_eq!(
            qual_rodando(Some(&reserva), Some(&guid), None, None, None),
            Rodando::Anterior
        );
        let padrao = efi_boot::OpcaoLida {
            rotulo: "UEFI OS".into(),
            guid: Some(guid),
            arquivo: None,
        };
        assert_eq!(
            qual_rodando(Some(&padrao), Some(&guid), None, None, None),
            Rodando::Atual
        );
        // Outra ESP: a BootCurrent não fala desta.
        let outra = efi_boot::OpcaoLida {
            rotulo: "Windows".into(),
            guid: Some([9u8; 16]),
            arquivo: Some("\\EFI\\Microsoft\\Boot\\bootmgfw.efi".into()),
        };
        assert_eq!(
            qual_rodando(Some(&outra), Some(&guid), None, None, None),
            Rodando::Desconhecido
        );
    }

    #[test]
    fn sem_bootcurrent_o_kernel_em_execucao_decide() {
        let atual = bzimage("7.2.7-distropica-live (d@h) #1 SMP B");
        let anterior = bzimage("7.1.8-distropica-live (d@h) #1 SMP A");
        let proc =
            "Linux version 7.1.8-distropica-live (d@h) (gcc (GCC) 15.3.0, GNU ld 2.45) #1 SMP A\n";
        assert_eq!(
            qual_rodando(None, None, Some(proc), Some(&atual), Some(&anterior)),
            Rodando::Anterior
        );
        let proc_novo = "Linux version 7.2.7-distropica-live (d@h) (gcc) #1 SMP B\n";
        assert_eq!(
            qual_rodando(None, None, Some(proc_novo), Some(&atual), Some(&anterior)),
            Rodando::Atual
        );
        assert_eq!(
            qual_rodando(
                None,
                None,
                Some("Linux version 6.0 (x) (y) #9 Z"),
                Some(&atual),
                Some(&anterior)
            ),
            Rodando::Desconhecido
        );
    }

    #[test]
    fn sem_nvram_a_esp_e_a_que_traz_o_kernel_desta_sessao() {
        let rodando = release_e_versao(
            "Linux version 7.1.8-distropica-live (d@h) (gcc (GCC) 15.3.0) #1 SMP A\n",
        )
        .unwrap();
        let o_mesmo = bzimage("7.1.8-distropica-live (d@h) #1 SMP A");
        // Mesmo release, outra compilação: a data no #1 é o que distingue.
        let outro_build = bzimage("7.1.8-distropica-live (d@h) #1 SMP B");
        assert!(traz_o_kernel(&rodando, Some(&o_mesmo)));
        assert!(!traz_o_kernel(&rodando, Some(&outro_build)));
        assert!(!traz_o_kernel(&rodando, Some(b"nao e um bzimage")));
        assert!(!traz_o_kernel(&rodando, None));
    }

    #[test]
    fn so_uma_esp_com_o_kernel_e_aceita() {
        let esp = |guid: u8| efi_boot::Esp {
            numero: 1,
            primeiro_lba: 2048,
            setores: 131_072,
            guid: [guid; 16],
        };
        let (particao, achada) =
            unica_com_o_kernel(vec![(PathBuf::from("/dev/vda1"), esp(5))]).unwrap();
        assert_eq!(particao, PathBuf::from("/dev/vda1"));
        assert_eq!(achada.guid, [5u8; 16]);
        let nenhuma = unica_com_o_kernel(Vec::new()).unwrap_err().to_string();
        assert!(nenhuma.contains("minipax efi-boot --esp"), "{nenhuma}");
        // A mídia de instalação ainda conectada traz o mesmo kernel.
        let duas = unica_com_o_kernel(vec![
            (PathBuf::from("/dev/vda1"), esp(5)),
            (PathBuf::from("/dev/sdb1"), esp(6)),
        ])
        .unwrap_err()
        .to_string();
        assert!(duas.contains("/dev/vda1, /dev/sdb1"), "{duas}");
    }

    #[test]
    fn nvram_fica_com_atual_na_frente_e_a_reserva_logo_atras() {
        let efivars = tempfile::tempdir().unwrap();
        // Uma entrada de outro sistema já na máquina.
        let alheia = efi_boot::Esp {
            numero: 1,
            primeiro_lba: 2048,
            setores: 1000,
            guid: [3u8; 16],
        };
        efi_boot::registra(
            efivars.path(),
            "Windows Boot Manager",
            &alheia,
            "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
        )
        .unwrap();
        let nossa = efi_boot::Esp {
            numero: 1,
            primeiro_lba: 2048,
            setores: 131_072,
            guid: [5u8; 16],
        };
        registra_entradas(efivars.path(), &nossa, true).unwrap();
        // Repetir não acumula entradas.
        registra_entradas(efivars.path(), &nossa, true).unwrap();
        let ordem = fs::read(
            efivars
                .path()
                .join(format!("BootOrder-{}", efi_boot::GLOBAL_GUID)),
        )
        .unwrap();
        let numeros: Vec<u16> = ordem[4..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        assert_eq!(
            numeros.len(),
            3,
            "três entradas, sem duplicata: {numeros:?}"
        );
        let rotulo = |n: u16| {
            let bruta = fs::read(
                efivars
                    .path()
                    .join(format!("Boot{n:04X}-{}", efi_boot::GLOBAL_GUID)),
            )
            .unwrap();
            efi_boot::le_opcao(&bruta[4..]).unwrap()
        };
        assert_eq!(rotulo(numeros[0]).rotulo, ROTULO_ATUAL);
        assert_eq!(rotulo(numeros[1]).rotulo, ROTULO_ANTERIOR);
        assert_eq!(
            rotulo(numeros[1]).arquivo.as_deref(),
            Some(CARREGADOR_ANTERIOR)
        );
        assert_eq!(rotulo(numeros[1]).guid, Some([5u8; 16]));
        assert_eq!(rotulo(numeros[2]).rotulo, "Windows Boot Manager");
    }
}
