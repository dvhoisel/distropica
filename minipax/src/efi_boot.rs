//! Registro da entrada de arranque UEFI na NVRAM do firmware.
//!
//! O instalador gravava o carregador SÓ no caminho de reserva,
//! `\EFI\BOOT\BOOTX64.EFI`. A norma UEFI obriga o firmware a procurar esse
//! caminho em mídia REMOVÍVEL; em disco fixo ele é opcional, e firmware da
//! era CSM costuma não procurar. O resultado, medido em máquina real: a
//! instalação termina dizendo que deu certo, e no reboot o firmware esgota a
//! lista de arranque, cai na ROM de PXE legada e imprime "Reboot and Select
//! proper Boot device". Nada no disco está errado — ESP com o GUID de tipo
//! certo, FAT32, carregador conferido por sha256. O que falta é o firmware
//! SABER que ele existe.
//!
//! Quem resolve isso é uma variável `Boot####` na NVRAM, mais o número dela
//! na `BootOrder`. Aqui isso é escrito direto no `efivarfs`, sem `efibootmgr`
//! e sem receita nova: é o mesmo princípio que fez o particionamento GPT sair
//! do `fdisk` do BusyBox para dentro do Rust auditado.
//!
//! O caminho de reserva CONTINUA sendo gravado. Não é redundância inútil: é o
//! que faz a instalação arrancar em firmware que perdeu a NVRAM, e é o único
//! caminho quando a máquina não expõe serviços de runtime.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` — EFI_GLOBAL_VARIABLE, o namespace
/// onde moram `Boot####` e `BootOrder`. No efivarfs ele é o sufixo do nome do
/// arquivo, em minúsculas e na forma textual canônica.
pub const GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS. Sem NON_VOLATILE a
/// variável não sobrevive ao desligamento, que é exatamente o que se quer
/// evitar; sem RUNTIME_ACCESS o sistema instalado não conseguiria relê-la.
const ATRIBUTOS: u32 = 0x0000_0007;

/// LOAD_OPTION_ACTIVE. Sem este bit o firmware guarda a entrada e não a usa.
const OPCAO_ATIVA: u32 = 0x0000_0001;

/// Diretório do efivarfs em sistema vivo.
pub const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// Onde a ESP mora, na forma que o device path do UEFI exige.
///
/// O firmware não acha a partição por nome de dispositivo — `/dev/sda1` não
/// existe para ele. Ele casa pelo trio (número, extensão em LBA, GUID único
/// da partição), que é o que o nó HD() do device path carrega.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Esp {
    pub numero: u32,
    pub primeiro_lba: u64,
    pub setores: u64,
    /// GUID ÚNICO da partição, nos bytes exatos em que o GPT o guarda. Não é
    /// o GUID de TIPO: dois discos com ESP têm o mesmo tipo e GUIDs únicos
    /// diferentes, e é o único que identifica esta partição.
    pub guid: [u8; 16],
}

/// `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` — EFI System Partition.
const TIPO_ESP: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

fn u32_em(buffer: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buffer[at..at + 4].try_into().expect("fatia de 4"))
}

fn u64_em(buffer: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(buffer[at..at + 8].try_into().expect("fatia de 8"))
}

/// Lê do GPT de `disco` a entrada `numero` (1-based) e confere que é uma ESP.
///
/// Ler em vez de receber por parâmetro é deliberado. Na rota automática o
/// próprio Minipax escreveu a tabela e saberia os números de cor; na rota
/// manual a ESP é pré-existente, escolhida pelo operador, e a única fonte
/// verdadeira dos LBAs e do GUID é o disco. Um caminho só, alimentado pelo
/// disco, não tem como divergir do outro.
pub fn le_esp(disco: &Path, numero: u32, setor: u64) -> Result<Esp> {
    if numero == 0 {
        bail!("número de partição começa em 1");
    }
    let mut file = fs::File::open(disco)
        .with_context(|| format!("abrindo {} para ler o GPT", disco.display()))?;

    let mut cabecalho = vec![0u8; setor as usize];
    file.seek(SeekFrom::Start(setor))
        .context("posicionando no cabeçalho GPT (LBA 1)")?;
    file.read_exact(&mut cabecalho)
        .context("lendo o cabeçalho GPT (LBA 1)")?;
    if &cabecalho[..8] != b"EFI PART" {
        bail!(
            "{} não tem GPT primário — assinatura ausente em LBA 1",
            disco.display()
        );
    }

    let entries_lba = u64_em(&cabecalho, 72);
    let quantidade = u32_em(&cabecalho, 80);
    let tamanho_entrada = u32_em(&cabecalho, 84);
    if numero > quantidade {
        bail!("o GPT tem {quantidade} entradas; a partição {numero} não existe");
    }
    // Uma entrada menor que 128 bytes não comporta os campos que este código
    // lê. O GPT permite tamanhos maiores, nunca menores.
    if tamanho_entrada < 128 {
        bail!("entrada de GPT com {tamanho_entrada} bytes — abaixo dos 128 da norma");
    }

    let deslocamento = entries_lba
        .checked_mul(setor)
        .and_then(|base| base.checked_add(u64::from(numero - 1) * u64::from(tamanho_entrada)))
        .context("deslocamento da entrada GPT estourou")?;
    let mut entrada = vec![0u8; tamanho_entrada as usize];
    file.seek(SeekFrom::Start(deslocamento))
        .context("posicionando na entrada da partição")?;
    file.read_exact(&mut entrada)
        .context("lendo a entrada da partição")?;

    if entrada[..16] != TIPO_ESP {
        bail!(
            "a partição {numero} de {} não é uma ESP (GUID de tipo diverge)",
            disco.display()
        );
    }
    let primeiro = u64_em(&entrada, 32);
    let ultimo = u64_em(&entrada, 40);
    if primeiro == 0 || ultimo < primeiro {
        bail!("a partição {numero} tem extensão inválida no GPT");
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&entrada[16..32]);
    if guid == [0u8; 16] {
        bail!("a partição {numero} está com GUID único zerado");
    }

    Ok(Esp {
        numero,
        primeiro_lba: primeiro,
        setores: ultimo - primeiro + 1,
        guid,
    })
}

/// Monta o device path que aponta para `carregador` dentro de `esp`.
///
/// São três nós encadeados, na ordem que a norma exige: HD() com a partição,
/// File() com o caminho dentro dela, e o nó de fim. O caminho vai em UCS-2
/// com barra INVERTIDA — o UEFI não fala barra normal, e um caminho com a
/// barra errada produz uma entrada que o firmware aceita e não arranca.
pub fn device_path(esp: &Esp, carregador: &str) -> Vec<u8> {
    let mut saida = Vec::new();

    // Nó HD(): tipo 4 (Media), subtipo 1 (Hard Drive), 42 bytes fixos.
    saida.push(0x04);
    saida.push(0x01);
    saida.extend_from_slice(&42u16.to_le_bytes());
    saida.extend_from_slice(&esp.numero.to_le_bytes());
    saida.extend_from_slice(&esp.primeiro_lba.to_le_bytes());
    saida.extend_from_slice(&esp.setores.to_le_bytes());
    saida.extend_from_slice(&esp.guid);
    saida.push(0x02); // MBRType: GPT
    saida.push(0x02); // SignatureType: GUID

    // Nó File(): tipo 4, subtipo 4, cabeçalho de 4 bytes mais o caminho em
    // UCS-2 terminado em zero.
    let mut caminho: Vec<u8> = Vec::new();
    for unidade in carregador.encode_utf16() {
        caminho.extend_from_slice(&unidade.to_le_bytes());
    }
    caminho.extend_from_slice(&0u16.to_le_bytes());
    let tamanho = u16::try_from(4 + caminho.len()).expect("caminho de carregador cabe em u16");
    saida.push(0x04);
    saida.push(0x04);
    saida.extend_from_slice(&tamanho.to_le_bytes());
    saida.extend_from_slice(&caminho);

    // Nó de fim da lista inteira.
    saida.push(0x7f);
    saida.push(0xff);
    saida.extend_from_slice(&4u16.to_le_bytes());

    saida
}

/// Monta o `EFI_LOAD_OPTION` inteiro, que é o conteúdo de uma `Boot####`.
pub fn load_option(rotulo: &str, esp: &Esp, carregador: &str) -> Vec<u8> {
    let caminho = device_path(esp, carregador);
    let mut saida = Vec::new();
    saida.extend_from_slice(&OPCAO_ATIVA.to_le_bytes());
    saida.extend_from_slice(
        &u16::try_from(caminho.len())
            .expect("device path cabe em u16")
            .to_le_bytes(),
    );
    for unidade in rotulo.encode_utf16() {
        saida.extend_from_slice(&unidade.to_le_bytes());
    }
    saida.extend_from_slice(&0u16.to_le_bytes());
    saida.extend_from_slice(&caminho);
    saida
}

/// Lê o rótulo de um `EFI_LOAD_OPTION`, para reconhecer uma entrada nossa de
/// instalação anterior em vez de acumular uma nova a cada reinstalação.
///
/// Recebe a opção NUA, sem o prefixo de atributos do efivarfs. São dois
/// campos de "atributos" diferentes em jogo — os 4 bytes que o efivarfs põe
/// na frente do arquivo e os 4 bytes do próprio EFI_LOAD_OPTION —, e
/// confundi-los faz o rótulo ser lido dois bytes fora do lugar, que foi
/// exatamente o defeito que o teste de reinstalação pegou.
fn rotulo_de(opcao: &[u8]) -> Option<String> {
    // 4 de atributos da opção + 2 de comprimento do device path, e daí em
    // diante o rótulo em UCS-2.
    let dados = opcao;
    if dados.len() < 6 {
        return None;
    }
    let mut unidades = Vec::new();
    let mut i = 6;
    while i + 1 < dados.len() {
        let unidade = u16::from_le_bytes([dados[i], dados[i + 1]]);
        if unidade == 0 {
            return String::from_utf16(&unidades).ok();
        }
        unidades.push(unidade);
        i += 2;
    }
    None
}

fn nome_variavel(nome: &str) -> String {
    format!("{nome}-{GLOBAL_GUID}")
}

/// Escreve uma variável no efivarfs.
///
/// Dois detalhes que não são opcionais. Primeiro, atributos e dados vão numa
/// ÚNICA chamada de escrita: o efivarfs interpreta cada write como uma
/// variável completa, e dois writes produzem lixo. Segundo, variável que já
/// existe vem com o atributo de imutável ligado, e sobrescrevê-la exige
/// desligá-lo antes — é isso que o `efibootmgr` faz, e é por isso que uma
/// escrita ingênua falha com EPERM em máquina real.
fn escreve_variavel(dir: &Path, nome: &str, dados: &[u8]) -> Result<()> {
    use rustix::fs::{ioctl_getflags, ioctl_setflags, IFlags};

    let caminho = dir.join(nome_variavel(nome));
    let mut conteudo = Vec::with_capacity(4 + dados.len());
    conteudo.extend_from_slice(&ATRIBUTOS.to_le_bytes());
    conteudo.extend_from_slice(dados);

    if caminho.exists() {
        // Só mexe na flag se ela estiver ligada: num diretório comum (teste,
        // ou efivarfs de kernel que não a use) o ioctl não se aplica e o
        // erro dele não é motivo para abortar.
        if let Ok(file) = fs::OpenOptions::new().read(true).open(&caminho) {
            if let Ok(flags) = ioctl_getflags(&file) {
                if flags.contains(IFlags::IMMUTABLE) {
                    ioctl_setflags(&file, flags & !IFlags::IMMUTABLE).with_context(|| {
                        format!("removendo o imutável de {}", caminho.display())
                    })?;
                }
            }
        }
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&caminho)
        .with_context(|| format!("abrindo {} para escrita", caminho.display()))?;
    file.write_all(&conteudo)
        .with_context(|| format!("gravando {}", caminho.display()))?;
    Ok(())
}

fn le_variavel(dir: &Path, nome: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(nome_variavel(nome))).ok()
}

/// Números `Boot####` já ocupados no efivarfs.
fn ocupados(dir: &Path) -> Result<Vec<u16>> {
    let mut saida = Vec::new();
    let sufixo = format!("-{GLOBAL_GUID}");
    for entrada in fs::read_dir(dir)
        .with_context(|| format!("listando {}", dir.display()))?
        .flatten()
    {
        let nome = entrada.file_name().to_string_lossy().to_string();
        let Some(base) = nome.strip_suffix(&sufixo) else {
            continue;
        };
        let Some(hexa) = base.strip_prefix("Boot") else {
            continue;
        };
        if hexa.len() == 4 {
            if let Ok(numero) = u16::from_str_radix(hexa, 16) {
                saida.push(numero);
            }
        }
    }
    saida.sort_unstable();
    Ok(saida)
}

/// Resultado do registro, para que o chamador diga ao operador o que houve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registro {
    pub numero: u16,
    /// Verdadeiro quando reaproveitou a entrada de uma instalação anterior
    /// com o mesmo rótulo, em vez de criar mais uma.
    pub reaproveitada: bool,
}

impl Registro {
    pub fn nome(&self) -> String {
        format!("Boot{:04X}", self.numero)
    }
}

/// Registra a entrada e a põe em primeiro lugar na `BootOrder`.
///
/// Reaproveita a entrada de mesmo rótulo quando existe: reinstalar dez vezes
/// não pode deixar dez entradas na NVRAM, que em firmware antigo é um recurso
/// pequeno e sem coleta de lixo.
pub fn registra(efivars: &Path, rotulo: &str, esp: &Esp, carregador: &str) -> Result<Registro> {
    if !efivars.is_dir() {
        bail!(
            "{} não existe — a máquina não expõe variáveis UEFI",
            efivars.display()
        );
    }
    let opcao = load_option(rotulo, esp, carregador);
    let ja_usados = ocupados(efivars)?;

    let mut escolhido = None;
    let mut reaproveitada = false;
    for numero in &ja_usados {
        let nome = format!("Boot{numero:04X}");
        if let Some(atual) = le_variavel(efivars, &nome) {
            // O arquivo do efivarfs é [atributos da variável][EFI_LOAD_OPTION].
            let nua = atual.get(4..).unwrap_or(&[]);
            if rotulo_de(nua).as_deref() == Some(rotulo) {
                escolhido = Some(*numero);
                reaproveitada = true;
                break;
            }
        }
    }
    let numero = match escolhido {
        Some(numero) => numero,
        None => (0u16..=0xffff)
            .find(|candidato| !ja_usados.contains(candidato))
            .context("a NVRAM não tem nenhum número Boot#### livre")?,
    };

    escreve_variavel(efivars, &format!("Boot{numero:04X}"), &opcao)?;

    // BootOrder: o nosso número na frente, o resto preservado na ordem em que
    // estava. Substituir a lista inteira apagaria o arranque de outro sistema
    // instalado, que é dano que o instalador não tem direito de causar.
    let mut ordem: Vec<u16> = Vec::new();
    ordem.push(numero);
    if let Some(atual) = le_variavel(efivars, "BootOrder") {
        // Os 4 primeiros bytes são os atributos, não dados.
        let corpo = atual.get(4..).unwrap_or(&[]);
        for par in corpo.chunks_exact(2) {
            let existente = u16::from_le_bytes([par[0], par[1]]);
            if existente != numero {
                ordem.push(existente);
            }
        }
    }
    let mut bytes = Vec::with_capacity(ordem.len() * 2);
    for valor in &ordem {
        bytes.extend_from_slice(&valor.to_le_bytes());
    }
    escreve_variavel(efivars, "BootOrder", &bytes)?;

    Ok(Registro {
        numero,
        reaproveitada,
    })
}

/// Descobre o disco e o número da partição a partir do nó de dispositivo dela,
/// pelo sysfs. `/dev/sda1` → (`/dev/sda`, 1); `/dev/nvme0n1p2` →
/// (`/dev/nvme0n1`, 2). Fazer isso por sysfs e não por regra de sufixo evita
/// a armadilha do `nvme0n1` versus `nvme0n1p1`, em que cortar dígitos do fim
/// produz um nome de disco que existe e é o errado.
pub fn disco_da_particao(sysfs: &Path, particao: &Path) -> Result<(PathBuf, u32)> {
    let nome = particao
        .file_name()
        .context("caminho de partição sem nome de arquivo")?
        .to_string_lossy()
        .to_string();
    let base = sysfs.join(&nome);
    let numero: u32 = fs::read_to_string(base.join("partition"))
        .with_context(|| format!("{nome} não é uma partição segundo o sysfs"))?
        .trim()
        .parse()
        .with_context(|| format!("número de partição ilegível para {nome}"))?;
    // O link do sysfs aponta o pai; o nome dele é o do disco inteiro.
    let pai = fs::canonicalize(base.join(".."))
        .with_context(|| format!("resolvendo o disco de {nome}"))?;
    let disco = pai
        .file_name()
        .context("disco sem nome no sysfs")?
        .to_string_lossy()
        .to_string();
    let pasta = particao.parent().unwrap_or_else(|| Path::new("/dev"));
    Ok((pasta.join(disco), numero))
}

/// Setor lógico do disco, lido do sysfs. Presumir 512 num 4Kn produziria LBAs
/// errados no device path — a entrada seria gravada e não arrancaria.
pub fn setor_logico(sysfs: &Path, disco: &Path) -> u64 {
    let nome = match disco.file_name() {
        Some(nome) => nome.to_string_lossy().to_string(),
        None => return crate::partition::DEFAULT_SECTOR,
    };
    fs::read_to_string(sysfs.join(nome).join("queue/logical_block_size"))
        .ok()
        .and_then(|texto| texto.trim().parse().ok())
        .filter(|valor| *valor > 0)
        .unwrap_or(crate::partition::DEFAULT_SECTOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esp_exemplo() -> Esp {
        Esp {
            numero: 1,
            primeiro_lba: 2048,
            setores: 131_072,
            guid: [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00,
            ],
        }
    }

    #[test]
    fn device_path_tem_os_tres_nos_na_ordem_da_norma() {
        let raw = device_path(&esp_exemplo(), "\\EFI\\BOOT\\BOOTX64.EFI");

        // HD(): 42 bytes, tipo 4 subtipo 1.
        assert_eq!(&raw[0..2], &[0x04, 0x01]);
        assert_eq!(u16::from_le_bytes([raw[2], raw[3]]), 42);
        assert_eq!(u32_em(&raw, 4), 1, "número da partição");
        assert_eq!(u64_em(&raw, 8), 2048, "primeiro LBA");
        assert_eq!(u64_em(&raw, 16), 131_072, "extensão em LBA");
        assert_eq!(&raw[24..40], &esp_exemplo().guid, "GUID único");
        assert_eq!(raw[40], 0x02, "MBRType precisa dizer GPT");
        assert_eq!(raw[41], 0x02, "SignatureType precisa dizer GUID");

        // File(): tipo 4 subtipo 4, caminho em UCS-2 terminado em zero.
        assert_eq!(&raw[42..44], &[0x04, 0x04]);
        let tamanho = u16::from_le_bytes([raw[44], raw[45]]) as usize;
        let texto: Vec<u16> = raw[46..42 + tamanho]
            .chunks_exact(2)
            .map(|par| u16::from_le_bytes([par[0], par[1]]))
            .collect();
        assert_eq!(texto.last(), Some(&0), "caminho sem terminador");
        assert_eq!(
            String::from_utf16(&texto[..texto.len() - 1]).unwrap(),
            "\\EFI\\BOOT\\BOOTX64.EFI"
        );

        // Fim da lista.
        let fim = 42 + tamanho;
        assert_eq!(&raw[fim..fim + 2], &[0x7f, 0xff]);
        assert_eq!(u16::from_le_bytes([raw[fim + 2], raw[fim + 3]]), 4);
        assert_eq!(raw.len(), fim + 4, "sobrou byte depois do nó de fim");
    }

    #[test]
    fn load_option_declara_o_tamanho_certo_do_device_path() {
        let esp = esp_exemplo();
        let raw = load_option("Distrópica", &esp, "\\EFI\\BOOT\\BOOTX64.EFI");
        assert_eq!(u32_em(&raw, 0), OPCAO_ATIVA, "entrada precisa nascer ativa");
        let declarado = u16::from_le_bytes([raw[4], raw[5]]) as usize;
        let caminho = device_path(&esp, "\\EFI\\BOOT\\BOOTX64.EFI");
        assert_eq!(declarado, caminho.len());
        // O device path é o RABO da estrutura: comprimento declarado tem de
        // casar com o que sobra depois do rótulo.
        assert_eq!(&raw[raw.len() - declarado..], &caminho[..]);
        assert_eq!(rotulo_de(&raw).as_deref(), Some("Distrópica"));
    }

    #[test]
    fn registra_cria_a_entrada_e_poe_na_frente_da_ordem() {
        let dir = tempfile::tempdir().unwrap();
        // Um firmware com outro sistema já instalado: Boot0000 é dele.
        fs::write(
            dir.path().join(nome_variavel("Boot0000")),
            [&ATRIBUTOS.to_le_bytes()[..], b"outro"].concat(),
        )
        .unwrap();
        fs::write(
            dir.path().join(nome_variavel("BootOrder")),
            [&ATRIBUTOS.to_le_bytes()[..], &0u16.to_le_bytes()[..]].concat(),
        )
        .unwrap();

        let registro = registra(
            dir.path(),
            "Distrópica",
            &esp_exemplo(),
            "\\EFI\\BOOT\\BOOTX64.EFI",
        )
        .unwrap();
        assert_eq!(registro.numero, 1, "devia ocupar o primeiro número livre");
        assert!(!registro.reaproveitada);

        let ordem = fs::read(dir.path().join(nome_variavel("BootOrder"))).unwrap();
        assert_eq!(u32_em(&ordem, 0), ATRIBUTOS);
        let numeros: Vec<u16> = ordem[4..]
            .chunks_exact(2)
            .map(|par| u16::from_le_bytes([par[0], par[1]]))
            .collect();
        assert_eq!(numeros, vec![1, 0], "o nosso na frente, o alheio preservado");
    }

    #[test]
    fn reinstalar_reaproveita_a_entrada_em_vez_de_acumular() {
        let dir = tempfile::tempdir().unwrap();
        let primeiro = registra(
            dir.path(),
            "Distrópica",
            &esp_exemplo(),
            "\\EFI\\BOOT\\BOOTX64.EFI",
        )
        .unwrap();
        let segundo = registra(
            dir.path(),
            "Distrópica",
            &esp_exemplo(),
            "\\EFI\\BOOT\\BOOTX64.EFI",
        )
        .unwrap();
        assert_eq!(primeiro.numero, segundo.numero);
        assert!(segundo.reaproveitada);
        assert_eq!(ocupados(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn le_esp_recusa_partição_que_não_é_esp() {
        let dir = tempfile::tempdir().unwrap();
        let disco = dir.path().join("disco.img");
        // O write_layout exige ESP que comporte um BOOTX64.EFI e ainda 64 MiB
        // de raiz; 192 MiB esparsos cobrem os dois com folga.
        fs::File::create(&disco)
            .unwrap()
            .set_len(192 * 1024 * 1024)
            .unwrap();
        crate::partition::write_layout(&disco, 64, 0, 512).unwrap();

        let esp = le_esp(&disco, 1, 512).unwrap();
        assert_eq!(esp.numero, 1);
        assert!(esp.setores > 0);
        assert_ne!(esp.guid, [0u8; 16]);

        // A 2 é a raiz Linux, e o device path de arranque não pode apontar
        // para ela — o firmware montaria uma partição que não é FAT.
        let erro = le_esp(&disco, 2, 512).unwrap_err().to_string();
        assert!(erro.contains("não é uma ESP"), "{erro}");
    }

    #[test]
    fn le_esp_recusa_disco_sem_gpt() {
        let dir = tempfile::tempdir().unwrap();
        let disco = dir.path().join("vazio.img");
        fs::write(&disco, vec![0u8; 4096]).unwrap();
        let erro = le_esp(&disco, 1, 512).unwrap_err().to_string();
        assert!(erro.contains("não tem GPT primário"), "{erro}");
    }

    #[test]
    fn disco_da_particao_nao_se_perde_no_nvme() {
        let dir = tempfile::tempdir().unwrap();
        let sysfs = dir.path();
        fs::create_dir_all(sysfs.join("nvme0n1")).unwrap();
        fs::create_dir_all(sysfs.join("nvme0n1/nvme0n1p2")).unwrap();
        fs::write(sysfs.join("nvme0n1/nvme0n1p2/partition"), "2\n").unwrap();
        // O sysfs de verdade tem a partição como filha do disco; o link do
        // topo é o que este código percorre.
        std::os::unix::fs::symlink(
            sysfs.join("nvme0n1/nvme0n1p2"),
            sysfs.join("nvme0n1p2"),
        )
        .unwrap();

        let (disco, numero) =
            disco_da_particao(sysfs, Path::new("/dev/nvme0n1p2")).unwrap();
        assert_eq!(numero, 2);
        assert_eq!(disco, PathBuf::from("/dev/nvme0n1"));
    }

    #[test]
    fn setor_logico_cai_no_default_sem_sysfs() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            setor_logico(dir.path(), Path::new("/dev/sda")),
            crate::partition::DEFAULT_SECTOR
        );
        fs::create_dir_all(dir.path().join("sda/queue")).unwrap();
        fs::write(dir.path().join("sda/queue/logical_block_size"), "4096\n").unwrap();
        assert_eq!(setor_logico(dir.path(), Path::new("/dev/sda")), 4096);
    }
}
