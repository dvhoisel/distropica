//! Particionamento GPT do disco de destino.
//!
//! O instalador criava MBR porque o `fdisk` do BusyBox 1.35 não escreve GPT.
//! Isso tinha dois limites em hardware real: MBR não endereça acima de 2 TiB,
//! e o esquema é o legado que firmware UEFI aceita por tolerância, não por
//! norma.
//!
//! O Minipax já sabia escrever GPT — é como ele compõe a IMG. Reusar esse
//! código aqui mantém o **caminho destrutivo** dentro do Rust auditado, em vez
//! de um script de shell montando uma sequência de teclas para o `fdisk`.
//!
//! Uma diferença deliberada em relação à IMG: lá os GUIDs derivam do hash do
//! payload, porque a imagem precisa ser reprodutível byte a byte. Aqui eles
//! vêm de `/dev/urandom` — dois discos instalados **não podem** compartilhar
//! GUID de partição, sob pena de o firmware ou o `blkid` confundirem um com o
//! outro.

use anyhow::{bail, Context, Result};
use crc32fast::Hasher as Crc32;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const ENTRY_COUNT: u32 = 128;
const ENTRY_SIZE: u32 = 128;
/// Setor lógico presumido quando o chamador não informa. Disco 4Kn existe, e
/// nele o LBA do GPT vale 4096 bytes — escrever como se fosse 512 produziria
/// uma tabela em endereço errado, num caminho que apaga disco.
pub const DEFAULT_SECTOR: u64 = 512;

type LbaRange = (u64, u64);
pub type WrittenLayout = (LbaRange, LbaRange, Option<LbaRange>);

const TYPE_ESP: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
/// `0FC63DAF-8483-4772-8E79-3D69D8477DE4` — Linux filesystem data.
const TYPE_LINUX: [u8; 16] = [
    0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
];
/// `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F` — Linux swap. O tipo importa: é por
/// ele que o drop-in de boot ACHA a área de troca, sem precisar de fstab nem de
/// um caminho de dispositivo gravado em lugar nenhum.
const TYPE_SWAP: [u8; 16] = [
    0x6d, 0xfd, 0x57, 0x06, 0xab, 0xa4, 0xc4, 0x43, 0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f,
];

fn put_u32(buffer: &mut [u8], at: usize, value: u32) {
    buffer[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buffer: &mut [u8], at: usize, value: u64) {
    buffer[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn random_guid() -> Result<[u8; 16]> {
    let mut raw = [0u8; 16];
    File::open("/dev/urandom")
        .context("abrindo /dev/urandom para o GUID da partição")?
        .read_exact(&mut raw)
        .context("lendo /dev/urandom")?;
    // Versão 4, variante RFC 4122 — nos campos que o GUID guarda em
    // little-endian, como a UEFI os interpreta.
    raw[7] = (raw[7] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    Ok(raw)
}

#[allow(clippy::too_many_arguments)]
fn header(
    sector: u64,
    first_usable: u64,
    current_lba: u64,
    backup_lba: u64,
    last_usable: u64,
    entries_lba: u64,
    disk_guid: [u8; 16],
    entries_crc: u32,
) -> Vec<u8> {
    let mut head = vec![0u8; sector as usize];
    head[..8].copy_from_slice(b"EFI PART");
    put_u32(&mut head, 8, 0x0001_0000);
    put_u32(&mut head, 12, 92);
    put_u64(&mut head, 24, current_lba);
    put_u64(&mut head, 32, backup_lba);
    put_u64(&mut head, 40, first_usable);
    put_u64(&mut head, 48, last_usable);
    head[56..72].copy_from_slice(&disk_guid);
    put_u64(&mut head, 72, entries_lba);
    put_u32(&mut head, 80, ENTRY_COUNT);
    put_u32(&mut head, 84, ENTRY_SIZE);
    put_u32(&mut head, 88, entries_crc);
    let mut crc = Crc32::new();
    crc.update(&head[..92]);
    put_u32(&mut head, 16, crc.finalize());
    head
}

fn entry(kind: [u8; 16], guid: [u8; 16], first: u64, last: u64, name: &str) -> [u8; 128] {
    let mut raw = [0u8; 128];
    raw[..16].copy_from_slice(&kind);
    raw[16..32].copy_from_slice(&guid);
    put_u64(&mut raw, 32, first);
    put_u64(&mut raw, 40, last);
    for (index, unit) in name.encode_utf16().take(36).enumerate() {
        raw[56 + index * 2..58 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    raw
}

/// Escreve um GPT com ESP + raiz Linux + swap sobre `target`, apagando o que
/// houver.
///
/// `esp_mib` dimensiona a ESP e `swap_mib` a área de troca; a RAIZ recebe todo
/// o resto do disco. Devolve (primeiro setor, último setor) de cada partição,
/// na ordem ESP, raiz, swap.
///
/// A ORDEM FÍSICA É ESP, RAIZ, SWAP, e a swap fica no fim do disco de
/// propósito. Não é preferência estética: o `bootstrap/live/init` acha a raiz
/// como partição 2, e pôr a swap no meio a empurraria para 3 — mudança que não
/// compra nada e quebra o instalador. Em disco de estado sólido a posição
/// física é indiferente, e em disco rotativo a swap no fim é o que se faz há
/// trinta anos.
///
/// `swap_mib` igual a zero não cria a partição, e o retorno traz `None`. Isso
/// não é um caso de teste: é o disco pequeno demais para pagar uma área de
/// troca, e um sistema sem swap é preferível a um que não coube.
pub fn write_layout(
    target: &Path,
    esp_mib: u64,
    swap_mib: u64,
    sector: u64,
) -> Result<WrittenLayout> {
    if !matches!(sector, 512 | 1024 | 2048 | 4096) {
        bail!("setor lógico não suportado: {sector}");
    }
    if esp_mib < 16 {
        bail!("ESP de {esp_mib} MiB é pequena demais para um BOOTX64.EFI");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target)
        .with_context(|| format!("abrindo {} para particionar", target.display()))?;
    let total_bytes = file.seek(SeekFrom::End(0))?;
    let total_sectors = total_bytes / sector;
    let esp_sectors = esp_mib * 1024 * 1024 / sector;
    // A tabela de entradas ocupa 16 KiB: 32 setores de 512, mas só 4 de 4096.
    let entries_bytes = u64::from(ENTRY_COUNT) * u64::from(ENTRY_SIZE);
    let entries_sectors = entries_bytes.div_ceil(sector);
    // 1 MiB de alinhamento, em setores — vale para qualquer tamanho de bloco.
    let first_usable = (1024 * 1024) / sector;

    let last_usable = total_sectors
        .checked_sub(entries_sectors + 2)
        .context("dispositivo pequeno demais para GPT")?;
    let esp_first = first_usable;
    let esp_last = esp_first + esp_sectors - 1;
    let root_first = esp_last + 1;
    // 64 MiB é o mesmo piso que o instalador já exigia da raiz.
    let piso_raiz = 64 * 1024 * 1024 / sector;
    if root_first + piso_raiz > last_usable {
        bail!(
            "disco de {} MiB não comporta ESP de {esp_mib} MiB mais uma raiz utilizável",
            total_bytes / (1024 * 1024)
        );
    }

    // A SWAP SÓ EXISTE SE SOBRAR RAIZ DEPOIS DELA, e o piso da raiz é o mesmo
    // que já valia. Um disco que só comporta ESP + swap não é um disco onde se
    // instala esta distro; recusar a swap e seguir é melhor que recusar a
    // instalação por causa de uma área de troca.
    let swap_sectors = if swap_mib == 0 {
        0
    } else {
        swap_mib * 1024 * 1024 / sector
    };
    let (root_last, swap) =
        if swap_sectors > 0 && root_first + piso_raiz + swap_sectors <= last_usable {
            let swap_first = last_usable - swap_sectors + 1;
            (swap_first - 1, Some((swap_first, last_usable)))
        } else {
            (last_usable, None)
        };

    let mut entries = vec![0u8; ENTRY_COUNT as usize * ENTRY_SIZE as usize];
    entries[..128].copy_from_slice(&entry(
        TYPE_ESP,
        random_guid()?,
        esp_first,
        esp_last,
        "DISTROPICA ESP",
    ));
    entries[128..256].copy_from_slice(&entry(
        TYPE_LINUX,
        random_guid()?,
        root_first,
        root_last,
        "DISTROPICA ROOT",
    ));
    if let Some((swap_first, swap_last)) = swap {
        entries[256..384].copy_from_slice(&entry(
            TYPE_SWAP,
            random_guid()?,
            swap_first,
            swap_last,
            "DISTROPICA SWAP",
        ));
    }
    let mut crc = Crc32::new();
    crc.update(&entries);
    let entries_crc = crc.finalize();

    // MBR protetivo: uma entrada 0xEE cobrindo o disco, para que ferramenta
    // antiga não veja espaço livre onde há GPT.
    let mut mbr = vec![0u8; sector as usize];
    let protective = &mut mbr[446..462];
    protective[1..4].copy_from_slice(&[0x00, 0x02, 0x00]);
    protective[4] = 0xee;
    protective[5..8].copy_from_slice(&[0xff, 0xff, 0xff]);
    protective[8..12].copy_from_slice(&1u32.to_le_bytes());
    protective[12..16].copy_from_slice(
        &(total_sectors.saturating_sub(1).min(u32::MAX as u64) as u32).to_le_bytes(),
    );
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);

    let last_lba = total_sectors - 1;
    let backup_entries_lba = last_lba - entries_sectors;
    let disk_guid = random_guid()?;
    let primary = header(
        sector,
        first_usable,
        1,
        last_lba,
        last_usable,
        2,
        disk_guid,
        entries_crc,
    );
    let backup = header(
        sector,
        first_usable,
        last_lba,
        1,
        last_usable,
        backup_entries_lba,
        disk_guid,
        entries_crc,
    );

    // Ordem deliberada: as cópias de reserva primeiro, o cabeçalho primário
    // por último. Uma interrupção no meio deixa um disco sem GPT válido — que
    // o instalador refaz — em vez de um GPT primário apontando para tabela de
    // reserva que ainda não existe.
    file.seek(SeekFrom::Start(backup_entries_lba * sector))?;
    file.write_all(&entries)?;
    file.seek(SeekFrom::Start(last_lba * sector))?;
    file.write_all(&backup)?;
    file.seek(SeekFrom::Start(2 * sector))?;
    file.write_all(&entries)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&mbr)?;
    file.seek(SeekFrom::Start(sector))?;
    file.write_all(&primary)?;
    file.sync_all()
        .context("sincronizando a tabela de partições no dispositivo")?;

    Ok(((esp_first, esp_last), (root_first, root_last), swap))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A swap fica no FIM do disco e a raiz recua para deixá-la caber; a raiz
    /// continua sendo a partição 2, que é o que o instalador assume.
    #[test]
    fn escreve_swap_no_fim_sem_mexer_no_indice_da_raiz() {
        let path = std::env::temp_dir().join(format!("minipax-swap-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(1024 * 1024 * 1024).unwrap();
        drop(file);

        let ((_, esp_last), (root_first, root_last), swap) =
            write_layout(&path, 64, 128, DEFAULT_SECTOR).unwrap();
        let (swap_first, swap_last) = swap.expect("swap de 128 MiB cabe em 1 GiB");
        assert_eq!(root_first, esp_last + 1, "a raiz segue logo apos a ESP");
        assert_eq!(swap_first, root_last + 1, "a swap comeca onde a raiz acaba");
        assert_eq!(
            swap_last - swap_first + 1,
            128 * 1024 * 1024 / DEFAULT_SECTOR,
            "a swap nao tem o tamanho pedido"
        );

        let raw = std::fs::read(&path).unwrap();
        let entries = &raw[1024..1024 + 384];
        assert_eq!(&entries[..16], &TYPE_ESP);
        assert_eq!(&entries[128..144], &TYPE_LINUX, "a raiz precisa ser a 2");
        assert_eq!(&entries[256..272], &TYPE_SWAP, "a swap precisa ser a 3");
        std::fs::remove_file(&path).ok();
    }

    /// Disco pequeno: a swap cede, a instalação continua. O contrário —
    /// recusar a instalação por causa da area de troca — seria trocar um
    /// sistema sem swap por nenhum sistema.
    #[test]
    fn swap_grande_demais_cede_o_lugar_a_raiz() {
        let path = std::env::temp_dir().join(format!("minipax-swap-nao-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(200 * 1024 * 1024).unwrap();
        drop(file);

        let (_, (root_first, root_last), swap) =
            write_layout(&path, 64, 4096, DEFAULT_SECTOR).unwrap();
        assert!(swap.is_none(), "swap de 4 GiB nao cabe em disco de 200 MiB");
        assert!(root_last > root_first, "a raiz precisa sobreviver");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn escreve_gpt_com_esp_e_raiz() {
        let path = std::env::temp_dir().join(format!("minipax-gpt-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        // 1 GiB de disco simulado.
        file.set_len(1024 * 1024 * 1024).unwrap();
        drop(file);

        let ((esp_first, esp_last), (root_first, root_last), swap) =
            write_layout(&path, 64, 0, DEFAULT_SECTOR).unwrap();
        assert!(swap.is_none(), "swap_mib=0 nao deve criar particao");
        assert_eq!(esp_first, 1024 * 1024 / DEFAULT_SECTOR);
        assert_eq!(esp_last - esp_first + 1, 64 * 1024 * 1024 / DEFAULT_SECTOR);
        assert_eq!(root_first, esp_last + 1);
        assert!(root_last > root_first);

        let raw = std::fs::read(&path).unwrap();
        assert_eq!(&raw[510..512], &[0x55, 0xaa], "MBR protetivo ausente");
        assert_eq!(raw[446 + 4], 0xee, "entrada protetiva não é 0xEE");
        assert_eq!(&raw[512..520], b"EFI PART", "GPT primário ausente");
        // Tipos das duas entradas, em 2 * SECTOR.
        let entries = &raw[1024..1024 + 256];
        assert_eq!(&entries[..16], &TYPE_ESP);
        assert_eq!(&entries[128..144], &TYPE_LINUX);
        // GUIDs únicos: duas partições não podem compartilhar identidade.
        assert_ne!(&entries[16..32], &entries[144..160]);
        // Cópia de reserva no fim do disco.
        let last_lba = (raw.len() as u64 / DEFAULT_SECTOR) - 1;
        let backup = &raw[(last_lba * DEFAULT_SECTOR) as usize..][..8];
        assert_eq!(backup, b"EFI PART", "GPT de reserva ausente");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn recusa_esp_minuscula_e_disco_pequeno() {
        let path = std::env::temp_dir().join(format!("minipax-gpt-mini-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(80 * 1024 * 1024).unwrap();
        drop(file);
        assert!(
            write_layout(&path, 8, 0, DEFAULT_SECTOR).is_err(),
            "ESP minúscula deveria falhar"
        );
        assert!(
            write_layout(&path, 64, 0, DEFAULT_SECTOR).is_err(),
            "disco sem espaço para raiz deveria falhar"
        );
        assert!(
            write_layout(&path, 64, 0, 999).is_err(),
            "setor lógico inválido deveria falhar"
        );
        std::fs::remove_file(&path).ok();
    }
}
