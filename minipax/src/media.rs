use crate::profile::{ProfileStatus, ResolvedProfile};
use anyhow::{bail, Context, Result};
use crc32fast::Hasher as Crc32;
use fatfs::{
    Date, DateTime, FatType, FileSystem, FormatVolumeOptions, FsOptions, Time, TimeProvider,
};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

const SECTOR_SIZE: u64 = 512;
const PARTITION_START_LBA: u64 = 2048;
const GPT_ENTRY_COUNT: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
const MEDIA_FORMAT: &str = "1";
const MEDIA_PUBLISH_FORMAT: &str = "2";
const MAX_BOOT_EFI_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PUBLICATION_CONTROL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaMode {
    Online,
    Offline,
}

impl FromStr for MediaMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "online" => Ok(Self::Online),
            "offline" => Ok(Self::Offline),
            _ => bail!("modo de mídia inválido {value:?} (online|offline)"),
        }
    }
}

impl MediaMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaFormat {
    Img,
    Iso,
}

impl FromStr for MediaFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "img" => Ok(Self::Img),
            "iso" => Ok(Self::Iso),
            _ => bail!("formato de mídia inválido {value:?} (img|iso)"),
        }
    }
}

impl MediaFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Img => "img",
            Self::Iso => "iso",
        }
    }
}

pub struct MediaOptions {
    pub mode: MediaMode,
    pub format: MediaFormat,
    pub boot_efi: PathBuf,
    pub output: PathBuf,
    /// Binário do minitrue usado para perguntar que fingerprint a árvore de
    /// receitas embarcada exige. Ver [`confere_identidade`].
    pub minitrue: Option<PathBuf>,
}

/// Lê `<cache>/channels/<canal>/index` e devolve `(pacote, versão, fingerprint)`.
///
/// O formato é o índice canônico v2 do minitrue: campos separados por espaço,
/// com nome, versão, arquitetura e — no quarto campo — o fingerprint da receita
/// que produziu aquele pacote.
fn indice_do_canal(index: &Path) -> Result<Vec<(String, String, String)>> {
    let texto = fs::read_to_string(index)
        .with_context(|| format!("não li o índice do canal: {}", index.display()))?;
    let mut saida = Vec::new();
    for linha in texto.lines() {
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let campos: Vec<&str> = linha.split_whitespace().collect();
        if campos.len() < 4 {
            bail!(
                "índice do canal com linha de {} campos: {}",
                campos.len(),
                index.display()
            );
        }
        saida.push((
            campos[0].to_string(),
            campos[1].to_string(),
            campos[3].to_string(),
        ));
    }
    Ok(saida)
}

/// AS RECEITAS QUE A MÍDIA EMBARCA TÊM DE SER AS QUE CONSTRUÍRAM OS PACOTES.
///
/// Uma mídia carrega duas coisas que vêm de lugares diferentes: os PACOTES,
/// que saíram de um `minitrue channel emit` contra alguma árvore de receitas, e
/// o TEXTO das receitas, que chega por `--newspeak`. Nada obrigava as duas a
/// serem a mesma árvore, e quando divergem o `crimestop` recusa a instalação
/// com "canal oferece X para fingerprint A, mas a receita efetiva exige B" —
/// na máquina de quem recebeu a mídia, depois de ela ter sido composta,
/// distribuída e o disco de destino já ter sido apagado.
///
/// Isso não é hipotético: uma linha acrescentada a uma guarda de
/// newspeak/linux, sem reconstruir o pacote, produziu uma ISO de 780 MB que só
/// falhou lá. O fingerprint é transitivo sobre o texto da receita, então
/// QUALQUER edição — inclusive um comentário — basta para descasar.
///
/// A pergunta "que fingerprint esta árvore exige?" é respondida pelo próprio
/// minitrue, e de propósito: a regra é dele (SPEC-0011 §4), e uma segunda
/// implementação aqui divergiria no primeiro detalhe que mudasse lá.
///
/// Falha, e não avisa. Uma mídia que descasa não instala em lugar nenhum.
fn confere_identidade(profile: &ResolvedProfile, minitrue: &Option<PathBuf>) -> Result<()> {
    let Some(cache) = profile.cache_path.as_ref() else {
        return Ok(());
    };
    let canais = cache.join("channels");
    if !canais.is_dir() {
        return Ok(());
    }
    let mut esperados: Vec<(String, String, String)> = Vec::new();
    let mut entradas: Vec<PathBuf> = fs::read_dir(&canais)
        .with_context(|| format!("não li {}", canais.display()))?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|e| e.path())
        .collect();
    entradas.sort();
    for canal in entradas {
        let index = canal.join("index");
        if index.is_file() {
            esperados.extend(indice_do_canal(&index)?);
        }
    }
    if esperados.is_empty() {
        return Ok(());
    }

    let ferramenta = minitrue
        .clone()
        .or_else(|| std::env::var_os("MINITRUE").map(PathBuf::from))
        .or_else(|| crate::install::find_in_path("minitrue"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "preciso do minitrue para conferir que as receitas embarcadas \
                 correspondem aos pacotes do cache; passe --minitrue, defina \
                 MINITRUE ou deixe-o no PATH"
            )
        })?;
    crate::ensure_real_file(&ferramenta, "minitrue")?;

    // A raiz é irrelevante para esta pergunta e por isso é um diretório vazio:
    // com NEWSPEAK_PATH absoluto o minitrue lê só a árvore de receitas, e dar-lhe
    // uma raiz de verdade convidaria a resposta a depender do que há instalado
    // nela — que é justamente o que não se está perguntando.
    //
    // O caminho da árvore precisa ser ABSOLUTO: o minitrue resolve entradas
    // relativas de NEWSPEAK_PATH contra --root, e com a raiz temporária isso
    // apontaria para o vazio. O sintoma seria "não há receita para <o primeiro
    // pacote do índice>", que não diz nada sobre a causa.
    let arvore = crate::absolute_path(&profile.newspeak_path)?;
    let raiz = tempfile::tempdir().context("não criei a raiz temporária")?;
    let mut comando = Command::new(&ferramenta);
    comando
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("NEWSPEAK_PATH", &arvore)
        .arg("--root")
        .arg(raiz.path())
        .arg("fingerprint");
    let mut nomes: Vec<&str> = esperados.iter().map(|(n, _, _)| n.as_str()).collect();
    nomes.sort();
    nomes.dedup();
    for nome in &nomes {
        comando.arg(nome);
    }
    let saida = comando
        .output()
        .with_context(|| format!("não consegui executar {}", ferramenta.display()))?;
    if !saida.status.success() {
        bail!(
            "minitrue fingerprint falhou com {}: {}",
            saida.status,
            String::from_utf8_lossy(&saida.stderr).trim()
        );
    }
    let texto = String::from_utf8(saida.stdout).context("minitrue devolveu saída não-UTF-8")?;
    let mut exigidos: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for linha in texto.lines() {
        let mut campos = linha.split_whitespace();
        if let (Some(nome), Some(fp)) = (campos.next(), campos.next()) {
            exigidos.insert(nome, fp);
        }
    }

    let mut divergentes = Vec::new();
    for (nome, versao, oferecido) in &esperados {
        let Some(exigido) = exigidos.get(nome.as_str()) else {
            bail!(
                "o cache oferece {nome} {versao}, mas a árvore de receitas \
                 embarcada não tem receita para ele"
            );
        };
        if exigido != oferecido {
            divergentes.push(format!(
                "  {nome} {versao}: o cache traz o pacote de {oferecido}, \
                 a receita embarcada exige {exigido}"
            ));
        }
    }
    if !divergentes.is_empty() {
        bail!(
            "as receitas embarcadas não correspondem aos pacotes do cache:\n{}\n\
             o crimestop recusaria a instalação no disco de quem recebesse esta \
             mídia. reconstrua os pacotes a partir destas receitas antes de compor.",
            divergentes.join("\n")
        );
    }
    Ok(())
}

/// De onde vêm os bytes de um arquivo do payload.
///
/// O `cache.tar` chega aqui como `OnDisk` porque pode ter centenas de MiB: ele
/// é escrito num temporário pelo `profile::artifacts` e daqui em diante só é
/// LIDO — para o hash, para a árvore da ISO e para o FAT da imagem. Todo o
/// resto (BOOTX64.EFI, os worlds, o lock, os tars pequenos) continua em
/// memória, onde já estava e onde não incomoda.
#[derive(Clone)]
enum PayloadBody {
    Inline(Vec<u8>),
    OnDisk { source: PathBuf, len: u64 },
}

#[derive(Clone)]
struct PayloadFile {
    path: String,
    body: PayloadBody,
}

impl PayloadFile {
    fn inline(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            body: PayloadBody::Inline(bytes),
        }
    }

    fn len(&self) -> u64 {
        match &self.body {
            PayloadBody::Inline(bytes) => bytes.len() as u64,
            PayloadBody::OnDisk { len, .. } => *len,
        }
    }

    /// Um leitor sobre o conteúdo, seja ele memória ou disco. Quem consome
    /// escreve em blocos e nunca segura o arquivo inteiro.
    fn reader(&self) -> Result<Box<dyn Read + '_>> {
        Ok(match &self.body {
            PayloadBody::Inline(bytes) => Box::new(&bytes[..]),
            PayloadBody::OnDisk { source, len } => Box::new(
                File::open(source)
                    .with_context(|| format!("payload: não abri {}", source.display()))?
                    .take(*len),
            ),
        })
    }
}

/// Copia um `Read` para um `Write` com buffer fixo. O ponto é o buffer ser
/// fixo: é ele que faz a memória não crescer com o tamanho do payload.
fn stream_copy<R: Read + ?Sized, W: Write + ?Sized>(source: &mut R, sink: &mut W) -> Result<u64> {
    let mut buffer = [0u8; 128 * 1024];
    let mut total = 0u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        sink.write_all(&buffer[..read])?;
        total += read as u64;
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// O hash do payload, calculado em fluxo. A serialização é EXATAMENTE a mesma
/// de antes — caminho, NUL, tamanho em little-endian, conteúdo — de modo que
/// uma mídia composta com a versão que segurava tudo em memória e outra
/// composta com esta produzem o mesmo `payload_hash`. Isso não é detalhe: o
/// GUID do GPT, o volume id do FAT e a identidade da mídia derivam dele.
fn payload_hash(files: &[PayloadFile]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"MINIPAX-PAYLOAD-V1\0");
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.len().to_le_bytes());
        let mut reader = file.reader()?;
        let written = stream_copy(&mut *reader, &mut hasher)?;
        if written != file.len() {
            bail!(
                "payload: {} mudou de tamanho durante a composição ({} de {} bytes)",
                file.path,
                written,
                file.len()
            );
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn validate_boot_efi(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        bail!("BOOTX64.EFI não possui cabeçalho PE/COFF (MZ)");
    }
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_offset
        .checked_add(4)
        .filter(|offset| offset + 20 <= bytes.len())
        .ok_or_else(|| anyhow::anyhow!("BOOTX64.EFI possui cabeçalho PE/COFF truncado"))?;
    if &bytes[pe_offset..coff] != b"PE\0\0" {
        bail!("BOOTX64.EFI possui cabeçalho PE/COFF truncado/inválido");
    }
    let machine = u16::from_le_bytes(bytes[coff..coff + 2].try_into().unwrap());
    if machine != 0x8664 {
        bail!("BOOTX64.EFI não declara COFF Machine AMD64 (0x8664)");
    }
    let sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    if sections == 0 {
        bail!("BOOTX64.EFI não declara seções PE/COFF");
    }
    let optional_size =
        u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap()) as usize;
    if optional_size < 70 {
        bail!("BOOTX64.EFI possui Optional Header curto demais");
    }
    let optional = coff + 20;
    let optional_end = optional
        .checked_add(optional_size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| anyhow::anyhow!("BOOTX64.EFI possui Optional Header truncado"))?;
    optional_end
        .checked_add(
            sections
                .checked_mul(40)
                .ok_or_else(|| anyhow::anyhow!("número de seções PE/COFF inválido"))?,
        )
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| anyhow::anyhow!("BOOTX64.EFI possui tabela de seções truncada"))?;
    let magic = u16::from_le_bytes(bytes[optional..optional + 2].try_into().unwrap());
    if magic != 0x20b {
        bail!("BOOTX64.EFI x86_64 precisa ser PE32+");
    }
    let subsystem = u16::from_le_bytes(bytes[optional + 68..optional + 70].try_into().unwrap());
    if subsystem != 10 {
        bail!("BOOTX64.EFI não declara IMAGE_SUBSYSTEM_EFI_APPLICATION");
    }
    Ok(())
}

fn media_meta(
    profile: &ResolvedProfile,
    profile_class: &str,
    media_class: &str,
    lock_hash: &str,
    boot_hash: &str,
    mode: MediaMode,
) -> String {
    format!(
        "MEDIA_FORMAT={MEDIA_FORMAT}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nMEDIA_CLASS={}\nPROFILE_LOCK_SHA256={lock_hash}\nARCH={}\nMODE={}\nBOOT_EFI_SHA256={boot_hash}\nMINIPAX_VERSION={}\n",
        profile.name,
        profile_class,
        media_class,
        profile.arch,
        mode.as_str(),
        crate::VERSION,
    )
}

pub(crate) fn canonical_profile(profile: &ResolvedProfile) -> Vec<u8> {
    let mut config = format!(
        "PROFILE_FORMAT=1\nNAME={}\nARCH={}\nSOURCE_DATE_EPOCH={}\nMEDIA_SIZE_MIB={}\nINSTALL_READY={}\nSTATUS={}\n",
        profile.name,
        profile.arch,
        profile.epoch,
        profile.media_size_mib,
        if profile.install_ready { "yes" } else { "no" },
        match profile.status {
            ProfileStatus::Development => "development",
            ProfileStatus::Release => "release",
        },
    );
    for (name, value) in [
        (
            "OFFICIAL_CONTENT_SHA256",
            profile.official_content_sha256.as_deref(),
        ),
        (
            "OFFICIAL_BOOT_EFI_SHA256",
            profile.official_boot_efi_sha256.as_deref(),
        ),
        (
            "OFFICIAL_MINITRUE_SHA256",
            profile.official_minitrue_sha256.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            config.push_str(name);
            config.push('=');
            config.push_str(value);
            config.push('\n');
        }
    }
    config.into_bytes()
}

type PayloadParts = (
    Vec<PayloadFile>,
    String,
    String,
    String,
    String,
    Option<crate::profile::CacheArchive>,
);

fn payload(profile: &ResolvedProfile, options: &MediaOptions) -> Result<PayloadParts> {
    crate::ensure_real_file(&options.boot_efi, "BOOTX64.EFI")?;
    let mut boot = Vec::new();
    File::open(&options.boot_efi)?
        .take(MAX_BOOT_EFI_BYTES + 1)
        .read_to_end(&mut boot)?;
    if boot.len() as u64 > MAX_BOOT_EFI_BYTES {
        bail!("BOOTX64.EFI excede o limite de 256 MiB deste marco");
    }
    validate_boot_efi(&boot)?;
    let profile_config = canonical_profile(profile);
    let artifacts = profile.artifacts()?;
    match (
        options.mode,
        artifacts.cache_tar.as_ref(),
        artifacts.channel_bootstrap_tar.as_ref(),
    ) {
        (MediaMode::Offline, None, _) => bail!("modo offline exige --cache DIR"),
        (MediaMode::Offline, Some(_), _) if artifacts.cache_entries.is_empty() => {
            bail!("modo offline exige --cache DIR não vazio")
        }
        (MediaMode::Online, Some(_), _) => {
            bail!("modo online usa channel-bootstrap/ do perfil e não aceita --cache")
        }
        (MediaMode::Online, None, None) => {
            bail!("modo online exige channel-bootstrap/ no perfil com config e índice assinado")
        }
        _ => {}
    }
    let boot_hash = sha256(&boot);
    let profile_class = artifacts.class.clone();
    let media_class = if profile_class == "official-inputs"
        && profile.official_boot_efi_sha256.as_deref() == Some(boot_hash.as_str())
    {
        "official-inputs".to_string()
    } else if profile_class == "development" {
        "development".to_string()
    } else {
        "custom".to_string()
    };
    let meta = media_meta(
        profile,
        &profile_class,
        &media_class,
        &artifacts.lock_hash,
        &boot_hash,
        options.mode,
    );
    let mut files = vec![
        PayloadFile::inline("EFI/BOOT/BOOTX64.EFI", boot),
        PayloadFile::inline(
            "distropica/profile.lock",
            artifacts.lock.as_bytes().to_vec(),
        ),
        PayloadFile::inline("distropica/profile", profile_config),
        PayloadFile::inline("distropica/live.world", artifacts.live_world.into_bytes()),
        PayloadFile::inline(
            "distropica/target.world",
            artifacts.target_world.into_bytes(),
        ),
        PayloadFile::inline("distropica/cache.world", artifacts.cache_world.into_bytes()),
        PayloadFile::inline("distropica/overlay.tar", artifacts.overlay_tar),
        PayloadFile::inline("distropica/newspeak.tar", artifacts.newspeak_tar),
        PayloadFile::inline("distropica/media.meta", meta.into_bytes()),
    ];
    if let Some(bootstrap) = artifacts.channel_bootstrap_tar {
        files.push(PayloadFile::inline(
            "distropica/channel-bootstrap.tar",
            bootstrap,
        ));
    }
    // O cache é o único que vem do disco: ele é o que pode ter centenas de
    // MiB, e o `profile::artifacts` já o deixou escrito num temporário cuja
    // vida dura até o fim desta composição.
    // O `CacheArchive` sai junto com os arquivos, e não por acidente: ele é
    // dono de um `NamedTempFile` que se APAGA no Drop. Se ficasse aqui dentro,
    // o payload sairia apontando para um caminho que já não existe — foi
    // exatamente assim que o teste da ISO falhou com "não abri /tmp/.tmpdOrz4c".
    // Quem compõe a mídia segura este valor até o fim.
    let cache_archive = artifacts.cache_tar;
    if let Some(cache) = &cache_archive {
        files.push(PayloadFile {
            path: "distropica/cache.tar".into(),
            body: PayloadBody::OnDisk {
                source: cache.path().to_path_buf(),
                len: cache.len(),
            },
        });
    }
    files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    Ok((
        files,
        artifacts.lock,
        artifacts.lock_hash,
        profile_class,
        media_class,
        cache_archive,
    ))
}

#[derive(Debug)]
struct FixedTime(DateTime);

impl TimeProvider for FixedTime {
    fn get_current_date(&self) -> Date {
        self.0.date
    }

    fn get_current_date_time(&self) -> DateTime {
        self.0
    }
}

fn utc_parts(epoch: u64) -> (u16, u16, u16, u16, u16, u16) {
    let secs = epoch.min(i64::MAX as u64) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year.clamp(1980, 2107) as u16,
        month as u16,
        day as u16,
        hour as u16,
        min as u16,
        sec as u16,
    )
}

fn fixed_time(epoch: u64) -> &'static FixedTime {
    let (year, month, day, hour, min, sec) = utc_parts(epoch);
    Box::leak(Box::new(FixedTime(DateTime {
        date: Date { year, month, day },
        time: Time {
            hour,
            min,
            sec,
            millis: 0,
        },
    })))
}

struct PartitionFile {
    file: File,
    start: u64,
    len: u64,
    position: u64,
}

impl PartitionFile {
    fn new(file: File, start: u64, len: u64) -> Self {
        Self {
            file,
            start,
            len,
            position: 0,
        }
    }
}

impl Read for PartitionFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.position);
        let wanted = buffer.len().min(remaining as usize);
        self.file
            .seek(SeekFrom::Start(self.start + self.position))?;
        let read = self.file.read(&mut buffer[..wanted])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Write for PartitionFile {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.position);
        if buffer.len() as u64 > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "escrita além da partição",
            ));
        }
        self.file
            .seek(SeekFrom::Start(self.start + self.position))?;
        let written = self.file.write(buffer)?;
        self.position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for PartitionFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::End(value) => self.len as i128 + value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
        };
        if next < 0 || next > self.len as i128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek além da partição",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

fn derived_bytes(label: &[u8], payload_hash: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"minipax-media-v1\0");
    hash.update(label);
    hash.update(b"\0");
    hash.update(payload_hash.as_bytes());
    hash.finalize().into()
}

fn guid_from(seed: [u8; 32]) -> [u8; 16] {
    let mut guid: [u8; 16] = seed[..16].try_into().unwrap();
    guid[7] = (guid[7] & 0x0f) | 0x40;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn gpt_header(
    current_lba: u64,
    backup_lba: u64,
    last_usable: u64,
    entries_lba: u64,
    disk_guid: [u8; 16],
    entries_crc: u32,
) -> [u8; SECTOR_SIZE as usize] {
    let mut header = [0u8; SECTOR_SIZE as usize];
    header[..8].copy_from_slice(b"EFI PART");
    put_u32(&mut header, 8, 0x0001_0000);
    put_u32(&mut header, 12, 92);
    put_u64(&mut header, 24, current_lba);
    put_u64(&mut header, 32, backup_lba);
    put_u64(&mut header, 40, 34);
    put_u64(&mut header, 48, last_usable);
    header[56..72].copy_from_slice(&disk_guid);
    put_u64(&mut header, 72, entries_lba);
    put_u32(&mut header, 80, GPT_ENTRY_COUNT);
    put_u32(&mut header, 84, GPT_ENTRY_SIZE);
    put_u32(&mut header, 88, entries_crc);
    let mut crc = Crc32::new();
    crc.update(&header[..92]);
    put_u32(&mut header, 16, crc.finalize());
    header
}

fn write_gpt(file: &mut File, total_sectors: u64, payload_hash: &str) -> Result<(u64, u64)> {
    if total_sectors <= PARTITION_START_LBA + 34 {
        bail!("imagem pequena demais para GPT");
    }
    let last_lba = total_sectors - 1;
    let last_usable = total_sectors - 34;
    let mut mbr = [0u8; SECTOR_SIZE as usize];
    let partition = &mut mbr[446..462];
    partition[1..4].copy_from_slice(&[0x00, 0x02, 0x00]);
    partition[4] = 0xee;
    partition[5..8].copy_from_slice(&[0xff, 0xff, 0xff]);
    partition[8..12].copy_from_slice(&1u32.to_le_bytes());
    partition[12..16].copy_from_slice(
        &(total_sectors.saturating_sub(1).min(u32::MAX as u64) as u32).to_le_bytes(),
    );
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);

    let mut entries = vec![0u8; GPT_ENTRY_COUNT as usize * GPT_ENTRY_SIZE as usize];
    let esp_type = [
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9,
        0x3b,
    ];
    entries[..16].copy_from_slice(&esp_type);
    entries[16..32].copy_from_slice(&guid_from(derived_bytes(b"partition", payload_hash)));
    put_u64(&mut entries, 32, PARTITION_START_LBA);
    put_u64(&mut entries, 40, last_usable);
    for (index, unit) in "DISTROPICA ESP".encode_utf16().enumerate() {
        entries[56 + index * 2..58 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let mut entries_hasher = Crc32::new();
    entries_hasher.update(&entries);
    let entries_crc = entries_hasher.finalize();
    let disk_guid = guid_from(derived_bytes(b"disk", payload_hash));
    let primary = gpt_header(1, last_lba, last_usable, 2, disk_guid, entries_crc);
    let backup_entries_lba = last_lba - 32;
    let backup = gpt_header(
        last_lba,
        1,
        last_usable,
        backup_entries_lba,
        disk_guid,
        entries_crc,
    );
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&mbr)?;
    file.seek(SeekFrom::Start(SECTOR_SIZE))?;
    file.write_all(&primary)?;
    file.seek(SeekFrom::Start(2 * SECTOR_SIZE))?;
    file.write_all(&entries)?;
    file.seek(SeekFrom::Start(backup_entries_lba * SECTOR_SIZE))?;
    file.write_all(&entries)?;
    file.seek(SeekFrom::Start(last_lba * SECTOR_SIZE))?;
    file.write_all(&backup)?;
    Ok((
        PARTITION_START_LBA * SECTOR_SIZE,
        (last_usable - PARTITION_START_LBA + 1) * SECTOR_SIZE,
    ))
}

fn mkdir_fat<T: Read + Write + Seek>(root: &fatfs::Dir<'_, T>, path: &str) -> Result<()> {
    let mut current = String::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        match root.create_dir(&current) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn populate_fat<T: Read + Write + Seek>(
    filesystem: &FileSystem<T>,
    files: &[PayloadFile],
) -> Result<()> {
    let root = filesystem.root_dir();
    for payload in files {
        if let Some(parent) = Path::new(&payload.path).parent().and_then(Path::to_str) {
            mkdir_fat(&root, parent)?;
        }
        let mut destination = root.create_file(&payload.path)?;
        destination.truncate()?;
        let mut reader = payload.reader()?;
        stream_copy(&mut *reader, &mut destination)?;
        destination.flush()?;
    }
    Ok(())
}

fn format_fat_partition(
    file: &File,
    start: u64,
    len: u64,
    files: &[PayloadFile],
    payload_hash: &str,
    epoch: u64,
) -> Result<()> {
    let volume_id =
        u32::from_le_bytes(derived_bytes(b"fat", payload_hash)[..4].try_into().unwrap());
    let options = FormatVolumeOptions::new()
        .fat_type(FatType::Fat32)
        .volume_id(volume_id)
        .volume_label(*b"DISTROPICA ");
    fatfs::format_volume(PartitionFile::new(file.try_clone()?, start, len), options)?;
    let filesystem = FileSystem::new(
        PartitionFile::new(file.try_clone()?, start, len),
        FsOptions::new()
            .time_provider(fixed_time(epoch))
            .update_accessed_date(false),
    )?;
    populate_fat(&filesystem, files)?;
    filesystem.unmount()?;
    file.sync_all()?;
    Ok(())
}

fn create_img(
    path: &Path,
    profile: &ResolvedProfile,
    files: &[PayloadFile],
    payload_hash: &str,
) -> Result<()> {
    let bytes = profile
        .media_size_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("MEDIA_SIZE_MIB excede o limite"))?;
    let payload_size: u64 = files.iter().map(PayloadFile::len).sum();
    if payload_size + 16 * 1024 * 1024 > bytes.saturating_sub(PARTITION_START_LBA * SECTOR_SIZE) {
        bail!(
            "payload de {} bytes não cabe em MEDIA_SIZE_MIB={}",
            payload_size,
            profile.media_size_mib
        );
    }
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    output.set_len(bytes)?;
    let (start, len) = write_gpt(&mut output, bytes / SECTOR_SIZE, payload_hash)?;
    format_fat_partition(&output, start, len, files, payload_hash, profile.epoch)
}

fn create_plain_esp(
    path: &Path,
    files: &[PayloadFile],
    payload_hash: &str,
    epoch: u64,
) -> Result<()> {
    let payload_size: u64 = files.iter().map(PayloadFile::len).sum();
    let size = (payload_size + 16 * 1024 * 1024)
        .max(64 * 1024 * 1024)
        .next_multiple_of(1024 * 1024);
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)?;
    output.set_len(size)?;
    format_fat_partition(&output, 0, size, files, payload_hash, epoch)
}

fn write_payload_tree(root: &Path, files: &[PayloadFile]) -> Result<()> {
    for file in files {
        let destination = root.join(&file.path);
        let parent = destination.parent().unwrap();
        fs::create_dir_all(parent)?;
        // Em fluxo, e não com `write_new`, porque o `cache.tar` passa por aqui
        // a caminho da árvore que o xorriso vai empacotar. O create_new
        // preserva a regra de `write_new`: saída nunca é sobrescrita.
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&destination)
            .with_context(|| {
                format!(
                    "não criei {} (saídas nunca são sobrescritas)",
                    destination.display()
                )
            })?;
        let mut reader = file.reader()?;
        stream_copy(&mut *reader, &mut output)?;
        output.sync_all()?;
    }
    Ok(())
}

fn timestamp(epoch: u64) -> String {
    let (year, month, day, hour, min, sec) = utc_parts(epoch);
    format!("{year:04}{month:02}{day:02}{hour:02}{min:02}{sec:02}00")
}

fn executable_in_path(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|directory| directory.join(name))
                .find(|candidate| candidate.is_file())
        })
        .ok_or_else(|| anyhow::anyhow!("{name} não foi encontrado em PATH"))?;
    let path = fs::canonicalize(path)?;
    crate::ensure_real_file(&path, name)?;
    Ok(path)
}

#[derive(Clone, Debug)]
struct IsoTool {
    path: PathBuf,
    hash: String,
    version: String,
}

impl IsoTool {
    fn identity(&self) -> String {
        format!("xorriso_{}_sha256_{}", self.version, self.hash)
    }
}

fn resolve_iso_tool() -> Result<IsoTool> {
    let path = executable_in_path("xorriso").context("xorriso é obrigatório para --format iso")?;
    let hash = sha256_file(&path)?;
    let version_output = Command::new(&path)
        .arg("-no_rc")
        .arg("-version")
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .output()
        .context("xorriso é obrigatório para --format iso")?;
    if !version_output.status.success() {
        bail!("xorriso -version falhou");
    }
    let version = String::from_utf8_lossy(&version_output.stdout)
        .lines()
        .next()
        .unwrap_or("xorriso")
        .trim()
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-') {
                byte as char
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(IsoTool {
        path,
        hash,
        version,
    })
}

fn create_iso(
    path: &Path,
    workspace: &Path,
    profile: &ResolvedProfile,
    files: &[PayloadFile],
    payload_hash: &str,
    tool: &IsoTool,
) -> Result<()> {
    // Workspace conhecido dentro do stage privado. Uma queda não deixa árvore
    // órfã no TMPDIR: recovery encontra exatamente `iso-workspace` e a limpa
    // antes de reutilizar/remover o stage.
    fs::create_dir(workspace).context("não criei workspace ISO recuperável")?;
    let tree = workspace.join("tree");
    fs::create_dir(&tree)?;
    write_payload_tree(&tree, files)?;
    let boot_dir = tree.join("boot");
    fs::create_dir(&boot_dir)?;
    let esp = boot_dir.join("esp.img");
    let boot_files = files
        .iter()
        .filter(|file| {
            file.path == "EFI/BOOT/BOOTX64.EFI" || file.path == "distropica/profile.lock"
        })
        .cloned()
        .collect::<Vec<_>>();
    create_plain_esp(&esp, &boot_files, payload_hash, profile.epoch)?;
    let date = timestamp(profile.epoch);
    let disk_guid = hex::encode(guid_from(derived_bytes(b"iso-gpt", payload_hash)));
    if sha256_file(&tool.path)? != tool.hash {
        bail!("xorriso mudou antes da composição da ISO");
    }
    let status = Command::new(&tool.path)
        .args([
            "-no_rc",
            "-as",
            "mkisofs",
            "-quiet",
            "-iso-level",
            "3",
            "-full-iso9660-filenames",
        ])
        .args(["-V", "DISTROPICA", "-volset", "DISTROPICA"])
        .args([
            "-uid",
            "0",
            "-gid",
            "0",
            "-dir-mode",
            "0755",
            "-file-mode",
            "0644",
        ])
        .arg(format!("--modification-date={date}"))
        .args(["--set_all_file_dates", &date])
        .args(["-e", "boot/esp.img", "-no-emul-boot"])
        .args(["-efi-boot-part", "--efi-boot-image"])
        .args(["--gpt_disk_guid", &disk_guid])
        .args(["--protective-msdos-label", "-o"])
        .arg(path)
        .arg(&tree)
        .env_clear()
        .env("SOURCE_DATE_EPOCH", profile.epoch.to_string())
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .status()
        .context("não consegui executar xorriso")?;
    if !status.success() {
        bail!("xorriso não conseguiu compor a ISO");
    }
    if sha256_file(&tool.path)? != tool.hash {
        bail!("xorriso mudou durante a composição da ISO");
    }
    // O hash e READY só podem observar bytes que já foram entregues ao
    // filesystem. Sem este sync, uma queda poderia deixar um journal durável
    // descrevendo uma ISO ainda apenas no page cache.
    let mut iso = OpenOptions::new().read(true).write(true).open(path)?;
    iso.set_permissions(fs::Permissions::from_mode(0o644))?;
    iso.sync_all()?;
    iso.seek(SeekFrom::Start(0x8001))?;
    let mut signature = [0u8; 5];
    iso.read_exact(&mut signature)?;
    if &signature != b"CD001" {
        bail!("xorriso produziu uma saída sem descritor ISO9660 válido");
    }
    drop(iso);
    fs::remove_dir_all(workspace).context("não limpei workspace ISO após composição")?;
    Ok(())
}

fn safe_output_name(output: &Path) -> Result<&str> {
    let name = output
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("saída sem nome"))?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("nome da saída precisa ser UTF-8"))?;
    if name.is_empty()
        || name.len() > 200
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("nome da saída não é canônico: {name:?} (use ASCII, '.', '_' ou '-')");
    }
    Ok(name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BundleMember {
    Image,
    Sha256,
    MediaLock,
    Manifest,
}

const BUNDLE_MEMBERS: [BundleMember; 4] = [
    BundleMember::Image,
    BundleMember::Sha256,
    BundleMember::MediaLock,
    BundleMember::Manifest,
];

// A imagem é o commit marker externo: nenhum leitor a observa antes dos três
// sidecars duráveis. Recovery e rollback usam, respectivamente, esta ordem e
// sua inversa (imagem primeiro ao desfazer).
const PROMOTION_ORDER: [BundleMember; 4] = [
    BundleMember::Sha256,
    BundleMember::MediaLock,
    BundleMember::Manifest,
    BundleMember::Image,
];

impl BundleMember {
    fn index(self) -> usize {
        match self {
            Self::Image => 0,
            Self::Sha256 => 1,
            Self::MediaLock => 2,
            Self::Manifest => 3,
        }
    }

    fn staged_name(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Sha256 => "image.sha256",
            Self::MediaLock => "image.media.lock",
            Self::Manifest => "image.manifest",
        }
    }

    fn field(self) -> &'static str {
        match self {
            Self::Image => "IMAGE",
            Self::Sha256 => "SHA256_SIDECAR",
            Self::MediaLock => "MEDIA_LOCK",
            Self::Manifest => "MANIFEST",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Image => "imagem",
            Self::Sha256 => "sidecar sha256",
            Self::MediaLock => "sidecar media.lock",
            Self::Manifest => "sidecar manifest",
        }
    }
}

#[derive(Clone, Debug)]
struct PublicationNames {
    output: String,
    stage: String,
    stage_cleanup: String,
    finals: [String; 4],
}

impl PublicationNames {
    fn new(output: &Path) -> Result<Self> {
        let output = safe_output_name(output)?.to_string();
        let stage = format!(".{output}.minipax-media-stage");
        Ok(Self {
            stage_cleanup: format!("{stage}.cleanup"),
            stage,
            finals: [
                output.clone(),
                format!("{output}.sha256"),
                format!("{output}.media.lock"),
                format!("{output}.manifest"),
            ],
            output,
        })
    }

    fn final_name(&self, member: BundleMember) -> &str {
        &self.finals[member.index()]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSeal {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    hash: String,
}

fn same_ready_identity(observed: &FileSeal, expected: &FileSeal) -> bool {
    observed.dev == expected.dev
        && observed.ino == expected.ino
        && observed.len == expected.len
        && observed.uid == expected.uid
        && observed.mode == expected.mode
        && observed.mtime == expected.mtime
        && observed.mtime_nsec == expected.mtime_nsec
        && observed.hash == expected.hash
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedBundle {
    members: [FileSeal; 4],
    request_hash: String,
}

impl ValidatedBundle {
    fn image_hash(&self) -> &str {
        &self.members[BundleMember::Image.index()].hash
    }
}

#[derive(Debug)]
struct ParentAnchor {
    file: File,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

fn validate_parent_metadata(metadata: &fs::Metadata, expected_uid: u32) -> Result<()> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        bail!(
            "diretório de saída precisa ser real, pertencer ao UID efetivo e não permitir escrita por grupo/outros (uid observado {}, uid esperado {expected_uid}, modo {:04o})",
            metadata.uid(),
            metadata.mode() & 0o7777,
        );
    }
    Ok(())
}

impl ParentAnchor {
    fn open(path: &Path) -> Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("não ancorei diretório de saída: {}", path.display()))?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        validate_parent_metadata(&metadata, effective_uid()?)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .context("não adquiri o lock de publicação de mídia")?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn sync(&self) -> Result<()> {
        self.file
            .sync_all()
            .context("não sincronizei diretório de saída")
    }

    fn ensure_still_named(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path).with_context(|| {
            format!(
                "o caminho do diretório de saída mudou durante a publicação: {}",
                self.path.display()
            )
        })?;
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.dev
            || metadata.ino() != self.ino
        {
            bail!(
                "o caminho do diretório de saída foi trocado durante a publicação: {}",
                self.path.display()
            );
        }
        validate_parent_metadata(&metadata, effective_uid()?)?;
        Ok(())
    }
}

#[derive(Debug)]
struct StageAnchor {
    file: File,
    name: String,
    dev: u64,
    ino: u64,
}

impl StageAnchor {
    fn from_fd(file: File, name: String, parent_dev: u64) -> Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != effective_uid()?
            || metadata.dev() != parent_dev
        {
            bail!(
                "staging precisa ser diretório real privado (0700), do UID efetivo e no filesystem do destino"
            );
        }
        Ok(Self {
            file,
            name,
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn sync(&self) -> Result<()> {
        self.file.sync_all().context("não sincronizei staging")
    }

    fn child_path(&self, name: &str) -> PathBuf {
        // O filho resolve o descritor do processo pai; CLOEXEC pode continuar
        // ativo e nenhuma troca de ancestral redireciona o compositor.
        PathBuf::from(format!(
            "/proc/{}/fd/{}/{}",
            std::process::id(),
            std::os::fd::AsRawFd::as_raw_fd(&self.file),
            name
        ))
    }
}

fn open_regular_at(directory: &File, name: &str, what: &str) -> Result<Option<File>> {
    match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            if !file.metadata()?.file_type().is_file() {
                bail!("{what} não é arquivo regular real: {name}");
            }
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(std::io::Error::from(error))
            .with_context(|| format!("não abri {what} sem seguir symlink: {name}")),
    }
}

fn effective_uid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status")
        .context("não li /proc/self/status para conferir o UID efetivo")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| anyhow::anyhow!("/proc/self/status não contém Uid"))?;
    line.split_whitespace()
        .nth(2)
        .ok_or_else(|| anyhow::anyhow!("Uid efetivo ausente em /proc/self/status"))?
        .parse()
        .context("Uid efetivo inválido em /proc/self/status")
}

fn validate_owned_regular(metadata: &fs::Metadata, what: &str, max_links: u64) -> Result<()> {
    if !metadata.file_type().is_file() {
        bail!("{what} não é arquivo regular real");
    }
    if metadata.uid() != effective_uid()? {
        bail!("{what} pertence a outro UID");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("{what} permite escrita por grupo/outros");
    }
    if metadata.nlink() == 0 || metadata.nlink() > max_links {
        bail!(
            "{what} tem contagem de links inválida: {} (máximo {max_links})",
            metadata.nlink()
        );
    }
    Ok(())
}

fn same_file_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn seal_file_with_links(mut file: File, what: &str, max_links: u64) -> Result<FileSeal> {
    let before = file.metadata()?;
    validate_owned_regular(&before, what, max_links)?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    stream_copy(&mut file, &mut hasher)?;
    let after = file.metadata()?;
    validate_owned_regular(&after, what, max_links)?;
    if !same_file_snapshot(&before, &after) {
        bail!("{what} mudou enquanto era validado");
    }
    Ok(FileSeal {
        dev: after.dev(),
        ino: after.ino(),
        len: after.len(),
        uid: after.uid(),
        mode: after.mode() & 0o7777,
        nlink: after.nlink(),
        mtime: after.mtime(),
        mtime_nsec: after.mtime_nsec(),
        hash: hex::encode(hasher.finalize()),
    })
}

fn seal_file(file: File, what: &str) -> Result<FileSeal> {
    seal_file_with_links(file, what, 1)
}

fn seal_at(directory: &File, name: &str, what: &str) -> Result<Option<FileSeal>> {
    open_regular_at(directory, name, what)?
        .map(|file| seal_file(file, what))
        .transpose()
}

fn seal_at_with_links(
    directory: &File,
    name: &str,
    what: &str,
    max_links: u64,
) -> Result<Option<FileSeal>> {
    open_regular_at(directory, name, what)?
        .map(|file| seal_file_with_links(file, what, max_links))
        .transpose()
}

fn seal_at_limited(
    directory: &File,
    name: &str,
    what: &str,
    limit: u64,
) -> Result<Option<FileSeal>> {
    let Some(file) = open_regular_at(directory, name, what)? else {
        return Ok(None);
    };
    if file.metadata()?.len() > limit {
        bail!("{what} excede o limite de 16 MiB");
    }
    seal_file(file, what).map(Some)
}

fn read_control_at(directory: &File, name: &str, what: &str) -> Result<Option<Vec<u8>>> {
    let Some(mut file) = open_regular_at(directory, name, what)? else {
        return Ok(None);
    };
    let before = file.metadata()?;
    validate_owned_regular(&before, what, 1)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PUBLICATION_CONTROL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PUBLICATION_CONTROL_BYTES {
        bail!("{what} excede o limite de 16 MiB");
    }
    let after = file.metadata()?;
    validate_owned_regular(&after, what, 1)?;
    if !same_file_snapshot(&before, &after) {
        bail!("{what} mudou enquanto era lido");
    }
    Ok(Some(bytes))
}

fn write_new_at_mode(
    directory: &File,
    name: &str,
    bytes: &[u8],
    mode: rustix::fs::Mode,
) -> Result<FileSeal> {
    let fd = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        mode,
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("não criei {name} sem substituir nome existente"))?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    seal_at(directory, name, name)?.ok_or_else(|| anyhow::anyhow!("{name} desapareceu"))
}

fn write_new_at(directory: &File, name: &str, bytes: &[u8]) -> Result<FileSeal> {
    write_new_at_mode(
        directory,
        name,
        bytes,
        rustix::fs::Mode::RUSR
            | rustix::fs::Mode::WUSR
            | rustix::fs::Mode::RGRP
            | rustix::fs::Mode::ROTH,
    )
}

fn validate_bundle_at(
    directory: &File,
    member_names: &[&str; 4],
    output_name: &str,
    binding: &PublicationBinding,
) -> Result<ValidatedBundle> {
    let directory_dev = directory.metadata()?.dev();
    let members: [FileSeal; 4] = BUNDLE_MEMBERS
        .map(|member| {
            let sealed = if member == BundleMember::Image {
                seal_at(directory, member_names[member.index()], member.label())?
            } else {
                // Os três sidecars são controles de publicação. Em especial,
                // media.lock não pode induzir hashing ilimitado antes de ser
                // lido/validado como controle.
                seal_at_limited(
                    directory,
                    member_names[member.index()],
                    member.label(),
                    MAX_PUBLICATION_CONTROL_BYTES,
                )?
            };
            let sealed =
                sealed.ok_or_else(|| anyhow::anyhow!("{} está ausente", member.label()))?;
            if sealed.dev != directory_dev {
                bail!(
                    "{} não está no filesystem do diretório ancorado",
                    member.label()
                );
            }
            Ok(sealed)
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .expect("quatro membros");
    let sha_sidecar = read_control_at(
        directory,
        member_names[BundleMember::Sha256.index()],
        "sidecar sha256",
    )?
    .expect("presença conferida");
    let expected_sha = format!(
        "{}  {output_name}\n",
        members[BundleMember::Image.index()].hash
    );
    if sha_sidecar != expected_sha.as_bytes() {
        bail!("sidecar sha256 não corresponde à imagem preparada");
    }
    if members[BundleMember::MediaLock.index()].hash != binding.profile_lock_hash {
        bail!("media.lock observado diverge do profile lock da invocação atual");
    }
    let manifest_bytes = read_control_at(
        directory,
        member_names[BundleMember::Manifest.index()],
        "sidecar manifest",
    )?
    .expect("presença conferida");
    if manifest_bytes != binding.manifest_bytes(&members[BundleMember::Image.index()].hash) {
        bail!("manifest de publicação não está em forma canônica ou diverge da invocação atual");
    }
    Ok(ValidatedBundle {
        members,
        request_hash: binding.request_hash(),
    })
}

#[derive(Clone, Debug)]
struct PublicationBinding {
    parent_dev: u64,
    parent_ino: u64,
    output: String,
    profile_lock_hash: String,
    mode: String,
    format: String,
    boot_hash: String,
    minipax_hash: String,
    tool: String,
    payload_hash: String,
    profile_name: String,
    profile_class: String,
    media_class: String,
    arch: String,
}

impl PublicationBinding {
    fn request_bytes(&self) -> Vec<u8> {
        format!(
            "MEDIA_REQUEST_FORMAT=1\nOUTPUT_NAME={}\nPROFILE_LOCK_SHA256={}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nMEDIA_CLASS={}\nARCH={}\nMODE={}\nFORMAT={}\nBOOT_EFI_SHA256={}\nMINIPAX_EXECUTABLE_SHA256={}\nTOOL={}\nMEDIA_INPUT_SHA256={}\n",
            self.output,
            self.profile_lock_hash,
            self.profile_name,
            self.profile_class,
            self.media_class,
            self.arch,
            self.mode,
            self.format,
            self.boot_hash,
            self.minipax_hash,
            self.tool,
            self.payload_hash,
        )
        .into_bytes()
    }

    fn request_hash(&self) -> String {
        sha256(&self.request_bytes())
    }

    fn manifest_bytes(&self, image_hash: &str) -> Vec<u8> {
        format!(
            "MEDIA_MANIFEST_FORMAT=1\nMEDIA_SHA256={image_hash}\nMEDIA_INPUT_SHA256={}\nMEDIA_REQUEST_SHA256={}\nPROFILE_LOCK_SHA256={}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nMEDIA_CLASS={}\nARCH={}\nMODE={}\nFORMAT={}\nBOOT_EFI_SHA256={}\nMINIPAX_EXECUTABLE_SHA256={}\nTOOL={}\n",
            self.payload_hash,
            self.request_hash(),
            self.profile_lock_hash,
            self.profile_name,
            self.profile_class,
            self.media_class,
            self.arch,
            self.mode,
            self.format,
            self.boot_hash,
            self.minipax_hash,
            self.tool,
        )
        .into_bytes()
    }

    fn owner_bytes(&self) -> Vec<u8> {
        format!(
            "MEDIA_STAGE_FORMAT={MEDIA_PUBLISH_FORMAT}\nPARENT_DEV={}\nPARENT_INO={}\nOUTPUT_NAME={}\nREQUEST_SHA256={}\nPROFILE_LOCK_SHA256={}\nMODE={}\nFORMAT={}\nBOOT_EFI_SHA256={}\nMINIPAX_EXECUTABLE_SHA256={}\nTOOL={}\n",
            self.parent_dev,
            self.parent_ino,
            self.output,
            self.request_hash(),
            self.profile_lock_hash,
            self.mode,
            self.format,
            self.boot_hash,
            self.minipax_hash,
            self.tool,
        )
        .into_bytes()
    }
}

fn ready_bytes(binding: &PublicationBinding, members: &[FileSeal; 4]) -> Vec<u8> {
    let mut ready = format!(
        "MEDIA_PUBLISH_FORMAT={MEDIA_PUBLISH_FORMAT}\nPARENT_DEV={}\nPARENT_INO={}\nOUTPUT_NAME={}\nREQUEST_SHA256={}\nPROFILE_LOCK_SHA256={}\nMODE={}\nFORMAT={}\nBOOT_EFI_SHA256={}\nMINIPAX_EXECUTABLE_SHA256={}\nTOOL={}\n",
        binding.parent_dev,
        binding.parent_ino,
        binding.output,
        binding.request_hash(),
        binding.profile_lock_hash,
        binding.mode,
        binding.format,
        binding.boot_hash,
        binding.minipax_hash,
        binding.tool,
    );
    for member in BUNDLE_MEMBERS {
        let seal = &members[member.index()];
        ready.push_str(&format!(
            "{}_DEV={}\n{}_INO={}\n{}_LEN={}\n{}_UID={}\n{}_MODE={}\n{}_NLINK={}\n{}_MTIME={}\n{}_MTIME_NSEC={}\n{}_SHA256={}\n",
            member.field(),
            seal.dev,
            member.field(),
            seal.ino,
            member.field(),
            seal.len,
            member.field(),
            seal.uid,
            member.field(),
            seal.mode,
            member.field(),
            seal.nlink,
            member.field(),
            seal.mtime,
            member.field(),
            seal.mtime_nsec,
            member.field(),
            seal.hash,
        ));
    }
    ready.into_bytes()
}

fn parse_fields(text: &str, what: &str) -> Result<std::collections::BTreeMap<String, String>> {
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{what} contém linha inválida"))?;
        if key.is_empty() || value.is_empty() || fields.insert(key.into(), value.into()).is_some() {
            bail!("{what} contém campo vazio ou duplicado: {key}");
        }
    }
    Ok(fields)
}

fn parse_ready(bytes: &[u8], binding: &PublicationBinding) -> Result<[FileSeal; 4]> {
    let text = std::str::from_utf8(bytes).context("READY não é UTF-8")?;
    let fields = parse_fields(text, "READY")?;
    let required = |key: &str| -> Result<&str> {
        fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| anyhow::anyhow!("READY não contém {key}"))
    };
    for (key, expected) in [
        ("MEDIA_PUBLISH_FORMAT", MEDIA_PUBLISH_FORMAT.to_string()),
        ("PARENT_DEV", binding.parent_dev.to_string()),
        ("PARENT_INO", binding.parent_ino.to_string()),
        ("OUTPUT_NAME", binding.output.clone()),
        ("REQUEST_SHA256", binding.request_hash()),
        ("PROFILE_LOCK_SHA256", binding.profile_lock_hash.clone()),
        ("MODE", binding.mode.clone()),
        ("FORMAT", binding.format.clone()),
        ("BOOT_EFI_SHA256", binding.boot_hash.clone()),
        ("MINIPAX_EXECUTABLE_SHA256", binding.minipax_hash.clone()),
        ("TOOL", binding.tool.clone()),
    ] {
        if required(key)? != expected {
            bail!("READY diverge da invocação atual em {key}");
        }
    }
    let members = BUNDLE_MEMBERS.map(|member| -> Result<FileSeal> {
        let field = member.field();
        let dev = required(&format!("{field}_DEV"))?.parse()?;
        let ino = required(&format!("{field}_INO"))?.parse()?;
        let len = required(&format!("{field}_LEN"))?.parse()?;
        let uid = required(&format!("{field}_UID"))?.parse()?;
        let mode = required(&format!("{field}_MODE"))?.parse()?;
        let nlink = required(&format!("{field}_NLINK"))?.parse()?;
        let mtime = required(&format!("{field}_MTIME"))?.parse()?;
        let mtime_nsec = required(&format!("{field}_MTIME_NSEC"))?.parse()?;
        let hash = required(&format!("{field}_SHA256"))?.to_string();
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("READY contém hash inválido para {field}");
        }
        Ok(FileSeal {
            dev,
            ino,
            len,
            uid,
            mode,
            nlink,
            mtime,
            mtime_nsec,
            hash,
        })
    });
    let members: [FileSeal; 4] = members
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .expect("quatro membros");
    for (member, seal) in BUNDLE_MEMBERS.into_iter().zip(members.iter()) {
        if seal.dev != binding.parent_dev
            || seal.uid != effective_uid()?
            || seal.mode & 0o022 != 0
            || seal.nlink != 1
        {
            bail!(
                "READY contém autoria/permissões/links inválidos para {}",
                member.label()
            );
        }
    }
    if members[BundleMember::MediaLock.index()].hash != binding.profile_lock_hash {
        bail!("READY descreve media.lock diferente da invocação atual");
    }
    if fields.len() != 11 + BUNDLE_MEMBERS.len() * 9 {
        bail!("READY contém campos desconhecidos");
    }
    if bytes != ready_bytes(binding, &members) {
        bail!("READY não está em forma canônica");
    }
    Ok(members)
}

fn stage_stat_at(directory: &File, name: &str) -> Result<Option<(u64, u64)>> {
    match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some((stat.st_dev, stat.st_ino))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

fn stage_stat(parent: &ParentAnchor, name: &str) -> Result<Option<(u64, u64)>> {
    stage_stat_at(&parent.file, name)
}

fn open_stage_at(directory: &File, parent_dev: u64, name: &str) -> Result<Option<StageAnchor>> {
    match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => StageAnchor::from_fd(File::from(fd), name.to_string(), parent_dev).map(Some),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(std::io::Error::from(error))
            .with_context(|| format!("não abri staging real ancorado: {name}")),
    }
}

fn open_stage(parent: &ParentAnchor, name: &str) -> Result<Option<StageAnchor>> {
    open_stage_at(&parent.file, parent.dev, name)
}

fn control_temp_name(name: &str) -> String {
    format!(".{name}.tmp")
}

fn unlink_private_regular(stage: &StageAnchor, name: &str, what: &str) -> Result<()> {
    let Some(file) = open_regular_at(&stage.file, name, what)? else {
        return Ok(());
    };
    validate_owned_regular(&file.metadata()?, what, 2)?;
    rustix::fs::unlinkat(&stage.file, name, rustix::fs::AtFlags::empty())
        .map_err(std::io::Error::from)
        .with_context(|| format!("não removi {what} do stage privado"))
}

fn reconcile_control_temp(stage: &StageAnchor, name: &str) -> Result<()> {
    let temp = control_temp_name(name);
    let final_seal = seal_at_with_links(&stage.file, name, name, 2)?;
    let temp_seal = seal_at_with_links(&stage.file, &temp, &temp, 2)?;
    match (final_seal, temp_seal) {
        (_, None) => Ok(()),
        (None, Some(_)) => {
            // A queda ocorreu antes da promoção do controle. Nenhuma fase
            // posterior pode depender deste temporário não publicado.
            unlink_private_regular(stage, &temp, &temp)?;
            stage.sync()
        }
        (Some(final_seal), Some(temp_seal))
            if final_seal.dev == temp_seal.dev
                && final_seal.ino == temp_seal.ino
                && final_seal.nlink == 2
                && temp_seal.nlink == 2 =>
        {
            // Queda entre linkat e unlinkat no fallback de um controle.
            unlink_private_regular(stage, &temp, &temp)?;
            stage.sync()
        }
        (Some(_), Some(_)) => {
            bail!("controle {name} e seu temporário existem com identidades diferentes")
        }
    }
}

fn read_stage_control(stage: &StageAnchor, name: &str, what: &str) -> Result<Option<Vec<u8>>> {
    reconcile_control_temp(stage, name)?;
    read_control_at(&stage.file, name, what)
}

fn write_control_atomic_at(stage: &StageAnchor, name: &str, bytes: &[u8]) -> Result<FileSeal> {
    reconcile_control_temp(stage, name)?;
    if open_regular_at(&stage.file, name, name)?.is_some() {
        bail!("controle {name} já existe");
    }
    let temp = control_temp_name(name);
    write_new_at_mode(
        &stage.file,
        &temp,
        bytes,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    stage.sync()?;
    move_noreplace(&stage.file, &temp, &stage.file, name)?;
    stage.sync()?;
    let observed = read_control_at(&stage.file, name, name)?
        .ok_or_else(|| anyhow::anyhow!("controle {name} sumiu após promoção"))?;
    if observed != bytes {
        bail!("controle {name} mudou durante a promoção");
    }
    seal_at(&stage.file, name, name)?.ok_or_else(|| anyhow::anyhow!("controle {name} sumiu"))
}

fn create_stage(
    parent: &ParentAnchor,
    names: &PublicationNames,
    binding: &PublicationBinding,
) -> Result<StageAnchor> {
    rustix::fs::mkdirat(&parent.file, names.stage.as_str(), rustix::fs::Mode::RWXU)
        .map_err(std::io::Error::from)
        .with_context(|| format!("não criei staging privado: {}", names.stage))?;
    let stage = open_stage(parent, &names.stage)?.expect("diretório recém-criado");
    let setup = (|| {
        write_control_atomic_at(&stage, "OWNER", &binding.owner_bytes())?;
        write_control_atomic_at(&stage, "REQUEST", &binding.request_bytes())?;
        stage.sync()?;
        parent.sync()?;
        Ok(())
    })();
    if let Err(error) = setup {
        let cleanup = cleanup_stage(parent, &stage, names, binding, None, None);
        return Err(publication_error(error, cleanup));
    }
    Ok(stage)
}

fn ensure_stage_bound(parent: &ParentAnchor, stage: &StageAnchor) -> Result<()> {
    if stage_stat(parent, &stage.name)? != Some((stage.dev, stage.ino)) {
        bail!("o nome do staging foi trocado durante a publicação");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MoveMethod {
    RenameNoreplace,
    HardlinkFallback,
}

fn move_noreplace_with<F>(
    from_dir: &File,
    from: &str,
    to_dir: &File,
    to: &str,
    rename_noreplace: F,
) -> Result<MoveMethod>
where
    F: FnOnce() -> rustix::io::Result<()>,
{
    match rename_noreplace() {
        Ok(()) => Ok(MoveMethod::RenameNoreplace),
        Err(rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) => {
            // Compatibilidade com kernels/filesystems antigos: somente este
            // ramo usa hardlink. O caminho normal funciona inclusive onde
            // hardlinks não existem.
            rustix::fs::linkat(from_dir, from, to_dir, to, rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
            rustix::fs::unlinkat(from_dir, from, rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
            Ok(MoveMethod::HardlinkFallback)
        }
        Err(error) => Err(std::io::Error::from(error)).with_context(|| {
            format!("não promovi {to} atomicamente sem substituir nome existente")
        }),
    }
}

fn move_noreplace(from_dir: &File, from: &str, to_dir: &File, to: &str) -> Result<MoveMethod> {
    move_noreplace_with(from_dir, from, to_dir, to, || {
        rustix::fs::renameat_with(
            from_dir,
            from,
            to_dir,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    })
}

fn rename_noreplace_compat_with<F>(
    from_dir: &File,
    from: &str,
    to_dir: &File,
    to: &str,
    rename_noreplace: F,
) -> Result<()>
where
    F: FnOnce() -> rustix::io::Result<()>,
{
    match rename_noreplace() {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) => {
            // Não há primitiva NOREPLACE em kernels antigos. O destino é um
            // nome reservado dentro do stage privado (ou seu tombstone
            // validado); conferir ausência e usar renameat preserva a
            // compatibilidade sem criar um terceiro hardlink.
            match rustix::fs::statat(to_dir, to, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Ok(_) => bail!("destino reservado já existe durante rename compatível: {to}"),
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            rustix::fs::renameat(from_dir, from, to_dir, to)
                .map_err(std::io::Error::from)
                .with_context(|| format!("não movi {from} para {to} sem renameat2"))
        }
        Err(error) => Err(std::io::Error::from(error))
            .with_context(|| format!("não movi {from} para {to} sem substituir nome existente")),
    }
}

fn rename_noreplace_compat(from_dir: &File, from: &str, to_dir: &File, to: &str) -> Result<()> {
    rename_noreplace_compat_with(from_dir, from, to_dir, to, || {
        rustix::fs::renameat_with(
            from_dir,
            from,
            to_dir,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    })
}

fn ensure_member_state(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    member: BundleMember,
    expected: &FileSeal,
) -> Result<()> {
    ensure_stage_bound(parent, stage)?;
    parent.ensure_still_named()?;
    let staged = seal_at_with_links(&stage.file, member.staged_name(), member.label(), 2)?;
    let final_seal = seal_at_with_links(&parent.file, names.final_name(member), member.label(), 2)?;
    match (staged, final_seal) {
        (Some(staged), None) if &staged == expected => {
            let _method = move_noreplace(
                &stage.file,
                member.staged_name(),
                &parent.file,
                names.final_name(member),
            )?;
            parent.sync()?;
            let observed = seal_at(&parent.file, names.final_name(member), member.label())?
                .ok_or_else(|| anyhow::anyhow!("{} sumiu após promoção", member.label()))?;
            if &observed != expected {
                bail!("{} mudou durante a promoção", member.label());
            }
            Ok(())
        }
        (None, Some(final_seal)) if &final_seal == expected => Ok(()),
        (Some(staged), Some(final_seal))
            if same_ready_identity(&staged, expected)
                && same_ready_identity(&final_seal, expected)
                && staged.dev == final_seal.dev
                && staged.ino == final_seal.ino =>
        {
            if staged.nlink != 2 || final_seal.nlink != 2 {
                bail!(
                    "{} tem fallback interrompido com nlink diferente de 2",
                    member.label()
                );
            }
            // Queda entre linkat e unlinkat no fallback. O nome removido fica
            // no staging privado, nunca no diretório público.
            rustix::fs::unlinkat(
                &stage.file,
                member.staged_name(),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(std::io::Error::from)?;
            stage.sync()?;
            Ok(())
        }
        (Some(_), None) => bail!("{} preparado diverge de READY", member.label()),
        (None, Some(_)) => bail!("{} final diverge de READY", member.label()),
        (Some(_), Some(_)) => bail!(
            "{} existe simultaneamente no staging e no destino com identidades diferentes",
            member.label()
        ),
        (None, None) => bail!("{} sumiu do staging e do destino", member.label()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishPhase {
    Staged,
    Validated,
    Sealed,
    Sha256Promoted,
    MediaLockPromoted,
    ManifestPromoted,
    SidecarsSynced,
    ImagePromoted,
    PublishedValidated,
    Committed,
    CleanupUnsealed,
    CleanupImageRemoved,
    CleanupSha256Removed,
    CleanupMediaLockRemoved,
    CleanupManifestRemoved,
    StageCapturedBeforeRemove,
    StageRemovedBeforeSync,
}

fn promoted_phase(member: BundleMember) -> PublishPhase {
    match member {
        BundleMember::Image => PublishPhase::ImagePromoted,
        BundleMember::Sha256 => PublishPhase::Sha256Promoted,
        BundleMember::MediaLock => PublishPhase::MediaLockPromoted,
        BundleMember::Manifest => PublishPhase::ManifestPromoted,
    }
}

fn cleanup_phase(member: BundleMember) -> PublishPhase {
    match member {
        BundleMember::Image => PublishPhase::CleanupImageRemoved,
        BundleMember::Sha256 => PublishPhase::CleanupSha256Removed,
        BundleMember::MediaLock => PublishPhase::CleanupMediaLockRemoved,
        BundleMember::Manifest => PublishPhase::CleanupManifestRemoved,
    }
}

fn member_names_staged() -> [&'static str; 4] {
    BUNDLE_MEMBERS.map(BundleMember::staged_name)
}

fn member_names_final(names: &PublicationNames) -> [&str; 4] {
    [
        names.final_name(BundleMember::Image),
        names.final_name(BundleMember::Sha256),
        names.final_name(BundleMember::MediaLock),
        names.final_name(BundleMember::Manifest),
    ]
}

fn complete_promotion<F>(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    binding: &PublicationBinding,
    expected: &[FileSeal; 4],
    checkpoint: &mut F,
) -> Result<ValidatedBundle>
where
    F: FnMut(PublishPhase) -> Result<()>,
{
    for member in PROMOTION_ORDER.iter().copied().take(3) {
        ensure_member_state(parent, stage, names, member, &expected[member.index()])?;
        checkpoint(promoted_phase(member))?;
    }
    parent.sync()?;
    checkpoint(PublishPhase::SidecarsSynced)?;
    ensure_member_state(
        parent,
        stage,
        names,
        BundleMember::Image,
        &expected[BundleMember::Image.index()],
    )?;
    parent.sync()?;
    checkpoint(PublishPhase::ImagePromoted)?;
    let published = validate_bundle_at(
        &parent.file,
        &member_names_final(names),
        &names.output,
        binding,
    )?;
    if published.members != *expected || published.request_hash != binding.request_hash() {
        bail!("conjunto final diverge de READY ou da invocação atual");
    }
    parent.ensure_still_named()?;
    checkpoint(PublishPhase::PublishedValidated)?;
    Ok(published)
}

fn move_back_owned(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    member: BundleMember,
    expected: &FileSeal,
) -> Result<()> {
    let final_name = names.final_name(member);
    let staged = seal_at_with_links(&stage.file, member.staged_name(), member.label(), 2)?;
    let final_seal = seal_at_with_links(&parent.file, final_name, member.label(), 2)?;
    match (staged, final_seal) {
        (Some(staged), None) if &staged == expected => Ok(()),
        (None, Some(final_seal)) if &final_seal == expected => {
            rename_noreplace_compat(&parent.file, final_name, &stage.file, member.staged_name())?;
            let moved = seal_at(&stage.file, member.staged_name(), member.label())?
                .ok_or_else(|| anyhow::anyhow!("{} sumiu no rollback", member.label()))?;
            if &moved != expected {
                // Não apaga substituto estrangeiro: tenta devolvê-lo ao nome
                // de onde veio, também sem substituição.
                let _ = rename_noreplace_compat(
                    &stage.file,
                    member.staged_name(),
                    &parent.file,
                    final_name,
                );
                bail!("{} foi substituído antes do rollback", member.label());
            }
            stage.sync()?;
            parent.sync()?;
            Ok(())
        }
        (Some(staged), Some(final_seal))
            if same_ready_identity(&staged, expected)
                && same_ready_identity(&final_seal, expected)
                && staged.dev == final_seal.dev
                && staged.ino == final_seal.ino =>
        {
            if staged.nlink != 2 || final_seal.nlink != 2 {
                bail!(
                    "{} tem rollback interrompido com nlink diferente de 2",
                    member.label()
                );
            }
            let rollback_name = format!("{}.rollback", member.staged_name());
            rename_noreplace_compat(
                &parent.file,
                final_name,
                &stage.file,
                rollback_name.as_str(),
            )?;
            let rollback = seal_at_with_links(&stage.file, &rollback_name, member.label(), 2)?
                .ok_or_else(|| anyhow::anyhow!("rollback temporário sumiu"))?;
            if !same_ready_identity(&rollback, expected) || rollback.nlink != 2 {
                let _ = rename_noreplace_compat(
                    &stage.file,
                    rollback_name.as_str(),
                    &parent.file,
                    final_name,
                );
                bail!("{} foi substituído antes do rollback", member.label());
            }
            rustix::fs::unlinkat(
                &stage.file,
                rollback_name.as_str(),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(std::io::Error::from)?;
            stage.sync()?;
            parent.sync()?;
            Ok(())
        }
        (Some(_), None) => bail!("{} preparado diverge de READY", member.label()),
        (None, Some(_)) => bail!("{} final não pertence a esta geração", member.label()),
        (Some(_), Some(_)) => bail!("{} tem duas identidades no rollback", member.label()),
        (None, None) => bail!("{} sumiu durante o rollback", member.label()),
    }
}

fn rollback_promotion(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    expected: &[FileSeal; 4],
) -> Result<()> {
    let mut failures = Vec::new();
    for member in PROMOTION_ORDER.iter().copied().rev() {
        if let Err(error) = move_back_owned(parent, stage, names, member, &expected[member.index()])
        {
            failures.push(format!("{}: {error:#}", member.label()));
        }
    }
    if !failures.is_empty() {
        bail!("rollback incompleto: {}", failures.join("; "));
    }
    Ok(())
}

fn remove_stage_regular(
    stage: &StageAnchor,
    name: &str,
    expected_seal: Option<&FileSeal>,
    expected_bytes: Option<&[u8]>,
) -> Result<()> {
    let Some(observed) = seal_at_with_links(&stage.file, name, name, 2)? else {
        return Ok(());
    };
    if expected_seal
        .is_some_and(|expected| !same_ready_identity(&observed, expected) || observed.nlink > 2)
    {
        bail!("não limpei {name}: inode/conteúdo diverge do journal");
    }
    let bytes_match = if let Some(expected) = expected_bytes {
        read_control_at(&stage.file, name, name)?.as_deref() == Some(expected)
    } else {
        true
    };
    if !bytes_match {
        bail!("não limpei {name}: conteúdo diverge do journal");
    }
    // O diretório é 0700, do UID efetivo e no mesmo filesystem do parent.
    // Outro UID não consegue trocar este nome; o mesmo UID já controla o
    // namespace de saída e é a fronteira de ameaça documentada do protocolo.
    unlink_private_regular(stage, name, name)
}

fn cleanup_iso_workspace(stage: &StageAnchor) -> Result<()> {
    let workspace = stage.child_path("iso-workspace");
    match fs::symlink_metadata(&workspace) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("não inspecionei workspace ISO recuperável"),
        Ok(metadata) if metadata.file_type().is_dir() => {
            // O ancestral é o fd do stage privado, não seu pathname original.
            // Assim uma troca do parent não redireciona a limpeza recursiva.
            fs::remove_dir_all(&workspace).context("não limpei workspace ISO recuperável")?;
            stage.sync()
        }
        Ok(_) => bail!("iso-workspace não é diretório real dentro do stage privado"),
    }
}

fn capture_and_remove_stage(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    mut checkpoint: Option<&mut dyn FnMut(PublishPhase) -> Result<()>>,
) -> Result<()> {
    ensure_stage_bound(parent, stage)?;
    if stage_stat(parent, &names.stage_cleanup)?.is_some() {
        bail!("tombstone de cleanup do staging já existe");
    }
    // O container é reservado atomicamente por mkdirat. A movimentação
    // seguinte usa renameat para um nome dentro deste diretório 0700; assim o
    // fallback não depende de renameat2 nem pode sobrescrever nome plantado
    // por outro UID no diretório público.
    rustix::fs::mkdirat(
        &parent.file,
        names.stage_cleanup.as_str(),
        rustix::fs::Mode::RWXU,
    )
    .map_err(std::io::Error::from)
    .context("não reservei container privado de cleanup")?;
    let tombstone = open_stage(parent, &names.stage_cleanup)?.expect("container recém-criado");
    parent.sync()?;
    ensure_stage_bound(parent, stage)?;
    rustix::fs::renameat(&parent.file, stage.name.as_str(), &tombstone.file, "stage")
        .map_err(std::io::Error::from)
        .context("não capturei staging dentro do container privado")?;
    if stage_stat_at(&tombstone.file, "stage")? != Some((stage.dev, stage.ino)) {
        bail!("não capturei o inode esperado do staging para cleanup");
    }
    tombstone.sync()?;
    parent.sync()?;
    if let Some(checkpoint) = checkpoint.as_mut() {
        (*checkpoint)(PublishPhase::StageCapturedBeforeRemove)?;
    }
    rustix::fs::unlinkat(&tombstone.file, "stage", rustix::fs::AtFlags::REMOVEDIR)
        .map_err(std::io::Error::from)
        .context("não removi staging vazio capturado")?;
    tombstone.sync()?;
    if stage_stat(parent, &names.stage_cleanup)? != Some((tombstone.dev, tombstone.ino)) {
        bail!("container de cleanup foi trocado antes da remoção");
    }
    rustix::fs::unlinkat(
        &parent.file,
        names.stage_cleanup.as_str(),
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(std::io::Error::from)
    .context("não removi container vazio do cleanup")?;
    if let Some(checkpoint) = checkpoint.as_mut() {
        (*checkpoint)(PublishPhase::StageRemovedBeforeSync)?;
    }
    parent.sync()
}

fn recover_stage_cleanup(parent: &ParentAnchor, names: &PublicationNames) -> Result<()> {
    let Some(tombstone) = open_stage(parent, &names.stage_cleanup)? else {
        return Ok(());
    };
    let canonical = stage_stat(parent, &names.stage)?;
    let captured = open_stage_at(&tombstone.file, parent.dev, "stage")?;
    if canonical.is_some() && captured.is_some() {
        bail!("staging canônico e capturado coexistem");
    }
    if let Some(captured) = captured {
        rustix::fs::unlinkat(&tombstone.file, "stage", rustix::fs::AtFlags::REMOVEDIR)
            .map_err(std::io::Error::from)
            .context("staging capturado não está vazio e não será removido")?;
        drop(captured);
        tombstone.sync()?;
    }
    if stage_stat(parent, &names.stage_cleanup)? != Some((tombstone.dev, tombstone.ino)) {
        bail!("tombstone de cleanup foi trocado durante a recuperação");
    }
    rustix::fs::unlinkat(
        &parent.file,
        names.stage_cleanup.as_str(),
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(std::io::Error::from)
    .context("container de cleanup não está vazio e não será removido")?;
    parent.sync()
}

fn cleanup_stage(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    binding: &PublicationBinding,
    expected: Option<&[FileSeal; 4]>,
    mut checkpoint: Option<&mut dyn FnMut(PublishPhase) -> Result<()>>,
) -> Result<()> {
    ensure_stage_bound(parent, stage)?;
    for control in ["OWNER", "REQUEST", "READY", "COMMITTED"] {
        reconcile_control_temp(stage, control)?;
    }
    // READY é a autorização durável para promoção. Invalide-a e sincronize o
    // diretório antes de apagar qualquer byte descrito por ela. Assim, uma
    // queda durante o cleanup sempre retorna pelo ramo unsealed, nunca tenta
    // promover um conjunto que o próprio cleanup já começou a desmontar.
    let committed = format!("REQUEST_SHA256={}\n", binding.request_hash()).into_bytes();
    let ready = expected.map(|members| ready_bytes(binding, members));
    for (name, exact) in [("COMMITTED", Some(committed)), ("READY", ready)] {
        remove_stage_regular(stage, name, None, exact.as_deref())?;
        remove_stage_regular(stage, &control_temp_name(name), None, None)?;
    }
    stage.sync()?;
    if let Some(checkpoint) = checkpoint.as_mut() {
        (*checkpoint)(PublishPhase::CleanupUnsealed)?;
    }

    cleanup_iso_workspace(stage)?;
    for member in BUNDLE_MEMBERS {
        remove_stage_regular(
            stage,
            member.staged_name(),
            expected.map(|members| &members[member.index()]),
            None,
        )?;
        remove_stage_regular(
            stage,
            &format!("{}.rollback", member.staged_name()),
            None,
            None,
        )?;
        if let Some(checkpoint) = checkpoint.as_mut() {
            (*checkpoint)(cleanup_phase(member))?;
        }
    }
    for (name, exact) in [
        ("REQUEST", Some(binding.request_bytes())),
        ("OWNER", Some(binding.owner_bytes())),
    ] {
        remove_stage_regular(stage, name, None, exact.as_deref())?;
        remove_stage_regular(stage, &control_temp_name(name), None, None)?;
    }
    stage.sync()?;
    capture_and_remove_stage(parent, stage, names, checkpoint)
}

fn publication_error(error: anyhow::Error, cleanup: Result<()>) -> anyhow::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup) => anyhow::anyhow!("{error:#}; além disso, {cleanup:#}"),
    }
}

fn final_member_count(parent: &ParentAnchor, names: &PublicationNames) -> Result<usize> {
    let mut count = 0;
    for member in BUNDLE_MEMBERS {
        if open_regular_at(&parent.file, names.final_name(member), member.label())?.is_some() {
            count += 1;
        }
    }
    Ok(count)
}

fn recognize_complete_output(
    parent: &ParentAnchor,
    names: &PublicationNames,
    binding: &PublicationBinding,
) -> Result<Option<String>> {
    match final_member_count(parent, names)? {
        0 => Ok(None),
        4 => {
            // Idempotência é deliberada para um bundle completo e canônico do
            // UID efetivo. O mesmo UID controla o namespace; outro UID, modo
            // gravável ou hardlinks adicionais são recusados pelo selamento.
            let bundle = validate_bundle_at(
                &parent.file,
                &member_names_final(names),
                &names.output,
                binding,
            )?;
            if bundle.request_hash != binding.request_hash() {
                bail!("conjunto final existente pertence a outra invocação");
            }
            Ok(Some(bundle.image_hash().to_string()))
        }
        _ => Ok(None),
    }
}

fn remove_empty_stage(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    checkpoint: &mut dyn FnMut(PublishPhase) -> Result<()>,
) -> Result<()> {
    ensure_stage_bound(parent, stage)?;
    // Temporários de controles são os únicos resíduos admitidos antes de
    // OWNER. São conhecidos, privados e podem ser descartados no retry.
    for control in ["OWNER", "REQUEST", "READY", "COMMITTED"] {
        reconcile_control_temp(stage, control)?;
    }
    capture_and_remove_stage(parent, stage, names, Some(checkpoint))
}

fn recover_publication<F>(
    parent: &ParentAnchor,
    names: &PublicationNames,
    binding: &PublicationBinding,
    checkpoint: &mut F,
) -> Result<Option<String>>
where
    F: FnMut(PublishPhase) -> Result<()>,
{
    recover_stage_cleanup(parent, names)?;
    // Um conjunto completo coerente é o recibo idempotente depois que o stage
    // foi removido. Isso fecha a janela remove(stage) -> fsync(parent).
    if let Some(image_hash) = recognize_complete_output(parent, names, binding)? {
        if let Some(stage) = open_stage(parent, &names.stage)? {
            match read_stage_control(&stage, "OWNER", "OWNER")? {
                Some(owner) if owner == binding.owner_bytes() => {
                    let expected = read_stage_control(&stage, "READY", "READY")?
                        .map(|ready| parse_ready(&ready, binding))
                        .transpose()?;
                    if let Err(error) = cleanup_stage(
                        parent,
                        &stage,
                        names,
                        binding,
                        expected.as_ref(),
                        Some(checkpoint),
                    ) {
                        eprintln!(
                            "aviso: conjunto final está íntegro, mas o staging não foi limpo: {error:#}"
                        );
                    }
                }
                None => {
                    if let Err(error) = remove_empty_stage(parent, &stage, names, checkpoint) {
                        eprintln!(
                            "aviso: conjunto final está íntegro, mas o staging sem OWNER não estava vazio: {error:#}"
                        );
                    }
                }
                Some(_) => {}
            }
        }
        parent.ensure_still_named()?;
        return Ok(Some(image_hash));
    }
    let Some(stage) = open_stage(parent, &names.stage)? else {
        let count = final_member_count(parent, names)?;
        if count != 0 {
            bail!("há conjunto final parcial sem journal recuperável ({count} de 4 membros)");
        }
        return Ok(None);
    };
    let owner = read_stage_control(&stage, "OWNER", "OWNER")?;
    if owner.is_none() {
        // Janela mkdir -> OWNER: só um diretório realmente vazio é nosso para
        // remover sem adivinhar propriedade de conteúdo desconhecido.
        remove_empty_stage(parent, &stage, names, checkpoint)?;
        return Ok(None);
    }
    if owner.as_deref() != Some(binding.owner_bytes().as_slice()) {
        bail!("staging pertence a profile/opções/BOOT/executor diferentes");
    }
    match read_stage_control(&stage, "REQUEST", "REQUEST")? {
        None => {
            cleanup_stage(parent, &stage, names, binding, None, Some(checkpoint))?;
            return Ok(None);
        }
        Some(request) if request != binding.request_bytes() => {
            bail!("REQUEST do staging diverge da invocação atual");
        }
        Some(_) => {}
    }
    let Some(ready) = read_stage_control(&stage, "READY", "READY")? else {
        cleanup_stage(parent, &stage, names, binding, None, Some(checkpoint))?;
        return Ok(None);
    };
    let expected = parse_ready(&ready, binding)?;
    let result = complete_promotion(parent, &stage, names, binding, &expected, checkpoint);
    let published = match result {
        Ok(published) => published,
        Err(error) => {
            let rollback = rollback_promotion(parent, &stage, names, &expected).and_then(|()| {
                cleanup_stage(parent, &stage, names, binding, Some(&expected), None)
            });
            return Err(publication_error(error, rollback));
        }
    };
    let committed = format!("REQUEST_SHA256={}\n", binding.request_hash());
    if read_stage_control(&stage, "COMMITTED", "COMMITTED")?.is_none() {
        write_control_atomic_at(&stage, "COMMITTED", committed.as_bytes())?;
        stage.sync()?;
        parent.sync()?;
    }
    checkpoint(PublishPhase::Committed)?;
    cleanup_stage(
        parent,
        &stage,
        names,
        binding,
        Some(&expected),
        Some(checkpoint),
    )?;
    parent.ensure_still_named()?;
    Ok(Some(published.image_hash().to_string()))
}

fn finish_publication<F>(
    parent: &ParentAnchor,
    stage: &StageAnchor,
    names: &PublicationNames,
    binding: &PublicationBinding,
    mut checkpoint: F,
) -> Result<String>
where
    F: FnMut(PublishPhase) -> Result<()>,
{
    if let Err(error) = checkpoint(PublishPhase::Staged) {
        return Err(publication_error(
            error,
            cleanup_stage(parent, stage, names, binding, None, None),
        ));
    }
    let staged =
        match validate_bundle_at(&stage.file, &member_names_staged(), &names.output, binding) {
            Ok(staged) => staged,
            Err(error) => {
                return Err(publication_error(
                    error,
                    cleanup_stage(parent, stage, names, binding, None, None),
                ));
            }
        };
    if staged.request_hash != binding.request_hash() {
        return Err(publication_error(
            anyhow::anyhow!("staging não pertence à invocação atual"),
            cleanup_stage(parent, stage, names, binding, None, None),
        ));
    }
    if let Err(error) = checkpoint(PublishPhase::Validated).and_then(|()| {
        write_control_atomic_at(stage, "READY", &ready_bytes(binding, &staged.members))?;
        stage.sync()?;
        parent.sync()?;
        Ok(())
    }) {
        return Err(publication_error(
            error,
            cleanup_stage(parent, stage, names, binding, None, None),
        ));
    }
    if let Err(error) = checkpoint(PublishPhase::Sealed) {
        let rollback = rollback_promotion(parent, stage, names, &staged.members).and_then(|()| {
            cleanup_stage(parent, stage, names, binding, Some(&staged.members), None)
        });
        return Err(publication_error(error, rollback));
    }
    let published = match complete_promotion(
        parent,
        stage,
        names,
        binding,
        &staged.members,
        &mut checkpoint,
    ) {
        Ok(published) => published,
        Err(error) => {
            let rollback =
                rollback_promotion(parent, stage, names, &staged.members).and_then(|()| {
                    cleanup_stage(parent, stage, names, binding, Some(&staged.members), None)
                });
            return Err(publication_error(error, rollback));
        }
    };
    write_control_atomic_at(
        stage,
        "COMMITTED",
        format!("REQUEST_SHA256={}\n", binding.request_hash()).as_bytes(),
    )?;
    stage.sync()?;
    parent.sync()?;
    checkpoint(PublishPhase::Committed)?;
    cleanup_stage(
        parent,
        stage,
        names,
        binding,
        Some(&staged.members),
        Some(&mut checkpoint),
    )?;
    parent.ensure_still_named()?;
    Ok(published.image_hash().to_string())
}

pub fn build(profile: &ResolvedProfile, options: &MediaOptions) -> Result<()> {
    let requested = crate::absolute_path(&options.output)?;
    let file_name = safe_output_name(&requested)?.to_string();
    let parent_path = requested
        .parent()
        .ok_or_else(|| anyhow::anyhow!("saída sem diretório pai"))?;
    crate::ensure_real_dir(parent_path, "diretório de saída")?;
    let parent_path = fs::canonicalize(parent_path)?;
    let output = parent_path.join(file_name);
    let names = PublicationNames::new(&output)?;
    let parent = ParentAnchor::open(&parent_path)?;
    parent.ensure_still_named()?;

    // Recovery só pode decidir depois de recalcular a identidade completa da
    // invocação: perfil/payload, modo, formato, BOOT, executor e tool externa.
    confere_identidade(profile, &options.minitrue)?;
    let (files, lock, lock_hash, profile_class, media_class, _cache_archive) =
        payload(profile, options)?;
    let payload_hash = payload_hash(&files)?;
    let boot_hash = {
        let boot = files
            .iter()
            .find(|file| file.path == "EFI/BOOT/BOOTX64.EFI")
            .expect("BOOTX64.EFI está sempre no payload");
        let mut hasher = Sha256::new();
        stream_copy(&mut *boot.reader()?, &mut hasher)?;
        hex::encode(hasher.finalize())
    };
    let minipax_hash = sha256_file(&std::env::current_exe()?)?;
    let iso_tool = match options.format {
        MediaFormat::Iso => Some(resolve_iso_tool()?),
        MediaFormat::Img => None,
    };
    let tool = iso_tool
        .as_ref()
        .map(IsoTool::identity)
        .unwrap_or_else(|| "minipax-fatfs-gpt-v1".to_string());
    let binding = PublicationBinding {
        parent_dev: parent.dev,
        parent_ino: parent.ino,
        output: names.output.clone(),
        profile_lock_hash: lock_hash.clone(),
        mode: options.mode.as_str().to_string(),
        format: options.format.as_str().to_string(),
        boot_hash: boot_hash.clone(),
        minipax_hash: minipax_hash.clone(),
        tool: tool.clone(),
        payload_hash: payload_hash.clone(),
        profile_name: profile.name.clone(),
        profile_class: profile_class.clone(),
        media_class: media_class.clone(),
        arch: profile.arch.clone(),
    };
    if let Some(image_hash) = recover_publication(&parent, &names, &binding, &mut |_| Ok(()))? {
        println!("{image_hash}  {}", output.display());
        return Ok(());
    }
    if final_member_count(&parent, &names)? != 0 {
        bail!("há saída existente e ela nunca será sobrescrita");
    }
    let stage = create_stage(&parent, &names, &binding)?;
    let preparation = (|| -> Result<()> {
        let image_path = stage.child_path(BundleMember::Image.staged_name());
        match options.format {
            MediaFormat::Img => create_img(&image_path, profile, &files, &payload_hash)?,
            MediaFormat::Iso => create_iso(
                &image_path,
                &stage.child_path("iso-workspace"),
                profile,
                &files,
                &payload_hash,
                iso_tool.as_ref().expect("resolvido para ISO"),
            )?,
        }
        // IMG já sincroniza ao desmontar o FAT; ISO sincroniza explicitamente
        // em create_iso. Reabrir ancorado prende também inode e hash.
        let image = seal_at(&stage.file, BundleMember::Image.staged_name(), "imagem")?
            .ok_or_else(|| anyhow::anyhow!("compositor não criou imagem"))?;
        let manifest = binding.manifest_bytes(&image.hash);
        write_new_at(
            &stage.file,
            BundleMember::Sha256.staged_name(),
            format!("{}  {}\n", image.hash, names.output).as_bytes(),
        )?;
        write_new_at(
            &stage.file,
            BundleMember::MediaLock.staged_name(),
            lock.as_bytes(),
        )?;
        write_new_at(&stage.file, BundleMember::Manifest.staged_name(), &manifest)?;
        stage.sync()?;
        parent.sync()?;
        Ok(())
    })();
    if let Err(error) = preparation {
        return Err(publication_error(
            error,
            cleanup_stage(&parent, &stage, &names, &binding, None, None),
        ));
    }
    let image_hash = finish_publication(&parent, &stage, &names, &binding, |_| Ok(()))?;
    println!("{image_hash}  {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileOverrides;

    fn fake_efi() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x80 + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&10u16.to_le_bytes());
        bytes
    }

    fn make_test_dir_private(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn profile_fixture() -> (tempfile::TempDir, ResolvedProfile, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        make_test_dir_private(temp.path());
        let profile_dir = temp.path().join("profile-dir");
        let newspeak = temp.path().join("newspeak");
        fs::create_dir(&profile_dir).unwrap();
        fs::create_dir(&newspeak).unwrap();
        fs::write(
            profile_dir.join("profile"),
            "PROFILE_FORMAT=1\nNAME=official\nARCH=x86_64\nSOURCE_DATE_EPOCH=1704067200\nMEDIA_SIZE_MIB=64\nSTATUS=development\n",
        )
        .unwrap();
        fs::write(profile_dir.join("target.world"), "base\n").unwrap();
        fs::write(profile_dir.join("live.world"), "busybox\n").unwrap();
        let bootstrap = profile_dir.join("channel-bootstrap");
        fs::create_dir_all(bootstrap.join("channel-config")).unwrap();
        fs::create_dir_all(bootstrap.join("channels/oficial")).unwrap();
        fs::write(
            bootstrap.join("newspeak-origem"),
            b"URL=https://example.invalid/newspeak/\nKEY=pinada\n",
        )
        .unwrap();
        fs::write(bootstrap.join("channel-config/oficial"), b"config\n").unwrap();
        fs::write(bootstrap.join("channels/oficial/index"), b"index\n").unwrap();
        fs::write(
            bootstrap.join("channels/oficial/index.minisig"),
            b"assinatura\n",
        )
        .unwrap();
        fs::create_dir(newspeak.join("base")).unwrap();
        fs::write(newspeak.join("base/recipe"), "NAME=base\n").unwrap();
        let efi = temp.path().join("BOOTX64.EFI");
        fs::write(&efi, fake_efi()).unwrap();
        let profile = ResolvedProfile::load(
            &profile_dir,
            ProfileOverrides {
                newspeak: Some(newspeak),
                ..Default::default()
            },
        )
        .unwrap();
        (temp, profile, efi)
    }

    struct PublicationFixture {
        temp: tempfile::TempDir,
        output_dir: PathBuf,
        parent: ParentAnchor,
        names: PublicationNames,
        binding: PublicationBinding,
        stage: StageAnchor,
    }

    fn test_binding(parent: &ParentAnchor, names: &PublicationNames) -> PublicationBinding {
        PublicationBinding {
            parent_dev: parent.dev,
            parent_ino: parent.ino,
            output: names.output.clone(),
            profile_lock_hash: sha256(b"PROFILE_LOCK_FORMAT=3\n"),
            mode: "online".into(),
            format: "img".into(),
            boot_hash: "b".repeat(64),
            minipax_hash: "e".repeat(64),
            tool: "minipax-fatfs-gpt-v1".into(),
            payload_hash: "p".repeat(64),
            profile_name: "teste".into(),
            profile_class: "development".into(),
            media_class: "development".into(),
            arch: "x86_64".into(),
        }
    }

    fn publication_fixture(name: &str) -> PublicationFixture {
        let temp = tempfile::tempdir().unwrap();
        let output_dir = temp.path().join("output");
        fs::create_dir(&output_dir).unwrap();
        make_test_dir_private(&output_dir);
        let output = output_dir.join(name);
        let names = PublicationNames::new(&output).unwrap();
        let parent = ParentAnchor::open(&output_dir).unwrap();
        let binding = test_binding(&parent, &names);
        let stage = create_stage(&parent, &names, &binding).unwrap();
        write_new_at(&stage.file, BundleMember::Image.staged_name(), b"imagem\n").unwrap();
        let image = seal_at(&stage.file, BundleMember::Image.staged_name(), "imagem")
            .unwrap()
            .unwrap();
        let lock = b"PROFILE_LOCK_FORMAT=3\n";
        write_new_at(
            &stage.file,
            BundleMember::Sha256.staged_name(),
            format!("{}  {name}\n", image.hash).as_bytes(),
        )
        .unwrap();
        write_new_at(&stage.file, BundleMember::MediaLock.staged_name(), lock).unwrap();
        write_new_at(
            &stage.file,
            BundleMember::Manifest.staged_name(),
            &binding.manifest_bytes(&image.hash),
        )
        .unwrap();
        stage.sync().unwrap();
        PublicationFixture {
            temp,
            output_dir,
            parent,
            names,
            binding,
            stage,
        }
    }

    fn seal_fixture(fixture: &PublicationFixture) -> [FileSeal; 4] {
        let bundle = validate_bundle_at(
            &fixture.stage.file,
            &member_names_staged(),
            &fixture.names.output,
            &fixture.binding,
        )
        .unwrap();
        write_control_atomic_at(
            &fixture.stage,
            "READY",
            &ready_bytes(&fixture.binding, &bundle.members),
        )
        .unwrap();
        fixture.stage.sync().unwrap();
        fixture.parent.sync().unwrap();
        bundle.members
    }

    fn final_path(fixture: &PublicationFixture, member: BundleMember) -> PathBuf {
        fixture.output_dir.join(fixture.names.final_name(member))
    }

    fn lstat_exists(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok()
    }

    fn assert_no_final_members(fixture: &PublicationFixture) {
        for member in BUNDLE_MEMBERS {
            assert!(
                !lstat_exists(&final_path(fixture, member)),
                "sobrou {} final",
                member.label()
            );
        }
    }

    #[test]
    fn falha_antes_do_commit_recolhe_todos_os_prefixos() {
        for failed_phase in [
            PublishPhase::Staged,
            PublishPhase::Validated,
            PublishPhase::Sealed,
            PublishPhase::Sha256Promoted,
            PublishPhase::MediaLockPromoted,
            PublishPhase::ManifestPromoted,
            PublishPhase::SidecarsSynced,
            PublishPhase::ImagePromoted,
            PublishPhase::PublishedValidated,
        ] {
            let fixture = publication_fixture(&format!("failure-{failed_phase:?}.img"));
            let error = finish_publication(
                &fixture.parent,
                &fixture.stage,
                &fixture.names,
                &fixture.binding,
                |phase| {
                    if phase == failed_phase {
                        Err(anyhow::anyhow!("falha injetada em {phase:?}"))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("falha injetada"),
                "erro inesperado em {failed_phase:?}: {error:#}"
            );
            assert_no_final_members(&fixture);
            assert!(!lstat_exists(
                &fixture.output_dir.join(&fixture.names.stage)
            ));
        }
    }

    #[test]
    fn recovery_completa_cada_prefixo_e_imagem_so_aparece_por_ultimo() {
        for prefix in 0..=PROMOTION_ORDER.len() {
            let fixture = publication_fixture(&format!("prefix-{prefix}.img"));
            let expected = seal_fixture(&fixture);
            for member in PROMOTION_ORDER.iter().copied().take(prefix) {
                ensure_member_state(
                    &fixture.parent,
                    &fixture.stage,
                    &fixture.names,
                    member,
                    &expected[member.index()],
                )
                .unwrap();
            }
            assert_eq!(
                lstat_exists(&final_path(&fixture, BundleMember::Image)),
                prefix == PROMOTION_ORDER.len()
            );
            assert_eq!(
                recover_publication(
                    &fixture.parent,
                    &fixture.names,
                    &fixture.binding,
                    &mut |_| Ok(())
                )
                .unwrap(),
                Some(expected[BundleMember::Image.index()].hash.clone())
            );
            for member in BUNDLE_MEMBERS {
                assert!(lstat_exists(&final_path(&fixture, member)));
            }
            assert!(!lstat_exists(
                &fixture.output_dir.join(&fixture.names.stage)
            ));
        }
    }

    #[test]
    fn rename_noreplace_e_o_caminho_primario_sem_exigir_hardlink() {
        let fixture = publication_fixture("rename-primary.img");
        let expected = seal_fixture(&fixture);
        let member = BundleMember::Sha256;
        let method = move_noreplace(
            &fixture.stage.file,
            member.staged_name(),
            &fixture.parent.file,
            fixture.names.final_name(member),
        )
        .unwrap();
        assert_eq!(method, MoveMethod::RenameNoreplace);
        assert!(
            seal_at(&fixture.stage.file, member.staged_name(), member.label())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            seal_at(
                &fixture.parent.file,
                fixture.names.final_name(member),
                member.label()
            )
            .unwrap(),
            Some(expected[member.index()].clone())
        );
    }

    #[test]
    fn fallback_nosys_publica_e_rollback_nao_cria_terceiro_link() {
        let fixture = publication_fixture("fallback-nosys.img");
        let expected = seal_fixture(&fixture);
        let member = BundleMember::Sha256;
        let method = move_noreplace_with(
            &fixture.stage.file,
            member.staged_name(),
            &fixture.parent.file,
            fixture.names.final_name(member),
            || Err(rustix::io::Errno::NOSYS),
        )
        .unwrap();
        assert_eq!(method, MoveMethod::HardlinkFallback);
        assert_eq!(
            seal_at(
                &fixture.parent.file,
                fixture.names.final_name(member),
                member.label()
            )
            .unwrap(),
            Some(expected[member.index()].clone())
        );

        rename_noreplace_compat_with(
            &fixture.parent.file,
            fixture.names.final_name(member),
            &fixture.stage.file,
            member.staged_name(),
            || Err(rustix::io::Errno::NOSYS),
        )
        .unwrap();
        let restored = seal_at(&fixture.stage.file, member.staged_name(), member.label())
            .unwrap()
            .unwrap();
        assert_eq!(restored, expected[member.index()]);

        rustix::fs::mkdirat(&fixture.parent.file, "fallback-dir", rustix::fs::Mode::RWXU).unwrap();
        rename_noreplace_compat_with(
            &fixture.parent.file,
            "fallback-dir",
            &fixture.parent.file,
            "fallback-dir-moved",
            || Err(rustix::io::Errno::NOSYS),
        )
        .unwrap();
        assert!(fixture.output_dir.join("fallback-dir-moved").is_dir());
    }

    #[test]
    fn recovery_fecha_fallback_interrompido_com_exatamente_dois_links() {
        let fixture = publication_fixture("fallback-interrupted.img");
        let expected = seal_fixture(&fixture);
        let member = BundleMember::Sha256;
        rustix::fs::linkat(
            &fixture.stage.file,
            member.staged_name(),
            &fixture.parent.file,
            fixture.names.final_name(member),
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(final_path(&fixture, member)).unwrap().nlink(),
            2
        );
        recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(final_path(&fixture, member)).unwrap().nlink(),
            1
        );
        assert_eq!(
            sha256_file(&final_path(&fixture, BundleMember::Image)).unwrap(),
            expected[BundleMember::Image.index()].hash
        );
    }

    #[test]
    fn request_e_sidecar_nao_dependem_do_inode_local_do_parent() {
        let first = publication_fixture("portable.img");
        let second = publication_fixture("portable.img");
        assert_ne!(
            (first.binding.parent_dev, first.binding.parent_ino),
            (second.binding.parent_dev, second.binding.parent_ino)
        );
        assert_eq!(
            first.binding.request_bytes(),
            second.binding.request_bytes()
        );
        assert_eq!(first.binding.request_hash(), second.binding.request_hash());
        assert_ne!(first.binding.owner_bytes(), second.binding.owner_bytes());
    }

    #[test]
    fn publication_sigkill_helper() {
        let Some(output_dir) = std::env::var_os("MINIPAX_MEDIA_SIGKILL_DIR") else {
            return;
        };
        let output_dir = PathBuf::from(output_dir);
        let output_name = std::env::var("MINIPAX_MEDIA_SIGKILL_OUTPUT").unwrap();
        let prefix: usize = std::env::var("MINIPAX_MEDIA_SIGKILL_PREFIX")
            .unwrap()
            .parse()
            .unwrap();
        let marker = PathBuf::from(std::env::var_os("MINIPAX_MEDIA_SIGKILL_MARKER").unwrap());
        let parent = ParentAnchor::open(&output_dir).unwrap();
        let names = PublicationNames::new(&output_dir.join(output_name)).unwrap();
        let binding = test_binding(&parent, &names);
        let stage = open_stage(&parent, &names.stage).unwrap().unwrap();
        let ready = read_stage_control(&stage, "READY", "READY")
            .unwrap()
            .unwrap();
        let expected = parse_ready(&ready, &binding).unwrap();
        for member in PROMOTION_ORDER.iter().copied().take(prefix) {
            ensure_member_state(&parent, &stage, &names, member, &expected[member.index()])
                .unwrap();
        }
        fs::write(&marker, b"ready\n").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    #[test]
    fn publication_control_sigkill_helper() {
        let Some(output_dir) = std::env::var_os("MINIPAX_MEDIA_CONTROL_KILL_DIR") else {
            return;
        };
        let output_dir = PathBuf::from(output_dir);
        let output_name = std::env::var("MINIPAX_MEDIA_CONTROL_KILL_OUTPUT").unwrap();
        let control = std::env::var("MINIPAX_MEDIA_CONTROL_KILL_NAME").unwrap();
        let marker = PathBuf::from(std::env::var_os("MINIPAX_MEDIA_CONTROL_KILL_MARKER").unwrap());
        let parent = ParentAnchor::open(&output_dir).unwrap();
        let names = PublicationNames::new(&output_dir.join(output_name)).unwrap();
        let stage = open_stage(&parent, &names.stage).unwrap().unwrap();
        write_new_at_mode(
            &stage.file,
            &control_temp_name(&control),
            b"controle interrompido",
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        fs::write(&marker, b"ready\n").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    #[test]
    fn publication_cleanup_sigkill_helper() {
        let Some(output_dir) = std::env::var_os("MINIPAX_MEDIA_CLEANUP_KILL_DIR") else {
            return;
        };
        let output_dir = PathBuf::from(output_dir);
        let output_name = std::env::var("MINIPAX_MEDIA_CLEANUP_KILL_OUTPUT").unwrap();
        let marker = PathBuf::from(std::env::var_os("MINIPAX_MEDIA_CLEANUP_KILL_MARKER").unwrap());
        let parent = ParentAnchor::open(&output_dir).unwrap();
        let names = PublicationNames::new(&output_dir.join(output_name)).unwrap();
        let binding = test_binding(&parent, &names);
        let stage = open_stage(&parent, &names.stage).unwrap().unwrap();
        finish_publication(&parent, &stage, &names, &binding, |phase| {
            if phase == PublishPhase::StageCapturedBeforeRemove {
                fs::write(&marker, b"ready\n").unwrap();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn publication_member_cleanup_sigkill_helper() {
        let Some(output_dir) = std::env::var_os("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_DIR") else {
            return;
        };
        let output_dir = PathBuf::from(output_dir);
        let output_name = std::env::var("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_OUTPUT").unwrap();
        let target = std::env::var("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_PHASE").unwrap();
        let marker =
            PathBuf::from(std::env::var_os("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_MARKER").unwrap());
        let parent = ParentAnchor::open(&output_dir).unwrap();
        let names = PublicationNames::new(&output_dir.join(output_name)).unwrap();
        let binding = test_binding(&parent, &names);
        let stage = open_stage(&parent, &names.stage).unwrap().unwrap();
        let ready = read_stage_control(&stage, "READY", "READY")
            .unwrap()
            .unwrap();
        let expected = parse_ready(&ready, &binding).unwrap();
        cleanup_stage(
            &parent,
            &stage,
            &names,
            &binding,
            Some(&expected),
            Some(&mut |phase| {
                if format!("{phase:?}") == target {
                    fs::write(&marker, b"ready\n").unwrap();
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
                Ok(())
            }),
        )
        .unwrap();
    }

    fn kill_control_writer(output_dir: &Path, output_name: &str, control: &str, marker: &Path) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "media::tests::publication_control_sigkill_helper",
                "--nocapture",
            ])
            .env("MINIPAX_MEDIA_CONTROL_KILL_DIR", output_dir)
            .env("MINIPAX_MEDIA_CONTROL_KILL_OUTPUT", output_name)
            .env("MINIPAX_MEDIA_CONTROL_KILL_NAME", control)
            .env("MINIPAX_MEDIA_CONTROL_KILL_MARKER", marker)
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if lstat_exists(marker) {
                break;
            }
            assert!(child.try_wait().unwrap().is_none(), "helper morreu cedo");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            lstat_exists(marker),
            "helper não materializou {control}.tmp"
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn sigkill_durante_cada_controle_atomico_e_recuperavel() {
        // OWNER.tmp com stage ainda sem autoria publicada.
        {
            let temp = tempfile::tempdir().unwrap();
            let output_dir = temp.path().join("output");
            fs::create_dir(&output_dir).unwrap();
            make_test_dir_private(&output_dir);
            let names = PublicationNames::new(&output_dir.join("owner-kill.img")).unwrap();
            let parent = ParentAnchor::open(&output_dir).unwrap();
            let binding = test_binding(&parent, &names);
            rustix::fs::mkdirat(&parent.file, &names.stage, rustix::fs::Mode::RWXU).unwrap();
            drop(parent);
            let marker = temp.path().join("owner-marker");
            kill_control_writer(&output_dir, &names.output, "OWNER", &marker);
            let parent = ParentAnchor::open(&output_dir).unwrap();
            assert!(
                recover_publication(&parent, &names, &binding, &mut |_| Ok(()))
                    .unwrap()
                    .is_none()
            );
        }

        for control in ["REQUEST", "READY", "COMMITTED"] {
            let fixture = publication_fixture(&format!("{}-kill.img", control.to_lowercase()));
            let expected = if control == "COMMITTED" {
                let expected = seal_fixture(&fixture);
                complete_promotion(
                    &fixture.parent,
                    &fixture.stage,
                    &fixture.names,
                    &fixture.binding,
                    &expected,
                    &mut |_| Ok(()),
                )
                .unwrap();
                Some(expected[BundleMember::Image.index()].hash.clone())
            } else {
                if control == "REQUEST" {
                    unlink_private_regular(&fixture.stage, "REQUEST", "REQUEST").unwrap();
                }
                None
            };
            let output_dir = fixture.output_dir.clone();
            let output_name = fixture.names.output.clone();
            let marker = fixture.temp.path().join(format!("{control}-marker"));
            drop(fixture.stage);
            drop(fixture.parent);
            kill_control_writer(&output_dir, &output_name, control, &marker);
            let parent = ParentAnchor::open(&output_dir).unwrap();
            let names = PublicationNames::new(&output_dir.join(&output_name)).unwrap();
            let binding = test_binding(&parent, &names);
            assert_eq!(
                recover_publication(&parent, &names, &binding, &mut |_| Ok(())).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn sigkill_entre_rename_e_unlink_do_cleanup_e_recuperavel() {
        let fixture = publication_fixture("cleanup-real-sigkill.img");
        let expected = validate_bundle_at(
            &fixture.stage.file,
            &member_names_staged(),
            &fixture.names.output,
            &fixture.binding,
        )
        .unwrap()
        .image_hash()
        .to_string();
        let marker = fixture.temp.path().join("cleanup-kill-marker");
        let output_dir = fixture.output_dir.clone();
        let output_name = fixture.names.output.clone();
        drop(fixture.stage);
        drop(fixture.parent);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "media::tests::publication_cleanup_sigkill_helper",
                "--nocapture",
            ])
            .env("MINIPAX_MEDIA_CLEANUP_KILL_DIR", &output_dir)
            .env("MINIPAX_MEDIA_CLEANUP_KILL_OUTPUT", &output_name)
            .env("MINIPAX_MEDIA_CLEANUP_KILL_MARKER", &marker)
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if lstat_exists(&marker) {
                break;
            }
            assert!(child.try_wait().unwrap().is_none(), "helper morreu cedo");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(lstat_exists(&marker));
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let names = PublicationNames::new(&output_dir.join(&output_name)).unwrap();
        assert!(lstat_exists(&output_dir.join(&names.stage_cleanup)));
        let parent = ParentAnchor::open(&output_dir).unwrap();
        let binding = test_binding(&parent, &names);
        assert_eq!(
            recover_publication(&parent, &names, &binding, &mut |_| Ok(())).unwrap(),
            Some(expected)
        );
        assert!(!lstat_exists(&output_dir.join(&names.stage_cleanup)));
    }

    #[test]
    fn sigkill_apos_cada_unlink_do_cleanup_abortivo_e_recuperavel() {
        for target in [
            PublishPhase::CleanupImageRemoved,
            PublishPhase::CleanupSha256Removed,
            PublishPhase::CleanupMediaLockRemoved,
            PublishPhase::CleanupManifestRemoved,
        ] {
            let fixture = publication_fixture(&format!("cleanup-member-{target:?}.img"));
            let expected = seal_fixture(&fixture);
            for member in PROMOTION_ORDER.iter().copied().take(3) {
                ensure_member_state(
                    &fixture.parent,
                    &fixture.stage,
                    &fixture.names,
                    member,
                    &expected[member.index()],
                )
                .unwrap();
            }
            rollback_promotion(&fixture.parent, &fixture.stage, &fixture.names, &expected).unwrap();
            assert_no_final_members(&fixture);
            let output_dir = fixture.output_dir.clone();
            let output_name = fixture.names.output.clone();
            let marker = fixture.temp.path().join(format!("{target:?}-marker"));
            drop(fixture.stage);
            drop(fixture.parent);
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "media::tests::publication_member_cleanup_sigkill_helper",
                    "--nocapture",
                ])
                .env("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_DIR", &output_dir)
                .env("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_OUTPUT", &output_name)
                .env(
                    "MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_PHASE",
                    format!("{target:?}"),
                )
                .env("MINIPAX_MEDIA_MEMBER_CLEANUP_KILL_MARKER", &marker)
                .spawn()
                .unwrap();
            for _ in 0..500 {
                if lstat_exists(&marker) {
                    break;
                }
                assert!(child.try_wait().unwrap().is_none(), "helper morreu cedo");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(lstat_exists(&marker), "helper não chegou a {target:?}");
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());

            let parent = ParentAnchor::open(&output_dir).unwrap();
            let names = PublicationNames::new(&output_dir.join(&output_name)).unwrap();
            let binding = test_binding(&parent, &names);
            let stage = open_stage(&parent, &names.stage).unwrap().unwrap();
            assert!(read_stage_control(&stage, "READY", "READY")
                .unwrap()
                .is_none());
            drop(stage);
            assert!(
                recover_publication(&parent, &names, &binding, &mut |_| Ok(()))
                    .unwrap()
                    .is_none()
            );
            assert!(!lstat_exists(&output_dir.join(&names.stage)));
            for member in BUNDLE_MEMBERS {
                assert!(!lstat_exists(&output_dir.join(names.final_name(member))));
            }
        }
    }

    #[test]
    fn sigkill_em_cada_prefixo_e_recuperavel_sem_imagem_prematura() {
        for prefix in 0..=PROMOTION_ORDER.len() {
            let fixture = publication_fixture(&format!("sigkill-{prefix}.img"));
            let expected = seal_fixture(&fixture);
            let expected_image = expected[BundleMember::Image.index()].hash.clone();
            let marker = fixture.temp.path().join("child-ready");
            let output_dir = fixture.output_dir.clone();
            let output_name = fixture.names.output.clone();
            drop(fixture.stage);
            drop(fixture.parent);

            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "media::tests::publication_sigkill_helper",
                    "--nocapture",
                ])
                .env("MINIPAX_MEDIA_SIGKILL_DIR", &output_dir)
                .env("MINIPAX_MEDIA_SIGKILL_OUTPUT", &output_name)
                .env("MINIPAX_MEDIA_SIGKILL_PREFIX", prefix.to_string())
                .env("MINIPAX_MEDIA_SIGKILL_MARKER", &marker)
                .spawn()
                .unwrap();
            for _ in 0..500 {
                if lstat_exists(&marker) {
                    break;
                }
                assert!(child.try_wait().unwrap().is_none(), "helper morreu cedo");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                lstat_exists(&marker),
                "helper não chegou ao prefixo {prefix}"
            );
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            assert_eq!(
                lstat_exists(&output_dir.join(&output_name)),
                prefix == PROMOTION_ORDER.len(),
                "imagem apareceu no prefixo {prefix}"
            );

            let parent = ParentAnchor::open(&output_dir).unwrap();
            let names = PublicationNames::new(&output_dir.join(&output_name)).unwrap();
            let binding = test_binding(&parent, &names);
            assert_eq!(
                recover_publication(&parent, &names, &binding, &mut |_| Ok(())).unwrap(),
                Some(expected_image)
            );
            for member in BUNDLE_MEMBERS {
                assert!(lstat_exists(&output_dir.join(names.final_name(member))));
            }
        }
    }

    #[test]
    fn retry_com_boot_diferente_nao_publica_geracao_antiga() {
        let fixture = publication_fixture("different-input.img");
        let expected = seal_fixture(&fixture);
        ensure_member_state(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            BundleMember::Sha256,
            &expected[BundleMember::Sha256.index()],
        )
        .unwrap();
        let mut other = fixture.binding.clone();
        other.boot_hash = "c".repeat(64);
        let error = recover_publication(&fixture.parent, &fixture.names, &other, &mut |_| Ok(()))
            .unwrap_err();
        assert!(error.to_string().contains("diferentes"));
        assert!(!lstat_exists(&final_path(&fixture, BundleMember::Image)));
        assert!(lstat_exists(&final_path(&fixture, BundleMember::Sha256)));
        assert!(lstat_exists(&fixture.output_dir.join(&fixture.names.stage)));

        // A invocação original continua capaz de recuperar sem mistura.
        recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn falha_entre_remove_stage_e_fsync_e_reconhecida_no_retry() {
        let fixture = publication_fixture("cleanup-window.img");
        let error = finish_publication(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            &fixture.binding,
            |phase| {
                if phase == PublishPhase::StageRemovedBeforeSync {
                    Err(anyhow::anyhow!("fsync injetado"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("fsync injetado"));
        assert!(!lstat_exists(
            &fixture.output_dir.join(&fixture.names.stage)
        ));
        for member in BUNDLE_MEMBERS {
            assert!(lstat_exists(&final_path(&fixture, member)));
        }
        assert!(recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(())
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn sigkill_logico_entre_capture_e_unlink_do_stage_fecha_tombstone_no_retry() {
        let fixture = publication_fixture("cleanup-tombstone.img");
        let error = finish_publication(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            &fixture.binding,
            |phase| {
                if phase == PublishPhase::StageCapturedBeforeRemove {
                    Err(anyhow::anyhow!("queda após captura"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("queda após captura"));
        assert!(!lstat_exists(
            &fixture.output_dir.join(&fixture.names.stage)
        ));
        assert!(lstat_exists(
            &fixture.output_dir.join(&fixture.names.stage_cleanup)
        ));
        assert!(recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(())
        )
        .unwrap()
        .is_some());
        assert!(!lstat_exists(
            &fixture.output_dir.join(&fixture.names.stage_cleanup)
        ));
    }

    #[test]
    fn controles_parciais_em_todas_as_fases_sao_recuperaveis() {
        // mkdir -> OWNER: só existe o temporário parcial conhecido.
        {
            let temp = tempfile::tempdir().unwrap();
            let output_dir = temp.path().join("output");
            fs::create_dir(&output_dir).unwrap();
            make_test_dir_private(&output_dir);
            let names = PublicationNames::new(&output_dir.join("owner-partial.img")).unwrap();
            let parent = ParentAnchor::open(&output_dir).unwrap();
            let binding = test_binding(&parent, &names);
            rustix::fs::mkdirat(&parent.file, &names.stage, rustix::fs::Mode::RWXU).unwrap();
            let stage = open_stage(&parent, &names.stage).unwrap().unwrap();
            write_new_at_mode(
                &stage.file,
                &control_temp_name("OWNER"),
                b"parcial",
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .unwrap();
            assert!(
                recover_publication(&parent, &names, &binding, &mut |_| Ok(()))
                    .unwrap()
                    .is_none()
            );
            assert!(!lstat_exists(&output_dir.join(&names.stage)));
        }

        // OWNER -> REQUEST e REQUEST -> READY: o temporário nunca autoriza
        // promoção e é descartado antes de limpar a preparação incompleta.
        for control in ["REQUEST", "READY"] {
            let fixture = publication_fixture(&format!("{control}-partial.img"));
            if control == "REQUEST" {
                unlink_private_regular(&fixture.stage, "REQUEST", "REQUEST").unwrap();
            }
            write_new_at_mode(
                &fixture.stage.file,
                &control_temp_name(control),
                b"parcial",
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .unwrap();
            assert!(recover_publication(
                &fixture.parent,
                &fixture.names,
                &fixture.binding,
                &mut |_| Ok(())
            )
            .unwrap()
            .is_none());
            assert_no_final_members(&fixture);
            assert!(!lstat_exists(
                &fixture.output_dir.join(&fixture.names.stage)
            ));
        }

        // Bundle já publicado + COMMITTED temporário: o bundle canônico é o
        // recibo idempotente e o temporário é recolhido.
        {
            let fixture = publication_fixture("committed-partial.img");
            let expected = seal_fixture(&fixture);
            complete_promotion(
                &fixture.parent,
                &fixture.stage,
                &fixture.names,
                &fixture.binding,
                &expected,
                &mut |_| Ok(()),
            )
            .unwrap();
            write_new_at_mode(
                &fixture.stage.file,
                &control_temp_name("COMMITTED"),
                b"parcial",
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .unwrap();
            assert!(recover_publication(
                &fixture.parent,
                &fixture.names,
                &fixture.binding,
                &mut |_| Ok(())
            )
            .unwrap()
            .is_some());
            assert!(!lstat_exists(
                &fixture.output_dir.join(&fixture.names.stage)
            ));
        }
    }

    #[test]
    fn workspace_iso_conhecido_e_recolhido_apos_queda_pre_ready() {
        let fixture = publication_fixture("iso-workspace.img");
        let workspace = fixture.stage.child_path("iso-workspace");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("tree")).unwrap();
        fs::write(workspace.join("tree/payload-grande"), b"residuo").unwrap();
        assert!(recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(())
        )
        .unwrap()
        .is_none());
        assert!(!lstat_exists(
            &fixture.output_dir.join(&fixture.names.stage)
        ));
    }

    #[test]
    fn troca_do_caminho_do_parent_nao_redireciona_publicacao() {
        let fixture = publication_fixture("parent-swap.img");
        seal_fixture(&fixture);
        let moved = fixture.temp.path().join("moved-parent");
        let foreign = fixture.temp.path().join("foreign-parent");
        fs::create_dir(&foreign).unwrap();
        fs::rename(&fixture.output_dir, &moved).unwrap();
        std::os::unix::fs::symlink(&foreign, &fixture.output_dir).unwrap();

        let error = recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("trocado"),
            "erro inesperado: {error:#}"
        );
        for name in &fixture.names.finals {
            assert!(!lstat_exists(&foreign.join(name)));
        }
    }

    #[test]
    fn parent_recusa_outro_uid_e_escrita_de_grupo_ou_outros() {
        let temp = tempfile::tempdir().unwrap();
        let trusted = temp.path().join("trusted");
        fs::create_dir(&trusted).unwrap();
        let metadata = fs::metadata(&trusted).unwrap();
        let other_uid = if metadata.uid() == u32::MAX {
            metadata.uid() - 1
        } else {
            metadata.uid() + 1
        };
        assert!(validate_parent_metadata(&metadata, other_uid).is_err());

        for (name, mode) in [("group-writable", 0o720), ("world-writable", 0o702)] {
            let path = temp.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let error = ParentAnchor::open(&path).unwrap_err();
            assert!(error.to_string().contains("grupo/outros"));
        }
    }

    #[test]
    fn troca_do_stage_por_symlink_falha_sem_tocar_no_alvo() {
        let fixture = publication_fixture("stage-swap.img");
        seal_fixture(&fixture);
        let moved = fixture.output_dir.join("moved-stage");
        let foreign = fixture.output_dir.join("foreign-stage");
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("sentinela"), b"nao tocar").unwrap();
        fs::rename(fixture.output_dir.join(&fixture.names.stage), &moved).unwrap();
        std::os::unix::fs::symlink(&foreign, fixture.output_dir.join(&fixture.names.stage))
            .unwrap();

        assert!(recover_publication(
            &fixture.parent,
            &fixture.names,
            &fixture.binding,
            &mut |_| Ok(())
        )
        .is_err());
        assert_eq!(fs::read(foreign.join("sentinela")).unwrap(), b"nao tocar");
        assert_no_final_members(&fixture);
    }

    #[test]
    fn membro_symlink_e_recusado_sem_seguir_alvo() {
        let fixture = publication_fixture("member-symlink.img");
        let target = fixture.temp.path().join("foreign-target");
        fs::write(&target, b"sentinela").unwrap();
        rustix::fs::unlinkat(
            &fixture.stage.file,
            BundleMember::Manifest.staged_name(),
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            &target,
            fixture
                .stage
                .child_path(BundleMember::Manifest.staged_name()),
        )
        .unwrap();

        assert!(finish_publication(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            &fixture.binding,
            |_| Ok(())
        )
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), b"sentinela");
        assert_no_final_members(&fixture);
        assert!(fs::symlink_metadata(
            fixture
                .stage
                .child_path(BundleMember::Manifest.staged_name())
        )
        .unwrap()
        .file_type()
        .is_symlink());
    }

    #[test]
    fn media_lock_e_limitado_antes_do_hash() {
        let fixture = publication_fixture("oversized-lock.img");
        OpenOptions::new()
            .write(true)
            .open(
                fixture
                    .stage
                    .child_path(BundleMember::MediaLock.staged_name()),
            )
            .unwrap()
            .set_len(MAX_PUBLICATION_CONTROL_BYTES + 1)
            .unwrap();
        let error = finish_publication(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            &fixture.binding,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("limite de 16 MiB"));
        assert_no_final_members(&fixture);
    }

    #[test]
    fn bundle_autorreferente_com_lock_estranho_nao_e_receipt() {
        let fixture = publication_fixture("self-certified.img");
        unlink_private_regular(
            &fixture.stage,
            BundleMember::MediaLock.staged_name(),
            "media.lock",
        )
        .unwrap();
        let foreign_lock = b"PROFILE_LOCK_FORMAT=2\nFOREIGN=1\n";
        write_new_at(
            &fixture.stage.file,
            BundleMember::MediaLock.staged_name(),
            foreign_lock,
        )
        .unwrap();
        let error = finish_publication(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            &fixture.binding,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("diverge do profile lock"));
        assert_no_final_members(&fixture);
    }

    #[test]
    fn receipt_final_recusa_modo_gravavel_e_hardlink_extra() {
        {
            let fixture = publication_fixture("writable-final.img");
            finish_publication(
                &fixture.parent,
                &fixture.stage,
                &fixture.names,
                &fixture.binding,
                |_| Ok(()),
            )
            .unwrap();
            fs::set_permissions(
                final_path(&fixture, BundleMember::Manifest),
                fs::Permissions::from_mode(0o664),
            )
            .unwrap();
            let error = recover_publication(
                &fixture.parent,
                &fixture.names,
                &fixture.binding,
                &mut |_| Ok(()),
            )
            .unwrap_err();
            assert!(error.to_string().contains("grupo/outros"));
        }
        {
            let fixture = publication_fixture("extra-link-final.img");
            finish_publication(
                &fixture.parent,
                &fixture.stage,
                &fixture.names,
                &fixture.binding,
                |_| Ok(()),
            )
            .unwrap();
            fs::hard_link(
                final_path(&fixture, BundleMember::Image),
                fixture.output_dir.join("foreign-hardlink"),
            )
            .unwrap();
            let error = recover_publication(
                &fixture.parent,
                &fixture.names,
                &fixture.binding,
                &mut |_| Ok(()),
            )
            .unwrap_err();
            assert!(error.to_string().contains("contagem de links"));
        }
    }

    #[test]
    fn colisao_estrangeira_e_preservada_e_prefixo_proprio_recolhido() {
        let fixture = publication_fixture("foreign-collision.img");
        let foreign_name = fixture
            .names
            .final_name(BundleMember::MediaLock)
            .to_string();
        let error = finish_publication(
            &fixture.parent,
            &fixture.stage,
            &fixture.names,
            &fixture.binding,
            |phase| {
                if phase == PublishPhase::Sha256Promoted {
                    write_new_at(&fixture.parent.file, &foreign_name, b"estrangeiro\n")?;
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("rollback"));
        assert_eq!(
            fs::read(fixture.output_dir.join(&foreign_name)).unwrap(),
            b"estrangeiro\n"
        );
        assert!(!lstat_exists(&final_path(&fixture, BundleMember::Sha256)));
        assert!(!lstat_exists(&final_path(&fixture, BundleMember::Image)));
    }

    #[test]
    fn img_e_reprodutivel_e_tem_gpt() {
        let (temp, profile, efi) = profile_fixture();
        let first = temp.path().join("first.img");
        let second = temp.path().join("second.img");
        for output in [&first, &second] {
            build(
                &profile,
                &MediaOptions {
                    mode: MediaMode::Online,
                    format: MediaFormat::Img,
                    boot_efi: efi.clone(),
                    output: output.clone(),
                    minitrue: None,
                },
            )
            .unwrap();
        }
        assert_eq!(sha256_file(&first).unwrap(), sha256_file(&second).unwrap());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&first)
            .unwrap();
        file.seek(SeekFrom::Start(SECTOR_SIZE)).unwrap();
        let mut signature = [0u8; 8];
        file.read_exact(&mut signature).unwrap();
        assert_eq!(&signature, b"EFI PART");
        let total_sectors = file.metadata().unwrap().len() / SECTOR_SIZE;
        let partition_len = (total_sectors - 34 - PARTITION_START_LBA + 1) * SECTOR_SIZE;
        let filesystem = FileSystem::new(
            PartitionFile::new(
                file.try_clone().unwrap(),
                PARTITION_START_LBA * SECTOR_SIZE,
                partition_len,
            ),
            FsOptions::new().update_accessed_date(false),
        )
        .unwrap();
        let mut boot = filesystem
            .root_dir()
            .open_file("EFI/BOOT/BOOTX64.EFI")
            .unwrap();
        let mut bytes = Vec::new();
        boot.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, fake_efi());
        let mut embedded_profile = filesystem
            .root_dir()
            .open_file("distropica/profile")
            .unwrap();
        let mut embedded_profile_bytes = Vec::new();
        embedded_profile
            .read_to_end(&mut embedded_profile_bytes)
            .unwrap();
        assert_eq!(embedded_profile_bytes, canonical_profile(&profile));
        let mut other_efi = fake_efi();
        other_efi[511] = 1;
        fs::write(&efi, other_efi).unwrap();
        let third = temp.path().join("third.img");
        build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Online,
                format: MediaFormat::Img,
                boot_efi: efi,
                output: third.clone(),
                minitrue: None,
            },
        )
        .unwrap();
        let disk_guid = |path: &Path| {
            let mut file = File::open(path).unwrap();
            file.seek(SeekFrom::Start(SECTOR_SIZE + 56)).unwrap();
            let mut guid = [0u8; 16];
            file.read_exact(&mut guid).unwrap();
            guid
        };
        assert_ne!(disk_guid(&first), disk_guid(&third));
    }

    #[test]
    fn offline_exige_cache_e_saida_nao_e_sobrescrita() {
        let (temp, mut profile, efi) = profile_fixture();
        let bootstrap_as_offline = temp.path().join("bootstrap-nao-e-offline.img");
        assert!(build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Offline,
                format: MediaFormat::Img,
                boot_efi: efi.clone(),
                output: bootstrap_as_offline.clone(),
                minitrue: None,
            },
        )
        .is_err());
        assert!(!bootstrap_as_offline.exists());

        profile.channel_bootstrap_path = None;
        let output = temp.path().join("x.img");
        let options = MediaOptions {
            mode: MediaMode::Offline,
            format: MediaFormat::Img,
            boot_efi: efi.clone(),
            output: output.clone(),
            minitrue: None,
        };
        assert!(build(&profile, &options).is_err());
        let online_without_channel = temp.path().join("online-sem-canal.img");
        assert!(build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Online,
                format: MediaFormat::Img,
                boot_efi: efi.clone(),
                output: online_without_channel.clone(),
                minitrue: None,
            },
        )
        .is_err());
        assert!(!online_without_channel.exists());

        let empty_cache = temp.path().join("empty-cache");
        fs::create_dir(&empty_cache).unwrap();
        profile.cache_path = Some(empty_cache);
        assert!(build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Offline,
                format: MediaFormat::Img,
                boot_efi: efi.clone(),
                output: temp.path().join("empty-cache.img"),
                minitrue: None,
            },
        )
        .is_err());

        fs::write(&output, b"sentinela").unwrap();
        assert!(build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Online,
                format: MediaFormat::Img,
                boot_efi: efi,
                output: output.clone(),
                minitrue: None,
            },
        )
        .is_err());
        assert_eq!(fs::read(output).unwrap(), b"sentinela");
    }

    #[test]
    fn efi_divergente_rebaixa_midia_oficial_para_custom() {
        let (temp, development, efi) = profile_fixture();
        let lock = development.lock().unwrap();
        let content_hash = lock
            .lines()
            .find_map(|line| line.strip_prefix("PROFILE_CONTENT_SHA256="))
            .unwrap();
        let boot_hash = sha256(&fake_efi());
        let profile_dir = temp.path().join("profile-dir");
        fs::write(
            profile_dir.join("profile"),
            format!(
                "PROFILE_FORMAT=1\nNAME=official\nARCH=x86_64\nSOURCE_DATE_EPOCH=1704067200\nMEDIA_SIZE_MIB=64\nSTATUS=release\nOFFICIAL_CONTENT_SHA256={content_hash}\nOFFICIAL_BOOT_EFI_SHA256={boot_hash}\nOFFICIAL_MINITRUE_SHA256={}\n",
                "0".repeat(64),
            ),
        )
        .unwrap();
        let release = ResolvedProfile::load(
            &profile_dir,
            ProfileOverrides {
                newspeak: Some(temp.path().join("newspeak")),
                ..Default::default()
            },
        )
        .unwrap();
        let options = MediaOptions {
            mode: MediaMode::Online,
            format: MediaFormat::Img,
            boot_efi: efi.clone(),
            output: temp.path().join("ignored.img"),
            minitrue: None,
        };
        let (_, _, _, profile_class, media_class, _cache) = payload(&release, &options).unwrap();
        assert_eq!(profile_class, "official-inputs");
        assert_eq!(media_class, "official-inputs");

        let mut other = fake_efi();
        other[511] = 1;
        fs::write(&efi, other).unwrap();
        let (_, _, _, profile_class, media_class, _cache) = payload(&release, &options).unwrap();
        assert_eq!(profile_class, "official-inputs");
        assert_eq!(media_class, "custom");
    }

    #[test]
    fn efi_de_arquitetura_errada_e_recusado() {
        let mut efi = fake_efi();
        let coff = 0x80 + 4;
        efi[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
        assert!(validate_boot_efi(&efi).is_err());
    }

    #[test]
    fn nome_de_saida_hostil_e_recusado() {
        assert!(safe_output_name(Path::new("linha\nnova.img")).is_err());
        assert_eq!(
            safe_output_name(Path::new("distropica.img")).unwrap(),
            "distropica.img"
        );
    }

    #[test]
    fn iso_e_reprodutivel_quando_xorriso_esta_disponivel() {
        if !Command::new("xorriso")
            .arg("-version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }
        let (temp, profile, efi) = profile_fixture();
        let first = temp.path().join("first.iso");
        let second = temp.path().join("second.iso");
        for output in [&first, &second] {
            build(
                &profile,
                &MediaOptions {
                    mode: MediaMode::Online,
                    format: MediaFormat::Iso,
                    boot_efi: efi.clone(),
                    output: output.clone(),
                    minitrue: None,
                },
            )
            .unwrap();
        }
        assert_eq!(sha256_file(&first).unwrap(), sha256_file(&second).unwrap());
        let bytes = fs::read(&first).unwrap();
        assert_eq!(&bytes[0x8001..0x8006], b"CD001");
    }

    /// Um `minitrue` de mentira: um script que imprime linhas
    /// `<pacote> <fingerprint>` fixas. Serve para exercitar a COMPARAÇÃO sem
    /// depender do binário de verdade nem de uma árvore de receitas real — o
    /// que este teste decide é o que `confere_identidade` faz com a resposta,
    /// não como o minitrue chega a ela.
    fn minitrue_de_mentira(dir: &Path, linhas: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let caminho = dir.join("minitrue-falso");
        fs::write(&caminho, format!("#!/bin/sh\ncat <<'FIM'\n{linhas}\nFIM\n")).unwrap();
        fs::set_permissions(&caminho, fs::Permissions::from_mode(0o755)).unwrap();
        caminho
    }

    /// Monta um cache offline mínimo: só o índice importa para esta pergunta.
    fn cache_com_indice(dir: &Path, index: &str) -> PathBuf {
        let cache = dir.join("cache");
        fs::create_dir_all(cache.join("channels/oficial")).unwrap();
        fs::write(cache.join("channels/oficial/index"), index).unwrap();
        cache
    }

    #[test]
    fn indice_do_canal_le_nome_versao_e_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let index = temp.path().join("index");
        fs::write(
            &index,
            "base 0.2 x86_64 aaaa pool/base-0.2-x86_64.tar.zst bbbb cccc
             linux 7.1.4 x86_64 dddd pool/linux-7.1.4-x86_64.tar.zst eeee ffff
",
        )
        .unwrap();
        let lido = indice_do_canal(&index).unwrap();
        assert_eq!(
            lido,
            vec![
                ("base".into(), "0.2".into(), "aaaa".into()),
                ("linux".into(), "7.1.4".into(), "dddd".into()),
            ]
        );
    }

    #[test]
    fn indice_do_canal_recusa_linha_curta_em_vez_de_ignora_la() {
        // Pular a linha em silêncio faria a guarda "passar" sobre um índice que
        // ela não entendeu — que é o modo de falhar que ela existe para evitar.
        let temp = tempfile::tempdir().unwrap();
        let index = temp.path().join("index");
        fs::write(
            &index,
            "base 0.2 x86_64
",
        )
        .unwrap();
        let erro = indice_do_canal(&index).unwrap_err().to_string();
        assert!(erro.contains("3 campos"), "mensagem inesperada: {erro}");
    }

    #[test]
    fn media_recusa_quando_a_receita_embarcada_nao_bate_com_o_pacote() {
        let (temp, mut profile, efi) = profile_fixture();
        let cache = cache_com_indice(
            temp.path(),
            "base 0.2 x86_64 aaaa pool/base-0.2-x86_64.tar.zst bbbb cccc
",
        );
        // A árvore embarcada exige 'zzzz'; o cache traz o pacote de 'aaaa'.
        let falso = minitrue_de_mentira(temp.path(), "base zzzz");
        profile.cache_path = Some(cache);
        let erro = build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Offline,
                format: MediaFormat::Img,
                boot_efi: efi,
                output: temp.path().join("saida.img"),
                minitrue: Some(falso),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(erro.contains("não correspondem"), "mensagem: {erro}");
        assert!(
            erro.contains("aaaa") && erro.contains("zzzz"),
            "mensagem: {erro}"
        );
        // E nada foi escrito: a guarda roda ANTES de compor.
        assert!(!temp.path().join("saida.img").exists());
    }

    #[test]
    fn media_recusa_quando_o_pacote_nao_tem_receita_na_arvore() {
        let (temp, mut profile, efi) = profile_fixture();
        let cache = cache_com_indice(
            temp.path(),
            "fantasma 1.0 x86_64 aaaa pool/fantasma-1.0-x86_64.tar.zst bbbb cccc
",
        );
        let falso = minitrue_de_mentira(temp.path(), "base zzzz");
        profile.cache_path = Some(cache);
        let erro = build(
            &profile,
            &MediaOptions {
                mode: MediaMode::Offline,
                format: MediaFormat::Img,
                boot_efi: efi,
                output: temp.path().join("saida.img"),
                minitrue: Some(falso),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(erro.contains("não tem receita"), "mensagem: {erro}");
    }

    #[test]
    fn o_channel_bootstrap_separado_nao_e_conferido_como_cache_de_pacote() {
        // Mídia online não leva payload: o que a máquina instalar vem do canal
        // vivo, e é lá que o crimestop faz a pergunta. Conferir aqui seria
        // afirmar hoje algo sobre um canal que muda amanhã.
        let (temp, profile, _efi) = profile_fixture();
        assert!(profile.cache_path.is_none());
        assert!(profile.channel_bootstrap_path.is_some());
        // O índice do fixture é um placeholder de um campo só; se a guarda o
        // lesse, falharia. Não falhar é a prova de que ela pulou.
        confere_identidade(&profile, &None).unwrap();
        drop(temp);
    }
}
