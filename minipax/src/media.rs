use crate::profile::{write_new, ProfileStatus, ResolvedProfile};
use crate::tree;
use anyhow::{bail, Context, Result};
use crc32fast::Hasher as Crc32;
use fatfs::{
    Date, DateTime, FatType, FileSystem, FormatVolumeOptions, FsOptions, Time, TimeProvider,
};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

const SECTOR_SIZE: u64 = 512;
const PARTITION_START_LBA: u64 = 2048;
const GPT_ENTRY_COUNT: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
const MEDIA_FORMAT: &str = "1";
const MAX_BOOT_EFI_BYTES: u64 = 256 * 1024 * 1024;

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
    // O channel-bootstrap/ do perfil NÃO é um cache de pacotes: ele leva só a
    // configuração e o índice assinado que abrem a descoberta online. Numa
    // mídia dessas não há payload para descasar da receita — o que a máquina
    // instalar vem do canal vivo, e é lá, na instalação, que o crimestop faz
    // esta mesma pergunta contra o índice que estiver valendo naquela hora.
    // Conferir aqui seria afirmar hoje algo sobre um canal que muda amanhã.
    if profile.cache_is_channel_bootstrap {
        return Ok(());
    }
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
            PayloadBody::OnDisk { source, len } => Box::new(File::open(source)
                .with_context(|| format!("payload: não abri {}", source.display()))?
                .take(*len)),
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

fn payload(
    profile: &ResolvedProfile,
    options: &MediaOptions,
) -> Result<(
    Vec<PayloadFile>,
    String,
    String,
    String,
    String,
    Option<crate::profile::CacheArchive>,
)> {
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
    if options.mode == MediaMode::Offline && profile.cache_is_channel_bootstrap {
        bail!(
            "modo offline exige --cache DIR completo; channel-bootstrap/ contém apenas metadados"
        );
    }
    let artifacts = profile.artifacts()?;
    match (options.mode, artifacts.cache_tar.as_ref()) {
        (MediaMode::Offline, None) => bail!("modo offline exige --cache DIR"),
        (MediaMode::Offline, Some(_)) if artifacts.cache_entries.is_empty() => {
            bail!("modo offline exige --cache DIR não vazio")
        }
        (MediaMode::Online, None) => {
            bail!(
                "modo online exige channel-bootstrap/ no perfil ou --cache DIR com config e índice assinado"
            )
        }
        (MediaMode::Online, Some(_)) => {
            tree::validate_channel_bootstrap(&artifacts.cache_entries)?;
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

fn create_iso(
    path: &Path,
    profile: &ResolvedProfile,
    files: &[PayloadFile],
    payload_hash: &str,
) -> Result<String> {
    let parent = path.parent().unwrap();
    let workspace = tempfile::Builder::new()
        .prefix(".minipax-iso-")
        .tempdir_in(parent)?;
    let tree = workspace.path().join("tree");
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
    let xorriso =
        executable_in_path("xorriso").context("xorriso é obrigatório para --format iso")?;
    let xorriso_hash = sha256_file(&xorriso)?;
    let version_output = Command::new(&xorriso)
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
    let status = Command::new(&xorriso)
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
    if sha256_file(&xorriso)? != xorriso_hash {
        bail!("xorriso mudou durante a composição da ISO");
    }
    let mut iso = File::open(path)?;
    iso.seek(SeekFrom::Start(0x8001))?;
    let mut signature = [0u8; 5];
    iso.read_exact(&mut signature)?;
    if &signature != b"CD001" {
        bail!("xorriso produziu uma saída sem descritor ISO9660 válido");
    }
    Ok(format!("xorriso_{version}_sha256_{xorriso_hash}"))
}

fn sidecar(output: &Path, suffix: &str) -> Result<PathBuf> {
    let name = safe_output_name(output)?;
    Ok(output.with_file_name(format!("{name}.{suffix}")))
}

fn temp_output(output: &Path) -> Result<PathBuf> {
    let name = safe_output_name(output)?;
    Ok(output.with_file_name(format!(".{name}.tmp-{}", std::process::id())))
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

struct TemporaryOutput {
    path: PathBuf,
    published: bool,
}

impl TemporaryOutput {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }
}

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn build(profile: &ResolvedProfile, options: &MediaOptions) -> Result<()> {
    // ANTES de qualquer byte: compor centenas de MiB e só então descobrir que o
    // texto não bate com o payload é o erro que esta guarda existe para evitar.
    confere_identidade(profile, &options.minitrue)?;
    let requested = crate::absolute_path(&options.output)?;
    let file_name = safe_output_name(&requested)?.to_string();
    let parent = requested
        .parent()
        .ok_or_else(|| anyhow::anyhow!("saída sem diretório pai"))?;
    crate::ensure_real_dir(parent, "diretório de saída")?;
    let output = fs::canonicalize(parent)?.join(file_name);
    for path in [
        output.clone(),
        sidecar(&output, "sha256")?,
        sidecar(&output, "media.lock")?,
        sidecar(&output, "manifest")?,
    ] {
        if fs::symlink_metadata(&path).is_ok() {
            bail!(
                "saída já existe e nunca será sobrescrita: {}",
                path.display()
            );
        }
    }
    let (files, lock, lock_hash, profile_class, media_class, _cache_archive) =
        payload(profile, options)?;
    let payload_hash = payload_hash(&files)?;
    let mut temporary = TemporaryOutput::new(temp_output(&output)?);
    if fs::symlink_metadata(&temporary.path).is_ok() {
        bail!(
            "temporário de saída já existe: {}",
            temporary.path.display()
        );
    }
    let tool = match options.format {
        MediaFormat::Img => {
            create_img(&temporary.path, profile, &files, &payload_hash)?;
            "minipax-fatfs-gpt-v1".to_string()
        }
        MediaFormat::Iso => create_iso(&temporary.path, profile, &files, &payload_hash)?,
    };
    let image_hash = sha256_file(&temporary.path)?;
    let minipax_hash = sha256_file(&std::env::current_exe()?)?;
    let boot_hash = {
        let boot = files
            .iter()
            .find(|file| file.path == "EFI/BOOT/BOOTX64.EFI")
            .expect("BOOTX64.EFI está sempre no payload");
        let mut hasher = Sha256::new();
        stream_copy(&mut *boot.reader()?, &mut hasher)?;
        hex::encode(hasher.finalize())
    };
    let manifest = format!(
        "MEDIA_MANIFEST_FORMAT=1\nMEDIA_SHA256={image_hash}\nMEDIA_INPUT_SHA256={payload_hash}\nPROFILE_LOCK_SHA256={lock_hash}\nPROFILE_NAME={}\nPROFILE_CLASS={}\nMEDIA_CLASS={}\nARCH={}\nMODE={}\nFORMAT={}\nBOOT_EFI_SHA256={boot_hash}\nMINIPAX_EXECUTABLE_SHA256={minipax_hash}\nTOOL={}\n",
        profile.name,
        profile_class,
        media_class,
        profile.arch,
        options.mode.as_str(),
        options.format.as_str(),
        tool,
    );
    let file_name = safe_output_name(&output)?;
    let sidecars = [
        (
            sidecar(&output, "sha256")?,
            format!("{image_hash}  {file_name}\n").into_bytes(),
        ),
        (sidecar(&output, "media.lock")?, lock.into_bytes()),
        (sidecar(&output, "manifest")?, manifest.into_bytes()),
    ];
    let mut temporary_sidecars = Vec::new();
    for (final_path, bytes) in &sidecars {
        let temporary_path = temp_output(final_path)?;
        if fs::symlink_metadata(&temporary_path).is_ok() {
            bail!(
                "temporário de saída já existe: {}",
                temporary_path.display()
            );
        }
        write_new(&temporary_path, bytes)?;
        temporary_sidecars.push(TemporaryOutput::new(temporary_path));
    }
    for ((final_path, _), temporary_sidecar) in sidecars.iter().zip(temporary_sidecars.iter_mut()) {
        crate::publish_noreplace(&temporary_sidecar.path, final_path)?;
        temporary_sidecar.published = true;
    }
    crate::publish_noreplace(&temporary.path, &output)?;
    temporary.published = true;
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

    fn profile_fixture() -> (tempfile::TempDir, ResolvedProfile, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
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

        profile.cache_path = None;
        profile.cache_is_channel_bootstrap = false;
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
        profile.cache_is_channel_bootstrap = false;
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
        fs::write(
            &caminho,
            format!("#!/bin/sh\ncat <<'FIM'\n{linhas}\nFIM\n"),
        )
        .unwrap();
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
        fs::write(&index, "base 0.2 x86_64
").unwrap();
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
        profile.cache_is_channel_bootstrap = false;
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
        assert!(erro.contains("aaaa") && erro.contains("zzzz"), "mensagem: {erro}");
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
        profile.cache_is_channel_bootstrap = false;
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
    fn o_channel_bootstrap_nao_e_conferido_porque_nao_carrega_pacote() {
        // Mídia online não leva payload: o que a máquina instalar vem do canal
        // vivo, e é lá que o crimestop faz a pergunta. Conferir aqui seria
        // afirmar hoje algo sobre um canal que muda amanhã.
        let (temp, profile, _efi) = profile_fixture();
        assert!(profile.cache_is_channel_bootstrap);
        // O índice do fixture é um placeholder de um campo só; se a guarda o
        // lesse, falharia. Não falhar é a prova de que ela pulou.
        confere_identidade(&profile, &None).unwrap();
        drop(temp);
    }
}
