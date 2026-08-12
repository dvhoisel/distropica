//! A árvore de receitas como pacote gerido — o *linchpin* da SPEC-0011 §3.1.
//!
//! POR QUE ISTO EXISTE. O sistema instalado leva as receitas congeladas no
//! momento da instalação. Um pacote criado DEPOIS do lançamento não tem receita
//! na máquina, e sem receita o minitrue não sabe URL, sha256 nem dependências.
//! Isso trava os três modos de aquisição de uma vez: o binário do mantenedor, o
//! pacote pronto do canal e a compilação no ato. Os três precisam da receita
//! antes de precisar de qualquer outra coisa.
//!
//! A EXCEÇÃO À P6, E POR QUE ELA É ESTREITA. "A rede nunca decide o que é
//! verdade" (SPEC-0001 P6), e em toda a árvore isso se traduz em sha256 pinado
//! ANTES do download. Aqui não há hash a pinar: o que se busca é justamente uma
//! árvore que ainda não se conhece — pinar o hash da árvore nova exigiria já
//! ter a árvore nova.
//!
//! A troca é: o hash deixa de ser pré-condição, e a ASSINATURA passa a ser
//! obrigatória e sem contorno. Sem `.minisig` válido pela chave pinada, é
//! crimestop. Não há flag que dispense, não há TOFU, não há "aceite este e
//! lembre" — o `--tofu` do resto do minitrue não alcança este caminho.
//!
//! E A CHAVE NÃO VEM DA REDE. Ela mora em `var/cache/minitrue/newspeak-origem`,
//! semeada pela mídia, no mesmo formato do `channel-config` que o canal já usa.
//! Pôr a chave dentro da própria árvore foi considerado e descartado pelo
//! motivo óbvio: a árvore assinaria a si mesma, e a assinatura deixaria de
//! provar coisa alguma.
//!
//! A TROCA É ATÔMICA, e não receita a receita. Árvore parcial é conjunto
//! inconsistente e viola a P1 — é a origem clássica do *partial upgrade*
//! quebrado, em que metade dos pacotes conhece um ABI e a outra metade conhece
//! outro.

use crate::{fail, Ctx};
use anyhow::{bail, Context, Result};
use minisign_verify::{PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use url::Url;

const NOME_TARBALL: &str = "newspeak.tar";
const NOME_ASSINATURA: &str = "newspeak.tar.minisig";
const MAX_TARBALL_BYTES: usize = 256 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_ORIGIN_BYTES: u64 = 16 * 1024;
const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 50_000;

/// De onde a árvore vem, e por qual chave ela é reconhecida.
///
/// Mesmo formato do `channel-config`: linhas `CHAVE=valor`, comentários com
/// '#'. A simetria é deliberada — quem já sabe ler um canal sabe ler isto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origem {
    pub url: String,
    pub key: String,
}

/// Onde a mídia semeia a origem.
pub fn caminho_da_origem(ctx: &Ctx) -> PathBuf {
    ctx.cache_dir().join("newspeak-origem")
}

/// Lê a origem, ou explica por que não dá para atualizar.
///
/// A ausência do arquivo NÃO é erro de programa: é uma máquina cuja mídia não
/// semeou origem nenhuma, e o texto diz isso em vez de reclamar de arquivo
/// faltando. Distinguir "não configurado" de "configurado e quebrado" é o que
/// permite ao operador saber se o problema é dele ou da mídia.
pub fn origem(ctx: &Ctx) -> Result<Origem> {
    let caminho = caminho_da_origem(ctx);
    crate::install::ensure_real_directory_or_absent(
        &ctx.root,
        &ctx.cache_dir(),
        "cache do minitrue",
    )?;
    let mut arquivo = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&caminho)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return fail(
                6,
                format!(
                    "esta instalação não tem origem de árvore configurada ({}).\n\
                     Sem ela não há de onde buscar receitas novas, e só se pode\n\
                     instalar o que a mídia trouxe.",
                    caminho.display()
                ),
            );
        }
        Err(e) => return Err(e).context(format!("lendo {}", caminho.display())),
    };
    let metadata = arquivo.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return fail(
            6,
            format!(
                "origem da árvore precisa ser arquivo regular real sem hardlinks: {}",
                caminho.display()
            ),
        );
    }
    if metadata.len() > MAX_ORIGIN_BYTES {
        return fail(
            6,
            format!(
                "origem da árvore excede {MAX_ORIGIN_BYTES} bytes: {}",
                caminho.display()
            ),
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut arquivo)
        .take(MAX_ORIGIN_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ORIGIN_BYTES {
        return fail(
            6,
            format!(
                "origem da árvore excede {MAX_ORIGIN_BYTES} bytes: {}",
                caminho.display()
            ),
        );
    }
    let texto = String::from_utf8(bytes).map_err(|_| crate::Fail {
        code: 6,
        msg: format!("origem da árvore não é UTF-8: {}", caminho.display()),
    })?;
    analisa_origem(&texto, &caminho.display().to_string())
}

/// Separado da leitura de disco PARA SER TESTÁVEL. O que decide se uma árvore
/// será aceita é este texto, e texto se testa sem forjar um sistema de
/// arquivos.
pub fn analisa_origem(texto: &str, onde: &str) -> Result<Origem> {
    let mut url = None;
    let mut key = None;
    for linha in texto.lines() {
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        match linha.split_once('=') {
            Some(("URL", v)) => url = Some(v.trim().to_string()),
            Some(("KEY", v)) => key = Some(v.trim().to_string()),
            // Chaves desconhecidas são ignoradas de propósito: um arquivo
            // escrito por uma versão mais nova não pode derrubar esta.
            _ => {}
        }
    }
    let url = match url {
        Some(u) if !u.is_empty() => u,
        _ => return fail(6, format!("{onde}: falta URL=")),
    };
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => return fail(6, format!("{onde}: falta KEY=")),
    };
    // HTTPS OBRIGATÓRIO. A assinatura protege o conteúdo, mas o transporte em
    // claro entrega a quem observa a lista exata de máquinas que ainda não
    // atualizaram — e, com redirecionamento, a chance de servir um 404 eterno
    // para congelar uma máquina numa árvore velha. Negar atualização é um
    // ataque mais barato que forjar assinatura.
    if !url.starts_with("https://") {
        return fail(6, format!("{onde}: URL precisa ser https:// (veio {url})"));
    }
    Ok(Origem { url, key })
}

/// O diretório em que a árvore vive, e os dois nomes de trabalho da troca.
fn caminhos(ctx: &Ctx) -> (PathBuf, PathBuf, PathBuf) {
    let base = ctx.root.join("var/lib/minitrue");
    (
        base.join("newspeak"),
        base.join(".newspeak.novo"),
        base.join(".newspeak.anterior"),
    )
}

fn diretorio_real_ou_ausente(path: &Path, what: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => bail!("{what} precisa ser diretório real: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn remove_diretorio_real_se_existe(path: &Path, what: &str) -> Result<()> {
    if diretorio_real_ou_ausente(path, what)? {
        fs::remove_dir_all(path).with_context(|| format!("removendo {}", path.display()))?;
    }
    Ok(())
}

/// Troca dois nomes de diretório em UMA operação do kernel.
///
/// `renameat2(RENAME_EXCHANGE)` é Linux (assim como o restante do Minitrue) e
/// fecha a janela de ENOENT que existe na sequência portátil
/// `atual -> anterior; novo -> atual`. Leitores que não participam do flock
/// global — `fingerprint` e `newspeak`, por exemplo — observam a árvore antiga
/// ou a nova, nunca ausência ou mistura das duas.
fn exchange(novo: &Path, atual: &Path) -> Result<()> {
    let novo_c = CString::new(novo.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("caminho da árvore nova contém NUL"))?;
    let atual_c = CString::new(atual.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("caminho da árvore atual contém NUL"))?;
    crate::linux::renameat2(
        libc::AT_FDCWD,
        &novo_c,
        libc::AT_FDCWD,
        &atual_c,
        libc::RENAME_EXCHANGE,
    )
    .context("trocando atomicamente a árvore com renameat2(RENAME_EXCHANGE)")?;
    Ok(())
}

/// Publica a árvore nova de uma vez. `.newspeak.anterior` só aparece aqui para
/// limpar/entender estados deixados pelo algoritmo antigo; atualizações novas
/// usam o exchange atômico e deixam a árvore velha em `.newspeak.novo` até a
/// limpeza.
fn troca_atomica(atual: &Path, novo: &Path, anterior: &Path) -> Result<()> {
    if !diretorio_real_ou_ausente(novo, "árvore nova")? {
        bail!("árvore nova desapareceu antes da publicação");
    }
    let havia_atual = diretorio_real_ou_ausente(atual, "árvore atual")?;
    remove_diretorio_real_se_existe(anterior, "árvore anterior legada")?;
    if havia_atual {
        exchange(novo, atual)?;
        // Depois do exchange, `novo` nomeia a árvore velha. Uma queda antes da
        // limpeza é inofensiva; a recuperação a remove na execução seguinte.
        let _ = fs::remove_dir_all(novo);
    } else {
        fs::rename(novo, atual).context("publicando a primeira árvore")?;
    }
    if let Some(parent) = atual.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Conserta o estado deixado por uma queda no meio da troca.
///
/// Chamado ANTES de qualquer coisa. Se `newspeak` sumiu e há
/// `.newspeak.anterior`, uma versão anterior caiu entre os dois renames do
/// algoritmo legado. Recuperá-la preserva a compatibilidade de reparo e
/// funciona sem rede. No algoritmo atual, uma queda após o exchange deixa a
/// nova em `newspeak` e a velha em `.newspeak.novo`; esta última é só limpa.
pub fn recupera_troca_interrompida(ctx: &Ctx) -> Result<()> {
    let (atual, novo, anterior) = caminhos(ctx);
    let atual_existe = diretorio_real_ou_ausente(&atual, "árvore atual")?;
    let anterior_existe = diretorio_real_ou_ausente(&anterior, "árvore anterior legada")?;
    if !atual_existe && anterior_existe {
        eprintln!("  troca interrompida detectada; recuperando a árvore anterior");
        fs::rename(&anterior, &atual).with_context(|| {
            format!("recuperando {} de {}", atual.display(), anterior.display())
        })?;
    }
    remove_diretorio_real_se_existe(&novo, "árvore temporária")?;
    Ok(())
}

/// Os dois objetos publicados sob a origem configurada.
///
/// `URL=` nomeia um diretório, como no `channel-config`. Aceitar também a
/// forma sem a barra final evita transformar um detalhe de pontuação num
/// protocolo diferente: as duas formas chegam aos mesmos nomes canônicos.
fn urls_da_origem(config: &Origem) -> Result<(Url, Url)> {
    let mut base = Url::parse(&config.url).map_err(|error| crate::Fail {
        code: 6,
        msg: format!(
            "URL da origem newspeak é inválida ({}): {error}",
            config.url
        ),
    })?;
    if base.scheme() != "https" || !base.has_host() {
        return fail(
            6,
            format!("origem newspeak precisa usar HTTPS: {}", config.url),
        );
    }
    if !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return fail(
            6,
            format!(
                "origem newspeak precisa ser um diretório HTTPS sem credenciais, query ou fragmento: {}",
                config.url
            ),
        );
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    let tarball = base.join(NOME_TARBALL).map_err(|error| crate::Fail {
        code: 6,
        msg: format!("não formei a URL de {NOME_TARBALL}: {error}"),
    })?;
    let signature = base.join(NOME_ASSINATURA).map_err(|error| crate::Fail {
        code: 6,
        msg: format!("não formei a URL de {NOME_ASSINATURA}: {error}"),
    })?;
    Ok((tarball, signature))
}

/// Download sem hash, deliberadamente privado deste módulo.
///
/// Este é o ÚNICO artefato da distro cujo hash ainda não pode estar pinado: o
/// objeto buscado contém os pinos novos. O limite e a assinatura obrigatória
/// mantêm a exceção estreita; expor este helper ao restante do crate tornaria
/// fácil usá-la por acidente para outra coisa.
fn baixa_limitado(url: &Url, limite: usize) -> Result<Vec<u8>> {
    let response = ureq::get(url.as_str())
        .call()
        .map_err(|error| crate::Fail {
            code: 6,
            msg: format!("rede falhou em {url}: {error}"),
        })?;
    let final_url = Url::parse(response.get_url()).map_err(|error| crate::Fail {
        code: 6,
        msg: format!("resposta de {url} trouxe URL final inválida: {error}"),
    })?;
    if final_url.scheme() != "https" || !final_url.has_host() {
        return fail(
            6,
            format!("redirecionamento de {url} rebaixou o transporte para {final_url}"),
        );
    }
    if response
        .header("Content-Length")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|size| size > limite)
    {
        return fail(6, format!("resposta de {url} excede {limite} bytes"));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((limite as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::Fail {
            code: 6,
            msg: format!("rede caiu no meio de {url}: {error}"),
        })?;
    if bytes.len() > limite {
        return fail(6, format!("resposta de {url} excede {limite} bytes"));
    }
    Ok(bytes)
}

fn chave_publica(texto: &str) -> Result<PublicKey> {
    PublicKey::from_base64(texto).map_err(|error| {
        crate::Fail {
            code: 7,
            msg: format!("chave minisign pinada para newspeak é inválida: {error}"),
        }
        .into()
    })
}

fn confere_assinatura(tarball: &[u8], assinatura: &[u8], chave: &PublicKey) -> Result<()> {
    let texto = std::str::from_utf8(assinatura).map_err(|_| crate::Fail {
        code: 7,
        msg: format!("{NOME_ASSINATURA} não é UTF-8"),
    })?;
    let assinatura = Signature::decode(texto).map_err(|error| crate::Fail {
        code: 7,
        msg: format!("{NOME_ASSINATURA} está malformada: {error}"),
    })?;
    chave.verify(tarball, &assinatura, false).map_err(|error| {
        crate::Fail {
            code: 7,
            msg: format!(
                "crimestop (árvore): {NOME_TARBALL} não foi assinado pela chave pinada ({error})"
            ),
        }
        .into()
    })
}

#[derive(Debug)]
enum TipoEntrada {
    Diretorio,
    Regular(Vec<u8>),
}

#[derive(Debug)]
struct Entrada {
    caminho: PathBuf,
    modo: u32,
    tipo: TipoEntrada,
}

fn caminho_canonico(caminho: &Path) -> bool {
    !caminho.as_os_str().is_empty()
        && !caminho.is_absolute()
        && caminho.as_os_str().as_bytes().len() <= 4096
        && caminho.to_str().is_some()
        && caminho
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Decodifica e valida a árvore INTEIRA antes de criar `.newspeak.novo`.
///
/// A biblioteca `tar` sabe desempacotar, mas `unpack()` não expressa o
/// contrato daqui: sem links/hardlinks/especiais, sem caminho repetido, com
/// orçamento total e com uma receita regular para cada pacote. Validar antes
/// de escrever é o que garante que um tar assinado porém quebrado não chega a
/// substituir uma árvore funcional.
fn decodifica_tarball(tarball: &[u8]) -> Result<Vec<Entrada>> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tarball));
    let mut entradas = Vec::new();
    let mut caminhos: BTreeMap<PathBuf, bool> = BTreeMap::new();
    let mut pacotes = BTreeSet::new();
    let mut receitas = BTreeSet::new();
    let mut bytes_regulares = 0u64;
    let mut viu_cabecalho_pack = false;
    let mut viu_payload = false;

    for item in archive
        .entries()
        .context("não li o cabeçalho do newspeak.tar")?
    {
        if entradas.len() >= MAX_TREE_ENTRIES {
            bail!("{NOME_TARBALL} excede {MAX_TREE_ENTRIES} entradas");
        }
        let mut item = item.context("entrada inválida em newspeak.tar")?;
        let entry_type = item.header().entry_type();
        if entry_type.as_byte() == b'g' {
            if viu_cabecalho_pack || viu_payload {
                bail!("{NOME_TARBALL} contém cabeçalho global fora da posição canônica");
            }
            if item.size() > 256 {
                bail!("{NOME_TARBALL} contém cabeçalho DISTROPICA.pack excessivo");
            }
            let mut corpo = Vec::new();
            Read::by_ref(&mut item).take(257).read_to_end(&mut corpo)?;
            let Some(separador) = corpo.iter().position(|byte| *byte == b' ') else {
                bail!("{NOME_TARBALL} não declara DISTROPICA.pack");
            };
            let (declarado, valor_com_espaco) = corpo.split_at(separador);
            let declarado = std::str::from_utf8(declarado)
                .ok()
                .and_then(|texto| texto.parse::<usize>().ok());
            let versao = std::str::from_utf8(&valor_com_espaco[1..])
                .ok()
                .and_then(|texto| texto.strip_prefix("DISTROPICA.pack="))
                .and_then(|texto| texto.strip_suffix('\n'))
                .filter(|versao| crate::pack::format_supported(versao));
            if declarado != Some(corpo.len()) || versao.is_none() {
                bail!("{NOME_TARBALL} usa cabeçalho DISTROPICA.pack inválido/desconhecido");
            }
            if versao != Some(crate::pack::PACK_FORMAT) {
                bail!(
                    "{NOME_TARBALL} declara pack com xattrs; a árvore newspeak não admite metadados que a mídia descartaria"
                );
            }
            viu_cabecalho_pack = true;
            continue;
        }
        viu_payload = true;
        let caminho = item
            .path()
            .context("caminho inválido em newspeak.tar")?
            .into_owned();
        if item.pax_extensions()?.is_some() {
            bail!(
                "{NOME_TARBALL} contém extensão PAX por entrada em {}",
                caminho.display()
            );
        }
        if !caminho_canonico(&caminho) {
            bail!("{NOME_TARBALL} contém caminho não canônico: {:?}", caminho);
        }
        let partes = caminho
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>();
        let pacote = partes[0];
        crate::recipe::validate_name(pacote).with_context(|| {
            format!(
                "{NOME_TARBALL} contém pacote inválido no caminho {}",
                caminho.display()
            )
        })?;
        pacotes.insert(pacote.to_string());

        let modo_no_tar = item.header().mode()?;
        if modo_no_tar > 0o7777 {
            bail!(
                "{NOME_TARBALL} contém modo inválido em {}",
                caminho.display()
            );
        }
        // A MESMA VISÃO DA MÍDIA. Git só conserva o bit executável: sob umask
        // 002, um checkout perfeitamente normal tem diretórios 0775 e arquivos
        // 0664. Assinar esses bits acidentais e reproduzi-los faria a árvore
        // atualizada divergir daquela congelada pelo Minipax, além de a guarda
        // de `files/` recusar os auxiliares graváveis por grupo. Portanto o
        // tar inteiro continua autenticado, mas sua materialização aplica a
        // política canônica já usada na mídia: dirs 0755, executáveis 0755,
        // demais regulares 0644.
        let modo = if entry_type == tar::EntryType::Directory
            || (entry_type == tar::EntryType::Regular && modo_no_tar & 0o111 != 0)
        {
            0o755
        } else {
            0o644
        };
        let (tipo, diretorio) = if entry_type == tar::EntryType::Directory {
            if item.size() != 0 {
                bail!(
                    "diretório com conteúdo em {NOME_TARBALL}: {}",
                    caminho.display()
                );
            }
            (TipoEntrada::Diretorio, true)
        } else if entry_type == tar::EntryType::Regular {
            if partes.len() < 2 {
                bail!(
                    "{NOME_TARBALL} contém arquivo fora de um pacote: {}",
                    caminho.display()
                );
            }
            let declarado = item.size();
            let restante = MAX_TREE_BYTES.saturating_sub(bytes_regulares);
            if declarado > restante {
                bail!(
                    "árvore newspeak excede {} MiB",
                    MAX_TREE_BYTES / 1024 / 1024
                );
            }
            let mut conteudo = Vec::with_capacity(declarado as usize);
            Read::by_ref(&mut item)
                .take(restante + 1)
                .read_to_end(&mut conteudo)?;
            if conteudo.len() as u64 != declarado {
                bail!(
                    "conteúdo truncado ou excessivo em {NOME_TARBALL}: {}",
                    caminho.display()
                );
            }
            bytes_regulares += declarado;
            if partes.len() == 2 && partes[1] == "recipe" {
                receitas.insert(pacote.to_string());
            }
            (TipoEntrada::Regular(conteudo), false)
        } else {
            bail!(
                "{NOME_TARBALL} contém tipo TAR não permitido em {}",
                caminho.display()
            );
        };
        if caminhos.insert(caminho.clone(), diretorio).is_some() {
            bail!("{NOME_TARBALL} repete o caminho {}", caminho.display());
        }
        entradas.push(Entrada {
            caminho,
            modo,
            tipo,
        });
    }

    if pacotes.is_empty() {
        bail!("{NOME_TARBALL} não contém pacote nenhum");
    }
    for pacote in &pacotes {
        if !receitas.contains(pacote) {
            bail!("{NOME_TARBALL}: pacote {pacote} não contém recipe regular");
        }
    }
    for caminho in caminhos.keys() {
        let mut ancestral = caminho.parent();
        while let Some(pai) = ancestral.filter(|pai| !pai.as_os_str().is_empty()) {
            if caminhos.get(pai).is_some_and(|diretorio| !diretorio) {
                bail!(
                    "{NOME_TARBALL} põe {} sob ancestral que não é diretório",
                    caminho.display()
                );
            }
            ancestral = pai.parent();
        }
    }
    Ok(entradas)
}

fn garante_diretorios_reais(base: &Path, relativo: &Path) -> Result<()> {
    let mut atual = base.to_path_buf();
    for componente in relativo.components() {
        let Component::Normal(nome) = componente else {
            unreachable!("caminho já validado como relativo e canônico")
        };
        atual.push(nome);
        match fs::symlink_metadata(&atual) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!("{} não é diretório real", atual.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o755).create(&atual)?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::set_permissions(&atual, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn materializa(entradas: &[Entrada], destino: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(destino)
        .with_context(|| format!("criando {}", destino.display()))?;

    let mut diretorios = entradas
        .iter()
        .filter(|entrada| matches!(&entrada.tipo, TipoEntrada::Diretorio))
        .collect::<Vec<_>>();
    diretorios.sort_by(|left, right| {
        left.caminho
            .components()
            .count()
            .cmp(&right.caminho.components().count())
            .then_with(|| left.caminho.cmp(&right.caminho))
    });
    for entrada in diretorios {
        garante_diretorios_reais(destino, &entrada.caminho)?;
    }
    for entrada in entradas {
        let TipoEntrada::Regular(conteudo) = &entrada.tipo else {
            continue;
        };
        let caminho = destino.join(&entrada.caminho);
        let pai = caminho
            .parent()
            .ok_or_else(|| anyhow::anyhow!("arquivo sem pai em {NOME_TARBALL}"))?;
        let pai_relativo = pai
            .strip_prefix(destino)
            .map_err(|_| anyhow::anyhow!("pai escapou da árvore nova"))?;
        garante_diretorios_reais(destino, pai_relativo)?;
        let mut arquivo = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&caminho)
            .with_context(|| format!("criando {}", caminho.display()))?;
        arquivo.write_all(conteudo)?;
        arquivo.set_permissions(fs::Permissions::from_mode(entrada.modo))?;
        arquivo.sync_all()?;
    }
    fs::set_permissions(destino, fs::Permissions::from_mode(0o755))?;
    // Torna a árvore montada durável antes de publicar seu nome. Diretórios
    // são sincronizados dos mais fundos para a raiz para que entradas e pais
    // cheguem ao disco antes do exchange.
    // Um TAR válido pode omitir cabeçalhos de diretório e deixar que os pais
    // sejam inferidos de `pkg/recipe`. Esses pais também precisam de fsync:
    // sincronizar só os diretórios explicitamente listados poderia publicar
    // após uma queda uma árvore cujo arquivo estava durável, mas cuja entrada
    // no diretório implícito não estava.
    let mut todos = BTreeSet::new();
    for entrada in entradas {
        let mut dir = match &entrada.tipo {
            TipoEntrada::Diretorio => destino.join(&entrada.caminho),
            TipoEntrada::Regular(_) => destino
                .join(&entrada.caminho)
                .parent()
                .ok_or_else(|| anyhow::anyhow!("entrada da árvore sem diretório pai"))?
                .to_path_buf(),
        };
        while dir != destino {
            if !dir.starts_with(destino) {
                bail!("diretório materializado escapou da árvore nova");
            }
            todos.insert(dir.clone());
            dir = dir
                .parent()
                .ok_or_else(|| anyhow::anyhow!("diretório materializado sem pai"))?
                .to_path_buf();
        }
    }
    let mut dirs = todos.into_iter().collect::<Vec<_>>();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        fs::File::open(dir)?.sync_all()?;
    }
    fs::File::open(destino)?.sync_all()?;
    Ok(())
}

fn aplica_tarball_assinado(
    ctx: &Ctx,
    tarball: &[u8],
    assinatura: &[u8],
    chave: &PublicKey,
) -> Result<()> {
    // AUTENTICA ANTES DE INTERPRETAR. Nem um cabeçalho TAR controlado pela
    // rede é analisado até a chave pinada dizer que o objeto é do projeto.
    confere_assinatura(tarball, assinatura, chave)?;
    let entradas = decodifica_tarball(tarball).map_err(|error| crate::Fail {
        code: 2,
        msg: format!("árvore newspeak assinada é inválida: {error}"),
    })?;
    let (atual, novo, anterior) = caminhos(ctx);
    remove_diretorio_real_se_existe(&novo, "tentativa anterior de árvore")?;
    if let Err(error) = materializa(&entradas, &novo) {
        let _ = fs::remove_dir_all(&novo);
        return Err(error);
    }
    if let Err(error) = troca_atomica(&atual, &novo, &anterior) {
        let _ = fs::remove_dir_all(&novo);
        return Err(error);
    }
    Ok(())
}

/// Implementa o nome especial da SPEC-0011 §3.1.
///
/// Não entra no `world`, não carrega receita chamada `newspeak` e não aceita
/// TOFU. A árvore é o registro que torna todas as outras receitas conhecidas;
/// tratá-la como pacote ordinário criaria a dependência circular que este
/// caminho especial existe para evitar.
pub fn rectify(ctx: &Ctx) -> Result<()> {
    let _lock = crate::install::acquire_lock(ctx)?;
    recupera_troca_interrompida(ctx)?;
    let config = origem(ctx)?;
    if ctx.offline {
        return fail(
            6,
            format!(
                "--offline não pode buscar a árvore newspeak em {}",
                config.url
            ),
        );
    }
    let chave = chave_publica(&config.key)?;
    let (tarball_url, assinatura_url) = urls_da_origem(&config)?;
    eprintln!("  buscando {NOME_ASSINATURA}");
    let assinatura = baixa_limitado(&assinatura_url, MAX_SIGNATURE_BYTES)?;
    eprintln!("  buscando {NOME_TARBALL}");
    let tarball = baixa_limitado(&tarball_url, MAX_TARBALL_BYTES)?;
    aplica_tarball_assinado(ctx, &tarball, &assinatura, &chave)?;
    println!("árvore newspeak retificada");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use blake2::{Blake2b512, Digest};
    use ed25519_dalek::{Signer, SigningKey};
    use std::os::unix::fs::symlink;

    #[test]
    fn origem_exige_url_e_chave() {
        let bom = "URL=https://distropica.com.br/newspeak/\nKEY=RWQabc\n";
        let o = analisa_origem(bom, "t").unwrap();
        assert_eq!(o.url, "https://distropica.com.br/newspeak/");
        assert_eq!(o.key, "RWQabc");

        for ruim in [
            "KEY=RWQabc\n",
            "URL=https://x/\n",
            "URL=\nKEY=RWQabc\n",
            "URL=https://x/\nKEY=\n",
            "",
        ] {
            assert!(
                analisa_origem(ruim, "t").is_err(),
                "aceitou origem incompleta: {ruim:?}"
            );
        }
    }

    /// HTTP em claro é recusado. A assinatura protege o CONTEÚDO; o transporte
    /// em claro entrega quem ainda não atualizou, e permite negar atualização —
    /// que é ataque mais barato que forjar assinatura.
    #[test]
    fn origem_recusa_transporte_em_claro() {
        let erro = analisa_origem("URL=http://distropica.com.br/n/\nKEY=RWQabc\n", "t")
            .unwrap_err()
            .to_string();
        assert!(erro.contains("https"), "mensagem: {erro}");
    }

    /// Chave desconhecida não derruba a leitura: um arquivo escrito por uma
    /// versão mais nova precisa continuar utilizável por esta.
    #[test]
    fn origem_ignora_chaves_que_nao_conhece() {
        let texto = "# comentário\nURL=https://x/\nKEY=RWQabc\nFUTURO=algo\nPRIORITY=100\n";
        let o = analisa_origem(texto, "t").unwrap();
        assert_eq!(o.key, "RWQabc");
    }

    #[test]
    fn origem_em_disco_recusa_symlink_hardlink_e_arquivo_excessivo() {
        let tmp = Raiz::nova("origem-confinada");
        let cache = tmp.path().join("var/cache/minitrue");
        fs::create_dir_all(&cache).unwrap();
        let outside = tmp.path().join("fora");
        fs::write(&outside, b"URL=https://x/\nKEY=RWQabc\n").unwrap();
        let origin = cache.join("newspeak-origem");

        symlink(&outside, &origin).unwrap();
        assert!(origem(&ctx_de_teste(tmp.path())).is_err());
        fs::remove_file(&origin).unwrap();

        fs::hard_link(&outside, &origin).unwrap();
        let error = origem(&ctx_de_teste(tmp.path())).unwrap_err().to_string();
        assert!(error.contains("hardlinks"), "mensagem: {error}");
        fs::remove_file(&origin).unwrap();

        fs::write(&origin, vec![b'x'; MAX_ORIGIN_BYTES as usize + 1]).unwrap();
        let error = origem(&ctx_de_teste(tmp.path())).unwrap_err().to_string();
        assert!(error.contains("excede"), "mensagem: {error}");
    }

    use std::sync::atomic::{AtomicU64, Ordering};
    static CNT: AtomicU64 = AtomicU64::new(0);

    /// Raiz temporária no idioma que este crate já usa — o minitrue não tem
    /// `tempfile` entre as dependências, e acrescentá-la por causa de três
    /// testes seria pagar uma crate para não escrever quatro linhas.
    struct Raiz(PathBuf);
    impl Raiz {
        fn nova(marca: &str) -> Raiz {
            let n = CNT.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("mt-arvore-{marca}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Raiz(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Raiz {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn ctx_de_teste(raiz: &Path) -> Ctx {
        Ctx {
            root: raiz.to_path_buf(),
            offline: true,
            tofu: false,
            jobs: 1,
        }
    }

    fn assina(mensagem: &[u8]) -> (PublicKey, Vec<u8>) {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let key_id = [8u8, 7, 6, 5, 4, 3, 2, 1];
        let mut publica = Vec::from(*b"ED");
        publica.extend_from_slice(&key_id);
        publica.extend_from_slice(&signing.verifying_key().to_bytes());
        let publica = base64::engine::general_purpose::STANDARD.encode(publica);

        let digest = Blake2b512::digest(mensagem);
        let assinatura = signing.sign(&digest);
        let trusted = "timestamp:0 file:newspeak.tar";
        let mut corpo_global = Vec::from(assinatura.to_bytes());
        corpo_global.extend_from_slice(trusted.as_bytes());
        let global = signing.sign(&corpo_global);
        let mut primeira = Vec::from(*b"ED");
        primeira.extend_from_slice(&key_id);
        primeira.extend_from_slice(&assinatura.to_bytes());
        let texto = format!(
            "untrusted comment: teste newspeak\n{}\ntrusted comment: {}\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(primeira),
            trusted,
            base64::engine::general_purpose::STANDARD.encode(global.to_bytes())
        );
        (chave_publica(&publica).unwrap(), texto.into_bytes())
    }

    fn tar_de(entradas: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            for (caminho, tipo, conteudo) in entradas {
                let mut header = tar::Header::new_gnu();
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_mode(if *tipo == tar::EntryType::Directory {
                    0o755
                } else {
                    0o644
                });
                header.set_entry_type(*tipo);
                header.set_size(conteudo.len() as u64);
                header.set_path(caminho).unwrap();
                header.set_cksum();
                builder.append(&header, *conteudo).unwrap();
            }
            builder.finish().unwrap();
        }
        bytes
    }

    fn tar_com_nome_bruto(caminho: &[u8], conteudo: &[u8]) -> Vec<u8> {
        assert!(caminho.len() < 100);
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(conteudo.len() as u64);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..caminho.len()].copy_from_slice(caminho);
        header.set_cksum();
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(conteudo);
        let padding = (512 - conteudo.len() % 512) % 512;
        bytes.resize(bytes.len() + padding + 1024, 0);
        bytes
    }

    #[test]
    fn origem_resolve_os_nomes_canonicos_com_ou_sem_barra() {
        for url in [
            "https://distropica.com.br/newspeak/",
            "https://distropica.com.br/newspeak",
        ] {
            let (tarball, assinatura) = urls_da_origem(&Origem {
                url: url.into(),
                key: "k".into(),
            })
            .unwrap();
            assert_eq!(
                tarball.as_str(),
                "https://distropica.com.br/newspeak/newspeak.tar"
            );
            assert_eq!(
                assinatura.as_str(),
                "https://distropica.com.br/newspeak/newspeak.tar.minisig"
            );
        }
    }

    #[test]
    fn tarball_assinado_substitui_a_arvore_inteira() {
        let tmp = Raiz::nova("assinada");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join("newspeak/velha")).unwrap();
        fs::write(base.join("newspeak/velha/recipe"), b"VERSION=1\n").unwrap();
        let tarball = tar_de(&[
            ("nova", tar::EntryType::Directory, b""),
            (
                "nova/recipe",
                tar::EntryType::Regular,
                b"NAME=nova\nVERSION=2\n",
            ),
            ("nova/versao-pinada", tar::EntryType::Regular, b"motivo\n"),
        ]);
        let (chave, assinatura) = assina(&tarball);

        aplica_tarball_assinado(&ctx_de_teste(tmp.path()), &tarball, &assinatura, &chave).unwrap();

        assert_eq!(
            fs::read_to_string(base.join("newspeak/nova/recipe")).unwrap(),
            "NAME=nova\nVERSION=2\n"
        );
        assert!(!base.join("newspeak/velha").exists());
        assert!(!base.join(".newspeak.novo").exists());
        assert!(!base.join(".newspeak.anterior").exists());
    }

    #[test]
    fn tarball_do_pack_normaliza_modos_como_a_midia() {
        let tmp = Raiz::nova("pack-modos");
        let fonte = tmp.path().join("fonte");
        fs::create_dir_all(fonte.join("pkg/files")).unwrap();
        fs::write(
            fonte.join("pkg/recipe"),
            b"NAME=pkg\nVERSION=1\nLICENSE=MIT\n",
        )
        .unwrap();
        fs::write(fonte.join("pkg/files/aux.sh"), b"#!/bin/sh\n").unwrap();
        for diretorio in [fonte.join("pkg"), fonte.join("pkg/files")] {
            fs::set_permissions(diretorio, fs::Permissions::from_mode(0o775)).unwrap();
        }
        fs::set_permissions(fonte.join("pkg/recipe"), fs::Permissions::from_mode(0o664)).unwrap();
        fs::set_permissions(
            fonte.join("pkg/files/aux.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut tarball = Vec::new();
        crate::pack::pack_deterministic(&fonte, 0, &mut tarball).unwrap();

        let entradas = decodifica_tarball(&tarball).unwrap();
        let recipe = entradas
            .iter()
            .find(|entrada| entrada.caminho == Path::new("pkg/recipe"))
            .unwrap();
        assert_eq!(recipe.modo, 0o644);
        let auxiliar = entradas
            .iter()
            .find(|entrada| entrada.caminho == Path::new("pkg/files/aux.sh"))
            .unwrap();
        assert_eq!(auxiliar.modo, 0o755);
    }

    #[test]
    fn assinatura_invalida_preserva_a_arvore_atual() {
        let tmp = Raiz::nova("assinatura-invalida");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join("newspeak/base")).unwrap();
        fs::write(base.join("newspeak/base/recipe"), b"velha\n").unwrap();
        let tarball = tar_de(&[(
            "nova/recipe",
            tar::EntryType::Regular,
            b"NAME=nova\nVERSION=2\n",
        )]);
        let (chave, mut assinatura) = assina(b"outro objeto");
        assinatura.extend_from_slice(b"\n");

        let erro =
            aplica_tarball_assinado(&ctx_de_teste(tmp.path()), &tarball, &assinatura, &chave)
                .unwrap_err();
        assert!(erro.to_string().contains("crimestop"), "erro: {erro}");
        assert_eq!(
            fs::read_to_string(base.join("newspeak/base/recipe")).unwrap(),
            "velha\n"
        );
        assert!(!base.join(".newspeak.novo").exists());
    }

    #[test]
    fn tarball_assinado_com_travessia_e_recusado_antes_da_troca() {
        let tmp = Raiz::nova("travessia");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join("newspeak/base")).unwrap();
        fs::write(base.join("newspeak/base/recipe"), b"velha\n").unwrap();
        let tarball = tar_com_nome_bruto(b"../escape", b"intruso\n");
        let (chave, assinatura) = assina(&tarball);

        let erro =
            aplica_tarball_assinado(&ctx_de_teste(tmp.path()), &tarball, &assinatura, &chave)
                .unwrap_err();
        assert!(erro.to_string().contains("inválida"), "erro: {erro}");
        assert!(base.join("newspeak/base/recipe").exists());
        assert!(!base.join("escape").exists());
        assert!(!base.join(".newspeak.novo").exists());
    }

    #[test]
    fn tarball_assinado_sem_recipe_regular_e_recusado() {
        let tmp = Raiz::nova("sem-recipe");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join("newspeak/base")).unwrap();
        fs::write(base.join("newspeak/base/recipe"), b"velha\n").unwrap();
        let tarball = tar_de(&[("nova/ABOUT", tar::EntryType::Regular, b"sem recipe\n")]);
        let (chave, assinatura) = assina(&tarball);

        let erro =
            aplica_tarball_assinado(&ctx_de_teste(tmp.path()), &tarball, &assinatura, &chave)
                .unwrap_err();
        assert!(
            erro.to_string().contains("não contém recipe"),
            "erro: {erro}"
        );
        assert!(base.join("newspeak/base/recipe").exists());
    }

    #[test]
    fn tarball_assinado_materializa_modo_canonico() {
        let tmp = Raiz::nova("modo");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join("newspeak/base")).unwrap();
        fs::write(base.join("newspeak/base/recipe"), b"velha\n").unwrap();
        let mut tarball = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tarball);
            let mut header = tar::Header::new_gnu();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_mode(0o664);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(b"NAME=nova\n".len() as u64);
            header.set_path("nova/recipe").unwrap();
            header.set_cksum();
            builder.append(&header, &b"NAME=nova\n"[..]).unwrap();
            builder.finish().unwrap();
        }
        let (chave, assinatura) = assina(&tarball);

        aplica_tarball_assinado(&ctx_de_teste(tmp.path()), &tarball, &assinatura, &chave).unwrap();
        assert!(!base.join("newspeak/base/recipe").exists());
        assert_eq!(
            fs::metadata(base.join("newspeak/nova/recipe"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }

    /// Estado legado: a queda entre os dois renames antigos deixava a máquina
    /// sem árvore. A versão atual ainda precisa recuperá-la, e sem rede.
    #[test]
    fn recupera_arvore_de_troca_interrompida() {
        let tmp = Raiz::nova("interrompida");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join(".newspeak.anterior/base")).unwrap();
        fs::write(base.join(".newspeak.anterior/base/recipe"), "VERSION=1\n").unwrap();
        fs::create_dir_all(base.join(".newspeak.novo")).unwrap();

        let ctx = ctx_de_teste(tmp.path());
        recupera_troca_interrompida(&ctx).unwrap();

        assert!(base.join("newspeak/base/recipe").exists(), "não recuperou");
        assert!(
            !base.join(".newspeak.novo").exists(),
            "sobrou lixo da tentativa"
        );
    }

    /// Com a árvore no lugar, a recuperação não mexe em nada.
    #[test]
    fn recuperacao_nao_toca_arvore_sa() {
        let tmp = Raiz::nova("sa");
        let base = tmp.path().join("var/lib/minitrue");
        fs::create_dir_all(base.join("newspeak/base")).unwrap();
        fs::write(base.join("newspeak/base/recipe"), "VERSION=2\n").unwrap();

        recupera_troca_interrompida(&ctx_de_teste(tmp.path())).unwrap();
        assert_eq!(
            fs::read_to_string(base.join("newspeak/base/recipe")).unwrap(),
            "VERSION=2\n"
        );
    }

    #[test]
    fn recuperacao_nao_promove_symlink_para_fora_como_arvore() {
        let tmp = Raiz::nova("recuperacao-symlink");
        let base = tmp.path().join("var/lib/minitrue");
        let outside = tmp.path().join("fora");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("recipe"), b"fora\n").unwrap();
        symlink(&outside, base.join(".newspeak.anterior")).unwrap();

        assert!(recupera_troca_interrompida(&ctx_de_teste(tmp.path())).is_err());
        assert!(!base.join("newspeak").exists());
        assert_eq!(fs::read(outside.join("recipe")).unwrap(), b"fora\n");
    }

    /// A troca publica a nova e some com a anterior, sem deixar rastro.
    #[test]
    fn troca_publica_a_nova_e_limpa() {
        let tmp = Raiz::nova("troca");
        let base = tmp.path().join("var/lib/minitrue");
        let (atual, novo, anterior) = (
            base.join("newspeak"),
            base.join(".newspeak.novo"),
            base.join(".newspeak.anterior"),
        );
        fs::create_dir_all(atual.join("base")).unwrap();
        fs::write(atual.join("base/recipe"), "velha\n").unwrap();
        fs::create_dir_all(novo.join("base")).unwrap();
        fs::write(novo.join("base/recipe"), "nova\n").unwrap();

        troca_atomica(&atual, &novo, &anterior).unwrap();

        assert_eq!(
            fs::read_to_string(atual.join("base/recipe")).unwrap(),
            "nova\n"
        );
        assert!(!novo.exists());
        assert!(!anterior.exists());
    }
}
