//! As telas do instalador de disco.
//!
//! A ORDEM DA SPEC-0008 §8 É PRESERVADA, e isto não é detalhe de organização:
//! a mídia é validada e a closure materializada em /run ANTES de o operador
//! sequer ver a lista de discos. Quando estas telas aparecem, nada foi escrito
//! em disco nenhum e uma desistência não deixa rastro. É uma disciplina cara
//! de descobrir e barata de perder.
//!
//! ESTE MÓDULO NÃO ESCREVE EM DISCO — com uma exceção que ele não controla: na
//! rota manual, o `cfdisk` é executado daqui, e é o OPERADOR quem grava a
//! tabela de partições por vontade própria, dentro de outro programa. Fora
//! isso, o módulo decide e devolve a decisão; quem aplica é o caminho já
//! auditado — `partition::write_layout` para o automático, `mkfs` no init para
//! o manual. Separar a escolha da execução é o que permite testar a primeira
//! sem arriscar a segunda.

use crate::disco::{self, Disco, Particao};
use crate::tui::Terminal;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Como o disco será particionado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rota {
    /// Layout automático: ESP + raiz + swap, apagando tudo.
    DiscoInteiro,
    /// O operador parte o disco no cfdisk e depois atribui as partições.
    Manual,
}

/// Os tamanhos mínimos, medidos por quem chama.
///
/// NENHUM DELES É CONSTANTE AQUI, e a razão é que nenhum deles é conhecido
/// aqui. O tamanho do EFI é o do arquivo que está na mídia; o mínimo da raiz
/// sai do `cache.tar` desta mídia pela fórmula que o init já calcula. Repetir
/// esses números no Rust criaria duas contas para a mesma coisa — e é assim que
/// se descobre tarde que uma delas estava errada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exigencias {
    /// Tamanho do BOOTX64.EFI que a mídia vai instalar.
    pub efi_bytes: u64,
    /// Tamanho da ESP que a rota automática cria.
    pub esp_automatica_bytes: u64,
    /// Raiz mínima estimada para o sistema caber.
    pub raiz_minima_bytes: u64,
}

/// Folga para os metadados do FAT, além do próprio EFI. É a mesma reserva que o
/// init aplica ao conferir se o EFI cabe na ESP de 64 MiB.
const FOLGA_FAT: u64 = 4 * 1024 * 1024;

/// Abaixo disto a área de troca não ajuda e ainda tira espaço da raiz. Mesmo
/// piso que o init aplica na rota automática.
const TROCA_MINIMA: u64 = 128 * 1024 * 1024;

impl Exigencias {
    /// Menor ESP que aceita o EFI desta mídia.
    pub fn esp_minima(&self) -> u64 {
        self.efi_bytes + FOLGA_FAT
    }
}

/// A decisão que sai destas telas, para o init executar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decisao {
    DiscoInteiro {
        disco: String,
    },
    Manual {
        disco: String,
        esp: String,
        formatar_esp: bool,
        raiz: String,
        troca: Option<String>,
    },
}

impl Decisao {
    /// Serialização lida pelo init.
    ///
    /// TODA CHAVE SAI SEMPRE, inclusive `TROCA=` vazia — mesma regra do
    /// `minipax partition`. Um script que lê isto precisa distinguir "não há
    /// troca" de "esta versão do minipax não escreve troca", e uma linha
    /// faltando é indistinguível das duas coisas.
    pub fn serializa(&self) -> String {
        let mut s = String::from("DISTROPICA_INSTALL_FORMAT=1\n");
        match self {
            Decisao::DiscoInteiro { disco } => {
                s.push_str("ROTA=disco-inteiro\n");
                s.push_str(&format!("DISCO={disco}\n"));
                s.push_str("ESP=\n");
                s.push_str("FORMATAR_ESP=sim\n");
                s.push_str("RAIZ=\n");
                s.push_str("TROCA=\n");
            }
            Decisao::Manual {
                disco,
                esp,
                formatar_esp,
                raiz,
                troca,
            } => {
                s.push_str("ROTA=manual\n");
                s.push_str(&format!("DISCO={disco}\n"));
                s.push_str(&format!("ESP={esp}\n"));
                s.push_str(&format!(
                    "FORMATAR_ESP={}\n",
                    if *formatar_esp { "sim" } else { "nao" }
                ));
                s.push_str(&format!("RAIZ={raiz}\n"));
                s.push_str(&format!("TROCA={}\n", troca.as_deref().unwrap_or("")));
            }
        }
        s
    }
}

/// Monta as linhas do menu de discos: rótulo e detalhe por item.
///
/// Função separada da tela PARA SER TESTÁVEL. A tela precisa de um terminal;
/// a decisão do que mostrar, não — e é no que se mostra que mora o defeito que
/// leva alguém a apagar o disco errado.
pub fn itens_de_disco(discos: &[Disco]) -> Vec<(String, String)> {
    discos.iter().map(|d| (d.resumo(), d.detalhe())).collect()
}

/// Tela de escolha do disco.
///
/// Devolve `None` quando o operador desiste — e desistir é uma saída legítima,
/// não um erro: até aqui nada foi escrito.
pub fn escolher_disco(
    term: &mut Terminal,
    sysfs: &Path,
    excluir: &[PathBuf],
) -> Result<Option<Disco>> {
    let discos = disco::candidatos(sysfs, excluir)?;
    if discos.is_empty() {
        // Lista vazia é ambígua, e a ambiguidade custa caro aqui: pode ser
        // máquina sem disco, driver ausente, ou o único disco ser a própria
        // mídia. O texto diz as três em vez de deixar o operador adivinhar —
        // mesma razão da tela vazia do miniluv.
        term.aviso(
            "instalação em disco",
            &[
                "Nenhum disco disponível para instalação.".into(),
                String::new(),
                "Isso acontece em três situações:".into(),
                "  · a máquina não tem disco reconhecido pelo kernel;".into(),
                "  · falta o driver do controlador nesta mídia;".into(),
                "  · o único disco presente é o que contém esta mídia,".into(),
                "    e instalar sobre ela destruiria a instalação em curso.".into(),
            ],
        )?;
        return Ok(None);
    }

    let intro = vec![
        "Escolha o disco que vai receber o sistema.".to_string(),
        "Nada foi escrito em disco algum até aqui.".to_string(),
    ];
    let itens = itens_de_disco(&discos);
    match term.menu_detalhado("escolha do disco", &intro, &itens)? {
        Some(i) => Ok(Some(discos[i].clone())),
        None => Ok(None),
    }
}

/// Tela de escolha da rota de particionamento.
pub fn escolher_rota(term: &mut Terminal, alvo: &Disco) -> Result<Option<Rota>> {
    let intro = vec![
        format!("Disco escolhido: {}", alvo.resumo()),
        alvo.detalhe().trim_start().to_string(),
        String::new(),
        "Como particionar?".to_string(),
    ];
    let itens = vec![
        (
            "Usar o disco inteiro".to_string(),
            "     apaga TUDO e cria ESP, raiz e área de troca automaticamente".to_string(),
        ),
        (
            "Particionar eu mesmo (cfdisk)".to_string(),
            "     abre o cfdisk; depois você diz qual partição é qual".to_string(),
        ),
    ];
    match term.menu_detalhado("particionamento", &intro, &itens)? {
        Some(0) => Ok(Some(Rota::DiscoInteiro)),
        Some(1) => Ok(Some(Rota::Manual)),
        _ => Ok(None),
    }
}

/// O disco comporta a rota automática?
///
/// Recusar AQUI, e não depois de apagar, é o ponto: o init já sabia fazer esta
/// conta, mas só a fazia depois de o operador confirmar a destruição. Devolve
/// a explicação em vez de um booleano porque "não cabe" sem o número não
/// permite ao operador decidir o que fazer com o disco.
pub fn cabe_disco_inteiro(alvo: &Disco, exig: &Exigencias) -> Result<(), String> {
    // 1 MiB de alinhamento inicial + ESP + raiz mínima. É o mesmo layout que o
    // `partition::write_layout` escreve.
    let preciso = 1024 * 1024 + exig.esp_automatica_bytes + exig.raiz_minima_bytes;
    if alvo.bytes >= preciso {
        return Ok(());
    }
    Err(format!(
        "{} tem {}, e a instalação precisa de ao menos {}.",
        alvo.caminho().display(),
        disco::tamanho_legivel(alvo.bytes),
        disco::tamanho_legivel(preciso)
    ))
}

/// As linhas do aviso de destruição. Separadas da tela pelo mesmo motivo dos
/// itens de disco: é texto que precisa estar certo, e texto se testa.
pub fn linhas_de_destruicao(alvo: &Disco) -> Vec<String> {
    let mut l = vec![format!("Vai ser APAGADO: {}", alvo.resumo()), String::new()];
    if alvo.particoes.is_empty() {
        l.push("O disco não tem partições — nada identificável se perde.".into());
    } else {
        l.push(format!(
            "As {} partição(ões) abaixo serão destruídas, com todo o conteúdo:",
            alvo.particoes.len()
        ));
        for p in &alvo.particoes {
            l.push(format!(
                "  · {} — {}",
                p.nome,
                disco::tamanho_legivel(p.bytes)
            ));
        }
    }
    l.push(String::new());
    l.push("Esta operação não tem volta.".into());
    l
}

/// Confirmação da escrita destrutiva.
///
/// UMA TECLA, e o cuidado mudou de lugar. A versão anterior exigia o nome do
/// disco digitado; a fricção era real e o ganho, menor do que parecia — quem
/// digita `sda` no automático está copiando o que a tela mostra, não conferindo
/// de novo qual disco escolheu.
///
/// O que impede o acidente agora é o `confirma_com_enter` descartar o que já
/// estava na fila do terminal: o Enter que trouxe o operador até aqui não
/// atravessa esta tela. Sem isso, um Enter repetido apagaria o disco sem que
/// ninguém tivesse lido o aviso — e AÍ sim a confirmação seria decorativa.
pub fn confirmar_destruicao(term: &mut Terminal, alvo: &Disco) -> Result<bool> {
    term.confirma_com_enter(
        "confirmação",
        &linhas_de_destruicao(alvo),
        "Enter APAGA o disco · Esc volta",
    )
}

/// O resultado de filtrar partições para um papel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triagem {
    pub servem: Vec<Particao>,
    /// Uma linha por partição recusada, DIZENDO O PORQUÊ. Uma lista que
    /// simplesmente omite a partição faz o operador procurar no cfdisk um
    /// defeito que não está lá.
    pub recusadas: Vec<String>,
}

/// Separa as partições que servem para um papel das que não servem.
pub fn triar(particoes: &[Particao], minimo: u64, ja_usadas: &[String]) -> Triagem {
    let mut servem = Vec::new();
    let mut recusadas = Vec::new();
    for p in particoes {
        if ja_usadas.contains(&p.nome) {
            recusadas.push(format!("{} — já atribuída", p.nome));
        } else if p.bytes < minimo {
            recusadas.push(format!(
                "{} — {} é pouco; preciso de {}",
                p.nome,
                disco::tamanho_legivel(p.bytes),
                disco::tamanho_legivel(minimo)
            ));
        } else {
            servem.push(p.clone());
        }
    }
    Triagem { servem, recusadas }
}

/// Itens de menu para uma triagem.
pub fn itens_de_particao(t: &Triagem) -> Vec<(String, String)> {
    t.servem
        .iter()
        .map(|p| {
            (
                format!("/dev/{}  {}", p.nome, disco::tamanho_legivel(p.bytes)),
                String::new(),
            )
        })
        .collect()
}

/// As linhas que descrevem o que a rota manual vai formatar.
///
/// Cada linha diz o VERBO e a consequência. "Será formatada" sem dizer que
/// isso apaga o conteúdo é a frase que faz alguém perder o carregador de
/// arranque do outro sistema achando que só estava escolhendo um caminho.
pub fn linhas_do_plano_manual(
    esp: &Particao,
    formatar_esp: bool,
    raiz: &Particao,
    troca: Option<&Particao>,
) -> Vec<String> {
    let mut l = vec![
        "O que vai acontecer com cada partição:".to_string(),
        String::new(),
    ];
    l.push(format!(
        "  /dev/{} ({}) — raiz: FORMATADA em ext4; tudo nela se perde",
        raiz.nome,
        disco::tamanho_legivel(raiz.bytes)
    ));
    if formatar_esp {
        l.push(format!(
            "  /dev/{} ({}) — ESP: FORMATADA em FAT32; se houver outro",
            esp.nome,
            disco::tamanho_legivel(esp.bytes)
        ));
        l.push("      sistema instalado, o carregador dele se perde".to_string());
    } else {
        // "PRESERVADA" sozinho seria meia verdade, e a metade que falta é a que
        // pode custar o arranque de outro sistema: o instalador grava em
        // EFI/BOOT/BOOTX64.EFI, que é o caminho de reserva do firmware. Numa
        // máquina cujo outro sistema arranca por ele — e não por entrada
        // própria na NVRAM —, esse arquivo É o carregador dele.
        l.push(format!(
            "  /dev/{} ({}) — ESP: PRESERVADA, exceto EFI/BOOT/BOOTX64.EFI,",
            esp.nome,
            disco::tamanho_legivel(esp.bytes)
        ));
        l.push("      que é substituído; o resto do conteúdo fica".to_string());
    }
    match troca {
        Some(t) => l.push(format!(
            "  /dev/{} ({}) — área de troca: FORMATADA; tudo nela se perde",
            t.nome,
            disco::tamanho_legivel(t.bytes)
        )),
        None => l.push("  sem área de troca".to_string()),
    }
    l.push(String::new());
    l.push("Nenhuma outra partição é tocada.".to_string());
    l.push("Esta operação não tem volta.".to_string());
    l
}

/// As linhas do aviso que antecede o cfdisk.
///
/// Função pura pelo mesmo motivo das outras telas deste módulo: é TEXTO QUE
/// PRECISA ESTAR CERTO, e texto se testa. Aqui o risco é concreto — o operador
/// está numa máquina que ainda não tem sistema e não pode pesquisar o que o
/// cfdisk está perguntando em inglês.
pub fn linhas_do_aviso_cfdisk(alvo: &Disco, exig: &Exigencias) -> Vec<String> {
    vec![
        format!("Vou abrir o cfdisk em {}.", alvo.caminho().display()),
        String::new(),
        "O cfdisk é outro programa e fala inglês. Duas perguntas dele:".into(),
        "  · tipo de rótulo (label): escolha SEMPRE gpt. Esta distro só".into(),
        "    arranca por UEFI, e o firmware procura a ESP numa GPT.".into(),
        "  · \"Device already contains a gpt signature. Remove it?\":".into(),
        "    responda Yes. É uma tabela velha; a nova substitui.".into(),
        String::new(),
        "Crie, no mínimo:".into(),
        format!(
            "  · EFI System — ao menos {} (64 MiB é folgado)",
            disco::tamanho_legivel(exig.esp_minima())
        ),
        format!(
            "  · Linux filesystem para a raiz — ao menos {}",
            disco::tamanho_legivel(exig.raiz_minima_bytes)
        ),
        format!(
            "  · Linux swap, se quiser troca — ao menos {}",
            disco::tamanho_legivel(TROCA_MINIMA)
        ),
        String::new(),
        "NADA do que você fizer lá vale até escolher [Write] e digitar".into(),
        "'yes'. Sair com [Quit] não grava coisa alguma.".into(),
    ]
}

/// Relê o disco depois que o cfdisk gravou.
///
/// A ESPERA EXISTE porque a tabela nova chega ao sysfs pelo BLKRRPART que o
/// cfdisk dispara ao gravar, e nem todo controlador responde a ele na mesma
/// hora. Cinco segundos é teto e não espera fixa: assim que aparecer partição,
/// devolve. É a mesma lição do `find_media` — o disco existir no kernel e
/// estar visível não são o mesmo instante.
fn reler_disco(sysfs: &Path, nome: &str, esperar: bool) -> Result<Disco> {
    for tentativa in 0..if esperar { 5 } else { 1 } {
        if tentativa > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let discos = disco::candidatos(sysfs, &[])?;
        if let Some(d) = discos.into_iter().find(|d| d.nome == nome) {
            if !d.particoes.is_empty() || !esperar {
                return Ok(d);
            }
        }
    }
    let discos = disco::candidatos(sysfs, &[])?;
    discos
        .into_iter()
        .find(|d| d.nome == nome)
        .with_context(|| format!("o disco {nome} sumiu da lista depois do cfdisk"))
}

/// A rota manual inteira: cfdisk, atribuição e confirmação.
///
/// É UMA MÁQUINA DE PASSOS, e não uma sequência de `?`, porque Esc precisa
/// voltar UMA tela — não a instalação inteira. Na versão anterior, um Esc na
/// tela da raiz descartava também a ESP e o "formatar ou preservar" já
/// escolhidos, e jogava o operador de volta na lista de discos: quem errou a
/// última escolha pagava por todas.
///
/// Voltar do primeiro passo sai da rota manual e devolve à escolha de
/// particionamento. O passo do cfdisk é o primeiro de propósito: voltar da
/// atribuição significa "quero mexer nas partições de novo", e é exatamente ali
/// que se reabre o cfdisk.
pub fn rota_manual(
    term: &mut Terminal,
    sysfs: &Path,
    alvo: &Disco,
    exig: &Exigencias,
    cfdisk: &Path,
) -> Result<Option<Decisao>> {
    let esp_minima = exig.esp_minima();
    let mut alvo = alvo.clone();
    let mut esp: Option<Particao> = None;
    let mut formatar_esp = false;
    let mut raiz: Option<Particao> = None;
    let mut troca: Option<Particao> = None;
    let mut passo = 0u8;

    loop {
        match passo {
            // 0 — aviso e cfdisk
            0 => {
                if !term.aviso("cfdisk", &linhas_do_aviso_cfdisk(&alvo, exig))? {
                    return Ok(None);
                }
                let caminho = alvo.caminho();
                let status = term.suspenso(|| {
                    std::process::Command::new(cfdisk)
                        .arg(&caminho)
                        .status()
                        .with_context(|| format!("não consegui executar {}", cfdisk.display()))
                })??;
                if !status.success() {
                    term.aviso(
                        "cfdisk",
                        &[
                            format!("O cfdisk terminou com erro ({status})."),
                            String::new(),
                            "Nenhuma decisão foi tomada. Você pode tentar de novo.".into(),
                        ],
                    )?;
                    continue;
                }
                alvo = reler_disco(sysfs, &alvo.nome, true)?;
                if alvo.particoes.len() < 2 {
                    term.aviso(
                        "partições",
                        &[
                            format!(
                                "{} tem {} partição(ões), e eu preciso de ao menos duas:",
                                alvo.caminho().display(),
                                alvo.particoes.len()
                            ),
                            "uma EFI System e uma para a raiz.".into(),
                            String::new(),
                            "Se você criou as partições no cfdisk mas não gravou com".into(),
                            "[Write], elas não existem. Tente de novo.".into(),
                        ],
                    )?;
                    continue;
                }
                passo = 1;
            }
            // 1 — qual é a ESP
            1 => {
                let triagem = triar(&alvo.particoes, esp_minima, &[]);
                match escolher_papel(
                    term,
                    "partição EFI (ESP)",
                    &[
                        "Qual partição o firmware vai ler para arrancar?".to_string(),
                        format!(
                            "Precisa de ao menos {} para o BOOTX64.EFI.",
                            disco::tamanho_legivel(esp_minima)
                        ),
                    ],
                    &triagem,
                )? {
                    Some(p) => {
                        esp = Some(p);
                        passo = 2;
                    }
                    None => passo = 0,
                }
            }
            // 2 — formatar a ESP ou preservá-la
            //
            // NÃO é pergunta de estilo: numa máquina com outro sistema instalado
            // a ESP é compartilhada, e formatá-la apaga o carregador do outro
            // sistema. Quem escolheu particionar à mão é exatamente quem sabe
            // responder isto — e quem mais perde se não for perguntado.
            2 => {
                let nome = esp.as_ref().expect("ESP escolhida no passo 1").nome.clone();
                match term.menu_detalhado(
                    "ESP",
                    &[
                        format!("/dev/{nome} vai ser a partição EFI."),
                        String::new(),
                        "Formatar ou aproveitar o que já está lá?".to_string(),
                    ],
                    &[
                        (
                            "Preservar o conteúdo".to_string(),
                            "     obrigatório se houver outro sistema arrancando por ela"
                                .to_string(),
                        ),
                        (
                            "Formatar em FAT32".to_string(),
                            "     apaga tudo, inclusive carregadores de outros sistemas"
                                .to_string(),
                        ),
                    ],
                )? {
                    Some(0) => {
                        formatar_esp = false;
                        passo = 3;
                    }
                    Some(1) => {
                        formatar_esp = true;
                        passo = 3;
                    }
                    _ => passo = 1,
                }
            }
            // 3 — qual é a raiz
            3 => {
                let usada = esp.as_ref().expect("ESP escolhida").nome.clone();
                let triagem = triar(&alvo.particoes, exig.raiz_minima_bytes, &[usada]);
                match escolher_papel(
                    term,
                    "partição raiz",
                    &[
                        "Qual partição recebe o sistema?".to_string(),
                        format!(
                            "Ela será formatada em ext4 e precisa de ao menos {}.",
                            disco::tamanho_legivel(exig.raiz_minima_bytes)
                        ),
                    ],
                    &triagem,
                )? {
                    Some(p) => {
                        raiz = Some(p);
                        passo = 4;
                    }
                    None => passo = 2,
                }
            }
            // 4 — área de troca, opcional. A opção de NÃO ter vem primeiro: é a
            // escolha segura, e é a que o Enter pega sem mover nada.
            4 => {
                let usadas = vec![
                    esp.as_ref().expect("ESP escolhida").nome.clone(),
                    raiz.as_ref().expect("raiz escolhida").nome.clone(),
                ];
                let triagem = triar(&alvo.particoes, TROCA_MINIMA, &usadas);
                let mut itens: Vec<(String, String)> = vec![(
                    "Sem área de troca".to_string(),
                    "     o sistema instala e roda; perde a folga em pico de memória".to_string(),
                )];
                itens.extend(itens_de_particao(&triagem));
                let mut intro = vec![
                    "Alguma partição para área de troca?".to_string(),
                    format!(
                        "Menor que {} não compensa.",
                        disco::tamanho_legivel(TROCA_MINIMA)
                    ),
                ];
                if !triagem.recusadas.is_empty() {
                    intro.push(String::new());
                    intro.push("Fora da lista:".to_string());
                    for r in &triagem.recusadas {
                        intro.push(format!("  {r}"));
                    }
                }
                match term.menu_detalhado("área de troca", &intro, &itens)? {
                    Some(0) => {
                        troca = None;
                        passo = 5;
                    }
                    Some(i) => {
                        troca = Some(triagem.servem[i - 1].clone());
                        passo = 5;
                    }
                    None => passo = 3,
                }
            }
            // 5 — confirmação
            _ => {
                let esp_p = esp.as_ref().expect("ESP escolhida");
                let raiz_p = raiz.as_ref().expect("raiz escolhida");
                let mut linhas =
                    linhas_do_plano_manual(esp_p, formatar_esp, raiz_p, troca.as_ref());
                linhas.insert(0, format!("Disco: {}", alvo.resumo()));
                linhas.insert(1, String::new());
                if term.confirma_com_enter(
                    "confirmação",
                    &linhas,
                    "Enter FORMATA as partições · Esc volta",
                )? {
                    return Ok(Some(Decisao::Manual {
                        disco: alvo.caminho().display().to_string(),
                        esp: format!("/dev/{}", esp_p.nome),
                        formatar_esp,
                        raiz: format!("/dev/{}", raiz_p.nome),
                        troca: troca.as_ref().map(|t| format!("/dev/{}", t.nome)),
                    }));
                }
                passo = 4;
            }
        }
    }
}

/// Uma tela de "qual partição faz este papel", já com a explicação das que
/// ficaram de fora.
fn escolher_papel(
    term: &mut Terminal,
    titulo: &str,
    intro: &[String],
    triagem: &Triagem,
) -> Result<Option<Particao>> {
    if triagem.servem.is_empty() {
        let mut linhas = intro.to_vec();
        linhas.push(String::new());
        linhas.push("Nenhuma partição serve para este papel.".to_string());
        if !triagem.recusadas.is_empty() {
            linhas.push(String::new());
            for r in &triagem.recusadas {
                linhas.push(format!("  {r}"));
            }
        }
        linhas.push(String::new());
        linhas.push("Volte e refaça as partições no cfdisk.".to_string());
        term.aviso(titulo, &linhas)?;
        return Ok(None);
    }
    let mut linhas = intro.to_vec();
    if !triagem.recusadas.is_empty() {
        linhas.push(String::new());
        linhas.push("Fora da lista:".to_string());
        for r in &triagem.recusadas {
            linhas.push(format!("  {r}"));
        }
    }
    let itens = itens_de_particao(triagem);
    match term.menu_detalhado(titulo, &linhas, &itens)? {
        Some(i) => Ok(Some(triagem.servem[i].clone())),
        None => Ok(None),
    }
}

/// As linhas da tela de desistência.
pub fn linhas_de_desistencia() -> Vec<String> {
    vec![
        "Desistir da instalação?".to_string(),
        String::new(),
        "Nada foi escrito em disco algum: sair agora não deixa rastro.".to_string(),
        "A máquina cai num shell de resgate, e reiniciar a traz de volta".to_string(),
        "para cá.".to_string(),
    ]
}

/// O instalador inteiro: escolhe disco, rota, e devolve a decisão.
///
/// ESC E SETA-ESQUERDA VOLTAM UMA TELA, e desistir é uma tela à parte.
///
/// A versão anterior tratava Esc na lista de discos como desistência imediata:
/// dois Esc — um para sair de uma tela, outro sem querer — derrubavam a máquina
/// no shell de resgate, que ainda por cima se parece com uma instalação
/// quebrada. Sair da primeira tela é a única saída que não tem "tela anterior",
/// e por isso é a única que pergunta.
pub fn executar(
    term: &mut Terminal,
    sysfs: &Path,
    excluir: &[PathBuf],
    exig: &Exigencias,
    cfdisk: &Path,
) -> Result<Option<Decisao>> {
    loop {
        let Some(alvo) = escolher_disco(term, sysfs, excluir)? else {
            if term.confirma_com_enter(
                "desistir",
                &linhas_de_desistencia(),
                "Enter desiste · Esc volta para a lista",
            )? {
                return Ok(None);
            }
            continue;
        };
        // Laço da rota: voltar daqui devolve à lista de discos, e voltar de
        // dentro de uma rota devolve a esta escolha — uma tela por vez.
        loop {
            let Some(rota) = escolher_rota(term, &alvo)? else {
                break;
            };
            match rota {
                Rota::DiscoInteiro => {
                    if let Err(motivo) = cabe_disco_inteiro(&alvo, exig) {
                        term.aviso(
                            "disco pequeno demais",
                            &[
                                motivo,
                                String::new(),
                                "Escolha outro disco, ou parta este à mão se quiser".into(),
                                "aproveitar espaço já existente.".into(),
                            ],
                        )?;
                        continue;
                    }
                    if confirmar_destruicao(term, &alvo)? {
                        return Ok(Some(Decisao::DiscoInteiro {
                            disco: alvo.caminho().display().to_string(),
                        }));
                    }
                }
                Rota::Manual => {
                    if let Some(d) = rota_manual(term, sysfs, &alvo, exig, cfdisk)? {
                        return Ok(Some(d));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disco::Particao;

    fn disco_de_teste(particoes: Vec<Particao>) -> Disco {
        Disco {
            nome: "sda".into(),
            bytes: 500_107_862_016,
            modelo: Some("Samsung SSD 860 EVO".into()),
            removivel: false,
            somente_leitura: false,
            particoes,
        }
    }

    fn exigencias() -> Exigencias {
        Exigencias {
            efi_bytes: 20 * 1024 * 1024,
            esp_automatica_bytes: 64 * 1024 * 1024,
            raiz_minima_bytes: 4 * 1024 * 1024 * 1024,
        }
    }

    #[test]
    fn item_de_disco_traz_o_que_identifica_o_disco() {
        let d = disco_de_teste(vec![Particao {
            nome: "sda1".into(),
            bytes: 536_870_912,
        }]);
        let itens = itens_de_disco(&[d]);
        assert_eq!(itens.len(), 1);
        let (rotulo, detalhe) = &itens[0];
        // O rótulo tem de permitir reconhecer o disco SEM abrir mais nada:
        // caminho, tamanho e modelo.
        assert!(rotulo.contains("/dev/sda"), "falta o caminho");
        assert!(rotulo.contains("500 GB"), "falta o tamanho");
        assert!(rotulo.contains("Samsung"), "falta o modelo");
        // O detalhe diz o que se perde.
        assert!(detalhe.contains("sda1"), "falta a partição existente");
    }

    /// O aviso precisa ENUMERAR o que será destruído. Um "o disco será
    /// apagado" genérico não permite ao operador perceber que escolheu o disco
    /// de dados em vez do disco novo.
    #[test]
    fn aviso_enumera_o_que_se_perde() {
        let d = disco_de_teste(vec![
            Particao {
                nome: "sda1".into(),
                bytes: 536_870_912,
            },
            Particao {
                nome: "sda2".into(),
                bytes: 499_000_000_000,
            },
        ]);
        let linhas = linhas_de_destruicao(&d).join("\n");
        assert!(linhas.contains("sda1"));
        assert!(linhas.contains("sda2"));
        assert!(
            linhas.contains("499 GB"),
            "o tamanho de cada partição importa"
        );
        assert!(linhas.contains("não tem volta"));
    }

    /// Disco vazio também precisa de aviso, e de um que não minta: dizer "as 0
    /// partições serão destruídas" seria absurdo, e omitir o aviso faria a tela
    /// parecer quebrada.
    #[test]
    fn aviso_de_disco_sem_particoes_nao_mente() {
        let linhas = linhas_de_destruicao(&disco_de_teste(vec![])).join("\n");
        assert!(linhas.contains("não tem partições"));
        assert!(!linhas.contains("0 partição"));
        assert!(linhas.contains("não tem volta"));
    }

    /// A recusa por disco pequeno tem de vir ANTES da confirmação de
    /// destruição. Um disco de 2 GB que só é recusado depois do `mkfs` é um
    /// disco apagado à toa.
    #[test]
    fn disco_pequeno_e_recusado_com_os_dois_numeros() {
        let mut d = disco_de_teste(vec![]);
        d.bytes = 2 * 1024 * 1024 * 1024;
        let erro = cabe_disco_inteiro(&d, &exigencias()).unwrap_err();
        assert!(erro.contains("2,1 GB"), "falta o tamanho do disco: {erro}");
        assert!(erro.contains("4,3 GB"), "falta o quanto é preciso: {erro}");
        // e o disco grande passa
        assert!(cabe_disco_inteiro(&disco_de_teste(vec![]), &exigencias()).is_ok());
    }

    /// A triagem precisa DIZER por que recusou. Sumir com a partição da lista
    /// manda o operador procurar no cfdisk um defeito que não existe.
    #[test]
    fn triagem_explica_cada_recusa() {
        let ps = vec![
            Particao {
                nome: "sda1".into(),
                bytes: 1024 * 1024,
            },
            Particao {
                nome: "sda2".into(),
                bytes: 512 * 1024 * 1024,
            },
            Particao {
                nome: "sda3".into(),
                bytes: 512 * 1024 * 1024,
            },
        ];
        let t = triar(&ps, 100 * 1024 * 1024, &["sda3".to_string()]);
        assert_eq!(t.servem.len(), 1);
        assert_eq!(t.servem[0].nome, "sda2");
        let motivos = t.recusadas.join("\n");
        assert!(motivos.contains("sda1"), "a pequena precisa aparecer");
        assert!(motivos.contains("é pouco"), "e com o motivo: {motivos}");
        assert!(motivos.contains("sda3 — já atribuída"));
    }

    /// O plano manual precisa dizer, para CADA partição, o verbo e a
    /// consequência — e precisa dizer que formatar a ESP mata o carregador do
    /// outro sistema, que é a perda silenciosa desta tela.
    #[test]
    fn plano_manual_diz_o_que_acontece_com_cada_particao() {
        let esp = Particao {
            nome: "sda1".into(),
            bytes: 512 * 1024 * 1024,
        };
        let raiz = Particao {
            nome: "sda2".into(),
            bytes: 50_000_000_000,
        };
        let troca = Particao {
            nome: "sda3".into(),
            bytes: 4 * 1024 * 1024 * 1024,
        };

        let com_formato = linhas_do_plano_manual(&esp, true, &raiz, Some(&troca)).join("\n");
        assert!(com_formato.contains("sda2") && com_formato.contains("ext4"));
        assert!(com_formato.contains("FORMATADA em FAT32"));
        assert!(
            com_formato.contains("carregador"),
            "falta o aviso do outro sistema"
        );
        assert!(com_formato.contains("sda3"));

        let preservando = linhas_do_plano_manual(&esp, false, &raiz, None).join("\n");
        assert!(preservando.contains("PRESERVADA"));
        assert!(!preservando.contains("carregador dele se perde"));
        assert!(preservando.contains("sem área de troca"));
        // Preservar a ESP não preserva TUDO: o EFI de reserva do firmware é
        // substituído, e numa máquina cujo outro sistema arranca por ele isso é
        // o carregador dele. Dizer só "preservada" seria meia verdade.
        assert!(
            preservando.contains("EFI/BOOT/BOOTX64.EFI"),
            "não avisa qual arquivo da ESP preservada é substituído:\n{preservando}"
        );
    }

    /// O aviso precisa responder as perguntas do cfdisk ANTES de o operador
    /// ficar sozinho com elas: ele está numa máquina que ainda não tem sistema
    /// e não tem como pesquisar o que "Device already contains a gpt signature"
    /// quer dizer.
    #[test]
    fn o_aviso_do_cfdisk_antecipa_as_perguntas_e_os_minimos() {
        let d = disco_de_teste(vec![]);
        let texto = linhas_do_aviso_cfdisk(&d, &exigencias()).join("\n");

        // O rótulo TEM de ser gpt — o init recusa o disco depois se não for, e
        // descobrir isso já no cfdisk custa uma volta inteira.
        assert!(texto.contains("gpt"), "não diz o tipo de rótulo:\n{texto}");
        // A pergunta da assinatura velha, com a resposta.
        assert!(
            texto.contains("signature"),
            "não antecipa a pergunta da assinatura"
        );
        assert!(
            texto.contains("Yes"),
            "antecipa a pergunta e não dá a resposta"
        );
        // Os três tipos de partição, com o nome que o cfdisk usa.
        for tipo in ["EFI System", "Linux filesystem", "Linux swap"] {
            assert!(texto.contains(tipo), "falta o tipo {tipo:?}");
        }
        // Os três mínimos, DERIVADOS das exigências e não digitados: um número
        // copiado à mão aqui envelheceria calado no dia em que o EFI crescesse,
        // e o teste passaria afirmando um valor que a tela não mostra mais.
        let e = exigencias();
        for (quem, bytes) in [
            ("ESP", e.esp_minima()),
            ("raiz", e.raiz_minima_bytes),
            ("troca", TROCA_MINIMA),
        ] {
            let esperado = disco::tamanho_legivel(bytes);
            assert!(
                texto.contains(&esperado),
                "falta o mínimo da {quem} ({esperado}):\n{texto}"
            );
        }
        // E o que faz tudo isso valer.
        assert!(
            texto.contains("[Write]") && texto.contains("'yes'"),
            "não diz que sem gravar nada vale"
        );
    }

    /// A serialização é o contrato com o init. Toda chave sai sempre.
    #[test]
    fn serializacao_traz_todas_as_chaves() {
        let auto = Decisao::DiscoInteiro {
            disco: "/dev/sda".into(),
        }
        .serializa();
        for chave in [
            "DISTROPICA_INSTALL_FORMAT=1",
            "ROTA=disco-inteiro",
            "DISCO=/dev/sda",
            "ESP=",
            "FORMATAR_ESP=",
            "RAIZ=",
            "TROCA=",
        ] {
            assert!(auto.contains(chave), "falta {chave} em:\n{auto}");
        }

        let manual = Decisao::Manual {
            disco: "/dev/sda".into(),
            esp: "/dev/sda1".into(),
            formatar_esp: false,
            raiz: "/dev/sda2".into(),
            troca: None,
        }
        .serializa();
        assert!(manual.contains("ROTA=manual"));
        assert!(manual.contains("ESP=/dev/sda1"));
        assert!(manual.contains("FORMATAR_ESP=nao"));
        assert!(manual.contains("RAIZ=/dev/sda2"));
        assert!(
            manual.contains("TROCA=\n"),
            "a troca vazia precisa sair mesmo assim"
        );
    }

    // ------------------------------------------------------------------
    // Sessões inteiras, do primeiro Enter à decisão gravada.
    //
    // ESTES SÃO OS TESTES QUE IMPORTAM. Os de cima provam pedaços; estes provam
    // que os pedaços se encaixam na ordem certa — que o Enter na lista escolhe
    // o disco que estava destacado, que a confirmação errada NÃO instala, que a
    // rota manual atravessa cfdisk, ESP, raiz e troca sem perder o que foi
    // escolhido antes. Código de instalador roda uma vez por gravação de
    // pendrive; sem isto, a primeira execução seria na máquina do usuário.
    // ------------------------------------------------------------------

    use crate::tui::{Tela, Terminal};
    use std::sync::atomic::{AtomicU64, Ordering};

    static CNT: AtomicU64 = AtomicU64::new(0);

    /// sysfs falso: `sda` de 500 GB com três partições e `sdb` de 8 GB, que faz
    /// o papel do pendrive da mídia.
    fn sysfs_falso(bytes_sda: u64) -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let raiz = std::env::temp_dir().join(format!("mp-id-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&raiz);

        let sda = raiz.join("sda");
        std::fs::create_dir_all(sda.join("device")).unwrap();
        std::fs::write(sda.join("size"), format!("{}\n", bytes_sda / 512)).unwrap();
        std::fs::write(sda.join("removable"), "0\n").unwrap();
        std::fs::write(sda.join("device/model"), "SSD 860 EVO\n").unwrap();
        std::fs::write(sda.join("device/vendor"), "Samsung\n").unwrap();
        for (p, bytes) in [
            ("sda1", 536_870_912u64),         // 512 MiB — serve de ESP
            ("sda2", 400_000_000_000),        // 400 GB — serve de raiz
            ("sda3", 2 * 1024 * 1024 * 1024), // 2 GiB — só serve de troca
        ] {
            std::fs::create_dir_all(sda.join(p)).unwrap();
            std::fs::write(sda.join(p).join("partition"), "1\n").unwrap();
            std::fs::write(sda.join(p).join("size"), format!("{}\n", bytes / 512)).unwrap();
        }

        let sdb = raiz.join("sdb");
        std::fs::create_dir_all(&sdb).unwrap();
        std::fs::write(sdb.join("size"), "15628053\n").unwrap();
        std::fs::write(sdb.join("removable"), "1\n").unwrap();

        raiz
    }

    fn sessao(roteiro: &[u8], bytes_sda: u64) -> (Option<Decisao>, Tela, PathBuf) {
        let raiz = sysfs_falso(bytes_sda);
        let (mut term, tela) = Terminal::de_roteiro(roteiro);
        let d = executar(
            &mut term,
            &raiz,
            &[PathBuf::from("/dev/sdb")],
            &exigencias(),
            // /bin/true faz o papel do cfdisk: sai com zero sem mexer em nada,
            // que é exatamente o operador que abre o cfdisk e sai sem gravar.
            Path::new("/bin/true"),
        )
        .unwrap();
        drop(term);
        (d, tela, raiz)
    }

    const DISCO_GRANDE: u64 = 500_107_862_016;

    /// A rota automática, de ponta a ponta: Enter escolhe o disco, Enter escolhe
    /// "disco inteiro", e o nome digitado confirma.
    #[test]
    fn sessao_automatica_devolve_o_disco_escolhido() {
        let (d, tela, raiz) = sessao(b"\r\r\r", DISCO_GRANDE);
        assert_eq!(
            d,
            Some(Decisao::DiscoInteiro {
                disco: "/dev/sda".into()
            })
        );
        // A mídia NUNCA pode ter sido oferecida.
        assert!(
            !tela.texto().contains("sdb"),
            "o disco da mídia apareceu na lista"
        );
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Desistir exige DUAS teclas: o Esc abre a tela de desistência e o Enter
    /// a confirma. Um Esc solto na primeira tela não pode mais derrubar a
    /// máquina no shell de resgate.
    #[test]
    fn desistir_pede_confirmacao() {
        let (d, _, raiz) = sessao(b"\x1b\r", DISCO_GRANDE);
        assert_eq!(d, None);
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Digitar o nome ERRADO na confirmação não instala. O laço volta à lista,
    /// e o Esc seguinte encerra sem decisão — este é o teste que impede a
    /// confirmação de virar decorativa.
    #[test]
    fn esc_na_confirmacao_nao_instala_e_volta_uma_tela() {
        //  \r      escolhe o disco
        //  \r      escolhe "usar o disco inteiro"
        //  \x1b    Esc na confirmação: não instala, volta para a rota
        //  \x1b    Esc na rota: volta para a lista de discos
        //  \x1b\r  Esc na lista, e Enter confirmando a desistência
        let (d, _, raiz) = sessao(b"\r\r\x1b\x1b\x1b\r", DISCO_GRANDE);
        assert_eq!(d, None, "a confirmação recusada instalou assim mesmo");
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Disco pequeno é recusado ANTES da confirmação, com os dois números na
    /// tela, e o instalador volta à lista em vez de morrer.
    #[test]
    fn disco_pequeno_e_recusado_e_o_laco_continua() {
        let (d, tela, raiz) = sessao(b"\r\r\r\x1b\x1b\r", 2 * 1024 * 1024 * 1024);
        assert_eq!(d, None);
        let visto = tela.texto();
        assert!(
            visto.contains("2,1 GB"),
            "falta o tamanho do disco:\n{visto}"
        );
        assert!(
            visto.contains("4,3 GB"),
            "falta o quanto seria preciso:\n{visto}"
        );
        assert!(
            !visto.contains("Enter APAGA o disco"),
            "chegou a oferecer a destruição"
        );
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// A rota manual inteira: cfdisk, ESP, decisão de formatar, raiz e troca.
    #[test]
    fn sessao_manual_atravessa_todas_as_telas() {
        //  \r   escolhe sda
        //  2    escolhe "particionar eu mesmo"
        //  \r   passa pelo aviso do cfdisk
        //  \r   ESP = sda1 (primeiro item)
        //  2    formatar a ESP
        //  \r   raiz = sda2 (único item ≥ 4 GiB fora a ESP)
        //  2    troca = sda3 (item 0 é "sem área de troca")
        //  sda\r confirma
        let (d, tela, raiz) = sessao(b"\r2\r\r2\r2\r", DISCO_GRANDE);
        assert_eq!(
            d,
            Some(Decisao::Manual {
                disco: "/dev/sda".into(),
                esp: "/dev/sda1".into(),
                formatar_esp: true,
                raiz: "/dev/sda2".into(),
                troca: Some("/dev/sda3".into()),
            })
        );
        let visto = tela.texto();
        assert!(visto.contains("cfdisk"), "o aviso do cfdisk não apareceu");
        assert!(
            visto.contains("carregador"),
            "faltou o aviso de formatar a ESP"
        );
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Preservar a ESP é a opção que protege outro sistema instalado, e ela
    /// precisa atravessar até a decisão — não adianta a tela oferecer se o
    /// valor se perde no caminho.
    #[test]
    fn sessao_manual_preserva_a_esp_quando_pedido() {
        let (d, _, raiz) = sessao(b"\r2\r\r\r\r1\r", DISCO_GRANDE);
        match d {
            Some(Decisao::Manual {
                formatar_esp,
                troca,
                ..
            }) => {
                assert!(
                    !formatar_esp,
                    "a ESP seria formatada mesmo tendo escolhido preservar"
                );
                assert_eq!(troca, None, "escolhi 'sem área de troca' e veio troca");
            }
            outro => panic!("esperava decisão manual, veio {outro:?}"),
        }
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Cada linha é `CHAVE=valor`, sem espaço e sem aspas: é o que o `while
    /// read` do init consegue ler sem `eval`.
    #[test]
    fn serializacao_e_legivel_por_shell_sem_eval() {
        let s = Decisao::Manual {
            disco: "/dev/nvme0n1".into(),
            esp: "/dev/nvme0n1p1".into(),
            formatar_esp: true,
            raiz: "/dev/nvme0n1p2".into(),
            troca: Some("/dev/nvme0n1p3".into()),
        }
        .serializa();
        for linha in s.lines() {
            let (chave, valor) = linha.split_once('=').expect("linha sem =");
            assert!(
                chave
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()),
                "chave estranha: {chave}"
            );
            assert!(
                !valor.contains(' ') && !valor.contains('"'),
                "valor perigoso: {valor}"
            );
        }
    }
}
