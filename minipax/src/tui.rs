//! Interface de texto do instalador.
//!
//! ESCRITA À MÃO, e a decisão é medida. Uma biblioteca de TUI — ratatui,
//! cursive — traria dezenas de crates transitivas para um binário que vive no
//! initramfs e é carregado pelo firmware a cada boot: o minipax tem hoje 1,5
//! MiB, e cada megabyte ali aparece em três lugares (tempo de carga, RAM no
//! boot, espaço na ESP de 64 MiB). O que o instalador precisa desenhar são
//! menus, campos de texto e confirmações; isso são sequências ANSI e um
//! `termios` em modo cru, e o `rustix` que o minipax JÁ usa oferece o segundo.
//! Zero crates novas.
//!
//! O ALVO É O CONSOLE DO LINUX, não um emulador rico. Nada aqui usa cor de 256
//! nem caractere fora do ASCII para desenhar moldura: o `linux` do terminfo tem
//! o suficiente, e um instalador que exige mais que o console da própria
//! máquina falha justamente onde precisa funcionar.
//!
//! SEM RAW MODE NÃO HÁ INSTALADOR INTERATIVO, e há uma armadilha nisso: se o
//! processo morrer com o terminal em modo cru, o console fica sem eco e sem
//! quebra de linha — inutilizável para quem tentar se recuperar no shell de
//! resgate. Por isso o modo cru vive num guarda com `Drop`, e o restauro
//! acontece mesmo em pânico.
//!
//! A ENTRADA E A SAÍDA SÃO INJETADAS, e isto não é gosto por abstração. Uma TUI
//! que só fala com o `stdin` de verdade só pode ser provada bootando a mídia —
//! ou seja, na máquina do usuário, uma vez por gravação de pendrive. Com
//! `Box<dyn Read>` os testes roteirizam a sessão inteira ("desce, desce, Enter,
//! digita sda, Enter") e conferem a decisão que saiu, em milissegundos e sem
//! hardware. O custo é uma chamada indireta por byte, o que para algo que
//! espera um humano digitar é exatamente zero.

use anyhow::{Context, Result};
use std::io::{Read, Write};

/// Sequências ANSI. Nomeadas em vez de literais espalhados: um `\x1b[2J` no
/// meio do código é indistinguível de lixo, e trocá-lo exige achar todas as
/// cópias.
mod ansi {
    pub const LIMPA_TELA: &str = "\x1b[2J";
    pub const CURSOR_TOPO: &str = "\x1b[H";
    pub const CURSOR_OCULTO: &str = "\x1b[?25l";
    pub const CURSOR_VISIVEL: &str = "\x1b[?25h";
    pub const NEGRITO: &str = "\x1b[1m";
    pub const INVERSO: &str = "\x1b[7m";
    pub const NORMAL: &str = "\x1b[0m";
    pub const APAGA_LINHA: &str = "\x1b[K";
}

/// Largura da barra de realce.
///
/// FIXA, e não medida com TIOCGWINSZ: um console de 80 colunas é o piso de
/// tudo o que esta distro roda, e uma barra de 76 mais os dois espaços de
/// margem fecham nele sem quebrar linha. Medir a janela daria uma barra mais
/// bonita num framebuffer largo e uma barra QUEBRADA em qualquer console que
/// mentisse o tamanho — e um menu que quebra linha some com o item de baixo.
const LARGURA: usize = 76;

/// Pinta a linha inteira em vídeo inverso, preenchida até a largura.
///
/// O REALCE É A SELEÇÃO, e isto foi aprendido numa foto de hardware real. A
/// primeira versão marcava o item escolhido só com um '>' e deixava o RODAPÉ em
/// vídeo inverso; numa lista de um item — uma máquina, um disco, o caso comum —
/// a tela mostrava um '>' discreto e uma barra brilhante embaixo, e o operador
/// leu o que estava brilhando como sendo o que estava selecionado. Concluiu, com
/// razão, que o disco não estava selecionado.
///
/// Agora há exatamente UMA coisa realçada na tela, e ela é a escolha.
fn realce(texto: &str) -> String {
    let mut s = String::from(ansi::INVERSO);
    s.push_str(texto);
    for _ in texto.chars().count()..LARGURA {
        s.push(' ');
    }
    s.push_str(ansi::NORMAL);
    s
}

/// Tecla lida do console, já traduzida.
///
/// As setas chegam como três bytes (`ESC [ A`), e ler byte a byte sem
/// interpretá-los faria a seta virar "ESC seguido de colchete seguido de A" —
/// que é como um menu ingênuo reage pulando para o começo e digitando letras.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Tecla {
    Cima,
    Baixo,
    /// Seta para a esquerda. VOLTAR, e sinônimo de Esc em toda tela — quem
    /// navega por setas espera que a da esquerda desfaça a da direita, e não
    /// que só o Esc sirva.
    Esquerda,
    Enter,
    Esc,
    Backspace,
    Char(char),
    Outra,
}

/// O terminal em modo cru, restaurado no Drop.
pub struct Terminal {
    /// Estado original do console; `None` quando não há tty — caso dos testes,
    /// e o que também impede o `Drop` de tentar restaurar o que nunca mexeu.
    original: Option<rustix::termios::Termios>,
    entrada: Box<dyn Read>,
    saida: Box<dyn Write>,
    /// Verdadeiro quando a entrada é um console de fato. Decide o que fazer
    /// diante de uma leitura vazia: no console ela é o VTIME expirando e a
    /// espera continua; num roteiro de teste é o fim do roteiro.
    tty: bool,
    /// Quantas teclas já chegaram. Aparece no rodapé como um marcador que gira,
    /// e não é enfeite.
    ///
    /// Num menu de um item só — que é o caso comum: uma máquina, um disco —
    /// apertar seta não muda nada na tela. Ali "a interface travou" e "a tecla
    /// não chega até aqui" são visualmente IDÊNTICOS, e essa dúvida custou uma
    /// viagem a hardware de verdade para ser levantada e não pôde ser resolvida
    /// à distância. Com o marcador, uma tecla apertada move alguma coisa,
    /// sempre — inclusive as que o menu ignora.
    teclas: u64,
}

impl Terminal {
    /// Entra em modo cru. Falha se não houver terminal — o que é informação e
    /// não acidente: significa que alguém está chamando o instalador
    /// interativo de um pipe, e o caminho certo ali é o automático.
    pub fn abrir() -> Result<Self> {
        let entrada = std::io::stdin();
        let original = rustix::termios::tcgetattr(&entrada)
            .context("este console não aceita modo cru; use o caminho automático")?;
        let mut cru = original.clone();
        cru.make_raw();
        // VMIN=0 e VTIME=1 (100 ms), e NÃO o VMIN=1/VTIME=0 que o make_raw
        // deixa. A diferença aparece num lugar só, e é o Esc.
        //
        // Com VMIN=1 a leitura bloqueia até vir um byte. Ao receber o ESC de um
        // Esc solto, o código precisa olhar o byte seguinte para saber se é uma
        // seta (`ESC [ A`) — e essa leitura fica pendurada até o operador
        // apertar OUTRA tecla. O Esc, que o rodapé promete como "cancela", só
        // faz efeito na tecla seguinte, e a tecla seguinte é engolida.
        //
        // Com VTIME=1 a leitura de desempate volta vazia depois de 100 ms e o
        // Esc é Esc. O preço é que a espera normal passa a acordar dez vezes por
        // segundo para reencontrar o nada; num programa cujo gargalo é um humano
        // digitando, isso não é custo.
        cru.special_codes[rustix::termios::SpecialCodeIndex::VMIN] = 0;
        cru.special_codes[rustix::termios::SpecialCodeIndex::VTIME] = 1;
        rustix::termios::tcsetattr(&entrada, rustix::termios::OptionalActions::Flush, &cru)
            .context("não consegui pôr o console em modo cru")?;
        let mut t = Terminal {
            original: Some(original),
            entrada: Box::new(std::io::stdin()),
            saida: Box::new(std::io::stdout()),
            tty: true,
            teclas: 0,
        };
        t.escreve(ansi::CURSOR_OCULTO)?;
        Ok(t)
    }

    fn escreve(&mut self, s: &str) -> Result<()> {
        self.saida.write_all(s.as_bytes())?;
        self.saida.flush()?;
        Ok(())
    }

    /// Desenha uma tela inteira a partir das linhas dadas.
    ///
    /// Redesenha TUDO a cada quadro em vez de atualizar o que mudou. Numa tela
    /// de menu isso são poucos kilobytes por tecla, e a alternativa — rastrear
    /// o que sujou — é a fonte clássica de artefato visual em TUI escrita à
    /// mão. O `\x1b[K` no fim de cada linha apaga o resto dela, para que um
    /// texto curto não deixe cauda do quadro anterior.
    pub fn quadro(&mut self, titulo: &str, linhas: &[String], rodape: &str) -> Result<()> {
        let mut buf = String::with_capacity(4096);
        buf.push_str(ansi::LIMPA_TELA);
        buf.push_str(ansi::CURSOR_TOPO);
        buf.push_str(ansi::NEGRITO);
        buf.push_str("  DISTRÓPICA — ");
        buf.push_str(titulo);
        buf.push_str(ansi::NORMAL);
        buf.push_str(ansi::APAGA_LINHA);
        buf.push_str("\r\n\r\n");
        for linha in linhas {
            buf.push_str("  ");
            buf.push_str(linha);
            buf.push_str(ansi::APAGA_LINHA);
            buf.push_str("\r\n");
        }
        buf.push_str("\r\n");
        // O rodapé é TEXTO SIMPLES, e deixou de ser barra invertida de
        // propósito: enquanto ele brilhava, era ele que parecia a seleção. O
        // único vídeo inverso desta tela é o item escolhido.
        buf.push_str("  ");
        buf.push_str(rodape);
        // ASCII puro de propósito: o console do Linux desenha estes quatro em
        // qualquer fonte, e um caractere bonito que vira caixinha branca não
        // serve para dizer "sua tecla chegou".
        buf.push_str("  ");
        buf.push(['|', '/', '-', '\\'][(self.teclas % 4) as usize]);
        buf.push_str(ansi::APAGA_LINHA);
        buf.push_str("\r\n");
        self.escreve(&buf)
    }

    /// Um byte, esperando o quanto for preciso.
    ///
    /// Leitura vazia no console é o VTIME expirando, e não fim de entrada: por
    /// isso o laço. Num roteiro de teste, vazio é fim mesmo, e devolver `None`
    /// ali é o que impede um teste mal escrito de girar para sempre.
    fn le_byte(&mut self) -> Result<Option<u8>> {
        let mut b = [0u8; 1];
        loop {
            match self.entrada.read(&mut b) {
                Ok(1) => return Ok(Some(b[0])),
                // Console: leitura vazia é o VTIME expirando, e a espera segue.
                Ok(_) if self.tty => continue,
                // Roteiro de teste: vazio aqui é o fim de verdade.
                Ok(_) => return Ok(None),
                // A PAUSA ENTRE TECLAS de um roteiro. Num console ela é tempo
                // passando; aqui é um `WouldBlock`, e significa a mesma coisa:
                // nada AGORA, mas ainda há o que vir.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Um byte, sem insistir. Só serve para desempatar o ESC: se nada vier
    /// dentro do VTIME, o ESC era um Esc solto.
    fn le_byte_curto(&mut self) -> Result<Option<u8>> {
        let mut b = [0u8; 1];
        match self.entrada.read(&mut b) {
            Ok(1) => Ok(Some(b[0])),
            Ok(_) => Ok(None),
            // Pausa entre teclas: para o desempate do ESC ela vale exatamente
            // como o VTIME expirando — o ESC era um Esc solto.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Lê uma tecla, traduzindo as sequências de escape das setas.
    pub fn tecla(&mut self) -> Result<Tecla> {
        let Some(primeiro) = self.le_byte()? else {
            // SÓ ACONTECE FORA DE UM CONSOLE: num tty não existe fim de
            // entrada, e o `le_byte` fica esperando. Aqui é o roteiro de um
            // teste que acabou no meio da sessão.
            //
            // Devolver Esc neste ponto era o que escondia laço infinito: a tela
            // pedia tecla, recebia Esc, voltava para a tela anterior, pedia
            // tecla de novo — e a suíte PENDURAVA em vez de reprovar. Erro aqui
            // faz o teste falhar dizendo o que faltou.
            anyhow::bail!("o roteiro de teclas acabou no meio da sessão");
        };
        // Uma tecla lógica, uma contagem — a seta chega em três bytes e não
        // pode girar o marcador três vezes.
        self.teclas = self.teclas.wrapping_add(1);
        match primeiro {
            b'\r' | b'\n' => Ok(Tecla::Enter),
            0x7f | 0x08 => Ok(Tecla::Backspace),
            0x1b => match self.le_byte_curto()? {
                // Só `ESC [` inicia sequência que nos interessa. Qualquer outra
                // coisa depois do ESC é tecla de função ou lixo: devolver
                // `Outra` faz o menu ignorá-la, que é melhor do que tratá-la
                // como o caractere que por acaso veio.
                Some(b'[') => match self.le_byte_curto()? {
                    Some(b'A') => Ok(Tecla::Cima),
                    Some(b'B') => Ok(Tecla::Baixo),
                    Some(b'D') => Ok(Tecla::Esquerda),
                    _ => Ok(Tecla::Outra),
                },
                Some(_) => Ok(Tecla::Outra),
                None => Ok(Tecla::Esc),
            },
            0x03 => Ok(Tecla::Esc), // Ctrl-C: sair é sair
            c if c.is_ascii_graphic() || c == b' ' => Ok(Tecla::Char(c as char)),
            _ => Ok(Tecla::Outra),
        }
    }

    /// Tela de aviso: mostra, e diz se o operador seguiu ou voltou.
    ///
    /// `true` = Enter, siga; `false` = Esc ou seta esquerda, volte. Nas telas de
    /// erro os dois dão no mesmo e o retorno é ignorado; nas de explicação —
    /// a do cfdisk é a que importa — voltar é uma saída legítima.
    pub fn aviso(&mut self, titulo: &str, linhas: &[String]) -> Result<bool> {
        loop {
            self.quadro(titulo, linhas, "Enter continua · Esc volta")?;
            match self.tecla()? {
                Tecla::Enter => return Ok(true),
                Tecla::Esc | Tecla::Esquerda => return Ok(false),
                _ => {}
            }
        }
    }

    /// Menu de escolha única. Devolve `None` se o operador desistiu.
    ///
    /// As setas movem e o Enter escolhe; os dígitos são atalho direto, porque
    /// num console sem teclado numérico separado a seta é lenta e o instalador
    /// é usado por quem já sabe o que quer.
    pub fn menu(&mut self, titulo: &str, intro: &[String], itens: &[String]) -> Result<Option<usize>> {
        let detalhados: Vec<(String, String)> =
            itens.iter().map(|i| (i.clone(), String::new())).collect();
        self.menu_detalhado(titulo, intro, &detalhados)
    }

    /// Menu em que cada item traz uma segunda linha de detalhe, mostrada só
    /// sob o item destacado.
    ///
    /// Existe porque a tela de disco precisa de duas informações por linha —
    /// o que o disco É e o que há NELE — e listar as duas para todos os discos
    /// ao mesmo tempo enche a tela de texto que ninguém está lendo. Mostrar o
    /// detalhe do item em foco é o que permite reconhecer o disco certo antes
    /// de apagá-lo.
    pub fn menu_detalhado(
        &mut self,
        titulo: &str,
        intro: &[String],
        itens: &[(String, String)],
    ) -> Result<Option<usize>> {
        if itens.is_empty() {
            return Ok(None);
        }
        let mut atual = 0usize;
        loop {
            let mut linhas: Vec<String> = intro.to_vec();
            if !intro.is_empty() {
                linhas.push(String::new());
            }
            // A ALTURA DE CADA ITEM NÃO DEPENDE DE QUAL ESTÁ ESCOLHIDO, e isto
            // é requisito e não estilo.
            //
            // A primeira versão só desenhava a linha de detalhe SOB O ITEM EM
            // FOCO. O resultado é que o item 2 ficava numa linha quando o 1
            // estava escolhido e noutra quando ele próprio estava: a lista
            // dançava embaixo do dedo de quem aperta a seta, e o alvo se move
            // enquanto se mira nele. É o mesmo defeito que o `disco.rs` já
            // evitava na horizontal ao ordenar os discos por nome — "uma ordem
            // que dança faz o operador escolher o disco errado" —, e ele voltou
            // pela vertical.
            //
            // Se ALGUM item tem detalhe, TODOS ganham a linha, ainda que vazia.
            // Como a linha existe de qualquer jeito, mostrar o detalhe custa
            // zero em altura e informa mais que deixá-la em branco.
            let com_detalhe = itens.iter().any(|(_, d)| !d.is_empty());
            for (i, (rotulo, detalhe)) in itens.iter().enumerate() {
                if i == atual {
                    // O '>' fica, junto com o realce: numa tela onde o vídeo
                    // inverso saia estranho — console serial, emulador pobre —
                    // ele continua dizendo qual é o item.
                    linhas.push(realce(&format!("> {}. {rotulo}", i + 1)));
                } else {
                    linhas.push(format!("  {}. {rotulo}", i + 1));
                }
                if com_detalhe {
                    linhas.push(detalhe.clone());
                }
            }
            self.quadro(titulo, &linhas, "setas movem · Enter escolhe · Esc volta")?;
            match self.tecla()? {
                Tecla::Cima => atual = if atual == 0 { itens.len() - 1 } else { atual - 1 },
                Tecla::Baixo => atual = (atual + 1) % itens.len(),
                Tecla::Enter => return Ok(Some(atual)),
                Tecla::Esc | Tecla::Esquerda => return Ok(None),
                Tecla::Char(c) if c.is_ascii_digit() => {
                    let n = c as usize - '0' as usize;
                    if n >= 1 && n <= itens.len() {
                        return Ok(Some(n - 1));
                    }
                }
                _ => {}
            }
        }
    }

    /// Campo de texto de uma linha. `oculto` troca os caracteres por asteriscos
    /// — é o que serve para senha, e o comprimento visível é intencional: uma
    /// senha em que nem o tamanho aparece esconde do operador que a tecla não
    /// registrou.
    pub fn campo(
        &mut self,
        titulo: &str,
        intro: &[String],
        rotulo: &str,
        inicial: &str,
        oculto: bool,
    ) -> Result<Option<String>> {
        let mut valor = String::from(inicial);
        loop {
            let mostrado = if oculto {
                "*".repeat(valor.chars().count())
            } else {
                valor.clone()
            };
            let mut linhas: Vec<String> = intro.to_vec();
            if !intro.is_empty() {
                linhas.push(String::new());
            }
            linhas.push(format!("{rotulo}: {mostrado}_"));
            self.quadro(titulo, &linhas, "Enter confirma · Esc cancela")?;
            match self.tecla()? {
                Tecla::Enter => return Ok(Some(valor)),
                Tecla::Esc | Tecla::Esquerda => return Ok(None),
                Tecla::Backspace => {
                    valor.pop();
                }
                Tecla::Char(c) => valor.push(c),
                _ => {}
            }
        }
    }

    /// Joga fora o que já estava digitado, antes de a tela pedir uma tecla.
    ///
    /// Existe por causa de UMA tecla: o Enter que trouxe o operador até aqui.
    /// Num console, a tecla apertada antes de a tela ser desenhada fica na fila
    /// do terminal e é entregue assim que alguém lê — então um Enter repetido,
    /// ou segurado meio segundo a mais, atravessaria a confirmação sem que
    /// ninguém tivesse lido o que ela diz. Numa tela que apaga disco isso não é
    /// um incômodo, é a confirmação deixando de existir.
    ///
    /// Sem tty não há fila nem tempo: um roteiro de teste entrega tudo de uma
    /// vez, e descartar ali comeria a tecla que o próprio teste quer mandar.
    /// Por isso o descarte é só no console de verdade — mesma regra do
    /// `suspenso`.
    fn descarta_pendentes(&mut self) -> Result<()> {
        if !self.tty {
            return Ok(());
        }
        // O VTIME de 100 ms é o que define "não havia mais nada": a leitura
        // curta volta vazia quando a fila secou.
        while self.le_byte_curto()?.is_some() {}
        Ok(())
    }

    /// Confirmação de uma tecla para a escrita destrutiva.
    ///
    /// O Enter confirma e QUALQUER OUTRA COISA não: o Esc cancela, e as demais
    /// teclas são ignoradas com a tela redesenhada — o marcador do rodapé gira,
    /// mostrando que a tecla chegou e não valeu.
    ///
    /// O que protege aqui não é a fricção de digitar, é o `descarta_pendentes`:
    /// a tecla que veio ANTES desta tela nunca a atravessa.
    pub fn confirma_com_enter(
        &mut self,
        titulo: &str,
        intro: &[String],
        rodape: &str,
    ) -> Result<bool> {
        self.quadro(titulo, intro, rodape)?;
        self.descarta_pendentes()?;
        loop {
            match self.tecla()? {
                Tecla::Enter => return Ok(true),
                Tecla::Esc | Tecla::Esquerda => return Ok(false),
                _ => self.quadro(titulo, intro, rodape)?,
            }
        }
    }

    /// Suspende o modo cru para rodar um programa externo de tela cheia — o
    /// cfdisk é o caso. Sem isto o cfdisk herdaria um terminal já em modo cru e
    /// desenharia por cima do nosso quadro, com o teclado respondendo a dois
    /// donos ao mesmo tempo.
    pub fn suspenso<T>(&mut self, f: impl FnOnce() -> T) -> Result<T> {
        // Sem tty não há o que suspender, e tentar mexer no termios de um
        // roteiro de teste falharia em ENOTTY. O programa externo roda igual.
        if !self.tty {
            return Ok(f());
        }
        let entrada = std::io::stdin();
        if let Some(original) = &self.original {
            let _ = rustix::termios::tcsetattr(
                &entrada,
                rustix::termios::OptionalActions::Flush,
                original,
            );
        }
        self.escreve(ansi::CURSOR_VISIVEL)?;
        self.escreve(ansi::LIMPA_TELA)?;
        let resultado = f();
        let mut cru = rustix::termios::tcgetattr(&entrada)?;
        cru.make_raw();
        cru.special_codes[rustix::termios::SpecialCodeIndex::VMIN] = 0;
        cru.special_codes[rustix::termios::SpecialCodeIndex::VTIME] = 1;
        rustix::termios::tcsetattr(&entrada, rustix::termios::OptionalActions::Flush, &cru)?;
        self.escreve(ansi::CURSOR_OCULTO)?;
        Ok(resultado)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Restaurar SEMPRE, inclusive em pânico. Um console deixado em modo
        // cru não tem eco nem quebra de linha, e quem cair no shell de resgate
        // depois disso não consegue nem ler o que digita.
        let _ = self.saida.write_all(ansi::CURSOR_VISIVEL.as_bytes());
        let _ = self.saida.write_all(ansi::NORMAL.as_bytes());
        let _ = self.saida.flush();
        if let Some(original) = self.original.take() {
            let _ = rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Flush,
                &original,
            );
        }
    }
}

/// Buffer de saída que o teste pode ler depois. Compartilhado com o `Terminal`
/// porque ele precisa ser dono do escritor.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct Tela(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

#[cfg(test)]
impl Write for Tela {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl Tela {
    /// A saída com as sequências ANSI intactas. Só serve para o que É a
    /// sequência: provar que o realce está no item certo.
    pub fn bruto(&self) -> String {
        String::from_utf8_lossy(&self.0.borrow()).to_string()
    }

    /// Tudo o que foi desenhado, com as sequências ANSI removidas — o que o
    /// teste quer conferir é o TEXTO que o operador leria, e um `\x1b[2J` no
    /// meio da string só atrapalha o `contains`.
    pub fn texto(&self) -> String {
        let bruto = String::from_utf8_lossy(&self.0.borrow()).to_string();
        let mut limpo = String::with_capacity(bruto.len());
        let mut chars = bruto.chars();
        while let Some(c) = chars.next() {
            if c != '\x1b' {
                limpo.push(c);
                continue;
            }
            // CSI: `ESC [` … até uma letra final.
            if chars.next() == Some('[') {
                for f in chars.by_ref() {
                    if f.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        }
        limpo
    }
}

/// Entrega um roteiro de teclas COMO UM CONSOLE ENTREGA, e não colado.
///
/// A diferença é o Esc. Num console, entre uma tecla e a seguinte passa tempo,
/// e é esse tempo que diz que o ESC recebido era um Esc solto e não o começo de
/// uma seta. Um `Cursor` entrega tudo de uma vez: o roteiro "Esc, Enter" virava
/// os bytes `1b 0d`, o desempate lia o `0d` como parte de uma sequência de
/// escape, e o Enter sumia — um defeito do teste que aparecia como defeito do
/// programa.
///
/// Aqui, entre teclas, o `read` devolve `WouldBlock`: nada agora, mais coisa
/// depois. É o análogo exato do VTIME expirando.
#[cfg(test)]
pub struct Roteiro {
    teclas: std::collections::VecDeque<std::collections::VecDeque<u8>>,
    atual: std::collections::VecDeque<u8>,
    pausa: bool,
}

/// Fatia bytes em teclas pela mesma regra que o `tecla()` usa para juntá-los:
/// `ESC [ x` é uma tecla; qualquer outro byte é uma tecla.
#[cfg(test)]
fn fatia_em_teclas(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut teclas = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 2 < bytes.len() && bytes[i + 1] == b'[' {
            teclas.push(bytes[i..i + 3].to_vec());
            i += 3;
        } else {
            teclas.push(vec![bytes[i]]);
            i += 1;
        }
    }
    teclas
}

#[cfg(test)]
impl Read for Roteiro {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.atual.is_empty() {
            if self.pausa {
                self.pausa = false;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "pausa entre teclas",
                ));
            }
            match self.teclas.pop_front() {
                Some(t) => self.atual = t,
                None => return Ok(0),
            }
        }
        buf[0] = self.atual.pop_front().expect("tecla não vazia");
        if self.atual.is_empty() {
            self.pausa = true;
        }
        Ok(1)
    }
}

#[cfg(test)]
impl Terminal {
    /// Terminal de teste: lê o roteiro de teclas e escreve numa `Tela`.
    ///
    /// É isto que permite provar as telas do instalador sem bootar nada — e o
    /// que faz a diferença entre "compila" e "funciona" para código que só roda
    /// uma vez por gravação de pendrive.
    pub fn de_roteiro(roteiro: &[u8]) -> (Terminal, Tela) {
        let tela = Tela::default();
        let term = Terminal {
            original: None,
            entrada: Box::new(Roteiro {
                teclas: fatia_em_teclas(roteiro)
                    .into_iter()
                    .map(std::collections::VecDeque::from)
                    .collect(),
                atual: std::collections::VecDeque::new(),
                pausa: false,
            }),
            saida: Box::new(tela.clone()),
            tty: false,
            teclas: 0,
        };
        (term, tela)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O quadro precisa terminar cada linha com \r\n, e não só \n: em modo cru
    /// o terminal NÃO traduz LF para CRLF, então um \n sozinho desce a linha
    /// sem voltar à coluna 1 — e a tela sai em escada. É o primeiro defeito
    /// que se comete escrevendo TUI à mão.
    #[test]
    fn quadro_usa_crlf() {
        let (mut t, tela) = Terminal::de_roteiro(b"");
        t.quadro("teste", &["um".into(), "dois".into()], "rodape").unwrap();
        drop(t);
        let bruto = String::from_utf8_lossy(&tela.0.borrow()).to_string();
        assert!(!bruto.contains("dois\x1b[K\n"), "linha sem CR antes do LF");
        // título, linha em branco, duas linhas, branco, rodapé
        assert!(bruto.matches("\r\n").count() >= 6);
    }

    #[test]
    fn setas_viram_cima_e_baixo() {
        let (mut t, _) = Terminal::de_roteiro(b"\x1b[A\x1b[B\r");
        assert_eq!(t.tecla().unwrap(), Tecla::Cima);
        assert_eq!(t.tecla().unwrap(), Tecla::Baixo);
        assert_eq!(t.tecla().unwrap(), Tecla::Enter);
    }

    /// O Esc solto TEM de virar Esc, e este teste existe porque a primeira
    /// versão lia dois bytes de uma vez: um Esc no fim da entrada devolvia
    /// `Esc` por acidente (leitura curta), e um Esc seguido de qualquer tecla
    /// engolia a tecla seguinte.
    #[test]
    fn esc_solto_nao_engole_a_tecla_seguinte() {
        // Esc, depois 'x', depois Enter: TRÊS teclas, e o Esc não come nenhuma.
        //
        // A primeira versão deste teste afirmava o contrário — que o Esc virava
        // `Outra` e levava o 'x' junto — porque o leitor de teste entregava os
        // bytes colados e o desempate do ESC via o 'x' como parte da sequência.
        // O nome do teste prometia uma coisa e a asserção travava a outra.
        let (mut t, _) = Terminal::de_roteiro(b"\x1bx\r");
        assert_eq!(t.tecla().unwrap(), Tecla::Esc);
        assert_eq!(t.tecla().unwrap(), Tecla::Char('x'));
        assert_eq!(t.tecla().unwrap(), Tecla::Enter);
    }

    /// A seta continua sendo UMA tecla: três bytes que chegam juntos, sem pausa
    /// entre eles. É o outro lado da mesma regra.
    #[test]
    fn seta_continua_sendo_uma_tecla_so() {
        let (mut t, _) = Terminal::de_roteiro(b"\x1b[B\x1b[D\x1b");
        assert_eq!(t.tecla().unwrap(), Tecla::Baixo);
        assert_eq!(t.tecla().unwrap(), Tecla::Esquerda);
        assert_eq!(t.tecla().unwrap(), Tecla::Esc);
    }

    #[test]
    fn menu_anda_com_seta_e_escolhe_com_enter() {
        let itens = vec!["um".to_string(), "dois".to_string(), "tres".to_string()];
        let (mut t, _) = Terminal::de_roteiro(b"\x1b[B\x1b[B\r");
        assert_eq!(t.menu("t", &[], &itens).unwrap(), Some(2));
    }

    /// O dígito é atalho: quem já sabe o que quer não deve precisar de setas.
    #[test]
    fn menu_aceita_digito_como_atalho() {
        let itens = vec!["um".to_string(), "dois".to_string()];
        let (mut t, _) = Terminal::de_roteiro(b"2");
        assert_eq!(t.menu("t", &[], &itens).unwrap(), Some(1));
    }

    /// Dígito fora da lista não pode escolher nada — nem o último item, que é
    /// o que um `min()` descuidado faria.
    #[test]
    fn menu_ignora_digito_fora_da_lista() {
        let itens = vec!["um".to_string(), "dois".to_string()];
        let (mut t, _) = Terminal::de_roteiro(b"9\r");
        assert_eq!(t.menu("t", &[], &itens).unwrap(), Some(0));
    }

    #[test]
    fn esc_cancela_o_menu() {
        let itens = vec!["um".to_string()];
        let (mut t, _) = Terminal::de_roteiro(b"\x1b");
        assert_eq!(t.menu("t", &[], &itens).unwrap(), None);
    }

    #[test]
    fn campo_edita_e_apaga() {
        let (mut t, _) = Terminal::de_roteiro(b"sdaX\x7f\r");
        assert_eq!(t.campo("t", &[], "disco", "", false).unwrap().as_deref(), Some("sda"));
    }

    /// A senha aparece como asteriscos, e aparece: um campo que não mostra nem
    /// o comprimento esconde do operador que a tecla não registrou.
    #[test]
    fn campo_oculto_mostra_asteriscos_e_nao_o_texto() {
        let (mut t, tela) = Terminal::de_roteiro(b"abc\r");
        assert_eq!(t.campo("t", &[], "senha", "", true).unwrap().as_deref(), Some("abc"));
        drop(t);
        let visto = tela.texto();
        assert!(visto.contains("***"), "o comprimento precisa aparecer");
        assert!(!visto.contains("abc"), "a senha vazou para a tela");
    }

    /// Enter confirma; Esc cancela; qualquer outra tecla não decide nada.
    #[test]
    fn confirmacao_so_aceita_enter() {
        for (roteiro, esperado) in [
            (&b"\r"[..], true),
            (&b"\n"[..], true),
            (&b"\x1b"[..], false),
            // teclas que não são nem uma coisa nem outra: a tela insiste, e a
            // decisão é a do Enter que vem depois.
            (&b"s\r"[..], true),
            (&b"x\x1b"[..], false),

        ] {
            let (mut t, _) = Terminal::de_roteiro(roteiro);
            assert_eq!(
                t.confirma_com_enter("t", &[], "Enter APAGA o disco · Esc volta").unwrap(),
                esperado,
                "roteiro {:?}",
                String::from_utf8_lossy(roteiro)
            );
        }
    }

    /// A tela precisa dizer o que o Enter FAZ. Um rodapé com "Enter confirma"
    /// não distingue esta tela de todas as outras em que Enter só avança.
    #[test]
    fn a_confirmacao_diz_que_o_enter_apaga() {
        let (mut t, tela) = Terminal::de_roteiro(b"\x1b");
        let _ = t.confirma_com_enter(
            "confirmação",
            &["Vai ser APAGADO: /dev/sda".into()],
            "Enter APAGA o disco · Esc volta",
        );
        drop(t);
        let visto = tela.texto();
        assert!(visto.contains("Enter APAGA"), "o rodapé não diz o que o Enter faz");
        assert!(visto.contains("Esc volta"));
    }

    /// O QUE BRILHA É O ITEM ESCOLHIDO, e mais nada.
    ///
    /// Este teste nasce de uma foto: numa lista de um disco só, o item vinha
    /// marcado com um '>' discreto e o RODAPÉ vinha em vídeo inverso. Quem
    /// olhou a tela leu a barra brilhante como sendo a seleção, viu que ela não
    /// estava no disco, e concluiu que nada estava selecionado. Estava certo
    /// sobre o que a tela dizia.
    #[test]
    fn o_realce_marca_o_item_escolhido_e_nao_o_rodape() {
        let itens = vec!["/dev/sda  8,5 GB".to_string(), "/dev/sdb  1,0 TB".to_string()];
        let (mut t, tela) = Terminal::de_roteiro(b"\x1b");
        assert_eq!(t.menu("escolha do disco", &[], &itens).unwrap(), None);
        drop(t);

        let bruto = tela.bruto();
        let mut realcadas: Vec<String> = Vec::new();
        for linha in bruto.split("\r\n") {
            if linha.contains(ansi::INVERSO) {
                // o texto entre o INVERSO e o NORMAL
                let dentro = linha
                    .split(ansi::INVERSO)
                    .nth(1)
                    .and_then(|r| r.split(ansi::NORMAL).next())
                    .unwrap_or("");
                realcadas.push(dentro.trim_end().to_string());
            }
        }
        assert_eq!(realcadas.len(), 1, "mais de uma coisa brilhando: {realcadas:?}");
        assert!(
            realcadas[0].contains("/dev/sda"),
            "o realce não está no item escolhido: {:?}",
            realcadas[0]
        );
        assert!(
            !bruto
                .split("\r\n")
                .any(|l| l.contains("Enter escolhe") && l.contains(ansi::INVERSO)),
            "o rodapé voltou a brilhar e disputa a atenção com a seleção"
        );
    }

    /// A LISTA NÃO PODE DANÇAR: cada item mora sempre na mesma linha, seja
    /// qual for o item escolhido.
    ///
    /// A primeira versão desenhava o detalhe só sob o item em foco, e com isso
    /// o item 2 ficava numa linha quando o 1 estava escolhido e subia uma
    /// quando ele próprio estava. Quem segura a seta vê o alvo se mexer
    /// enquanto mira nele — e é assim que se escolhe o disco errado.
    #[test]
    fn a_posicao_dos_itens_nao_muda_com_a_selecao() {
        let itens = vec![
            ("Usar o disco inteiro".to_string(), "     apaga TUDO".to_string()),
            ("Particionar eu mesmo".to_string(), "     abre o cfdisk".to_string()),
        ];

        // Duas telas: uma com o item 1 escolhido, outra com o 2.
        let mut linhas_por_quadro: Vec<Vec<String>> = Vec::new();
        for roteiro in [&b"\x1b"[..], &b"\x1b[B\x1b"[..]] {
            let (mut t, tela) = Terminal::de_roteiro(roteiro);
            let _ = t.menu_detalhado("t", &[], &itens).unwrap();
            drop(t);
            // Só o ÚLTIMO quadro interessa: cada tecla redesenha a tela
            // inteira depois de um LIMPA_TELA, então os anteriores são história.
            let texto = tela.texto();
            let ultimo = texto.rsplit(ansi::LIMPA_TELA).next().unwrap_or("").to_string();
            linhas_por_quadro.push(ultimo.lines().map(|l| l.trim_end().to_string()).collect());
        }

        let linha_de = |quadro: &Vec<String>, agulha: &str| -> usize {
            quadro
                .iter()
                .position(|l| l.contains(agulha))
                .unwrap_or_else(|| panic!("não achei {agulha:?} em {quadro:?}"))
        };
        for agulha in ["Usar o disco inteiro", "Particionar eu mesmo", "Enter escolhe"] {
            assert_eq!(
                linha_de(&linhas_por_quadro[0], agulha),
                linha_de(&linhas_por_quadro[1], agulha),
                "{agulha:?} mudou de linha ao mover a seleção"
            );
        }
    }

    /// Num menu SEM detalhe nenhum, não se gasta uma linha em branco por item:
    /// a regra é "a altura não depende da seleção", e não "sempre duas linhas".
    #[test]
    fn menu_sem_detalhe_nao_ganha_linhas_vazias() {
        let itens = vec!["um".to_string(), "dois".to_string(), "tres".to_string()];
        let (mut t, tela) = Terminal::de_roteiro(b"\x1b");
        let _ = t.menu("t", &[], &itens).unwrap();
        drop(t);
        let quadro = tela.texto();
        let ultimo = quadro.rsplit(ansi::LIMPA_TELA).next().unwrap_or("");
        let um = ultimo.lines().position(|l| l.contains("1. um")).unwrap();
        let dois = ultimo.lines().position(|l| l.contains("2. dois")).unwrap();
        assert_eq!(dois - um, 1, "apareceu linha em branco entre itens sem detalhe");
    }

    /// A barra precisa ser BARRA: preenchida até a largura, e não só o texto
    /// invertido. Um realce que termina onde o nome do disco termina fica
    /// diferente em cada item e não lê como seleção.
    #[test]
    fn o_realce_preenche_a_linha_inteira() {
        let itens = vec!["curto".to_string(), "um item bem mais comprido".to_string()];
        let (mut t, tela) = Terminal::de_roteiro(b"\x1b");
        let _ = t.menu("t", &[], &itens).unwrap();
        drop(t);
        let bruto = tela.bruto();
        let barra = bruto
            .split(ansi::INVERSO)
            .nth(1)
            .and_then(|r| r.split(ansi::NORMAL).next())
            .expect("nenhuma barra desenhada");
        assert_eq!(barra.chars().count(), LARGURA, "barra com largura irregular");
    }

    /// O marcador do rodapé precisa MUDAR a cada tecla, inclusive numa tecla
    /// que o menu ignora. É a única evidência que o operador tem, num menu de
    /// um item só, de que o teclado chega até aqui — e foi a falta dela que
    /// tornou "travou" e "não recebe tecla" indistinguíveis em hardware real.
    #[test]
    fn marcador_do_rodape_gira_a_cada_tecla() {
        let itens = vec!["um".to_string()];
        // 'x' não faz nada no menu; a tela tem de mudar mesmo assim.
        let (mut t, tela) = Terminal::de_roteiro(b"xx\r");
        assert_eq!(t.menu("t", &[], &itens).unwrap(), Some(0));
        drop(t);
        let visto = tela.texto();
        let marcadores: String = visto
            .lines()
            .filter(|l| l.contains("Enter escolhe"))
            .filter_map(|l| l.trim_end().chars().last())
            .collect();
        // Três quadros desenhados: o inicial e um por tecla ignorada.
        assert_eq!(marcadores, "|/-", "o marcador não girou: {marcadores:?}");
    }

    /// Uma seta são três bytes e UMA tecla: o marcador não pode girar três
    /// vezes, senão ele deixa de contar teclas e passa a contar bytes.
    #[test]
    fn seta_gira_o_marcador_uma_vez_so() {
        let itens = vec!["um".to_string(), "dois".to_string()];
        let (mut t, tela) = Terminal::de_roteiro(b"\x1b[B\r");
        assert_eq!(t.menu("t", &[], &itens).unwrap(), Some(1));
        drop(t);
        let marcadores: String = tela
            .texto()
            .lines()
            .filter(|l| l.contains("Enter escolhe"))
            .filter_map(|l| l.trim_end().chars().last())
            .collect();
        assert_eq!(marcadores, "|/", "a seta girou o marcador mais de uma vez");
    }

    /// Roteiro que acaba no meio REPROVA, e não gira para sempre nem finge um
    /// Esc. Um teste que fica sem teclas está incompleto, e dizer isso é a
    /// diferença entre uma falha em milissegundos e uma suíte pendurada.
    #[test]
    fn fim_do_roteiro_reprova_em_vez_de_pendurar() {
        let (mut t, _) = Terminal::de_roteiro(b"");
        let erro = t.tecla().unwrap_err().to_string();
        assert!(erro.contains("acabou no meio"), "mensagem: {erro}");
    }

    /// A `Tela` precisa devolver texto legível: se as sequências ANSI ficassem,
    /// todo `contains` de teste passaria a depender de onde caiu um `\x1b[K`.
    #[test]
    fn tela_remove_as_sequencias_ansi() {
        let (mut t, tela) = Terminal::de_roteiro(b"");
        t.quadro("titulo", &["conteudo".into()], "rodape").unwrap();
        drop(t);
        let visto = tela.texto();
        assert!(visto.contains("DISTRÓPICA — titulo"));
        assert!(visto.contains("conteudo"));
        assert!(!visto.contains('\x1b'), "sobrou sequência ANSI: {visto:?}");
    }
}
