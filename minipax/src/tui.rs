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

/// Tecla lida do console, já traduzida.
///
/// As setas chegam como três bytes (`ESC [ A`), e ler byte a byte sem
/// interpretá-los faria a seta virar "ESC seguido de colchete seguido de A" —
/// que é como um menu ingênuo reage pulando para o começo e digitando letras.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Tecla {
    Cima,
    Baixo,
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
        buf.push_str(ansi::INVERSO);
        buf.push_str("  ");
        buf.push_str(rodape);
        buf.push_str(ansi::NORMAL);
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
            match self.entrada.read(&mut b)? {
                1 => return Ok(Some(b[0])),
                _ if self.tty => continue,
                _ => return Ok(None),
            }
        }
    }

    /// Um byte, sem insistir. Só serve para desempatar o ESC: se nada vier
    /// dentro do VTIME, o ESC era um Esc solto.
    fn le_byte_curto(&mut self) -> Result<Option<u8>> {
        let mut b = [0u8; 1];
        match self.entrada.read(&mut b)? {
            1 => Ok(Some(b[0])),
            _ => Ok(None),
        }
    }

    /// Lê uma tecla, traduzindo as sequências de escape das setas.
    pub fn tecla(&mut self) -> Result<Tecla> {
        let Some(primeiro) = self.le_byte()? else {
            return Ok(Tecla::Esc);
        };
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

    /// Tela de aviso: mostra e espera o Enter. Serve para erro e para
    /// explicação — um instalador que recusa uma escolha sem dizer por quê
    /// parece quebrado.
    pub fn aviso(&mut self, titulo: &str, linhas: &[String]) -> Result<()> {
        self.quadro(titulo, linhas, "Enter continua")?;
        loop {
            match self.tecla()? {
                Tecla::Enter | Tecla::Esc => return Ok(()),
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
            for (i, (rotulo, detalhe)) in itens.iter().enumerate() {
                if i == atual {
                    linhas.push(format!("> {}. {rotulo}", i + 1));
                    if !detalhe.is_empty() {
                        linhas.push(detalhe.clone());
                    }
                } else {
                    linhas.push(format!("  {}. {rotulo}", i + 1));
                }
            }
            self.quadro(titulo, &linhas, "setas movem · Enter escolhe · Esc cancela")?;
            match self.tecla()? {
                Tecla::Cima => atual = if atual == 0 { itens.len() - 1 } else { atual - 1 },
                Tecla::Baixo => atual = (atual + 1) % itens.len(),
                Tecla::Enter => return Ok(Some(atual)),
                Tecla::Esc => return Ok(None),
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
                Tecla::Esc => return Ok(None),
                Tecla::Backspace => {
                    valor.pop();
                }
                Tecla::Char(c) => valor.push(c),
                _ => {}
            }
        }
    }

    /// Confirmação explícita por PALAVRA DIGITADA, e não por tecla.
    ///
    /// Onde se apaga disco não se usa "s/n": uma tecla errada num console é
    /// barata demais para uma operação irreversível. O operador digita a
    /// palavra que a tela mostra, e só ela vale.
    pub fn confirma_digitando(
        &mut self,
        titulo: &str,
        intro: &[String],
        palavra: &str,
    ) -> Result<bool> {
        let rotulo = format!("digite {palavra} para confirmar");
        match self.campo(titulo, intro, &rotulo, "", false)? {
            Some(resposta) => Ok(resposta.trim() == palavra),
            None => Ok(false),
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
            entrada: Box::new(std::io::Cursor::new(roteiro.to_vec())),
            saida: Box::new(tela.clone()),
            tty: false,
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
        let (mut t, _) = Terminal::de_roteiro(b"\x1bx\r");
        // ESC seguido de algo que não é '[': não é seta, e não é o 'x'.
        assert_eq!(t.tecla().unwrap(), Tecla::Outra);
        assert_eq!(t.tecla().unwrap(), Tecla::Enter);
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

    /// A confirmação só aceita a palavra EXATA. Um "sim", um "s", ou o nome de
    /// outro disco não podem passar.
    #[test]
    fn confirmacao_exige_a_palavra_exata() {
        for (roteiro, esperado) in [
            (&b"sda\r"[..], true),
            (&b"sdb\r"[..], false),
            (&b"s\r"[..], false),
            (&b"sim\r"[..], false),
            (&b"\r"[..], false),
            (&b"\x1b"[..], false),
        ] {
            let (mut t, _) = Terminal::de_roteiro(roteiro);
            assert_eq!(
                t.confirma_digitando("t", &[], "sda").unwrap(),
                esperado,
                "roteiro {:?}",
                String::from_utf8_lossy(roteiro)
            );
        }
    }

    /// Espaço em volta não pode reprovar quem digitou certo.
    #[test]
    fn confirmacao_tolera_espaco_em_volta() {
        let (mut t, _) = Terminal::de_roteiro(b" sda \r");
        assert!(t.confirma_digitando("t", &[], "sda").unwrap());
    }

    /// Roteiro que acaba no meio devolve Esc, e não gira para sempre. Sem isto
    /// um teste mal escrito trava a suíte inteira.
    #[test]
    fn fim_do_roteiro_e_esc() {
        let (mut t, _) = Terminal::de_roteiro(b"");
        assert_eq!(t.tecla().unwrap(), Tecla::Esc);
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
