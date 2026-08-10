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
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

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
    let texto = match fs::read_to_string(&caminho) {
        Ok(t) => t,
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

/// Troca a árvore por outra, de uma vez.
///
/// A ORDEM DAS OPERAÇÕES É O QUE TORNA ISTO ATÔMICO O BASTANTE. Não existe
/// rename de dois diretórios em um único passo no POSIX, então o que se faz é
/// garantir que NENHUM instante intermediário deixe `newspeak` ausente ou
/// pela metade:
///
///   1. a árvore nova é montada inteira sob outro nome;
///   2. a atual vira `.newspeak.anterior` (rename, atômico);
///   3. a nova vira `newspeak` (rename, atômico);
///   4. a anterior é removida.
///
/// A janela em que `newspeak` não existe é entre 2 e 3, e dura um rename. Uma
/// queda ali deixa `.newspeak.anterior` e `.newspeak.novo` no disco, e nenhuma
/// árvore — situação que a próxima execução detecta e conserta, em vez de
/// deixar meia árvore parecendo inteira.
fn troca_atomica(atual: &Path, novo: &Path, anterior: &Path) -> Result<()> {
    if anterior.exists() {
        fs::remove_dir_all(anterior)
            .with_context(|| format!("removendo {}", anterior.display()))?;
    }
    if atual.exists() {
        fs::rename(atual, anterior)
            .with_context(|| format!("movendo {} para {}", atual.display(), anterior.display()))?;
    }
    match fs::rename(novo, atual) {
        Ok(()) => {}
        Err(e) => {
            // Não conseguimos publicar a nova: devolve a antiga ao lugar, para
            // não deixar a máquina sem árvore nenhuma.
            if anterior.exists() && !atual.exists() {
                let _ = fs::rename(anterior, atual);
            }
            return Err(e).context("publicando a árvore nova");
        }
    }
    if anterior.exists() {
        fs::remove_dir_all(anterior).ok();
    }
    Ok(())
}

/// Conserta o estado deixado por uma queda no meio da troca.
///
/// Chamado ANTES de qualquer coisa. Se `newspeak` sumiu e há `.newspeak.anterior`,
/// a queda foi entre os dois renames e a árvore antiga é recuperável — recuperá-la
/// é melhor que baixar de novo, porque funciona sem rede.
pub fn recupera_troca_interrompida(ctx: &Ctx) -> Result<()> {
    let (atual, novo, anterior) = caminhos(ctx);
    if !atual.exists() && anterior.exists() {
        eprintln!("  troca interrompida detectada; recuperando a árvore anterior");
        fs::rename(&anterior, &atual).with_context(|| {
            format!("recuperando {} de {}", atual.display(), anterior.display())
        })?;
    }
    if novo.exists() {
        fs::remove_dir_all(&novo).ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    use std::sync::atomic::{AtomicU64, Ordering};
    static CNT: AtomicU64 = AtomicU64::new(0);

    /// Raiz temporária no idioma que este crate já usa — o minitrue não tem
    /// `tempfile` entre as dependências, e acrescentá-la por causa de três
    /// testes seria pagar uma crate para não escrever quatro linhas.
    struct Raiz(PathBuf);
    impl Raiz {
        fn nova(marca: &str) -> Raiz {
            let n = CNT.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir()
                .join(format!("mt-arvore-{marca}-{}-{n}", std::process::id()));
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

    /// A queda entre os dois renames deixa a máquina sem árvore. A próxima
    /// execução tem de recuperá-la, e sem rede.
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
        assert!(!base.join(".newspeak.novo").exists(), "sobrou lixo da tentativa");
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

        assert_eq!(fs::read_to_string(atual.join("base/recipe")).unwrap(), "nova\n");
        assert!(!novo.exists());
        assert!(!anterior.exists());
    }
}
