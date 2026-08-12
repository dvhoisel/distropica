//! Descoberta dos discos candidatos a receber a instalação.
//!
//! LÊ O SYSFS, e não `lsblk` nem `fdisk -l`. O initramfs não tem nenhum dos
//! dois — o `lsblk` sequer existe no BusyBox —, e mais importante: o sysfs é a
//! fonte, os dois seriam intermediários que precisariam ser analisados como
//! texto. Um campo a mais na saída do `lsblk` de amanhã quebraria o parser; um
//! arquivo do sysfs ou existe ou não existe.
//!
//! A LISTA É DE DISCOS INTEIROS. Partições não entram: instalar dentro de uma
//! partição que o operador escolheu por engano na lista é o tipo de acidente
//! que a interface tem de tornar impossível, e não apenas improvável. Quem
//! quiser escolher partições usa o caminho manual, onde a atribuição é
//! explícita.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Uma partição já existente no disco. Serve para MOSTRAR o que será perdido —
/// um disco descrito só por tamanho não permite ao operador reconhecer se é o
/// disco certo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Particao {
    pub nome: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disco {
    pub nome: String,
    pub bytes: u64,
    /// Modelo relatado pelo dispositivo. Ausente em virtio e em alguns NVMe —
    /// e a ausência é dito na tela em vez de virar string vazia.
    pub modelo: Option<String>,
    pub removivel: bool,
    pub somente_leitura: bool,
    pub particoes: Vec<Particao>,
}

impl Disco {
    pub fn caminho(&self) -> PathBuf {
        PathBuf::from("/dev").join(&self.nome)
    }

    /// Descrição de uma linha para o menu.
    pub fn resumo(&self) -> String {
        let mut s = format!("/dev/{}  {}", self.nome, tamanho_legivel(self.bytes));
        if let Some(m) = &self.modelo {
            s.push_str("  ");
            s.push_str(m);
        } else {
            s.push_str("  (sem modelo)");
        }
        if self.removivel {
            s.push_str("  [removível]");
        }
        if self.somente_leitura {
            s.push_str("  [somente leitura]");
        }
        s
    }

    /// Segunda linha: o que existe hoje no disco. Vazio quando não há tabela.
    pub fn detalhe(&self) -> String {
        if self.particoes.is_empty() {
            "      sem partições".to_string()
        } else {
            let lista: Vec<String> = self
                .particoes
                .iter()
                .map(|p| format!("{} ({})", p.nome, tamanho_legivel(p.bytes)))
                .collect();
            format!(
                "      {} partição(ões): {}",
                self.particoes.len(),
                lista.join(", ")
            )
        }
    }
}

/// Tamanho em unidades de 1000, e não de 1024.
///
/// É o que está escrito na caixa do disco e o que o fabricante vende — um
/// operador procurando "o de 500 GB" precisa ver 500, não 465. A conversão
/// binária é a certa em quase todo o resto desta árvore e é a errada aqui.
pub fn tamanho_legivel(bytes: u64) -> String {
    const UNIDADES: [(&str, u64); 4] = [
        ("TB", 1_000_000_000_000),
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("kB", 1_000),
    ];
    for (nome, escala) in UNIDADES {
        if bytes >= escala {
            let inteiro = bytes / escala;
            let decimo = (bytes % escala) * 10 / escala;
            return if inteiro >= 100 {
                format!("{inteiro} {nome}")
            } else {
                format!("{inteiro},{decimo} {nome}")
            };
        }
    }
    format!("{bytes} B")
}

/// Nomes que nunca são alvo de instalação, por prefixo.
///
/// `loop` e `ram` são virtuais; `sr` é óptico; `dm-` é device-mapper e `md` é
/// RAID — os dois últimos são construídos SOBRE outros discos, e instalar
/// neles a partir daqui exigiria montar a pilha antes, que este instalador não
/// faz. Aparecer na lista o que não se pode usar é pior que não listar.
const PREFIXOS_EXCLUIDOS: [&str; 6] = ["loop", "ram", "zram", "sr", "dm-", "md"];

fn le_texto(caminho: &Path) -> Option<String> {
    fs::read_to_string(caminho)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn le_u64(caminho: &Path) -> Option<u64> {
    le_texto(caminho).and_then(|s| s.parse().ok())
}

/// Enumera os discos que podem receber a instalação.
///
/// `sysfs` é parâmetro para que isto seja TESTÁVEL: um teste monta uma árvore
/// falsa em disco e confere a leitura, sem depender do hardware de quem roda a
/// suíte. Em produção é `/sys/class/block`.
///
/// `excluir` recebe os caminhos que não podem ser alvo — na prática o
/// dispositivo que contém a MÍDIA de instalação. Instalar sobre a própria
/// mídia destrói a instalação em curso, e a única defesa é não oferecer.
pub fn candidatos(sysfs: &Path, excluir: &[PathBuf]) -> Result<Vec<Disco>> {
    let mut achados = Vec::new();
    let entradas = fs::read_dir(sysfs)
        .with_context(|| format!("lendo os dispositivos de bloco em {}", sysfs.display()))?;
    for entrada in entradas {
        let entrada = entrada?;
        let nome = entrada.file_name().to_string_lossy().to_string();
        if PREFIXOS_EXCLUIDOS.iter().any(|p| nome.starts_with(p)) {
            continue;
        }
        let base = entrada.path();
        // Partição tem o arquivo `partition`; disco inteiro não. É esta a
        // distinção, e não heurística sobre dígito no fim do nome — que
        // classificaria `nvme0n1` como partição de `nvme0n`.
        if base.join("partition").exists() {
            continue;
        }
        let setores = match le_u64(&base.join("size")) {
            Some(s) if s > 0 => s,
            // Leitor de cartão vazio publica size=0. Não é erro: é um disco
            // que não está lá.
            _ => continue,
        };
        // O `size` do sysfs é SEMPRE em setores de 512 bytes, inclusive em
        // disco 4Kn — é o único campo em que isso vale, e confundi-lo com o
        // setor lógico daria um tamanho oito vezes maior.
        let bytes = setores * 512;
        let caminho = PathBuf::from("/dev").join(&nome);
        if excluir.contains(&caminho) {
            continue;
        }

        let modelo = le_texto(&base.join("device/model")).map(|m| {
            match le_texto(&base.join("device/vendor")) {
                Some(v) if !m.starts_with(&v) => format!("{v} {m}"),
                _ => m,
            }
        });

        let mut particoes = Vec::new();
        if let Ok(filhos) = fs::read_dir(&base) {
            for filho in filhos.flatten() {
                let pnome = filho.file_name().to_string_lossy().to_string();
                if !pnome.starts_with(&nome) || !filho.path().join("partition").exists() {
                    continue;
                }
                if let Some(psetores) = le_u64(&filho.path().join("size")) {
                    particoes.push(Particao {
                        nome: pnome,
                        bytes: psetores * 512,
                    });
                }
            }
        }
        particoes.sort_by(|a, b| a.nome.cmp(&b.nome));

        achados.push(Disco {
            nome,
            bytes,
            modelo,
            removivel: le_u64(&base.join("removable")).unwrap_or(0) == 1,
            somente_leitura: le_u64(&base.join("ro")).unwrap_or(0) == 1,
            particoes,
        });
    }
    // Ordem estável por nome: a lista é redesenhada e uma ordem que dança faz
    // o operador escolher o disco errado — a mesma razão da ordenação no
    // miniluv.
    achados.sort_by(|a, b| a.nome.cmp(&b.nome));
    Ok(achados)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CNT: AtomicU64 = AtomicU64::new(0);

    fn sysfs_falso() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let raiz = std::env::temp_dir().join(format!("mp-sys-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&raiz);

        // sda: disco de 500 GB com duas partições, com modelo e fabricante
        let sda = raiz.join("sda");
        fs::create_dir_all(sda.join("device")).unwrap();
        fs::write(sda.join("size"), "976773168\n").unwrap();
        fs::write(sda.join("removable"), "0\n").unwrap();
        fs::write(sda.join("ro"), "0\n").unwrap();
        fs::write(sda.join("device/model"), "SSD 860 EVO\n").unwrap();
        fs::write(sda.join("device/vendor"), "Samsung\n").unwrap();
        for (p, tam) in [("sda1", "1048576"), ("sda2", "975724592")] {
            fs::create_dir_all(sda.join(p)).unwrap();
            fs::write(sda.join(p).join("partition"), "1\n").unwrap();
            fs::write(sda.join(p).join("size"), format!("{tam}\n")).unwrap();
        }

        // vda: virtio sem modelo, sem partições
        let vda = raiz.join("vda");
        fs::create_dir_all(&vda).unwrap();
        fs::write(vda.join("size"), "16777216\n").unwrap();

        // sdb: pendrive removível — é o candidato a ser a própria mídia
        let sdb = raiz.join("sdb");
        fs::create_dir_all(sdb.join("device")).unwrap();
        fs::write(sdb.join("size"), "31266816\n").unwrap();
        fs::write(sdb.join("removable"), "1\n").unwrap();
        fs::write(sdb.join("device/model"), "DataTraveler\n").unwrap();

        // o que NÃO pode aparecer
        for lixo in ["loop0", "ram0", "sr0", "dm-0", "md0"] {
            let d = raiz.join(lixo);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("size"), "2048\n").unwrap();
        }
        // leitor de cartão vazio
        let vazio = raiz.join("sdz");
        fs::create_dir_all(&vazio).unwrap();
        fs::write(vazio.join("size"), "0\n").unwrap();
        // uma partição solta no topo, como o sysfs de fato expõe
        let solta = raiz.join("sda1");
        fs::create_dir_all(&solta).unwrap();
        fs::write(solta.join("partition"), "1\n").unwrap();
        fs::write(solta.join("size"), "1048576\n").unwrap();

        raiz
    }

    #[test]
    fn lista_so_discos_inteiros_utilizaveis() {
        let raiz = sysfs_falso();
        let d = candidatos(&raiz, &[]).unwrap();
        let nomes: Vec<&str> = d.iter().map(|x| x.nome.as_str()).collect();
        assert_eq!(
            nomes,
            vec!["sda", "sdb", "vda"],
            "loop/ram/sr/dm/md, partição e disco de tamanho zero não podem aparecer"
        );
        let _ = fs::remove_dir_all(&raiz);
    }

    #[test]
    fn le_tamanho_modelo_e_particoes() {
        let raiz = sysfs_falso();
        let d = candidatos(&raiz, &[]).unwrap();
        let sda = d.iter().find(|x| x.nome == "sda").unwrap();
        // 976773168 setores de 512 = exatamente 500,1 GB
        assert_eq!(sda.bytes, 976_773_168 * 512);
        assert_eq!(tamanho_legivel(sda.bytes), "500 GB");
        assert_eq!(sda.modelo.as_deref(), Some("Samsung SSD 860 EVO"));
        assert!(!sda.removivel);
        assert_eq!(sda.particoes.len(), 2);
        assert_eq!(sda.particoes[0].nome, "sda1");

        // virtio não tem device/model, e a ausência é ausência — não string
        // vazia, que apareceria na tela como espaço em branco sem explicação.
        let vda = d.iter().find(|x| x.nome == "vda").unwrap();
        assert_eq!(vda.modelo, None);
        assert!(vda.resumo().contains("(sem modelo)"));

        let sdb = d.iter().find(|x| x.nome == "sdb").unwrap();
        assert!(sdb.removivel, "pendrive precisa aparecer como removível");
        let _ = fs::remove_dir_all(&raiz);
    }

    /// A mídia de instalação não pode ser oferecida como alvo: instalar sobre
    /// ela destrói a instalação em curso.
    #[test]
    fn exclui_o_disco_da_midia() {
        let raiz = sysfs_falso();
        let d = candidatos(&raiz, &[PathBuf::from("/dev/sdb")]).unwrap();
        assert!(
            !d.iter().any(|x| x.nome == "sdb"),
            "o disco da midia foi oferecido como alvo"
        );
        assert_eq!(d.len(), 2);
        let _ = fs::remove_dir_all(&raiz);
    }

    #[test]
    fn tamanho_em_unidades_de_mil() {
        // O que está escrito na CAIXA do disco, e não a conversão binária: quem
        // procura "o de 500 GB" precisa ver 500, e não 465.
        assert_eq!(tamanho_legivel(500_107_862_016), "500 GB");
        // Acima de 100 o décimo sai, porque ali ele é ruído — "500,1 GB" não
        // ajuda ninguém a reconhecer o disco. Abaixo, fica: a diferença entre
        // 8,5 e 8,0 GB decide se a instalação cabe.
        assert_eq!(tamanho_legivel(8 * 1024 * 1024 * 1024), "8,5 GB");
        assert_eq!(tamanho_legivel(2_000_398_934_016), "2,0 TB");
        assert_eq!(tamanho_legivel(512), "512 B");
    }
}
