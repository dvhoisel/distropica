//! Leitura estática de ELF e de shebang (SPEC-0013 §4.1).
//!
//! O auditor de fechamento NÃO PODE usar `ldd` nem iniciar o executável que
//! está examinando: `ldd` é o próprio *loader* rodando o objeto sob análise, e
//! o payload auditado pode ser exatamente aquele em que não se confia. Aqui
//! tudo é lido como dado — cabeçalho, tabela de programa, `PT_DYNAMIC` e
//! tabela de strings — sem executar um byte.
//!
//! O caminho completo é feito **pela tabela de programa**, não pela de seções:
//! um artefato passado por `strip` continua com `PT_DYNAMIC`, mas pode perder
//! as seções. Endereços virtuais (`DT_STRTAB`, `DT_VERNEED`, `DT_VERDEF`) são
//! traduzidos para deslocamento de arquivo pelos `PT_LOAD`, como faz o loader.
//!
//! O parser lê apenas as faixas de que precisa (`pread`), então medir um GCC
//! de dezenas de MiB não carrega o arquivo em memória. Todo limite abaixo é
//! deliberado: entrada adulterada deve falhar fechado, nunca virar alocação
//! gigante.
//!
//! **Escopo do v1:** o detalhamento dinâmico é feito para ELF de 64 bits
//! *little-endian*. Objeto de outra classe ou ordem de bytes é reconhecido e
//! devolvido com [`Elf::detailed`] falso — o auditor trata isso como erro de
//! arquitetura, não como "sem dependências".

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// `EM_X86_64` — a única máquina que a árvore atual produz.
pub const EM_X86_64: u16 = 62;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_VERDEF: u64 = 0x6fff_fffc;
const DT_VERDEFNUM: u64 = 0x6fff_fffd;
const DT_VERNEED: u64 = 0x6fff_fffe;
const DT_VERNEEDNUM: u64 = 0x6fff_ffff;

/// Entrada de `verdef` que nomeia o próprio objeto (o SONAME), não uma versão
/// de ABI oferecida. Contá-la como versão fornecida daria falso positivo.
const VER_FLG_BASE: u16 = 1;

// Limites de sanidade. Um ELF legítimo desta árvore fica ordens de grandeza
// abaixo de todos eles; ultrapassar significa arquivo corrompido ou hostil.
const MAX_PHNUM: u16 = 4096;
const MAX_DYNAMIC: usize = 65536;
const MAX_STRTAB: u64 = 16 * 1024 * 1024;
const MAX_VERSION_ENTRIES: usize = 4096;
const MAX_STRING: usize = 4096;
/// `BINPRM_BUF_SIZE` do Linux: o kernel só lê esse tanto da linha de shebang.
const SHEBANG_BUF: usize = 256;

/// O que um caminho de manifesto é, do ponto de vista do fechamento.
#[derive(Debug)]
pub enum Object {
    Elf(Box<Elf>),
    Script(Script),
    /// Arquivo estático `!<arch>` (`.a`): insumo de link, não de runtime.
    Archive,
    /// Nada que participe do fechamento de runtime (texto, dados, imagem…).
    Other,
}

/// Interpretador declarado na primeira linha de um script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub interpreter: String,
    /// Primeiro argumento, quando existe: em `#!/usr/bin/env perl` o provedor
    /// real do trabalho é `perl`, e `env` é só o despachante.
    pub argument: Option<String>,
}

/// Tudo que o fechamento precisa saber de um objeto ELF.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Elf {
    pub class: u8,
    pub data: u8,
    pub etype: u16,
    pub machine: u16,
    /// Falso quando a classe/ordem de bytes está fora do escopo do v1: os
    /// campos dinâmicos abaixo então não foram lidos e nada pode ser
    /// concluído sobre o fechamento deste arquivo.
    pub detailed: bool,
    /// `PT_INTERP` — o carregador exigido por um executável dinâmico.
    pub interp: Option<String>,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    /// Versões exigidas, por biblioteca: `libc.so.6` → `[GLIBC_2.34, …]`.
    pub verneed: Vec<(String, Vec<String>)>,
    /// Versões de ABI que este objeto **fornece** (`GLIBC_2.34`, `ZLIB_1.2.9`).
    pub verdef: Vec<String>,
}

impl Elf {
    /// Um objeto sem `PT_DYNAMIC` (estático, `static-pie` sem dependências ou
    /// relocável) não exige nada em runtime.
    pub fn is_static(&self) -> bool {
        self.needed.is_empty() && self.interp.is_none()
    }
}

/// Classifica o arquivo pelo seu conteúdo, sem executá-lo e sem confiar na
/// extensão ou no bit de execução.
pub fn inspect(path: &Path) -> Result<Object> {
    let file = File::open(path).with_context(|| format!("abrindo {}", path.display()))?;
    let size = file.metadata()?.len();
    let mut head = [0u8; SHEBANG_BUF];
    let head = read_head(&file, &mut head, size);

    if head.starts_with(b"\x7fELF") {
        return Ok(Object::Elf(Box::new(parse_elf(&file, size, head)?)));
    }
    if head.starts_with(b"!<arch>\n") {
        return Ok(Object::Archive);
    }
    if let Some(script) = parse_shebang(head) {
        return Ok(Object::Script(script));
    }
    Ok(Object::Other)
}

fn read_head<'a>(file: &File, buf: &'a mut [u8; SHEBANG_BUF], size: u64) -> &'a [u8] {
    let want = size.min(SHEBANG_BUF as u64) as usize;
    match file.read_at(&mut buf[..want], 0) {
        Ok(n) => &buf[..n],
        Err(_) => &buf[..0],
    }
}

fn parse_shebang(head: &[u8]) -> Option<Script> {
    let rest = head.strip_prefix(b"#!")?;
    let line = match rest.iter().position(|b| *b == b'\n') {
        Some(end) => &rest[..end],
        None => rest,
    };
    // O kernel não interpreta o resto da linha: só intérprete e um argumento.
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    let interpreter = parts.next()?.to_string();
    if !interpreter.starts_with('/') {
        return None;
    }
    Some(Script {
        argument: parts.next().map(str::to_string),
        interpreter,
    })
}

fn parse_elf(file: &File, size: u64, head: &[u8]) -> Result<Elf> {
    if head.len() < 64 {
        bail!("ELF truncado: {} bytes de cabeçalho", head.len());
    }
    let mut elf = Elf {
        class: head[4],
        data: head[5],
        ..Default::default()
    };
    if elf.class != ELFCLASS64 || elf.data != ELFDATA2LSB {
        // Reconhecido, não detalhado: quem audita decide o que fazer com um
        // objeto de arquitetura estrangeira. Aqui não se inventa conteúdo.
        return Ok(elf);
    }
    elf.etype = u16le(head, 16);
    elf.machine = u16le(head, 18);
    elf.detailed = true;

    let phoff = u64le(head, 32);
    let phentsize = u16le(head, 54);
    let phnum = u16le(head, 56);
    if phnum == 0 {
        return Ok(elf); // relocável (.o): nada de dinâmico a extrair.
    }
    if phnum > MAX_PHNUM {
        bail!("ELF declara {phnum} cabeçalhos de programa");
    }
    if phentsize < 56 {
        bail!("cabeçalho de programa de {phentsize} bytes é curto demais");
    }

    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // (vaddr, filesz, offset)
    let mut dynamic: Option<(u64, u64)> = None; // (offset, filesz)
    for i in 0..phnum {
        let at = phoff
            .checked_add(u64::from(i) * u64::from(phentsize))
            .context("tabela de programa fora de faixa")?;
        let ph = read_range(file, size, at, 56)?;
        match u32le(&ph, 0) {
            PT_LOAD => loads.push((u64le(&ph, 16), u64le(&ph, 32), u64le(&ph, 8))),
            PT_DYNAMIC => dynamic = Some((u64le(&ph, 8), u64le(&ph, 32))),
            PT_INTERP => {
                let raw = read_range(
                    file,
                    size,
                    u64le(&ph, 8),
                    u64le(&ph, 32).min(MAX_STRING as u64),
                )?;
                elf.interp = Some(cstr(&raw, 0)?);
            }
            _ => {}
        }
    }

    let Some((dyn_off, dyn_size)) = dynamic else {
        return Ok(elf);
    };
    let count = (dyn_size / 16) as usize;
    if count > MAX_DYNAMIC {
        bail!("PT_DYNAMIC declara {count} entradas");
    }
    let raw = read_range(file, size, dyn_off, dyn_size.min((MAX_DYNAMIC * 16) as u64))?;

    // 1ª passada: a tabela de strings precede a resolução de qualquer nome.
    let mut strtab_va = None;
    let mut strsz = 0u64;
    let mut entries: Vec<(u64, u64)> = Vec::new();
    for chunk in raw.chunks_exact(16) {
        let tag = u64le(chunk, 0);
        let val = u64le(chunk, 8);
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_STRTAB => strtab_va = Some(val),
            DT_STRSZ => strsz = val,
            _ => entries.push((tag, val)),
        }
    }
    let Some(strtab_va) = strtab_va else {
        return Ok(elf); // sem strtab não há nome a resolver.
    };
    if strsz > MAX_STRTAB {
        bail!("DT_STRSZ declara {strsz} bytes de tabela de strings");
    }
    let strtab_off = to_offset(&loads, strtab_va).context("DT_STRTAB fora de todo PT_LOAD")?;
    let strtab = read_range(file, size, strtab_off, strsz)?;

    // 2ª passada: agora cada deslocamento vira nome.
    let mut verneed = None;
    let mut verneednum = 0usize;
    let mut verdef = None;
    let mut verdefnum = 0usize;
    for (tag, val) in entries {
        match tag {
            DT_NEEDED => elf.needed.push(cstr(&strtab, val as usize)?),
            DT_SONAME => elf.soname = Some(cstr(&strtab, val as usize)?),
            DT_RPATH => elf.rpath = split_paths(&cstr(&strtab, val as usize)?),
            DT_RUNPATH => elf.runpath = split_paths(&cstr(&strtab, val as usize)?),
            DT_VERNEED => verneed = Some(val),
            DT_VERNEEDNUM => verneednum = val as usize,
            DT_VERDEF => verdef = Some(val),
            DT_VERDEFNUM => verdefnum = val as usize,
            _ => {}
        }
    }
    if let Some(va) = verneed {
        elf.verneed = read_verneed(file, size, &loads, &strtab, va, verneednum)?;
    }
    if let Some(va) = verdef {
        elf.verdef = read_verdef(file, size, &loads, &strtab, va, verdefnum)?;
    }
    Ok(elf)
}

/// `Elf64_Verneed` + `Elf64_Vernaux`: o que este objeto exige de cada
/// biblioteca. É aqui que mora a diferença entre "achei `libc.so.6`" e
/// "aquela `libc.so.6` fornece `GLIBC_2.38`" (SPEC-0013 §4.3).
fn read_verneed(
    file: &File,
    size: u64,
    loads: &[(u64, u64, u64)],
    strtab: &[u8],
    va: u64,
    num: usize,
) -> Result<Vec<(String, Vec<String>)>> {
    let mut out = Vec::new();
    let mut at = to_offset(loads, va).context("DT_VERNEED fora de todo PT_LOAD")?;
    for _ in 0..num.min(MAX_VERSION_ENTRIES) {
        let vn = read_range(file, size, at, 16)?;
        let file_name = cstr(strtab, u32le(&vn, 4) as usize)?;
        let cnt = u16le(&vn, 2) as usize;
        let aux_rel = u32le(&vn, 8) as u64;
        let next_rel = u32le(&vn, 12) as u64;

        let mut versions = Vec::new();
        let mut aux_at = at.checked_add(aux_rel).context("vn_aux fora de faixa")?;
        for _ in 0..cnt.min(MAX_VERSION_ENTRIES) {
            let aux = read_range(file, size, aux_at, 16)?;
            versions.push(cstr(strtab, u32le(&aux, 8) as usize)?);
            let step = u32le(&aux, 12) as u64;
            if step == 0 {
                break;
            }
            aux_at = aux_at.checked_add(step).context("vna_next fora de faixa")?;
        }
        out.push((file_name, versions));
        if next_rel == 0 {
            break;
        }
        at = at.checked_add(next_rel).context("vn_next fora de faixa")?;
    }
    Ok(out)
}

/// `Elf64_Verdef` + `Elf64_Verdaux`: as versões de ABI que este objeto
/// fornece. A entrada `VER_FLG_BASE` nomeia o próprio arquivo e é descartada.
fn read_verdef(
    file: &File,
    size: u64,
    loads: &[(u64, u64, u64)],
    strtab: &[u8],
    va: u64,
    num: usize,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut at = to_offset(loads, va).context("DT_VERDEF fora de todo PT_LOAD")?;
    for _ in 0..num.min(MAX_VERSION_ENTRIES) {
        let vd = read_range(file, size, at, 20)?;
        let flags = u16le(&vd, 2);
        let aux_rel = u32le(&vd, 12) as u64;
        let next_rel = u32le(&vd, 16) as u64;
        if flags & VER_FLG_BASE == 0 {
            let aux_at = at.checked_add(aux_rel).context("vd_aux fora de faixa")?;
            let aux = read_range(file, size, aux_at, 8)?;
            out.push(cstr(strtab, u32le(&aux, 0) as usize)?);
        }
        if next_rel == 0 {
            break;
        }
        at = at.checked_add(next_rel).context("vd_next fora de faixa")?;
    }
    Ok(out)
}

/// Traduz endereço virtual em deslocamento de arquivo pelos `PT_LOAD` — a
/// mesma conta que o loader faria, sem carregar nada.
fn to_offset(loads: &[(u64, u64, u64)], va: u64) -> Option<u64> {
    loads
        .iter()
        .find(|(vaddr, filesz, _)| va >= *vaddr && va - *vaddr < *filesz)
        .map(|(vaddr, _, offset)| offset + (va - vaddr))
}

fn read_range(file: &File, size: u64, at: u64, len: u64) -> Result<Vec<u8>> {
    let end = at.checked_add(len).context("faixa fora de faixa")?;
    if end > size {
        bail!("faixa {at}..{end} ultrapassa o arquivo de {size} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    file.read_exact_at(&mut buf, at)
        .with_context(|| format!("lendo {len} bytes em {at}"))?;
    Ok(buf)
}

fn cstr(buf: &[u8], at: usize) -> Result<String> {
    let rest = buf
        .get(at..)
        .context("deslocamento fora da tabela de strings")?;
    let end = rest
        .iter()
        .take(MAX_STRING)
        .position(|b| *b == 0)
        .context("string sem terminador na faixa admitida")?;
    String::from_utf8(rest[..end].to_vec()).context("string não é UTF-8")
}

fn split_paths(value: &str) -> Vec<String> {
    value
        .split(':')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64le(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Monta um ELF64 LSB sintético completo: `PT_LOAD` identidade
    /// (vaddr = offset), `PT_INTERP`, `PT_DYNAMIC`, tabela de strings,
    /// `verneed` e `verdef`. Fixture sintética prova o parser sem depender de
    /// nenhum binário do host.
    struct Fixture {
        strtab: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture { strtab: vec![0] }
        }
        fn intern(&mut self, s: &str) -> u32 {
            let at = self.strtab.len() as u32;
            self.strtab.extend_from_slice(s.as_bytes());
            self.strtab.push(0);
            at
        }
    }

    fn synthetic_elf() -> Vec<u8> {
        let mut f = Fixture::new();
        let libc = f.intern("libc.so.6");
        let libz = f.intern("libz.so.1");
        let soname = f.intern("libtest.so.1");
        let runpath = f.intern("/opt/exemplo/lib:/usr/lib");
        let v234 = f.intern("GLIBC_2.34");
        let v238 = f.intern("GLIBC_2.38");
        let provided = f.intern("LIBTEST_1.0");

        let interp = b"/usr/lib/ld-linux-x86-64.so.2\0";
        let interp_off = 64u64 + 3 * 56;
        let strtab_off = interp_off + interp.len() as u64;
        let verneed_off = strtab_off + f.strtab.len() as u64;
        let verdef_off = verneed_off + 48;
        let dyn_off = verdef_off + 56;

        let mut verneed = Vec::new();
        verneed.extend_from_slice(&1u16.to_le_bytes()); // vn_version
        verneed.extend_from_slice(&2u16.to_le_bytes()); // vn_cnt
        verneed.extend_from_slice(&libc.to_le_bytes()); // vn_file
        verneed.extend_from_slice(&16u32.to_le_bytes()); // vn_aux
        verneed.extend_from_slice(&0u32.to_le_bytes()); // vn_next
        for (name, next) in [(v234, 16u32), (v238, 0)] {
            verneed.extend_from_slice(&0u32.to_le_bytes()); // vna_hash
            verneed.extend_from_slice(&0u16.to_le_bytes()); // vna_flags
            verneed.extend_from_slice(&2u16.to_le_bytes()); // vna_other
            verneed.extend_from_slice(&name.to_le_bytes()); // vna_name
            verneed.extend_from_slice(&next.to_le_bytes()); // vna_next
        }

        let mut verdef = Vec::new();
        for (flags, name, next) in [(VER_FLG_BASE, soname, 28u32), (0, provided, 0)] {
            verdef.extend_from_slice(&1u16.to_le_bytes()); // vd_version
            verdef.extend_from_slice(&flags.to_le_bytes()); // vd_flags
            verdef.extend_from_slice(&1u16.to_le_bytes()); // vd_ndx
            verdef.extend_from_slice(&1u16.to_le_bytes()); // vd_cnt
            verdef.extend_from_slice(&0u32.to_le_bytes()); // vd_hash
            verdef.extend_from_slice(&20u32.to_le_bytes()); // vd_aux
            verdef.extend_from_slice(&next.to_le_bytes()); // vd_next
            verdef.extend_from_slice(&name.to_le_bytes()); // vda_name
            verdef.extend_from_slice(&0u32.to_le_bytes()); // vda_next
        }

        let dynamic: Vec<(u64, u64)> = vec![
            (DT_NEEDED, u64::from(libc)),
            (DT_NEEDED, u64::from(libz)),
            (DT_SONAME, u64::from(soname)),
            (DT_RUNPATH, u64::from(runpath)),
            (DT_STRTAB, strtab_off),
            (DT_STRSZ, f.strtab.len() as u64),
            (DT_VERNEED, verneed_off),
            (DT_VERNEEDNUM, 1),
            (DT_VERDEF, verdef_off),
            (DT_VERDEFNUM, 2),
            (DT_NULL, 0),
        ];
        let dyn_size = (dynamic.len() * 16) as u64;
        let total = dyn_off + dyn_size;

        let mut out = Vec::new();
        out.extend_from_slice(b"\x7fELF");
        out.push(ELFCLASS64);
        out.push(ELFDATA2LSB);
        out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // resto do e_ident
        out.extend_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        out.extend_from_slice(&EM_X86_64.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // e_version
        out.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        out.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        out.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        out.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        out.extend_from_slice(&3u16.to_le_bytes()); // e_phnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        let mut ph = |ptype: u32, off: u64, size: u64| {
            out.extend_from_slice(&ptype.to_le_bytes());
            out.extend_from_slice(&4u32.to_le_bytes()); // p_flags
            out.extend_from_slice(&off.to_le_bytes()); // p_offset
            out.extend_from_slice(&off.to_le_bytes()); // p_vaddr = offset
            out.extend_from_slice(&off.to_le_bytes()); // p_paddr
            out.extend_from_slice(&size.to_le_bytes()); // p_filesz
            out.extend_from_slice(&size.to_le_bytes()); // p_memsz
            out.extend_from_slice(&1u64.to_le_bytes()); // p_align
        };
        ph(PT_LOAD, 0, total);
        ph(PT_INTERP, interp_off, interp.len() as u64);
        ph(PT_DYNAMIC, dyn_off, dyn_size);

        out.extend_from_slice(interp);
        out.extend_from_slice(&f.strtab);
        out.extend_from_slice(&verneed);
        out.extend_from_slice(&verdef);
        for (tag, val) in dynamic {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        assert_eq!(out.len() as u64, total);
        out
    }

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("minitrue-elf-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn le_dinamico_completo() {
        let path = write_temp("objeto.so", &synthetic_elf());
        let Object::Elf(elf) = inspect(&path).unwrap() else {
            panic!("não reconheceu ELF");
        };
        assert!(elf.detailed);
        assert_eq!(elf.machine, EM_X86_64);
        assert_eq!(elf.needed, ["libc.so.6", "libz.so.1"]);
        assert_eq!(elf.soname.as_deref(), Some("libtest.so.1"));
        assert_eq!(elf.runpath, ["/opt/exemplo/lib", "/usr/lib"]);
        assert!(elf.rpath.is_empty());
        assert_eq!(elf.interp.as_deref(), Some("/usr/lib/ld-linux-x86-64.so.2"));
        assert_eq!(
            elf.verneed,
            [(
                "libc.so.6".to_string(),
                vec!["GLIBC_2.34".to_string(), "GLIBC_2.38".to_string()]
            )]
        );
        // A entrada VER_FLG_BASE nomeia o próprio arquivo e não é versão.
        assert_eq!(elf.verdef, ["LIBTEST_1.0"]);
        assert!(!elf.is_static());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn classe_estrangeira_nao_vira_sem_dependencia() {
        let mut bytes = synthetic_elf();
        bytes[4] = 1; // ELFCLASS32
        let path = write_temp("estrangeiro.so", &bytes);
        let Object::Elf(elf) = inspect(&path).unwrap() else {
            panic!("não reconheceu ELF");
        };
        // O ponto: `detailed` falso não pode ser confundido com "não precisa
        // de nada". O auditor tem de tratar isso como erro de arquitetura.
        assert!(!elf.detailed);
        assert!(elf.needed.is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn shebang_com_env_expoe_o_provedor_real() {
        let path = write_temp("script.sh", b"#!/usr/bin/env perl -w\nprint 1;\n");
        let Object::Script(script) = inspect(&path).unwrap() else {
            panic!("não reconheceu script");
        };
        assert_eq!(script.interpreter, "/usr/bin/env");
        assert_eq!(script.argument.as_deref(), Some("perl"));

        let direto = write_temp("direto.sh", b"#!/bin/sh\nexit 0\n");
        let Object::Script(script) = inspect(&direto).unwrap() else {
            panic!("não reconheceu script");
        };
        assert_eq!(script.interpreter, "/bin/sh");
        assert_eq!(script.argument, None);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(direto.parent().unwrap()).ok();
    }

    #[test]
    fn nao_elf_e_arquivo_estatico() {
        let ar = write_temp("libz.a", b"!<arch>\nqualquer coisa");
        assert!(matches!(inspect(&ar).unwrap(), Object::Archive));
        let txt = write_temp("leia.txt", b"nao sou binario\n");
        assert!(matches!(inspect(&txt).unwrap(), Object::Other));
        std::fs::remove_dir_all(ar.parent().unwrap()).ok();
        std::fs::remove_dir_all(txt.parent().unwrap()).ok();
    }

    #[test]
    fn truncado_falha_fechado() {
        let bytes = synthetic_elf();
        let path = write_temp("truncado.so", &bytes[..bytes.len() - 200]);
        // Faixa declarada além do fim do arquivo é erro, não silêncio.
        assert!(inspect(&path).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
