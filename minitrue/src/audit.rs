//! Auditoria de fechamento de dependências (SPEC-0013 §4).
//!
//! `DEPS` é uma declaração humana. Este módulo confronta essa declaração com o
//! **payload realmente instalado**: lê cada arquivo do manifesto como dado,
//! extrai o que ele exige em runtime e exige que cada requisito resolva para
//! exatamente um provedor válido dentro da closure declarada.
//!
//! Três invariantes, todas do §4.4:
//!
//! - requisito observado sem provedor no próprio pacote ou numa `DEPS`
//!   **direta** é erro — depender por acaso da dependência de outro pacote é
//!   proibido, ainda que funcione hoje;
//! - achar o nome não basta: as versões de símbolo exigidas (`GLIBC_*`,
//!   `GLIBCXX_*`, `CXXABI_*`) têm de estar entre as fornecidas pelo provedor
//!   (§4.3);
//! - `RPATH`/`RUNPATH` que aponta para fora do rootfs é fuga: o artefato
//!   resolveu contra a máquina de quem compilou, não contra a closure.
//!
//! A auditoria é **somente-leitura e não executa nada** do que audita
//! (SPEC-0013 §4.1): sem `ldd`, sem rodar o binário. Ela também não substitui
//! `verify` — não confere hash de claim; pressupõe um registro íntegro e
//! pergunta outra coisa: *o conjunto declarado se fecha?*
//!
//! O resultado ganha uma serialização canônica e um `CLOSURE_SHA256`
//! (`AUDIT_FORMAT=1`): o mesmo grafo observado sempre dá o mesmo hash, o que
//! permite virar gate de publicação sem depender do texto do relatório.

use crate::elf::{self, Elf, Object, EM_X86_64};
use crate::install::{manifest_integrity, manifest_path, read_manifest, read_meta};
use crate::{fail, Ctx};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Versão da serialização canônica da auditoria. Muda sempre que o conjunto
/// de fatos ou sua ordem mudar — o `CLOSURE_SHA256` de formatos diferentes
/// não é comparável.
pub const AUDIT_FORMAT: &str = "1";

/// Diretórios em que o loader procura biblioteca por nome quando o objeto não
/// declara `RUNPATH`. A árvore é usr-merged, mas `/lib` e `/lib64` continuam
/// alcançáveis por link e aparecem em objetos vindos de binário do mantenedor.
const DEFAULT_LIB_DIRS: [&str; 4] = ["/usr/lib", "/lib", "/usr/lib64", "/lib64"];

/// Teto de saltos ao seguir uma cadeia de symlinks dentro do rootfs.
const MAX_LINK_HOPS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    /// Impede publicação: o conjunto declarado não se fecha.
    Erro,
    /// Não impede, mas o linter pede justificativa (§4.4).
    Observacao,
}

#[derive(Debug)]
struct Finding {
    severity: Severity,
    package: String,
    file: String,
    message: String,
}

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    deps: Vec<String>,
    /// Caminhos virtuais do manifesto, com o tipo da claim (`f`, `l`, `d`).
    claims: Vec<(char, String)>,
}

/// Índice de quem fornece o quê, montado a partir dos registros (§4.2).
struct Providers {
    /// caminho virtual exato → pacote dono da claim.
    owner: BTreeMap<String, String>,
    /// raiz de claim `d:` → pacote. No mundo A o payload inteiro de
    /// `/opt/<pacote>/<versão>` é **uma** claim de árvore, não uma claim por
    /// arquivo: quem procura `/opt/busybox/1.35.0/bin/sh` tem de achar o dono
    /// subindo até a raiz da árvore.
    trees: BTreeMap<String, String>,
}

impl Providers {
    fn owner_of(&self, virt: &str) -> Option<&str> {
        if let Some(pkg) = self.owner.get(virt) {
            return Some(pkg);
        }
        let mut cursor = virt;
        while let Some(at) = cursor.rfind('/') {
            if at == 0 {
                break;
            }
            cursor = &cursor[..at];
            if let Some(pkg) = self.trees.get(cursor) {
                return Some(pkg);
            }
        }
        None
    }

    fn covers_directory(&self, dir: &str) -> bool {
        self.owner
            .keys()
            .any(|path| path.starts_with(&format!("{dir}/")))
            || self.trees.contains_key(dir)
            || self
                .trees
                .keys()
                .any(|root| dir.starts_with(&format!("{root}/")))
    }
}

/// Resultado da análise, separado do relatório para que o gate de publicação
/// e a CLI usem exatamente o mesmo veredito.
struct Analysis {
    /// (nome, versão) de cada pacote auditado, na ordem em que foi pedido.
    targets: Vec<(String, String)>,
    findings: Vec<Finding>,
    facts: BTreeSet<String>,
    inspected: usize,
    missing: usize,
}

pub fn audit(ctx: &Ctx, names: &[String], output: Option<&std::path::Path>) -> Result<()> {
    let analysis = analyze(ctx, names)?;
    report(&analysis, output)
}

/// Gate de publicação (SPEC-0013 §10.2). Usa a mesma análise da CLI e
/// **recusa** a emissão quando algum requisito observado não tem provedor
/// declarado — é a diferença entre auditar e impedir.
pub(crate) fn gate(ctx: &Ctx, names: &[String]) -> Result<()> {
    let analysis = analyze(ctx, names)?;
    let erros: Vec<&Finding> = analysis
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Erro)
        .collect();
    if erros.is_empty() {
        println!(
            "  fechamento conferido: {} requisito(s) observado(s), todos com provedor declarado",
            analysis.facts.len()
        );
        return Ok(());
    }
    for finding in &erros {
        eprintln!(
            "  erro: {} {} — {}",
            finding.package, finding.file, finding.message
        );
    }
    fail(
        1,
        format!(
            "channel emit recusado: {} erro(s) de fechamento. \
             Publicar isto propagaria dependência acidental; \
             `minitrue audit` dá o relatório completo",
            erros.len()
        ),
    )
}

fn analyze(ctx: &Ctx, names: &[String]) -> Result<Analysis> {
    let packages = load_packages(ctx)?;
    if packages.is_empty() {
        return fail(1, "audit: nenhum registro para auditar");
    }
    let providers = Providers {
        owner: packages
            .values()
            .flat_map(|p| {
                p.claims
                    .iter()
                    .map(|(_, path)| (path.clone(), p.name.clone()))
            })
            .collect(),
        trees: packages
            .values()
            .flat_map(|p| {
                p.claims
                    .iter()
                    .filter(|(kind, _)| *kind == 'd')
                    .map(|(_, path)| (path.clone(), p.name.clone()))
            })
            .collect(),
    };

    let targets: Vec<&Package> = if names.is_empty() {
        packages.values().collect()
    } else {
        let mut out = Vec::new();
        for name in names {
            match packages.get(name) {
                Some(p) => out.push(p),
                None => return fail(2, format!("audit: {name} não tem registro")),
            }
        }
        out
    };

    let mut findings = Vec::new();
    let mut facts = BTreeSet::new();
    let mut inspected = 0usize;
    let mut missing = 0usize;

    for pkg in &targets {
        let allowed: BTreeSet<&str> = std::iter::once(pkg.name.as_str())
            .chain(pkg.deps.iter().map(String::as_str))
            .collect();
        let mut satisfied: BTreeSet<String> = BTreeSet::new();

        for (kind, virt) in &pkg.claims {
            if *kind != 'f' {
                continue;
            }
            let real = rooted(ctx, virt);
            if !real.exists() {
                missing += 1;
                continue;
            }
            match elf::inspect(&real) {
                Ok(Object::Elf(info)) => {
                    inspected += 1;
                    audit_elf(
                        ctx,
                        pkg,
                        virt,
                        &info,
                        &providers,
                        &allowed,
                        &mut satisfied,
                        &mut findings,
                        &mut facts,
                    );
                }
                Ok(Object::Script(script)) => {
                    inspected += 1;
                    let mut wanted = vec![script.interpreter.clone()];
                    // `#!/usr/bin/env perl` depende de env **e** de perl; o
                    // provedor real do trabalho é o segundo.
                    if let Some(arg) = &script.argument {
                        if script.interpreter.ends_with("/env") && !arg.starts_with('-') {
                            for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
                                let candidate = format!("{dir}/{arg}");
                                if providers.owner_of(&candidate).is_some() {
                                    wanted.push(candidate);
                                    break;
                                }
                            }
                        }
                    }
                    for path in wanted {
                        resolve_and_charge(
                            ctx,
                            pkg,
                            virt,
                            "shebang",
                            &path,
                            &providers,
                            &allowed,
                            &mut satisfied,
                            &mut findings,
                            &mut facts,
                        );
                    }
                }
                Ok(_) => {}
                Err(e) => findings.push(Finding {
                    severity: Severity::Erro,
                    package: pkg.name.clone(),
                    file: virt.clone(),
                    message: format!("não foi possível interpretar estaticamente: {e}"),
                }),
            }
        }

        // §4.4: `DEPS` sem requisito estático observado é permitido — pode ser
        // dependência semântica — mas o linter deve pedir justificativa.
        for dep in &pkg.deps {
            if !satisfied.contains(dep) && packages.contains_key(dep) {
                findings.push(Finding {
                    severity: Severity::Observacao,
                    package: pkg.name.clone(),
                    file: String::new(),
                    message: format!(
                        "DEPS declara {dep}, mas nenhum requisito estático observado o exige"
                    ),
                });
            }
        }
    }

    Ok(Analysis {
        targets: targets
            .iter()
            .map(|pkg| (pkg.name.clone(), pkg.version.clone()))
            .collect(),
        findings,
        facts,
        inspected,
        missing,
    })
}

#[allow(clippy::too_many_arguments)]
fn audit_elf(
    ctx: &Ctx,
    pkg: &Package,
    virt: &str,
    info: &Elf,
    providers: &Providers,
    allowed: &BTreeSet<&str>,
    satisfied: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
    facts: &mut BTreeSet<String>,
) {
    if !info.detailed {
        findings.push(Finding {
            severity: Severity::Erro,
            package: pkg.name.clone(),
            file: virt.to_string(),
            message: format!(
                "ELF de classe {} / ordem de bytes {} fora do escopo desta árvore: \
                 nada pode ser concluído sobre seu fechamento",
                info.class, info.data
            ),
        });
        return;
    }
    if info.machine != EM_X86_64 {
        findings.push(Finding {
            severity: Severity::Erro,
            package: pkg.name.clone(),
            file: virt.to_string(),
            message: format!("máquina ELF {} não é x86_64", info.machine),
        });
        return;
    }

    if info.is_static() {
        // Não exigir nada também é um fato do fechamento: é o que se espera
        // dos executores `static-pie` e do que vem de binário do mantenedor
        // ligado estaticamente.
        facts.insert(format!("{}\t{}\testatico\t-\t-\t-\t-", pkg.name, virt));
        return;
    }

    let origin = parent_of(virt);
    for entry in info.rpath.iter().chain(info.runpath.iter()) {
        let expanded = entry
            .replace("$ORIGIN", &origin)
            .replace("${ORIGIN}", &origin);
        if !expanded.starts_with('/') {
            findings.push(Finding {
                severity: Severity::Erro,
                package: pkg.name.clone(),
                file: virt.to_string(),
                message: format!("RPATH/RUNPATH relativo: {entry:?}"),
            });
            continue;
        }
        let normalized = normalize(&expanded);
        let confined = DEFAULT_LIB_DIRS.contains(&normalized.as_str())
            || providers.covers_directory(&normalized);
        if !confined {
            // Fuga: o artefato aponta para um diretório que nenhum pacote
            // fornece. Costuma ser o diretório de build de quem compilou.
            findings.push(Finding {
                severity: Severity::Erro,
                package: pkg.name.clone(),
                file: virt.to_string(),
                message: format!("RPATH/RUNPATH foge da closure: {entry:?}"),
            });
        }
    }

    if let Some(interp) = &info.interp {
        resolve_and_charge(
            ctx, pkg, virt, "interp", interp, providers, allowed, satisfied, findings, facts,
        );
    }

    let search: Vec<String> = info
        .runpath
        .iter()
        .chain(info.rpath.iter())
        .map(|p| normalize(&p.replace("$ORIGIN", &origin).replace("${ORIGIN}", &origin)))
        .chain(DEFAULT_LIB_DIRS.iter().map(|d| d.to_string()))
        .collect();

    for needed in &info.needed {
        let Some((target, owner)) = resolve_library(ctx, needed, &search, providers) else {
            findings.push(Finding {
                severity: Severity::Erro,
                package: pkg.name.clone(),
                file: virt.to_string(),
                message: format!("exige {needed}, sem provedor na closure"),
            });
            facts.insert(format!(
                "{}\t{}\tneeded\t{}\t?\t?\t-",
                pkg.name, virt, needed
            ));
            continue;
        };
        satisfied.insert(owner.clone());
        // A versão exigida faz parte do fato observado: "precisa de libc.so.6"
        // e "precisa de libc.so.6 com GLIBC_2.38" são fechamentos diferentes.
        // Ordenadas: a serialização é canônica, então não pode depender da
        // ordem em que o linker gravou o `verneed`.
        let versions = info
            .verneed
            .iter()
            .find(|(lib, _)| lib == needed)
            .map(|(_, v)| {
                let mut sorted: Vec<&str> = v.iter().map(String::as_str).collect();
                sorted.sort_unstable();
                sorted.join(",")
            })
            .unwrap_or_else(|| "-".to_string());
        facts.insert(format!(
            "{}\t{}\tneeded\t{}\t{}\t{}\t{}",
            pkg.name, virt, needed, owner, target, versions
        ));
        if !allowed.contains(owner.as_str()) {
            findings.push(Finding {
                severity: Severity::Erro,
                package: pkg.name.clone(),
                file: virt.to_string(),
                message: format!(
                    "exige {needed}, fornecida por {owner} ({target}), que não está em DEPS"
                ),
            });
            continue;
        }
        check_symbol_versions(ctx, pkg, virt, info, needed, &target, &owner, findings);
    }
}

/// §4.3: encontrar `libc.so.6` não prova compatibilidade. Cada versão exigida
/// precisa constar entre as fornecidas pelo arquivo que de fato vai carregar.
#[allow(clippy::too_many_arguments)]
fn check_symbol_versions(
    ctx: &Ctx,
    pkg: &Package,
    virt: &str,
    info: &Elf,
    needed: &str,
    target: &str,
    owner: &str,
    findings: &mut Vec<Finding>,
) {
    let Some((_, required)) = info.verneed.iter().find(|(lib, _)| lib == needed) else {
        return;
    };
    if required.is_empty() {
        return;
    }
    let Ok(Object::Elf(provider)) = elf::inspect(&rooted(ctx, target)) else {
        return;
    };
    let provided: BTreeSet<&str> = provider.verdef.iter().map(String::as_str).collect();
    if provided.is_empty() {
        // Provedor sem versionamento de símbolos: a presença do SONAME é
        // necessária mas pode não bastar (§4.3). Fica registrado, não inventado.
        findings.push(Finding {
            severity: Severity::Observacao,
            package: pkg.name.clone(),
            file: virt.to_string(),
            message: format!(
                "exige versões {} de {needed}, mas {owner} não versiona símbolos",
                required.join(", ")
            ),
        });
        return;
    }
    let missing: Vec<&str> = required
        .iter()
        .map(String::as_str)
        .filter(|v| !provided.contains(v))
        .collect();
    if !missing.is_empty() {
        findings.push(Finding {
            severity: Severity::Erro,
            package: pkg.name.clone(),
            file: virt.to_string(),
            message: format!(
                "exige {} de {needed}, que {owner} ({target}) não fornece",
                missing.join(", ")
            ),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_and_charge(
    ctx: &Ctx,
    pkg: &Package,
    virt: &str,
    kind: &str,
    wanted: &str,
    providers: &Providers,
    allowed: &BTreeSet<&str>,
    satisfied: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
    facts: &mut BTreeSet<String>,
) {
    let resolved = resolve_virtual(ctx, wanted);
    match resolved.as_deref().and_then(|p| providers.owner_of(p)) {
        Some(owner) => {
            satisfied.insert(owner.to_string());
            facts.insert(format!(
                "{}\t{}\t{kind}\t{wanted}\t{owner}\t{}\t-",
                pkg.name,
                virt,
                resolved.as_deref().unwrap_or("?")
            ));
            if !allowed.contains(owner) {
                findings.push(Finding {
                    severity: Severity::Erro,
                    package: pkg.name.clone(),
                    file: virt.to_string(),
                    message: format!("exige {wanted}, fornecido por {owner}, que não está em DEPS"),
                });
            }
        }
        None => {
            facts.insert(format!("{}\t{}\t{kind}\t{wanted}\t?\t?\t-", pkg.name, virt));
            findings.push(Finding {
                severity: Severity::Erro,
                package: pkg.name.clone(),
                file: virt.to_string(),
                message: format!("exige {wanted}, sem provedor na closure"),
            });
        }
    }
}

/// Busca por nome nos diretórios de procura, como o loader faria — e então
/// atribui o dono pelo registro, não pelo sistema de arquivos.
fn resolve_library(
    ctx: &Ctx,
    needed: &str,
    search: &[String],
    providers: &Providers,
) -> Option<(String, String)> {
    if needed.contains('/') {
        let target = resolve_virtual(ctx, needed)?;
        let owner = providers.owner_of(&target)?.to_string();
        return Some((target, owner));
    }
    for dir in search {
        let candidate = format!("{dir}/{needed}");
        if providers.owner_of(&candidate).is_none() && !rooted(ctx, &candidate).exists() {
            continue;
        }
        let Some(target) = resolve_virtual(ctx, &candidate) else {
            continue;
        };
        if let Some(owner) = providers.owner_of(&target) {
            return Some((target, owner.to_string()));
        }
    }
    None
}

/// Segue symlinks **dentro do rootfs**, componente a componente, e devolve o
/// caminho virtual final.
///
/// Tem de ser componente a componente porque a árvore é usr-merged por link de
/// **diretório**: `/lib64 → usr/lib` e `/bin → usr/bin`. Um `PT_INTERP` de
/// `/lib64/ld-linux-x86-64.so.2` só encontra o dono depois que o `lib64` do
/// meio do caminho é resolvido — olhar apenas o último componente daria
/// "sem provedor" para o carregador que a glibc claramente fornece.
///
/// A leitura é do sistema de arquivos porque o manifesto prende o hash do
/// alvo, não o texto dele; a atribuição de dono continua vindo do registro.
fn resolve_virtual(ctx: &Ctx, virt: &str) -> Option<String> {
    let mut pending: Vec<String> = normalize(virt)
        .split('/')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .rev()
        .collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0usize;

    while let Some(component) = pending.pop() {
        match component.as_str() {
            "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        let candidate = format!("/{}/{component}", resolved.join("/")).replace("//", "/");
        let md = std::fs::symlink_metadata(rooted(ctx, &candidate)).ok()?;
        if !md.file_type().is_symlink() {
            resolved.push(component);
            continue;
        }
        hops += 1;
        if hops > MAX_LINK_HOPS {
            return None; // ciclo de links: não resolve, e não trava.
        }
        let target = std::fs::read_link(rooted(ctx, &candidate)).ok()?;
        let text = target.to_str()?;
        if text.starts_with('/') {
            resolved.clear();
        }
        // O alvo entra na frente da fila; o que faltava percorrer continua atrás.
        for part in text.split('/').filter(|c| !c.is_empty()).rev() {
            pending.push(part.to_string());
        }
    }
    Some(format!("/{}", resolved.join("/")))
}

fn rooted(ctx: &Ctx, virt: &str) -> PathBuf {
    ctx.root.join(virt.trim_start_matches('/'))
}

fn parent_of(virt: &str) -> String {
    match virt.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(at) => virt[..at].to_string(),
    }
}

/// Normalização puramente textual de caminho absoluto: resolve `.` e `..` e
/// colapsa barras. Não toca no disco, então não é enganada por link durante a
/// própria normalização.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

fn load_packages(ctx: &Ctx) -> Result<BTreeMap<String, Package>> {
    let dir = ctx.records_dir();
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let rec = entry.path();
        if !rec.is_dir() {
            continue;
        }
        let Some(meta) = read_meta(&rec) else {
            continue;
        };
        let name = match meta.get("NAME") {
            Some(n) => n.clone(),
            None => continue,
        };
        let claims = read_manifest(&rec)
            .iter()
            .map(|line| {
                let kind = manifest_integrity(line)
                    .and_then(|tag| tag.chars().next())
                    .unwrap_or('f');
                (kind, manifest_path(line).to_string())
            })
            .collect();
        out.insert(
            name.clone(),
            Package {
                name,
                version: meta.get("VERSION").cloned().unwrap_or_default(),
                deps: meta
                    .get("DEPS")
                    .map(|d| d.split_whitespace().map(str::to_string).collect())
                    .unwrap_or_default(),
                claims,
            },
        );
    }
    Ok(out)
}

fn report(analysis: &Analysis, output: Option<&std::path::Path>) -> Result<()> {
    let Analysis {
        targets,
        findings,
        facts,
        inspected,
        missing,
    } = analysis;
    let body: String = facts
        .iter()
        .map(|f| format!("{f}\n"))
        .collect::<Vec<_>>()
        .concat();
    let closure = hex::encode(Sha256::digest(body.as_bytes()));

    // A serialização canônica é o que um gate de publicação consome; o texto
    // do relatório abaixo é para gente. Só o corpo entra no hash — cabeçalho
    // e rodapé descrevem o corpo, não fazem parte dele.
    if let Some(path) = output {
        let text = format!("AUDIT_FORMAT={AUDIT_FORMAT}\n{body}CLOSURE_SHA256={closure}\n");
        std::fs::write(path, text)
            .map_err(|e| anyhow::anyhow!("audit: não gravou {}: {e}", path.display()))?;
    }

    println!(
        "auditoria de fechamento — {} pacote(s), {inspected} arquivo(s) interpretado(s), \
         {} requisito(s) observado(s)",
        targets.len(),
        facts.len()
    );
    for (name, version) in targets {
        if findings.iter().any(|finding| finding.package == *name) {
            println!("  {name} {version}");
        }
    }
    for finding in findings {
        let tag = match finding.severity {
            Severity::Erro => "erro",
            Severity::Observacao => "nota",
        };
        if finding.file.is_empty() {
            println!("  {tag}: {} — {}", finding.package, finding.message);
        } else {
            println!(
                "  {tag}: {} {} — {}",
                finding.package, finding.file, finding.message
            );
        }
    }
    if *missing > 0 {
        println!("  nota: {missing} caminho(s) do manifesto ausente(s) no rootfs — a auditoria não é completa; rode verify");
    }
    println!("AUDIT_FORMAT={AUDIT_FORMAT}");
    println!("CLOSURE_SHA256={closure}");

    let erros = findings
        .iter()
        .filter(|f| f.severity == Severity::Erro)
        .count();
    if erros > 0 {
        return fail(
            1,
            format!("fechamento não provado: {erros} erro(s) de dependência"),
        );
    }
    println!(
        "fechamento provado: todo requisito observado tem provedor declarado. doubleplusgood."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("minitrue-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Regressão dos dois enganos que a closure real revelou: seguir link só
    /// no último componente, e ignorar que o mundo A entrega uma árvore.
    #[test]
    fn resolve_atravessa_usr_merge_e_link_relativo() {
        use std::os::unix::fs::symlink;
        let root = temp_root("usrmerge");
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir_all(root.join("opt/busybox/1.35.0/bin")).unwrap();
        std::fs::write(root.join("usr/lib/ld-linux-x86-64.so.2"), b"carregador").unwrap();
        std::fs::write(root.join("opt/busybox/1.35.0/bin/sh"), b"shell").unwrap();
        symlink("usr/lib", root.join("lib64")).unwrap();
        symlink("usr/bin", root.join("bin")).unwrap();
        symlink("1.35.0", root.join("opt/busybox/current")).unwrap();
        symlink("../../opt/busybox/current/bin/sh", root.join("usr/bin/sh")).unwrap();

        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        // Link de diretório no MEIO do caminho: sem resolver componente a
        // componente, o carregador da glibc apareceria como "sem provedor".
        assert_eq!(
            resolve_virtual(&ctx, "/lib64/ld-linux-x86-64.so.2").as_deref(),
            Some("/usr/lib/ld-linux-x86-64.so.2")
        );
        // Duas travessias encadeadas e um alvo relativo com `..`.
        assert_eq!(
            resolve_virtual(&ctx, "/bin/sh").as_deref(),
            Some("/opt/busybox/1.35.0/bin/sh")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// O gate não é o relatório: ele **impede**. Publicar um payload que exige
    /// provedor não declarado propaga a dependência acidental para todo mundo
    /// que instalar o artefato.
    #[test]
    fn gate_recusa_publicar_requisito_sem_provedor() {
        let root = temp_root("gate");
        let zeros = "0".repeat(64);
        let registros = root.join("var/lib/minitrue/records");
        std::fs::create_dir_all(registros.join("pkg")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/ferramenta"), b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(
            registros.join("pkg/meta"),
            "RECORD_FORMAT=2\nNAME=pkg\nVERSION=1\nDEPS=\n",
        )
        .unwrap();
        std::fs::write(
            registros.join("pkg/manifest"),
            format!("f:{zeros}  /usr/bin/ferramenta\n"),
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };

        let erro = gate(&ctx, &["pkg".to_string()]).unwrap_err();
        assert!(erro.to_string().contains("recusado"), "erro: {erro}");

        // Com o shell declarado — e existindo —, o mesmo pacote passa.
        std::fs::create_dir_all(registros.join("shell")).unwrap();
        std::fs::write(root.join("usr/bin/sh"), b"shell\n").unwrap();
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();
        std::fs::write(
            registros.join("shell/meta"),
            "RECORD_FORMAT=2\nNAME=shell\nVERSION=1\nDEPS=\n",
        )
        .unwrap();
        std::fs::write(
            registros.join("shell/manifest"),
            format!("f:{zeros}  /usr/bin/sh\n"),
        )
        .unwrap();
        std::fs::write(
            registros.join("pkg/meta"),
            "RECORD_FORMAT=2\nNAME=pkg\nVERSION=1\nDEPS=shell\n",
        )
        .unwrap();
        gate(&ctx, &["pkg".to_string()]).unwrap();

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn arvore_do_mundo_a_fornece_seus_arquivos() {
        let providers = Providers {
            owner: [("/usr/bin/sh".to_string(), "busybox".to_string())]
                .into_iter()
                .collect(),
            trees: [("/opt/busybox/1.35.0".to_string(), "busybox".to_string())]
                .into_iter()
                .collect(),
        };
        // Uma única claim `d:` responde por tudo que está sob ela.
        assert_eq!(
            providers.owner_of("/opt/busybox/1.35.0/bin/sh"),
            Some("busybox")
        );
        assert_eq!(providers.owner_of("/usr/bin/sh"), Some("busybox"));
        assert_eq!(providers.owner_of("/opt/outro/1.0/bin/sh"), None);
        assert!(providers.covers_directory("/opt/busybox/1.35.0/lib"));
        assert!(!providers.covers_directory("/tmp/build"));
    }

    #[test]
    fn normaliza_caminho_textualmente() {
        assert_eq!(
            normalize("/usr/lib/../lib64/libc.so.6"),
            "/usr/lib64/libc.so.6"
        );
        assert_eq!(normalize("/usr//lib/./libz.so"), "/usr/lib/libz.so");
        assert_eq!(normalize("/"), "/");
        assert_eq!(parent_of("/usr/lib/libz.so.1"), "/usr/lib");
        assert_eq!(parent_of("/usr"), "/");
    }
}
