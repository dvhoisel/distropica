use crate::{fail, Ctx};
use anyhow::Result;
use std::collections::HashSet;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Binary,
    Source,
}

/// Toolchain de build por estágio (SPEC-0005). O executor injeta `CC`/`AR`/…
/// conforme o perfil; é o que permite a cadeia pass-1 → glibc → pass-2 existir
/// como fluxo, em vez de tudo cair no zig/musl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Toolchain {
    /// Receita de montagem: não recebe uma toolchain pelo contrato de build.
    /// As variáveis de compilação apontam para `false`; shell e utilitários do
    /// PATH continuam disponíveis, portanto isto não é uma fronteira de segurança.
    None,
    /// `zig cc -target x86_64-linux-musl` — a semente. Default (pré-E2).
    #[default]
    Seed,
    /// `x86_64-distropica-linux-gnu-*` — gcc passada 1 + binutils-cross.
    Cross,
    /// `gcc`/`g++` nativo, hospedado na glibc nova (pós-E2).
    Native,
}

#[derive(Debug, Clone)]
pub struct Recipe {
    pub name: String,
    pub version: String,
    /// Descrição curta declarada pela receita. É capturada durante o parse e
    /// persistida no registro; comandos de inspeção nunca devem executar a
    /// cópia histórica da receita apenas para exibi-la.
    pub about: String,
    pub kind: Kind,
    pub srcs: Vec<String>,
    pub sha256: Vec<String>,
    pub deps: Vec<String>,
    pub build_deps: Vec<String>,
    pub links: Vec<(String, String)>,
    pub sig: Vec<String>,
    pub sigsums: Option<String>,
    pub sigkey: Option<String>,
    /// Hash reprodutível canônico do artefato (SPEC-0009 §6): o sha256 do
    /// `pack(STAGE)`. Pinado, é a AUTORIDADE ÚNICA da corroboração — o build
    /// DEVE reproduzi-lo (crimestop se divergir).
    pub reprocorr: Option<String>,
    pub requires_glibc: bool,
    pub provisional: bool,
    pub epoch: Option<String>,
    pub toolchain: Toolchain,
    pub retries: u32,
    /// Pacotes PROVISIONAL cujos caminhos esta receita tem licença de tomar
    /// (SPEC-0003 §7): a supersessão vira declarativa — colisão com um
    /// provisional NÃO listado aqui é *doublethink*, não cessão.
    pub supersedes: Vec<String>,
    /// Snapshot exato avaliado pelo parser e posteriormente executado/registrado.
    /// Evita que uma edição concorrente troque a receita entre fingerprint,
    /// build e escrita do registro.
    pub(crate) recipe_bytes: Vec<u8>,
    files_archive: Option<Vec<u8>>,
    files_fingerprint: Option<String>,
}

impl Recipe {
    /// Dependências implicadas pelo contrato de `TOOLCHAIN`, mesmo quando a
    /// receita não repete o nome em `BUILD_DEPS`. A semente também permanece
    /// necessária no estágio cross para as ferramentas executadas no host.
    /// Elas participam do fingerprint sempre, mas o plano só as instala quando
    /// o pacote será realmente compilado da fonte.
    pub fn toolchain_build_deps(&self) -> &'static [&'static str] {
        if self.kind == Kind::Source && matches!(self.toolchain, Toolchain::Seed | Toolchain::Cross)
        {
            &["zig"]
        } else {
            &[]
        }
    }

    /// Fingerprint **próprio** (só desta receita): o arquivo `recipe` — que já
    /// carrega VERSION, SRC, SHA256, TOOLCHAIN, DEPS, BUILD_DEPS e o corpo de
    /// `build()` — mais o diretório `files/` (patches, chaves). Muda quando
    /// qualquer um deles muda, **mesmo sem bump de VERSION**. É o átomo do
    /// fingerprint de build transitivo ([`build_fingerprints`], SPEC-0011 §4),
    /// que é o que a idempotência do `rectify` e o `--sync` de fato usam.
    pub fn own_fingerprint(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"minitrue-fp-v2\0recipe\0");
        h.update(&self.recipe_bytes);
        if let Some(fh) = &self.files_fingerprint {
            h.update(b"\0files\0");
            h.update(fh.as_bytes());
        }
        Ok(hex::encode(h.finalize()))
    }

    /// Materializa o snapshot de `files/` diretamente em `$WORK`, como exige
    /// o contrato Newspeak. O tar foi produzido durante `load`, portanto os
    /// auxiliares usados no build são exatamente os que entraram no fingerprint.
    pub fn materialize_files(&self, work: &Path) -> Result<()> {
        if let Some(bytes) = &self.files_archive {
            let mut archive = tar::Archive::new(Cursor::new(bytes.as_slice()));
            archive.unpack(work)?;
        }
        Ok(())
    }
}

const DUMP: &str = r#"printf 'NAME=%s\n' "${NAME:-}"
printf 'VERSION=%s\n' "${VERSION:-}"
printf 'ABOUT=%s\n' "${ABOUT:-}"
printf 'KIND=%s\n' "${KIND:-}"
printf 'SRC=%s\n' "${SRC:-}"
printf 'SHA256=%s\n' "${SHA256:-}"
printf 'DEPS=%s\n' "${DEPS:-}"
printf 'BUILD_DEPS=%s\n' "${BUILD_DEPS:-}"
printf 'LINKS=%s\n' "${LINKS:-}"
printf 'SIG=%s\n' "${SIG:-}"
printf 'SIGSUMS=%s\n' "${SIGSUMS:-}"
printf 'SIGKEY=%s\n' "${SIGKEY:-}"
printf 'REPROCORR=%s\n' "${REPROCORR:-}"
printf 'REQUIRES_GLIBC=%s\n' "${REQUIRES_GLIBC:-}"
printf 'PROVISIONAL=%s\n' "${PROVISIONAL:-}"
printf 'SUPERSEDES=%s\n' "${SUPERSEDES:-}"
printf 'EPOCH=%s\n' "${EPOCH:-}"
printf 'TOOLCHAIN=%s\n' "${TOOLCHAIN:-}"
printf 'RETRIES=%s\n' "${RETRIES:-}"
# `type` deve reconhecer somente funções/builtins da receita, nunca um
# executável homônimo herdado do PATH do host.
PATH=
type build >/dev/null 2>&1 && printf 'HAS_BUILD=1\n' || :
type install_pkg >/dev/null 2>&1 && printf 'HAS_INSTALL=1\n' || :
"#;

const DUMP_FIELDS: &[&str] = &[
    "NAME",
    "VERSION",
    "ABOUT",
    "KIND",
    "SRC",
    "SHA256",
    "DEPS",
    "BUILD_DEPS",
    "LINKS",
    "SIG",
    "SIGSUMS",
    "SIGKEY",
    "REPROCORR",
    "REQUIRES_GLIBC",
    "PROVISIONAL",
    "SUPERSEDES",
    "EPOCH",
    "TOOLCHAIN",
    "RETRIES",
    "HAS_BUILD",
    "HAS_INSTALL",
];

fn evaluate_snapshot(recipe_bytes: &[u8]) -> Result<std::process::Output> {
    let mut child = Command::new("sh")
        .arg("-e")
        .arg("-s")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| crate::Fail {
            code: 2,
            msg: format!("não consegui avaliar a receita: {e}"),
        })?;
    let mut stdin = child.stdin.take().ok_or_else(|| crate::Fail {
        code: 2,
        msg: "stdin do shell indisponível".into(),
    })?;
    let mut payload = Vec::with_capacity(recipe_bytes.len() + DUMP.len() + 1);
    payload.extend_from_slice(recipe_bytes);
    payload.push(b'\n');
    payload.extend_from_slice(DUMP.as_bytes());
    // O shell pode escrever no stdout/stderr enquanto ainda lê uma receita
    // grande. O escritor separado permite `wait_with_output` drenar ambos os
    // pipes ao mesmo tempo, evitando o deadlock clássico de buffers cheios.
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        stdin.write_all(&payload)?;
        stdin.flush()
    });
    let out = child.wait_with_output().map_err(|e| crate::Fail {
        code: 2,
        msg: format!("não consegui aguardar a avaliação da receita: {e}"),
    })?;
    let write_result = writer.join().map_err(|_| crate::Fail {
        code: 2,
        msg: "thread que enviava a receita ao shell abortou".into(),
    })?;
    if let Err(e) = write_result {
        return fail(2, format!("não consegui enviar a receita ao shell: {e}"));
    }
    Ok(out)
}

fn snapshot_files(recipe_path: &Path) -> Result<(Option<Vec<u8>>, Option<String>)> {
    let Some(files) = recipe_path.parent().map(|p| p.join("files")) else {
        return Ok((None, None));
    };
    match std::fs::symlink_metadata(&files) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(e) => return Err(e.into()),
        Ok(md) if !md.file_type().is_dir() => {
            return fail(
                2,
                format!(
                    "{} deve ser diretório real, não link/arquivo",
                    files.display()
                ),
            )
        }
        Ok(_) => {}
    }
    // `$WORK/recipe` é reservado para o snapshot executável. Sem esta regra,
    // `files/recipe` poderia ser symlink absoluto: a escrita posterior do
    // snapshot seguiria o link ainda no host. Um hardlink também faria a
    // escrita alterar outro auxiliar depois de ele entrar no fingerprint.
    match std::fs::symlink_metadata(files.join("recipe")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => {
            return fail(
                2,
                format!(
                    "{} é nome reservado; renomeie o auxiliar",
                    files.join("recipe").display()
                ),
            )
        }
    }
    let mut archive = Vec::new();
    let fingerprint = crate::pack::pack_deterministic(&files, 0, &mut archive)?;
    // O tar é o snapshot factual que será materializado. Um symlink nele faria
    // o build ler um alvo mutável que não entrou no fingerprint (inclusive fora
    // de `files/`), portanto auxiliares precisam ser dados autocontidos.
    for entry in tar::Archive::new(Cursor::new(archive.as_slice())).entries()? {
        let entry = entry?;
        if entry.header().entry_type().is_symlink() {
            return fail(
                2,
                format!(
                    "{} contém symlink; auxiliares de build devem ser autocontidos",
                    files.display()
                ),
            );
        }
    }
    Ok((Some(archive), Some(fingerprint)))
}

pub fn find(ctx: &Ctx, name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    for tree in ctx.newspeak_paths() {
        let p = tree.join(name).join("recipe");
        if p.is_file() {
            return Ok(p);
        }
    }
    fail(
        2,
        format!("não há receita para '{name}' em nenhuma árvore newspeak"),
    )
}

/// Nomes viram componentes de caminhos em recipes, records e journals. O
/// alfabeto pequeno de Newspeak impede travessia (`..`), separadores e bytes de
/// controle antes que qualquer operação de filesystem seja tentada.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '+')
    });
    if !first_ok || !rest_ok || name.len() > 128 || name.contains("..") {
        return fail(
            2,
            format!("nome de pacote inválido: '{name}' (use [a-z0-9][a-z0-9+_.-]*)"),
        );
    }
    Ok(())
}

pub(crate) fn validate_version(name: &str, version: &str) -> Result<()> {
    let mut chars = version.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok =
        chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-'));
    if !first_ok
        || !rest_ok
        || version.len() > 128
        || version.contains("..")
        || version != version.trim()
    {
        return fail(
            2,
            format!("{name}: VERSION não é componente de caminho canônico: {version:?}"),
        );
    }
    Ok(())
}

pub(crate) fn validate_link(name: &str, command: &str, relative: &str) -> Result<()> {
    let command_ok = !command.is_empty()
        && command.len() <= 255
        && !matches!(command, "." | "..")
        && !command.chars().any(char::is_control)
        && !command.contains('/');
    let relative_ok = !relative.is_empty()
        && !relative.chars().any(char::is_control)
        && !relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        && Path::new(relative)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
    if !command_ok || !relative_ok {
        return fail(
            2,
            format!("{name}: LINKS '{command}={relative}' não é nome=caminho/relativo canônico"),
        );
    }
    Ok(())
}

pub fn load(ctx: &Ctx, name: &str) -> Result<Recipe> {
    let path = find(ctx, name)?;
    let recipe_bytes = std::fs::read(&path)?;
    let (files_archive, files_fingerprint) = snapshot_files(&path)?;
    // Avalia o mesmo snapshot que será usado no build e persistido no registro;
    // nunca volta a sourcear um caminho que possa ter mudado no intervalo.
    let out = evaluate_snapshot(&recipe_bytes)?;
    if !out.status.success() {
        return fail(
            2,
            format!(
                "receita inválida em {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        );
    }

    let stdout = String::from_utf8(out.stdout).map_err(|_| crate::Fail {
        code: 2,
        msg: format!("{name}: metadados da receita não são UTF-8"),
    })?;
    let mut get = std::collections::HashMap::new();
    for (line_no, line) in stdout.lines().enumerate() {
        let Some((k, v)) = line.split_once('=') else {
            return fail(
                2,
                format!(
                    "{name}: saída inesperada ao avaliar receita (linha {})",
                    line_no + 1
                ),
            );
        };
        if !DUMP_FIELDS.contains(&k) {
            return fail(2, format!("{name}: campo avaliado desconhecido '{k}'"));
        }
        if get.insert(k.to_string(), v.to_string()).is_some() {
            return fail(2, format!("{name}: campo avaliado duplicado '{k}'"));
        }
    }
    // Todos os campos fixos são impressos mesmo quando vazios. Ausência indica
    // que o snapshot interrompeu/manipulou a avaliação antes do dump canônico.
    for required in &DUMP_FIELDS[..DUMP_FIELDS.len() - 2] {
        if !get.contains_key(*required) {
            return fail(
                2,
                format!("{name}: avaliação não produziu o campo {required}"),
            );
        }
    }
    let field = |k: &str| get.get(k).cloned().unwrap_or_default();
    let list =
        |k: &str| -> Vec<String> { field(k).split_whitespace().map(str::to_string).collect() };

    let rname = field("NAME");
    if rname != name {
        return fail(2, format!("NAME='{rname}' difere do diretório '{name}'"));
    }
    let version = field("VERSION");
    validate_version(name, &version)?;
    let about = field("ABOUT");
    if about.chars().any(char::is_control) {
        return fail(2, format!("{name}: ABOUT deve ocupar uma única linha"));
    }
    let kind = match field("KIND").as_str() {
        "binary" => Kind::Binary,
        "source" => Kind::Source,
        other => {
            return fail(
                2,
                format!("{name}: KIND '{other}' inválido (binary|source)"),
            )
        }
    };
    let srcs = list("SRC");
    let sha256: Vec<String> = list("SHA256").iter().map(|s| s.to_lowercase()).collect();
    let sig = list("SIG");
    if kind == Kind::Binary && srcs.is_empty() {
        return fail(
            2,
            format!("{name}: KIND=binary exige SRC; montagem sem download é mundo B"),
        );
    }
    if srcs.is_empty() {
        // Receita de MONTAGEM (sem SRC): o pacote é gerado pelo próprio build()
        // — config, esqueleto de /etc. Nada a baixar, logo nada a hashear ou
        // assinar. Um SHA256/SIG aqui é engano (não há artefato).
        if !sha256.is_empty() || !sig.is_empty() {
            return fail(
                2,
                format!("{name}: SHA256/SIG sem SRC (receita de montagem não baixa nada)"),
            );
        }
    } else {
        if !sha256.is_empty() && sha256.len() != srcs.len() {
            return fail(2, format!("{name}: SHA256 e SRC com contagens diferentes"));
        }
        if sha256
            .iter()
            .any(|h| h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return fail(
                2,
                format!("{name}: SHA256 mal-formado (64 hex por artefato)"),
            );
        }
        if sha256.is_empty() && !ctx.tofu {
            return fail(
                2,
                format!("{name}: receita sem SHA256 (só com --tofu, e com aviso)"),
            );
        }
        if !sig.is_empty() && sig.len() != srcs.len() {
            return fail(2, format!("{name}: SIG e SRC com contagens diferentes"));
        }
    }
    let mut links = Vec::new();
    let mut link_commands = HashSet::new();
    for item in list("LINKS") {
        match item.split_once('=') {
            Some((cmd, rel)) => {
                validate_link(name, cmd, rel)?;
                if !link_commands.insert(cmd.to_string()) {
                    return fail(2, format!("{name}: LINKS repete o comando '{cmd}'"));
                }
                links.push((cmd.to_string(), rel.to_string()))
            }
            _ => {
                return fail(
                    2,
                    format!("{name}: LINKS '{item}' inválido (nome=caminho/relativo)"),
                )
            }
        }
    }
    let sigsums = Some(field("SIGSUMS")).filter(|s| !s.is_empty());
    let sigkey = Some(field("SIGKEY")).filter(|s| !s.is_empty());
    if !sig.is_empty() && sigkey.is_none() {
        return fail(2, format!("{name}: SIG exige SIGKEY pinada"));
    }
    let reprocorr = Some(field("REPROCORR")).filter(|s| !s.is_empty());
    if let Some(rc) = &reprocorr {
        let canonical = rc
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if rc.len() != 64 || !canonical {
            return fail(
                2,
                format!("{name}: REPROCORR mal-formado (64 hex minúsculos)"),
            );
        }
    }
    let toolchain = match field("TOOLCHAIN").as_str() {
        "none" => Toolchain::None,
        "" | "seed" => Toolchain::Seed,
        "cross" => Toolchain::Cross,
        "native" => Toolchain::Native,
        other => {
            return fail(
                2,
                format!("{name}: TOOLCHAIN '{other}' inválido (none|seed|cross|native)"),
            )
        }
    };
    let retries: u32 = match field("RETRIES").as_str() {
        "" => 0,
        s => s.parse().map_err(|_| crate::Fail {
            code: 2,
            msg: format!("{name}: RETRIES '{s}' não é número"),
        })?,
    };
    let epoch = Some(field("EPOCH")).filter(|s| !s.is_empty());
    if let Some(value) = &epoch {
        value.parse::<u64>().map_err(|_| crate::Fail {
            code: 2,
            msg: format!("{name}: EPOCH '{value}' não é timestamp Unix"),
        })?;
    }
    let bool_field = |key: &str| -> Result<bool> {
        match field(key).as_str() {
            "" | "0" => Ok(false),
            "1" => Ok(true),
            value => fail(2, format!("{name}: {key}='{value}' inválido (0|1)")),
        }
    };
    let requires_glibc = bool_field("REQUIRES_GLIBC")?;
    let provisional = bool_field("PROVISIONAL")?;

    let deps = list("DEPS");
    let build_deps = list("BUILD_DEPS");
    let supersedes = list("SUPERSEDES");
    for dependency in deps.iter().chain(&build_deps).chain(&supersedes) {
        validate_name(dependency)?;
    }

    if kind == Kind::Binary && !get.contains_key("HAS_INSTALL") {
        return fail(2, format!("{name}: KIND=binary exige install_pkg()"));
    }
    if kind == Kind::Source && !get.contains_key("HAS_BUILD") {
        return fail(2, format!("{name}: KIND=source exige build()"));
    }

    Ok(Recipe {
        name: rname,
        version,
        about,
        kind,
        srcs,
        sha256,
        deps,
        build_deps,
        links,
        sig,
        sigsums,
        sigkey,
        reprocorr,
        requires_glibc,
        provisional,
        epoch,
        toolchain,
        retries,
        supersedes,
        recipe_bytes,
        files_archive,
        files_fingerprint,
    })
}

/// Lê uma atribuição shell que seja comprovadamente literal, sem executar a
/// receita. Serve apenas como compatibilidade para registros antigos, criados
/// antes de ABOUT/REPROCORR serem congelados em `meta`.
///
/// Formas aceitas: `KEY=palavra`, `KEY='texto'` e `KEY="texto"`. Expansões,
/// substituições de comando, concatenações e atribuições ambíguas são
/// recusadas. Em caso de dúvida, é melhor omitir informação legada do que
/// executar código histórico durante um comando de inspeção.
pub(crate) fn literal_assignment(path: &Path, key: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    literal_assignment_bytes(&bytes, key)
}

/// Variante sobre bytes já abertos pelo chamador. Fluxos de integridade usam
/// esta forma depois de uma abertura `O_NOFOLLOW`, para que a compatibilidade
/// com receitas legadas não reintroduza seguimento de symlink.
pub(crate) fn literal_assignment_bytes(bytes: &[u8], key: &str) -> Option<String> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let prefix = format!("{key}=");
    let mut found = None;
    for line in text.lines() {
        let Some(value) = line.strip_prefix(&prefix) else {
            continue;
        };
        // Mais de uma atribuição exigiria interpretar fluxo de controle shell;
        // não tente adivinhar qual delas vigoraria.
        if found.is_some() {
            return None;
        }
        found = Some(parse_literal_value(value.trim())?);
    }
    found
}

fn parse_literal_value(value: &str) -> Option<String> {
    let trailing_ok = |s: &str| {
        let s = s.trim_start();
        s.is_empty() || s.starts_with('#')
    };

    if let Some(rest) = value.strip_prefix('\'') {
        let end = rest.find('\'')?;
        if !trailing_ok(&rest[end + 1..]) {
            return None;
        }
        return Some(rest[..end].to_string());
    }

    if let Some(rest) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    if trailing_ok(&rest[i + c.len_utf8()..]) {
                        return Some(out);
                    }
                    return None;
                }
                // Sem expansão: `$x` e `$(...)` são dinâmicos; backticks são
                // substituição de comando. As versões escapadas são literais.
                '$' | '`' => return None,
                '\\' => {
                    let (_, next) = chars.next()?;
                    match next {
                        '$' | '`' | '"' | '\\' => out.push(next),
                        _ => {
                            // Em aspas duplas POSIX, a barra é preservada
                            // diante dos demais caracteres.
                            out.push('\\');
                            out.push(next);
                        }
                    }
                }
                _ => out.push(c),
            }
        }
        return None;
    }

    let (word, trailing) = value
        .find(char::is_whitespace)
        .map(|i| (&value[..i], &value[i..]))
        .unwrap_or((value, ""));
    if word.is_empty()
        || !word.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '-' | '.' | '/' | ':' | '+' | '@' | '%' | ',')
        })
        || !trailing_ok(trailing)
    {
        return None;
    }
    Some(word.to_string())
}

/// Fingerprint de build **transitivo** (SPEC-0011 §4): o `own_fingerprint` da
/// receita combinado com os fingerprints das suas `DEPS`, `BUILD_DEPS` e
/// dependências de toolchain implícitas, recursivamente. Assim, se o `binutils`
/// ou a semente Zig muda, o fingerprint dos dependentes afetados também muda —
/// e o `rectify`/`--sync` re-builda o dependente, não só o pacote alterado.
/// Consertando o limite não-transitivo do v1.
///
/// Recebe a resolução inteira já carregada e calcula todos os fingerprints sem
/// reler a árvore. Assim a closure (receitas + `files/`) é um snapshot único do
/// começo do `rectify`, inclusive quando um arquivo muda durante um build longo.
pub fn build_fingerprints(recipes: &[Recipe]) -> Result<std::collections::HashMap<String, String>> {
    let by_name: std::collections::HashMap<&str, &Recipe> = recipes
        .iter()
        .map(|recipe| (recipe.name.as_str(), recipe))
        .collect();
    let mut cache = std::collections::HashMap::new();
    for recipe in recipes {
        build_fp_from_snapshots(&recipe.name, &by_name, &mut cache, &mut Vec::new())?;
    }
    Ok(cache)
}

fn build_fp_from_snapshots(
    name: &str,
    recipes: &std::collections::HashMap<&str, &Recipe>,
    cache: &mut std::collections::HashMap<String, String>,
    stack: &mut Vec<String>,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    if let Some(fp) = cache.get(name) {
        return Ok(fp.clone());
    }
    if stack.iter().any(|item| item == name) {
        return fail(
            2,
            format!(
                "ciclo no snapshot de fingerprints: {} -> {name}",
                stack.join(" -> ")
            ),
        );
    }
    let r = recipes.get(name).copied().ok_or_else(|| crate::Fail {
        code: 2,
        msg: format!("snapshot incompleto: dependência '{name}' não foi coletada"),
    })?;
    let mut h = Sha256::new();
    h.update(b"minitrue-bfp-v1\0self\0");
    h.update(r.own_fingerprint()?.as_bytes());
    stack.push(name.to_string());
    // Ordem canônica dos deps para o hash ser estável. A toolchain declarada
    // também faz parte da identidade: trocar a receita do Zig invalida tudo
    // que foi produzido pelos estágios seed/cross.
    let mut deps: Vec<&str> = r
        .deps
        .iter()
        .chain(r.build_deps.iter())
        .map(String::as_str)
        .chain(r.toolchain_build_deps().iter().copied())
        .collect();
    deps.sort();
    deps.dedup();
    for d in deps {
        h.update(b"\0dep\0");
        h.update(d.as_bytes());
        h.update(b"=");
        h.update(build_fp_from_snapshots(d, recipes, cache, stack)?.as_bytes());
    }
    stack.pop();
    let fp = hex::encode(h.finalize());
    cache.insert(name.to_string(), fp.clone());
    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Grava um recipe num tree temporário e o carrega via `load`.
    fn load_body(extra: &str) -> Result<Recipe> {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-recipe-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/foo");
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "a".repeat(64);
        let body = format!(
            "NAME=foo\nVERSION=1.0\nKIND=source\nSRC=https://e/foo.tar.xz\nSHA256={hash}\n{extra}\nbuild(){{ :; }}\n"
        );
        std::fs::write(dir.join("recipe"), body).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let r = load(&ctx, "foo");
        let _ = std::fs::remove_dir_all(&root);
        r
    }

    /// Carrega uma receita (opcionalmente com arquivos em `files/`), computa o
    /// fingerprint ANTES de limpar (o fingerprint lê o arquivo do disco).
    fn fp_of(extra: &str, files: &[(&str, &str)]) -> String {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-fp-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/foo");
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "a".repeat(64);
        std::fs::write(
            dir.join("recipe"),
            format!("NAME=foo\nVERSION=1.0\nKIND=source\nSRC=https://e/f.tar.xz\nSHA256={hash}\n{extra}\nbuild(){{ :; }}\n"),
        )
        .unwrap();
        if !files.is_empty() {
            std::fs::create_dir_all(dir.join("files")).unwrap();
            for (name, content) in files {
                std::fs::write(dir.join("files").join(name), content).unwrap();
            }
        }
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let f = load(&ctx, "foo").unwrap().own_fingerprint().unwrap();
        let _ = std::fs::remove_dir_all(&root);
        f
    }

    /// Receita de MONTAGEM (sem SRC): parseia sem SHA256 (nada a baixar); mas
    /// SHA256 sem SRC é engano e deve falhar.
    #[test]
    fn receita_sem_src_monta() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-nosrc-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/base");
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        // sem SRC, sem SHA256 → OK (o build() monta o pacote)
        std::fs::write(
            dir.join("recipe"),
            "NAME=base\nVERSION=0.1\nKIND=source\nTOOLCHAIN=native\nbuild(){ :; }\n",
        )
        .unwrap();
        let r = load(&ctx, "base").expect("receita de montagem (sem SRC) deve parsear");
        assert!(r.srcs.is_empty() && r.sha256.is_empty());

        // sem SRC, mas COM SHA256 → erro
        std::fs::write(
            dir.join("recipe"),
            format!(
                "NAME=base\nVERSION=0.1\nKIND=source\nSHA256={}\nbuild(){{ :; }}\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        assert!(load(&ctx, "base").is_err(), "SHA256 sem SRC deve falhar");

        // Mundo A nunca pode usar a exceção de montagem para executar
        // `install_pkg` sem artefato verificado no host.
        std::fs::write(
            dir.join("recipe"),
            "NAME=base\nVERSION=0.1\nKIND=binary\ninstall_pkg(){ :; }\n",
        )
        .unwrap();
        assert!(load(&ctx, "base").is_err(), "binary sem SRC deve falhar");

        std::fs::write(dir.join("recipe"), "NAME=base\nVERSION=0.1\nKIND=source\n").unwrap();
        assert!(
            load(&ctx, "base").is_err(),
            "source sem build() deve falhar"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// REPROCORR chega ao struct (regressão: o DUMP tem lista fixa de printf — um
    /// campo esquecido lá vira None silencioso, desligando a verificação de raiz).
    #[test]
    fn reprocorr_parseado() {
        let h = "d".repeat(64);
        assert_eq!(
            load_body(&format!("REPROCORR={h}"))
                .unwrap()
                .reprocorr
                .as_deref(),
            Some(h.as_str())
        );
        assert!(
            load_body("REPROCORR=xyz").is_err(),
            "REPROCORR mal-formado deve falhar"
        );
        assert!(load_body("").unwrap().reprocorr.is_none());
        assert!(
            load_body("SIG=https://e/foo.sig").is_err(),
            "SIG sem SIGKEY não pode ser aceita"
        );
    }

    #[test]
    fn about_parseado_e_literal_legado_nao_executa_shell() {
        let r = load_body("ABOUT='uma receita com história'").unwrap();
        assert_eq!(r.about, "uma receita com história");

        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-literal-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let recipe = root.join("recipe");
        let marker = root.join("nao-deve-existir");
        std::fs::write(
            &recipe,
            format!(
                "ABOUT=\"$(touch {})\"\nREPROCORR={}\n",
                marker.display(),
                "a".repeat(64)
            ),
        )
        .unwrap();

        assert_eq!(literal_assignment(&recipe, "ABOUT"), None);
        assert!(!marker.exists(), "a inspeção legada executou a receita");
        assert_eq!(
            literal_assignment(&recipe, "REPROCORR").as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );

        std::fs::write(&recipe, "ABOUT=\"texto com \\\"aspas\\\"\" # nota\n").unwrap();
        assert_eq!(
            literal_assignment(&recipe, "ABOUT").as_deref(),
            Some("texto com \"aspas\"")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fingerprint_estavel_e_sensivel() {
        let base = fp_of("", &[]);
        // determinístico: mesma receita → mesmo fingerprint
        assert_eq!(base, fp_of("", &[]));
        // MESMA versão (1.0), receita diferente → fingerprint diferente.
        // É o bug do review consertado: mudar a receita sem bump de VERSION
        // agora dispara rebuild.
        assert_ne!(base, fp_of("TOOLCHAIN=cross", &[]), "toolchain muda o fp");
        assert_ne!(base, fp_of("DEPS=glibc", &[]), "deps mudam o fp");
        // files/ entra no fingerprint (patches, chaves)
        let com_patch = fp_of("", &[("fix.patch", "--- a\n+++ b\n")]);
        assert_ne!(base, com_patch, "files/ muda o fp");
        assert_eq!(com_patch, fp_of("", &[("fix.patch", "--- a\n+++ b\n")]));
        assert_ne!(
            com_patch,
            fp_of("", &[("fix.patch", "outro conteúdo\n")]),
            "conteúdo de files/ conta"
        );
    }

    #[test]
    fn snapshot_congela_receita_e_files_usados_no_build() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-snapshot-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/foo");
        let files = dir.join("files");
        std::fs::create_dir_all(&files).unwrap();
        let hash = "a".repeat(64);
        let original = format!(
            "NAME=foo\nVERSION=1\nKIND=source\nTOOLCHAIN=none\nSRC=https://e/foo\nSHA256={hash}\nABOUT='original'\nbuild(){{ :; }}\n"
        );
        std::fs::write(dir.join("recipe"), &original).unwrap();
        std::fs::write(files.join("fix.patch"), "patch original\n").unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };

        let recipe = load(&ctx, "foo").unwrap();
        let fingerprint = recipe.own_fingerprint().unwrap();
        let build_fingerprint = build_fingerprints(std::slice::from_ref(&recipe))
            .unwrap()
            .remove("foo")
            .unwrap();
        std::fs::write(dir.join("recipe"), original.replace("original", "alterada")).unwrap();
        std::fs::write(files.join("fix.patch"), "patch alterado\n").unwrap();

        assert_eq!(recipe.about, "original");
        assert_eq!(recipe.own_fingerprint().unwrap(), fingerprint);
        assert_eq!(
            build_fingerprints(std::slice::from_ref(&recipe))
                .unwrap()
                .remove("foo")
                .unwrap(),
            build_fingerprint
        );
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        recipe.materialize_files(&work).unwrap();
        assert_eq!(
            std::fs::read_to_string(work.join("fix.patch")).unwrap(),
            "patch original\n"
        );
        assert_eq!(recipe.recipe_bytes, original.as_bytes());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn files_nao_pode_substituir_snapshot_recipe() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-reserved-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/foo");
        let files = dir.join("files");
        std::fs::create_dir_all(&files).unwrap();
        std::fs::write(
            dir.join("recipe"),
            "NAME=foo\nVERSION=1\nKIND=source\nbuild(){ :; }\n",
        )
        .unwrap();
        let victim = root.join("nao-alterar");
        std::fs::write(&victim, b"INTEGRO").unwrap();
        symlink(&victim, files.join("recipe")).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        assert!(
            load(&ctx, "foo").is_err(),
            "nome reservado deve ser recusado"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"INTEGRO");

        std::fs::remove_file(files.join("recipe")).unwrap();
        std::fs::hard_link(&victim, files.join("recipe")).unwrap();
        assert!(
            load(&ctx, "foo").is_err(),
            "hardlink reservado deve ser recusado"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"INTEGRO");

        std::fs::remove_file(files.join("recipe")).unwrap();
        symlink(&victim, files.join("fix.patch")).unwrap();
        assert!(
            load(&ctx, "foo").is_err(),
            "symlink auxiliar poderia escapar do snapshot"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"INTEGRO");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn avaliacao_drena_saida_enquanto_envia_snapshot() {
        // Mais que o buffer usual de pipe. O padrão antigo escrevia todo stdin
        // antes de ler stdout e podia bloquear quando o shell executava esta
        // linha enquanto ainda havia receita por receber.
        let mut body =
            b"i=0; while [ $i -lt 20000 ]; do printf 12345678; i=$((i+1)); done\n".to_vec();
        body.extend(std::iter::repeat_n(b'#', 200_000));
        body.extend_from_slice(b"\n");
        let out = evaluate_snapshot(&body).unwrap();
        assert!(out.status.success());
        assert!(out.stdout.len() >= 160_000);
    }

    #[test]
    fn build_fingerprint_transitivo() {
        // Árvore A → B: A depende de B. Mudar B muda o fingerprint de A.
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-bfp-{}-{n}", std::process::id()));
        let tree = root.join("var/lib/minitrue/newspeak");
        let hash = "a".repeat(64);
        let write = |name: &str, extra: &str| {
            let d = tree.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("recipe"),
                format!("NAME={name}\nVERSION=1\nKIND=source\nTOOLCHAIN=none\nSRC=https://e/{name}.tar.xz\nSHA256={hash}\n{extra}\nbuild(){{ :; }}\n"),
            )
            .unwrap();
        };
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let fingerprint_a = || {
            let closure = [load(&ctx, "b").unwrap(), load(&ctx, "a").unwrap()];
            build_fingerprints(&closure).unwrap().remove("a").unwrap()
        };

        write("b", "");
        write("a", "DEPS=b");
        let fp_a1 = fingerprint_a();
        // determinístico
        assert_eq!(fp_a1, fingerprint_a());
        // muda B (mesma versão) → o fingerprint de A muda também (transitivo)
        write("b", "# toque em b");
        let fp_a2 = fingerprint_a();
        assert_ne!(fp_a1, fp_a2, "mudar um dep deve mudar o fp do dependente");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn zig_implicito_participa_do_fingerprint_seed() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-bfp-zig-{}-{n}", std::process::id()));
        let tree = root.join("var/lib/minitrue/newspeak");
        let pkg = tree.join("pkg");
        let zig = tree.join("zig");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::create_dir_all(&zig).unwrap();
        std::fs::write(
            pkg.join("recipe"),
            "NAME=pkg\nVERSION=1\nKIND=source\nTOOLCHAIN=seed\nbuild(){ :; }\n",
        )
        .unwrap();
        let write_zig = |about: &str| {
            std::fs::write(
                zig.join("recipe"),
                format!(
                    "NAME=zig\nVERSION=1\nKIND=binary\nABOUT={about}\nSRC=https://e/zig.tar.xz\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                    "a".repeat(64)
                ),
            )
            .unwrap();
        };
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let fingerprint = || {
            let closure = [load(&ctx, "zig").unwrap(), load(&ctx, "pkg").unwrap()];
            build_fingerprints(&closure).unwrap().remove("pkg").unwrap()
        };

        write_zig("semente-a");
        let first = fingerprint();
        write_zig("semente-b");
        assert_ne!(first, fingerprint());
        assert!(
            build_fingerprints(&[load(&ctx, "pkg").unwrap()]).is_err(),
            "snapshot seed sem a receita Zig precisa falhar fechado"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn toolchain_default_e_seed_sem_retries() {
        let r = load_body("").unwrap();
        assert_eq!(r.toolchain, Toolchain::Seed);
        assert_eq!(r.retries, 0);
        assert_eq!(r.toolchain_build_deps(), &["zig"]);
    }

    #[test]
    fn toolchain_none() {
        let r = load_body("TOOLCHAIN=none").unwrap();
        assert_eq!(r.toolchain, Toolchain::None);
        assert!(r.toolchain_build_deps().is_empty());
    }

    #[test]
    fn toolchain_cross_com_retries() {
        let r = load_body("TOOLCHAIN=cross\nRETRIES=50").unwrap();
        assert_eq!(r.toolchain, Toolchain::Cross);
        assert_eq!(r.retries, 50);
        assert_eq!(r.toolchain_build_deps(), &["zig"]);
    }

    #[test]
    fn toolchain_native() {
        let r = load_body("TOOLCHAIN=native").unwrap();
        assert_eq!(r.toolchain, Toolchain::Native);
        assert!(r.toolchain_build_deps().is_empty());
    }

    #[test]
    fn pacote_binario_nao_puxa_zig_da_toolchain() {
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-binary-tc-{}-{n}", std::process::id()));
        let dir = root.join("var/lib/minitrue/newspeak/tool");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recipe"),
            format!(
                "NAME=tool\nVERSION=1\nKIND=binary\nSRC=https://e/tool.tar.xz\nSHA256={}\ninstall_pkg(){{ :; }}\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: false,
            tofu: false,
            jobs: 1,
        };
        let recipe = load(&ctx, "tool").unwrap();
        assert_eq!(recipe.toolchain, Toolchain::Seed);
        assert!(recipe.toolchain_build_deps().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn toolchain_invalido_recusado() {
        assert!(load_body("TOOLCHAIN=quantum").is_err());
    }

    #[test]
    fn retries_nao_numero_recusado() {
        assert!(load_body("RETRIES=muitas").is_err());
    }

    #[test]
    fn nome_de_pacote_nao_permite_travessia() {
        for valid in ["gcc-pass2", "libstdcxx", "python3", "c-plus+tools"] {
            assert!(validate_name(valid).is_ok(), "deveria aceitar {valid}");
        }
        for invalid in ["", "../fora", "a/b", ".oculto", "A", "x\ny", "a..b"] {
            assert!(
                validate_name(invalid).is_err(),
                "deveria recusar {invalid:?}"
            );
        }
    }

    #[test]
    fn versao_links_e_dependencias_sao_componentes_seguros() {
        assert!(load_body("VERSION='1.0 '").is_err());
        assert!(load_body("VERSION=../../fora").is_err());
        assert!(load_body("LINKS='../escape=bin/tool'").is_err());
        assert!(load_body("LINKS='tool=../../fora'").is_err());
        assert!(load_body("LINKS='tool=bin/a tool=bin/b'").is_err());
        assert!(load_body("DEPS=../fora").is_err());
        assert!(load_body("SUPERSEDES=../../fora").is_err());
    }

    #[test]
    fn arvore_newspeak_do_projeto_carrega_por_snapshot() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("minitrue deve viver dentro do projeto");
        let tree = project.join("newspeak");
        assert!(tree.is_dir(), "árvore newspeak do checkout ausente");
        let n = CNT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("mt-tree-{}-{n}", std::process::id()));
        let parent = root.join("var/lib/minitrue");
        std::fs::create_dir_all(&parent).unwrap();
        symlink(&tree, parent.join("newspeak")).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };
        let mut names: Vec<String> = std::fs::read_dir(&tree)
            .unwrap()
            .flatten()
            .filter(|entry| entry.path().join("recipe").is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert!(names.len() >= 20, "árvore inesperadamente pequena");
        for name in names {
            load(&ctx, &name).unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
