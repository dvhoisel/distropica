mod arvore;
mod attest;
mod audit;
mod channel;
mod elf;
mod fetch;
mod install;
mod linux;
mod openpgp;
mod openpgp_schema;
mod pack;
pub mod plan;
mod recipe;
mod sign;

use std::path::{Path, PathBuf};

pub struct Ctx {
    pub root: PathBuf,
    pub offline: bool,
    pub tofu: bool,
    pub jobs: usize,
}

impl Ctx {
    /// TOFU só pode ser ativado num binário compilado para autoria. Manter a
    /// decisão aqui, além da fronteira da CLI, impede que um chamador interno
    /// transforme `tofu: true` em bypass num build distribuível.
    pub fn tofu_enabled(&self) -> bool {
        #[cfg(feature = "tofu-authoring")]
        {
            self.tofu
        }
        #[cfg(not(feature = "tofu-authoring"))]
        {
            false
        }
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("var/cache/minitrue")
    }
    pub fn records_dir(&self) -> PathBuf {
        self.root.join("var/lib/minitrue/records")
    }
    pub fn room101(&self) -> PathBuf {
        self.root.join("var/log/room101")
    }
    pub fn world_path(&self) -> PathBuf {
        self.root.join("etc/minitrue/world")
    }
    pub fn usr_bin(&self) -> PathBuf {
        self.root.join("usr/bin")
    }
    pub fn opt(&self, name: &str) -> PathBuf {
        self.root.join("opt").join(name)
    }
    /// Árvores de receitas em ordem de precedência (NEWSPEAK_PATH, primeira vence).
    /// Entradas relativas são resolvidas contra --root.
    pub fn newspeak_paths(&self) -> Vec<PathBuf> {
        match std::env::var("NEWSPEAK_PATH") {
            Ok(v) if !v.trim().is_empty() => v
                .split(':')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let p = PathBuf::from(s);
                    if p.is_absolute() {
                        p
                    } else {
                        self.root.join(p)
                    }
                })
                .collect(),
            _ => vec![self.root.join("var/lib/minitrue/newspeak")],
        }
    }
}

/// Erro com código de saída da SPEC-0003 §9.
#[derive(Debug)]
pub struct Fail {
    pub code: i32,
    pub msg: String,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl std::error::Error for Fail {}

pub fn fail<T>(code: i32, msg: impl Into<String>) -> anyhow::Result<T> {
    Err(Fail {
        code,
        msg: msg.into(),
    }
    .into())
}

const USO_CABECALHO: &str = "\
minitrue — o Ministério da Verdade (v0.1: mundos A e B)
";

#[cfg(not(feature = "tofu-authoring"))]
const USO_SINOPSE: &str = "uso: minitrue [--root DIR] [--offline] [--no-binary|--only-binary] [--jobs N] <comando> [args]";

#[cfg(feature = "tofu-authoring")]
const USO_SINOPSE: &str = "uso: minitrue [--root DIR] [--offline] [--tofu] [--no-binary|--only-binary] [--jobs N] <comando> [args]";

const USO_CORPO: &str = "\
  rectify   <pacote>…   instala/atualiza; acrescenta ao world
  rectify   newspeak    busca e troca atomicamente a árvore oficial assinada
  plan      <pacote>…   resolve e imprime PLAN_LOCK_FORMAT=1 sem persistir
  plan --sync            compara o world com records íntegros; apenas relata ORPHAN
  plan --media --world ARQ [--cache-world ARQ] [--output ARQ]
                        resolve a composição de uma mídia: PURPOSE=media com
                        ABI estrita, worlds como raízes (target=install,
                        cache=availability). --output grava os bytes canônicos
                        do PLAN_LOCK, que é o que o perfil prende em vez de
                        re-resolver
  memoryhole <pacote>…  remove do sistema e do world
  archives              lista os registros
  verify                confere registros e varre /usr por links órfãos
  audit     [pacote]…   confronta DEPS com o que o payload realmente exige
                        (ELF/shebang, sem executar nada); sem argumento, tudo.
                        --output DIR|ARQ grava a serialização canônica
  lint      [pacote]…   audita comandos literais de build contra
                        DEPS/BUILD_DEPS/toolchain; sem argumento, toda a árvore
  newspeak  <pacote>    imprime a receita efetiva e sua origem
  fingerprint <pacote>… imprime '<pacote> <fingerprint>' da closure de
                        identidade; é o número que o crimestop exige do canal
  explain   <caminho>   de quem é o arquivo e toda a sua proveniência
  why       <pacote>    por que este pacote está no sistema
  pack <dir> [saída]    tara <dir> determinístico; imprime o sha256 (SPEC-0010)
  attest keygen <nome> <chave>  cria identidade ed25519 de builder
  attest <pacote> <builder> <chave>  emite attestation assinada
  corroborate <pacote>  coteja attestations confiáveis com o registro local
  cache verify --closure <pacote>…
  cache verify --closure --world ARQUIVO
                        resolve a mesma closure e confere objetos/índices/assinaturas,
                        sem rede, instalação ou persistência
  channel refresh [canal]…
                        autentica o índice e mostra o diff antes de persistir
  channel emit [--release] --output DIR <pacote>...
                        emite tar.zst + índice v2 a partir de registros B íntegros;
                        --release exige o tar selado retido do próprio build
  channel keygen <base>  cria par minisign (base.key 0600 + base.pub)
  channel sign [--passphrase-fd N] <chave> <arquivo> <chave-pública-esperada>
                        lê senha somente do descritor não-TTY já aberto,
                        coteja a pública antes de assinar, escreve e confere
                        <arquivo>.minisig

chegam no Marco 0.2: rectify --sync, rollback e unperson.";

fn imprime_uso() {
    println!("{USO_CABECALHO}\n{USO_SINOPSE}\n\n{USO_CORPO}");
    #[cfg(feature = "tofu-authoring")]
    println!("\n  --tofu                autoria somente: obtém e imprime o SHA256 ainda ausente");
}

/// A correspondência entre world e papel é FIXADA aqui, e não deixada a cada
/// chamador: `target.world` é o que a mídia instala, `cache.world` é o que ela
/// precisa ter disponível sem instalar. Dois chamadores com convenções
/// diferentes produziriam dois PLAN_LOCK distintos para a mesma mídia, e o
/// perfil não teria como saber qual dos dois prendeu.
fn raizes_de_midia(
    target_world: &std::path::Path,
    cache_world: Option<&std::path::Path>,
) -> anyhow::Result<Vec<plan::PlanRoot>> {
    let mut roots = plan::roots_from_world(target_world, plan::RootRole::Install)?;
    if let Some(path) = cache_world {
        roots.extend(plan::roots_from_world(path, plan::RootRole::Availability)?);
    }
    Ok(roots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DespachoPlan {
    Media,
    Sync,
    Pacotes,
}

/// As três resoluções que `plan` sabe fazer são mutuamente exclusivas e leem
/// fontes de raiz diferentes: `--media` lê os worlds do perfil, `--sync` lê o
/// world do sistema e a forma ordinária lê os nomes da linha de comando.
/// Aceitar duas ao mesmo tempo produziria um plano cujas raízes ninguém sabe
/// dizer de onde vieram, então a classificação é separada do efeito para ser
/// testável.
fn classifica_plan(media: bool, sync: bool, names: &[String]) -> anyhow::Result<DespachoPlan> {
    if names.iter().any(|name| name == "newspeak") {
        return fail(1, "plan resolve pacotes; newspeak é a árvore reservada");
    }
    if media && sync {
        return fail(1, "plan --media e plan --sync são resoluções distintas");
    }
    if media {
        if !names.is_empty() {
            return fail(1, "plan --media lê exclusivamente os worlds do perfil");
        }
        return Ok(DespachoPlan::Media);
    }
    if sync {
        if !names.is_empty() {
            return fail(1, "plan --sync lê exclusivamente o world canônico");
        }
        return Ok(DespachoPlan::Sync);
    }
    if names.is_empty() {
        return fail(1, "plan: diga ao menos um pacote");
    }
    Ok(DespachoPlan::Pacotes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DespachoRectify {
    Arvore,
    Pacotes(install::BinaryPolicy),
}

/// `newspeak` é nome reservado pela SPEC-0011, não uma receita ordinária.
/// Separar a classificação do efeito deixa testável a fronteira que impede a
/// árvore de cair no resolvedor de pacotes (e de acabar acrescentada ao world).
fn classifica_rectify(
    names: &[String],
    no_binary: bool,
    only_binary: bool,
) -> anyhow::Result<DespachoRectify> {
    if names.iter().any(|name| name == "newspeak") {
        if names.len() != 1 {
            return fail(1, "rectify newspeak precisa ser executado sozinho");
        }
        if no_binary || only_binary {
            return fail(
                1,
                "--no-binary/--only-binary não se aplicam a rectify newspeak",
            );
        }
        return Ok(DespachoRectify::Arvore);
    }
    let policy = if no_binary {
        install::BinaryPolicy::SourceOnly
    } else if only_binary {
        install::BinaryPolicy::BinaryOnly
    } else {
        install::BinaryPolicy::PreferBinary
    };
    Ok(DespachoRectify::Pacotes(policy))
}

fn channel_sign_operands(names: &[String]) -> anyhow::Result<(&str, &str, &str)> {
    match names {
        [subcommand, secret, input, expected_public] if subcommand == "sign" => {
            Ok((secret, input, expected_public))
        }
        _ => fail(
            1,
            "channel sign: diga [--passphrase-fd N] <chave-secreta> <arquivo> <chave-pública-esperada>",
        ),
    }
}

/// Estes comandos precedem o resolvedor tipado, mas leem o mesmo estado que
/// os mutadores substituem. O lock fica no despacho para cobrir a operação
/// inteira sem introduzir um lock aninhado nos handlers reutilizáveis.
fn legacy_reader_lock(
    ctx: &Ctx,
    command: Option<&str>,
    names: &[String],
    closure: bool,
) -> anyhow::Result<Option<install::RootLock>> {
    let cache_verify =
        command == Some("cache") && names.first().map(String::as_str) == Some("verify") && !closure;
    if matches!(command, Some("archives" | "newspeak")) || cache_verify {
        Ok(Some(install::acquire_read_lock(ctx)?))
    } else {
        Ok(None)
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            let code = e.downcast_ref::<Fail>().map(|f| f.code).unwrap_or(1);
            eprintln!("minitrue: {e}");
            std::process::exit(code);
        }
    }
}

fn run() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut root = std::env::var("MINITRUE_ROOT").unwrap_or_else(|_| "/".into());
    let mut offline = false;
    #[cfg(feature = "tofu-authoring")]
    let mut tofu = false;
    #[cfg(not(feature = "tofu-authoring"))]
    let tofu = false;
    let mut sync = false;
    let mut no_binary = false;
    let mut only_binary = false;
    let mut release = false;
    let mut closure = false;
    let mut world: Option<PathBuf> = None;
    let mut cache_world: Option<PathBuf> = None;
    let mut media = false;
    let mut output: Option<PathBuf> = None;
    let mut passphrase_fd: Option<i32> = None;
    let mut jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut cmd: Option<String> = None;
    let mut names: Vec<String> = Vec::new();

    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => {
                root = args.next().ok_or_else(|| Fail {
                    code: 1,
                    msg: "--root exige diretório".into(),
                })?
            }
            "--offline" => offline = true,
            #[cfg(feature = "tofu-authoring")]
            "--tofu" => tofu = true,
            // Força a compilação local de KIND=source e proíbe qualquer
            // seleção nos canais binários configurados.
            "--no-binary" => no_binary = true,
            "--only-binary" => only_binary = true,
            "--release" => release = true,
            "--closure" => closure = true,
            "--world" => {
                if world.is_some() {
                    return fail(1, "--world não pode ser repetido");
                }
                world = Some(PathBuf::from(args.next().ok_or_else(|| Fail {
                    code: 1,
                    msg: "--world exige arquivo".into(),
                })?));
            }
            "--cache-world" => {
                if cache_world.is_some() {
                    return fail(1, "--cache-world não pode ser repetido");
                }
                cache_world = Some(PathBuf::from(args.next().ok_or_else(|| Fail {
                    code: 1,
                    msg: "--cache-world exige arquivo".into(),
                })?));
            }
            "--media" => media = true,
            "--sync" => sync = true,
            "--jobs" => {
                jobs = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| Fail {
                        code: 1,
                        msg: "--jobs exige número".into(),
                    })?
            }
            "--output" => {
                output = Some(PathBuf::from(args.next().ok_or_else(|| Fail {
                    code: 1,
                    msg: "--output exige diretório".into(),
                })?));
            }
            "--passphrase-fd" => {
                if passphrase_fd.is_some() {
                    return fail(1, "--passphrase-fd não pode ser repetido");
                }
                passphrase_fd = Some(
                    args.next()
                        .and_then(|value| value.parse::<i32>().ok())
                        .filter(|fd| *fd >= 0)
                        .ok_or_else(|| Fail {
                            code: 1,
                            msg: "--passphrase-fd exige descritor não negativo".into(),
                        })?,
                );
            }
            "-h" | "--help" => {
                imprime_uso();
                return Ok(());
            }
            _ if a.starts_with('-') => {
                return fail(1, format!("opção desconhecida: {a}"));
            }
            _ if cmd.is_none() => cmd = Some(a),
            _ => names.push(a),
        }
    }

    // ROOT ABSOLUTO, e a normalização é AQUI e não em cada uso. Um --root
    // relativo quebrava o caminho de Mundo A com uma mensagem que acusava o
    // lugar errado:
    //
    //     sh: 1: .: cannot open target/…/tmp/minitrue-work-go/recipe
    //
    // O runner de install_pkg faz `current_dir(&work)` e passa RECIPE, PREFIX,
    // WORK e ROOT no ambiente. Com root relativo, esses caminhos também são
    // relativos — e passam a ser interpretados a partir do diretório NOVO, que
    // não é o de onde vieram. Os artefatos escapavam por acidente, porque
    // passam por canonicalize().
    //
    // O Mundo B não sofria, e isso mascarou o defeito: ele monta o ambiente com
    // caminhos já absolutos. Então `rectify` de fonte funcionava com --root
    // relativo e `rectify` de binário não, o que faz o defeito parecer do
    // pacote.
    //
    // Absolutiza sem canonicalize DE PROPÓSITO: canonicalize resolve links
    // simbólicos, e esta árvore tem /lib -> usr/lib e /sbin -> usr/bin. Trocar
    // o root por sua forma resolvida mudaria o significado de todo caminho
    // derivado dele, que é conserto maior que o defeito.
    let root = PathBuf::from(root);
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .map_err(|e| crate::Fail {
                code: 1,
                msg: format!("não consegui ler o diretório corrente para resolver --root: {e}"),
            })?
            .join(root)
    };
    let ctx = Ctx {
        root,
        offline,
        tofu,
        jobs,
    };

    if no_binary && only_binary {
        return fail(1, "--no-binary e --only-binary são mutuamente exclusivos");
    }
    let cache_closure = cmd.as_deref() == Some("cache")
        && names.first().map(String::as_str) == Some("verify")
        && closure;
    if (no_binary || only_binary)
        && !matches!(cmd.as_deref(), Some("rectify" | "plan"))
        && !cache_closure
    {
        return fail(
            1,
            "--no-binary/--only-binary só se aplicam a rectify, plan e cache verify --closure",
        );
    }
    if closure && !cache_closure {
        return fail(1, "--closure só se aplica a cache verify");
    }
    let plan_media = matches!(cmd.as_deref(), Some("plan")) && media;
    if world.is_some() && !cache_closure && !plan_media {
        return fail(
            1,
            "--world só se aplica a cache verify --closure e a plan --media",
        );
    }
    if cache_world.is_some() && !plan_media {
        return fail(1, "--cache-world só se aplica a plan --media");
    }
    if media && !matches!(cmd.as_deref(), Some("plan")) {
        return fail(1, "--media só se aplica a plan");
    }
    if sync && !matches!(cmd.as_deref(), Some("rectify" | "plan")) {
        return fail(1, "--sync só se aplica a rectify ou plan");
    }
    if output.is_some() && !matches!(cmd.as_deref(), Some("channel") | Some("audit")) && !plan_media
    {
        return fail(
            1,
            "--output só se aplica a channel emit, a audit e a plan --media",
        );
    }
    if release
        && !(cmd.as_deref() == Some("channel") && names.first().map(String::as_str) == Some("emit"))
    {
        return fail(1, "--release só se aplica a channel emit");
    }
    if passphrase_fd.is_some()
        && !(cmd.as_deref() == Some("channel") && names.first().map(String::as_str) == Some("sign"))
    {
        return fail(1, "--passphrase-fd só se aplica a channel sign");
    }

    // Leitores legados precisam observar records/newspeak/cache como um
    // snapshot em relação aos mutadores. `cache verify --closure` já toma
    // seu próprio SH no ramo abaixo e, portanto, fica deliberadamente fora.
    let _legacy_reader_lock = legacy_reader_lock(&ctx, cmd.as_deref(), &names, closure)?;

    match cmd.as_deref() {
        Some("rectify") => {
            if sync {
                return fail(1, "rectify --sync chega no Marco 0.2");
            }
            if names.is_empty() {
                return fail(1, "rectify: diga o que retificar");
            }
            match classifica_rectify(&names, no_binary, only_binary)? {
                DespachoRectify::Arvore => arvore::rectify(&ctx),
                DespachoRectify::Pacotes(policy) => install::rectify(&ctx, &names, policy),
            }
        }
        Some("plan") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            let despacho = classifica_plan(media, sync, &names)?;
            let policy = if no_binary {
                install::BinaryPolicy::SourceOnly
            } else if only_binary {
                install::BinaryPolicy::BinaryOnly
            } else {
                install::BinaryPolicy::PreferBinary
            };
            if despacho == DespachoPlan::Media {
                let target = world.as_deref().ok_or_else(|| Fail {
                    code: 1,
                    msg: "plan --media exige --world com o target.world do perfil".into(),
                })?;
                let roots = raizes_de_midia(target, cache_world.as_deref())?;
                // ABI estrita não é opção do chamador: uma mídia resolvida em
                // Development aceitaria ABI pendente e produziria um lock que
                // não descreve o que o alvo vai encontrar.
                let mut resolved = plan::resolve_for(
                    &ctx,
                    &roots,
                    plan::PlanPurpose::Media,
                    policy,
                    plan::AbiPolicy::Strict,
                    channel::LoadMode::ReadOnly,
                )?;
                resolved.authenticate_objects(&ctx, true)?;
                resolved.revalidate_tree(&ctx)?;
                match output.as_deref() {
                    // create_new: um lock de mídia é insumo de composição, e
                    // sobrescrever o anterior em silêncio esconderia que a
                    // resolução mudou entre duas execuções.
                    Some(path) => {
                        let bytes = resolved.canonical_bytes()?;
                        let lock_sha256 = resolved.lock_sha256()?;
                        install::write_new(path, &bytes)?;
                        println!("PLAN_LOCK_SHA256={lock_sha256}");
                        Ok(())
                    }
                    None => resolved.print(),
                }
            } else if despacho == DespachoPlan::Sync {
                let roots = plan::roots_from_system_world(&ctx)?;
                plan::resolve_for(
                    &ctx,
                    &roots,
                    plan::PlanPurpose::Sync,
                    policy,
                    plan::AbiPolicy::Development,
                    channel::LoadMode::ReadOnly,
                )?
                .print()
            } else {
                plan::resolve(
                    &ctx,
                    &names,
                    policy,
                    plan::AbiPolicy::Development,
                    channel::LoadMode::ReadOnly,
                )?
                .print()
            }
        }
        Some("memoryhole") => {
            if names.is_empty() {
                return fail(1, "memoryhole: diga o que nunca existiu");
            }
            install::memoryhole(&ctx, &names)
        }
        Some("archives") => install::archives(&ctx),
        Some("verify") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            install::verify(&ctx)
        }
        // Fechamento de dependências (SPEC-0013 §4): a declaração da receita
        // confrontada com o payload instalado.
        Some("audit") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            audit::audit(&ctx, &names, output.as_deref())
        }
        // SPEC-0013 §5: orientação estática para autoria. O enforcement é a
        // view fechada do próprio build; o lint não finge cobrir ramos gerados
        // por configure/make que não aparecem literalmente na receita.
        Some("lint") => install::lint_build(&ctx, &names),
        Some("newspeak") => match names.first() {
            Some(n) => install::newspeak_show(&ctx, n),
            None => fail(1, "newspeak: diga o pacote"),
        },
        // O fingerprint que ESTA árvore de receitas exige, para que outro
        // programa possa confrontá-lo com o que um canal oferece sem
        // reimplementar a regra. Ver install::fingerprint.
        Some("fingerprint") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            if names.is_empty() {
                return fail(1, "fingerprint: diga ao menos um pacote");
            }
            install::fingerprint(&ctx, &names)
        }
        Some("explain") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            match names.first() {
                Some(t) => install::explain(&ctx, t),
                None => fail(1, "explain: diga o caminho ou o comando"),
            }
        }
        Some("why") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            match names.first() {
                Some(n) => install::why(&ctx, n),
                None => fail(1, "why: diga o pacote"),
            }
        }
        // Attestation e corroboração (SPEC-0009 §6/§8) — o Miniluv com lei escrita.
        Some("attest") => match names.first().map(String::as_str) {
            Some("keygen") => match (names.get(1), names.get(2)) {
                (Some(name), Some(path)) => attest::keygen(name, std::path::Path::new(path)),
                _ => fail(1, "attest keygen <nome> <arquivo-da-chave>"),
            },
            Some(pkg) => match (names.get(1), names.get(2)) {
                (Some(builder), Some(key)) => {
                    let _lock = install::acquire_read_lock(&ctx)?;
                    attest::attest(&ctx, pkg, builder, std::path::Path::new(key))
                }
                _ => fail(1, "attest <pacote> <builder> <arquivo-da-chave>"),
            },
            None => fail(
                1,
                "attest: 'keygen <nome> <arq>' ou '<pacote> <builder> <arq>'",
            ),
        },
        Some("corroborate") => {
            let _lock = install::acquire_read_lock(&ctx)?;
            match names.first() {
                Some(p) => attest::corroborate(&ctx, p),
                None => fail(1, "corroborate: diga o pacote"),
            }
        }
        Some("cache") => match names.first().map(String::as_str) {
            Some("verify") if closure => {
                let _lock = install::acquire_read_lock(&ctx)?;
                let mut roots: Vec<plan::PlanRoot> = names[1..]
                    .iter()
                    .map(|name| plan::PlanRoot {
                        name: name.clone(),
                        role: plan::RootRole::Availability,
                    })
                    .collect();
                if let Some(path) = world.as_deref() {
                    roots.extend(plan::roots_from_world(path, plan::RootRole::Availability)?);
                } else if roots.is_empty() {
                    return fail(1, "cache verify --closure: diga pacotes ou --world ARQUIVO");
                }
                let policy = if no_binary {
                    install::BinaryPolicy::SourceOnly
                } else if only_binary {
                    install::BinaryPolicy::BinaryOnly
                } else {
                    install::BinaryPolicy::PreferBinary
                };
                let offline = Ctx {
                    root: ctx.root.clone(),
                    offline: true,
                    tofu: false,
                    jobs: ctx.jobs,
                };
                let mut resolved = plan::resolve_for(
                    &offline,
                    &roots,
                    plan::PlanPurpose::CacheClosure,
                    policy,
                    plan::AbiPolicy::Development,
                    channel::LoadMode::ReadOnly,
                )?;
                resolved.authenticate_objects(&offline, true)?;
                resolved.revalidate_tree(&offline)?;
                println!(
                    "cache closure íntegra: PLAN_LOCK_SHA256={}",
                    resolved.lock_sha256()?
                );
                Ok(())
            }
            Some("verify") if names.len() >= 2 => install::cache_verify(&ctx, &names[1..]),
            Some("verify") => fail(1, "cache verify: diga ao menos um pacote"),
            Some(other) => fail(1, format!("cache: subcomando desconhecido {other}")),
            None => fail(1, "cache: diga o subcomando (verify)"),
        },
        Some("channel") => match names.first().map(String::as_str) {
            Some("refresh") if output.is_some() => fail(1, "channel refresh não aceita --output"),
            Some("refresh") => channel::refresh(&ctx, &names[1..]),
            Some("emit") if names.len() >= 2 => {
                let output = output.ok_or_else(|| Fail {
                    code: 1,
                    msg: "channel emit exige --output DIR".into(),
                })?;
                install::channel_emit(&ctx, &output, &names[1..], release)
            }
            Some("emit") => fail(1, "channel emit: diga ao menos um pacote"),
            // Assinar é do produtor, e o produtor é esta árvore. Antes disto o
            // índice saía sem assinatura e o mantenedor tinha de chamar o
            // `minisign` do hospedeiro — uma dependência de host bem no ponto
            // mais sensível, o da raiz de confiança do canal.
            Some("keygen") if names.len() == 2 => {
                let base = PathBuf::from(&names[1]);
                sign::keygen(
                    &names[1],
                    &base.with_extension("key"),
                    &base.with_extension("pub"),
                )
            }
            Some("keygen") => fail(1, "channel keygen: diga o caminho-base da chave"),
            Some("sign") => {
                let (secret, input, expected_public) = channel_sign_operands(&names)?;
                let passphrase = passphrase_fd.map(sign::read_passphrase_fd).transpose()?;
                sign::sign_file(
                    Path::new(secret),
                    Path::new(input),
                    &PathBuf::from(format!("{input}.minisig")),
                    None,
                    None,
                    Some(expected_public),
                    passphrase.as_ref().map(sign::Passphrase::as_bytes),
                )
            }
            Some(other) => fail(1, format!("channel: subcomando desconhecido {other}")),
            None => fail(
                1,
                "channel: diga o subcomando (refresh, emit, keygen, sign)",
            ),
        },
        Some("pack") => {
            let dir = match names.first() {
                Some(d) => PathBuf::from(d),
                None => return fail(1, "pack: diga o diretório"),
            };
            if !dir.is_dir() {
                return fail(1, format!("pack: {} não é um diretório", dir.display()));
            }
            let epoch = pack::epoch_from_env();
            let sha = match names.get(1) {
                Some(out) => {
                    let f = std::fs::File::create(out).map_err(|e| Fail {
                        code: 1,
                        msg: format!("pack: não gravou {out}: {e}"),
                    })?;
                    pack::pack_deterministic(&dir, epoch, std::io::BufWriter::new(f))?
                }
                None => pack::pack_deterministic(&dir, epoch, std::io::sink())?,
            };
            println!("{sha}  {}", dir.display());
            Ok(())
        }
        Some(c @ ("rollback" | "unperson")) => {
            fail(1, format!("{c} chega no Marco 0.2 (SPEC-0003)"))
        }
        _ => {
            imprime_uso();
            fail(1, "comando ausente ou desconhecido")
        }
    }
}

/// Data/hora UTC em ISO-8601, sem dependências (algoritmo civil de Hinnant).
pub fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static LOCK_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn midia_instala_o_target_world_e_apenas_disponibiliza_o_cache_world() {
        let serial = LOCK_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mt-main-raizes-midia-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.world");
        let cache = dir.join("cache.world");
        std::fs::write(&target, "base\nfirefox\n").unwrap();
        std::fs::write(&cache, "zig\n").unwrap();

        let roots = raizes_de_midia(&target, Some(&cache)).unwrap();
        let papeis: Vec<(&str, plan::RootRole)> = roots
            .iter()
            .map(|root| (root.name.as_str(), root.role))
            .collect();
        assert_eq!(
            papeis,
            vec![
                ("base", plan::RootRole::Install),
                ("firefox", plan::RootRole::Install),
                ("zig", plan::RootRole::Availability),
            ]
        );

        // Sem cache.world a mídia continua resolvendo — o cache offline é
        // override de composição, não parte obrigatória da identidade.
        let so_target = raizes_de_midia(&target, None).unwrap();
        assert_eq!(so_target.len(), 2);
        assert!(so_target
            .iter()
            .all(|root| root.role == plan::RootRole::Install));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_tem_tres_resolucoes_e_elas_nao_se_misturam() {
        assert_eq!(
            classifica_plan(true, false, &[]).unwrap(),
            DespachoPlan::Media
        );
        assert_eq!(
            classifica_plan(false, true, &[]).unwrap(),
            DespachoPlan::Sync
        );
        assert_eq!(
            classifica_plan(false, false, &["base".into()]).unwrap(),
            DespachoPlan::Pacotes
        );
        // Cada uma lê uma fonte de raiz diferente; pedir duas ao mesmo tempo
        // não tem resposta certa, só uma escolha silenciosa.
        assert!(classifica_plan(true, true, &[]).is_err());
    }

    #[test]
    fn plan_recusa_raiz_que_a_resolucao_escolhida_nao_leria() {
        // Nomes na linha de comando seriam ignorados por --media e por --sync:
        // aceitá-los faria o chamador crer que pediu uma mídia daqueles
        // pacotes.
        assert!(classifica_plan(true, false, &["base".into()]).is_err());
        assert!(classifica_plan(false, true, &["base".into()]).is_err());
        assert!(classifica_plan(false, false, &[]).is_err());
        // `newspeak` é a árvore reservada da SPEC-0011, não uma receita.
        assert!(classifica_plan(false, false, &["newspeak".into()]).is_err());
        assert!(classifica_plan(true, false, &["newspeak".into()]).is_err());
    }

    #[test]
    fn rectify_newspeak_tem_despacho_proprio() {
        assert_eq!(
            classifica_rectify(&["newspeak".into()], false, false).unwrap(),
            DespachoRectify::Arvore
        );
    }

    #[test]
    fn rectify_newspeak_nao_se_mistura_com_pacote_ou_politica_binaria() {
        assert!(classifica_rectify(&["newspeak".into(), "base".into()], false, false).is_err());
        assert!(classifica_rectify(&["newspeak".into()], true, false).is_err());
        assert!(classifica_rectify(&["newspeak".into()], false, true).is_err());
    }

    #[test]
    fn rectify_ordinario_preserva_politica_binaria() {
        let nomes = ["base".into()];
        assert_eq!(
            classifica_rectify(&nomes, false, false).unwrap(),
            DespachoRectify::Pacotes(install::BinaryPolicy::PreferBinary)
        );
        assert_eq!(
            classifica_rectify(&nomes, true, false).unwrap(),
            DespachoRectify::Pacotes(install::BinaryPolicy::SourceOnly)
        );
        assert_eq!(
            classifica_rectify(&nomes, false, true).unwrap(),
            DespachoRectify::Pacotes(install::BinaryPolicy::BinaryOnly)
        );
    }

    #[test]
    fn channel_sign_exige_chave_publica_esperada() {
        assert!(channel_sign_operands(&["sign".into(), "secret".into(), "input".into()]).is_err());
        assert!(channel_sign_operands(&[
            "sign".into(),
            "secret".into(),
            "input".into(),
            "expected.pub".into(),
        ])
        .is_ok());
        assert!(channel_sign_operands(&[
            "sign".into(),
            "secret".into(),
            "input".into(),
            "expected.pub".into(),
            "extra".into(),
        ])
        .is_err());
    }

    #[test]
    fn leitores_legados_tomam_sh_sem_incluir_mutadores() {
        let serial = LOCK_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "mt-main-reader-lock-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = Ctx {
            root: root.clone(),
            offline: true,
            tofu: false,
            jobs: 1,
        };

        let exclusive = install::acquire_lock(&ctx).expect("lock exclusivo de mutador");
        for (command, names, closure) in [
            ("archives", Vec::new(), false),
            ("newspeak", vec!["pkg".to_string()], false),
            (
                "cache",
                vec!["verify".to_string(), "pkg".to_string()],
                false,
            ),
        ] {
            assert!(
                legacy_reader_lock(&ctx, Some(command), &names, closure).is_err(),
                "{command} passou pelo lock exclusivo"
            );
        }

        // Mutadores e o leitor tipado que já possui SH próprio não podem
        // tentar adquirir este lock adicional enquanto seguram EX/SH.
        assert!(
            legacy_reader_lock(&ctx, Some("rectify"), &["newspeak".into()], false)
                .unwrap()
                .is_none()
        );
        assert!(
            legacy_reader_lock(&ctx, Some("cache"), &["verify".into(), "pkg".into()], true,)
                .unwrap()
                .is_none()
        );
        assert!(
            legacy_reader_lock(&ctx, Some("channel"), &["refresh".into()], false)
                .unwrap()
                .is_none()
        );
        drop(exclusive);

        // SH é compatível com SH: os três guardas podem coexistir pelo
        // tempo integral dos handlers.
        let archives = legacy_reader_lock(&ctx, Some("archives"), &[], false)
            .unwrap()
            .expect("SH de archives");
        let newspeak = legacy_reader_lock(&ctx, Some("newspeak"), &["pkg".into()], false)
            .unwrap()
            .expect("SH de newspeak");
        let cache =
            legacy_reader_lock(&ctx, Some("cache"), &["verify".into(), "pkg".into()], false)
                .unwrap()
                .expect("SH de cache verify");
        drop((cache, newspeak, archives));

        let _ = std::fs::remove_dir_all(root);
    }
}
