mod attest;
mod channel;
mod fetch;
mod install;
mod pack;
mod recipe;

use std::path::PathBuf;

pub struct Ctx {
    pub root: PathBuf,
    pub offline: bool,
    pub tofu: bool,
    pub jobs: usize,
}

impl Ctx {
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

const USO: &str = "\
minitrue — o Ministério da Verdade (v0.1: mundos A e B)

uso: minitrue [--root DIR] [--offline] [--tofu] [--no-binary|--only-binary] [--jobs N] <comando> [args]

  rectify   <pacote>…   instala/atualiza; acrescenta ao world
  memoryhole <pacote>…  remove do sistema e do world
  archives              lista os registros
  verify                confere registros e varre /usr por links órfãos
  newspeak  <pacote>    imprime a receita efetiva e sua origem
  explain   <caminho>   de quem é o arquivo e toda a sua proveniência
  why       <pacote>    por que este pacote está no sistema
  pack <dir> [saída]    tara <dir> determinístico; imprime o sha256 (SPEC-0010)
  attest keygen <nome> <chave>  cria identidade ed25519 de builder
  attest <pacote> <builder> <chave>  emite attestation assinada
  corroborate <pacote>  coteja attestations confiáveis com o registro local
  cache verify <pacote>…
                        confere artefatos/assinaturas já presentes, sem rede ou instalação
  channel emit --output DIR <pacote>...
                        emite tar.zst + índice v2 a partir de registros B íntegros

chegam no Marco 0.2: rectify --sync, rollback, unperson, lint, SIGSUMS e
OpenPGP.";

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
    let mut tofu = false;
    let mut sync = false;
    let mut no_binary = false;
    let mut only_binary = false;
    let mut output: Option<PathBuf> = None;
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
            "--tofu" => tofu = true,
            // Força a compilação local de KIND=source e proíbe qualquer
            // seleção nos canais binários configurados.
            "--no-binary" => no_binary = true,
            "--only-binary" => only_binary = true,
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
            "-h" | "--help" => {
                println!("{USO}");
                return Ok(());
            }
            _ if cmd.is_none() => cmd = Some(a),
            _ => names.push(a),
        }
    }

    let ctx = Ctx {
        root: PathBuf::from(root),
        offline,
        tofu,
        jobs,
    };

    if no_binary && only_binary {
        return fail(1, "--no-binary e --only-binary são mutuamente exclusivos");
    }
    if (no_binary || only_binary) && cmd.as_deref() != Some("rectify") {
        return fail(1, "--no-binary/--only-binary só se aplicam a rectify");
    }
    if output.is_some() && cmd.as_deref() != Some("channel") {
        return fail(1, "--output só se aplica a channel emit");
    }

    match cmd.as_deref() {
        Some("rectify") => {
            if sync {
                return fail(1, "rectify --sync chega no Marco 0.2");
            }
            if names.is_empty() {
                return fail(1, "rectify: diga o que retificar");
            }
            let policy = if no_binary {
                install::BinaryPolicy::SourceOnly
            } else if only_binary {
                install::BinaryPolicy::BinaryOnly
            } else {
                install::BinaryPolicy::PreferBinary
            };
            install::rectify(&ctx, &names, policy)
        }
        Some("memoryhole") => {
            if names.is_empty() {
                return fail(1, "memoryhole: diga o que nunca existiu");
            }
            install::memoryhole(&ctx, &names)
        }
        Some("archives") => install::archives(&ctx),
        Some("verify") => install::verify(&ctx),
        Some("newspeak") => match names.first() {
            Some(n) => install::newspeak_show(&ctx, n),
            None => fail(1, "newspeak: diga o pacote"),
        },
        Some("explain") => match names.first() {
            Some(t) => install::explain(&ctx, t),
            None => fail(1, "explain: diga o caminho ou o comando"),
        },
        Some("why") => match names.first() {
            Some(n) => install::why(&ctx, n),
            None => fail(1, "why: diga o pacote"),
        },
        // Attestation e corroboração (SPEC-0009 §6/§8) — o Miniluv com lei escrita.
        Some("attest") => match names.first().map(String::as_str) {
            Some("keygen") => match (names.get(1), names.get(2)) {
                (Some(name), Some(path)) => attest::keygen(name, std::path::Path::new(path)),
                _ => fail(1, "attest keygen <nome> <arquivo-da-chave>"),
            },
            Some(pkg) => match (names.get(1), names.get(2)) {
                (Some(builder), Some(key)) => {
                    attest::attest(&ctx, pkg, builder, std::path::Path::new(key))
                }
                _ => fail(1, "attest <pacote> <builder> <arquivo-da-chave>"),
            },
            None => fail(
                1,
                "attest: 'keygen <nome> <arq>' ou '<pacote> <builder> <arq>'",
            ),
        },
        Some("corroborate") => match names.first() {
            Some(p) => attest::corroborate(&ctx, p),
            None => fail(1, "corroborate: diga o pacote"),
        },
        Some("cache") => match names.first().map(String::as_str) {
            Some("verify") if names.len() >= 2 => install::cache_verify(&ctx, &names[1..]),
            Some("verify") => fail(1, "cache verify: diga ao menos um pacote"),
            Some(other) => fail(1, format!("cache: subcomando desconhecido {other}")),
            None => fail(1, "cache: diga o subcomando (verify)"),
        },
        Some("channel") => match names.first().map(String::as_str) {
            Some("emit") if names.len() >= 2 => {
                let output = output.ok_or_else(|| Fail {
                    code: 1,
                    msg: "channel emit exige --output DIR".into(),
                })?;
                install::channel_emit(&ctx, &output, &names[1..])
            }
            Some("emit") => fail(1, "channel emit: diga ao menos um pacote"),
            Some(other) => fail(1, format!("channel: subcomando desconhecido {other}")),
            None => fail(1, "channel: diga o subcomando (emit)"),
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
        Some(c @ ("rollback" | "unperson" | "lint")) => {
            fail(1, format!("{c} chega no Marco 0.2 (SPEC-0003)"))
        }
        _ => {
            println!("{USO}");
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
