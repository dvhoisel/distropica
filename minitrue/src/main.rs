mod fetch;
mod install;
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
                    if p.is_absolute() { p } else { self.root.join(p) }
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
    Err(Fail { code, msg: msg.into() }.into())
}

const USO: &str = "\
minitrue — o Ministério da Verdade (v0.1, Marco 0.1: mundo A)

uso: minitrue [--root DIR] [--offline] [--tofu] [--jobs N] <comando> [args]

  rectify   <pacote>…   instala/atualiza; acrescenta ao world
  memoryhole <pacote>…  remove do sistema e do world
  archives              lista os registros
  verify                confere registros e varre /usr por links órfãos
  newspeak  <pacote>    imprime a receita efetiva e sua origem

chegam no Marco 0.2: rectify --sync, rollback, unperson, lint, mundo B
(fonte), SIGSUMS e OpenPGP.";

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
    let mut jobs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let mut cmd: Option<String> = None;
    let mut names: Vec<String> = Vec::new();

    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => root = args.next().ok_or_else(|| Fail { code: 1, msg: "--root exige diretório".into() })?,
            "--offline" => offline = true,
            "--tofu" => tofu = true,
            "--sync" => sync = true,
            "--jobs" => {
                jobs = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| Fail { code: 1, msg: "--jobs exige número".into() })?
            }
            "-h" | "--help" => {
                println!("{USO}");
                return Ok(());
            }
            _ if cmd.is_none() => cmd = Some(a),
            _ => names.push(a),
        }
    }

    let ctx = Ctx { root: PathBuf::from(root), offline, tofu, jobs };

    match cmd.as_deref() {
        Some("rectify") => {
            if sync {
                return fail(1, "rectify --sync chega no Marco 0.2");
            }
            if names.is_empty() {
                return fail(1, "rectify: diga o que retificar");
            }
            install::rectify(&ctx, &names)
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
