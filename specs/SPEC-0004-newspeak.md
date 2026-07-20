# SPEC-0004 — newspeak, o formato das receitas

**Status:** rascunho v0.4 · 2026-07-19
**Depende de:** SPEC-0001 (elegibilidade), SPEC-0003 (contrato de execução).

Newspeak é o vocabulário mínimo: uma receita diz **de onde vem, como se
confere e onde se encaixa** — e nada mais. Toda expressividade extra foi
removida do idioma.

## 1. Forma

Uma receita é um diretório `newspeak/<nome>/` contendo um arquivo `recipe`:
shell POSIX puro, avaliável por `busybox sh`. Opcionalmente `files/` com
patches e auxiliares (copiados para `$WORK` antes do build).

Sem YAML, sem TOML, sem DSL nova: a receita é executável e legível pelo
interpretador que já existe no Estágio 0.

Árvores múltiplas: `NEWSPEAK_PATH` (SPEC-0003 §2) lista árvores em ordem
de precedência — a primeira ocorrência de `<árvore>/<nome>/recipe` vence.
É o mecanismo para receitas locais e privadas sem tocar na árvore oficial
(herança do `KISS_PATH` do KISS Linux e das ports collections do CRUX). A
confiança não muda de natureza: hash e assinatura são pinados **na
receita**, venha ela de onde vier — adicionar uma árvore ao path é
responsabilidade explícita de quem a adicionou.

## 2. Campos

Obrigatórios:

| Campo | Significado |
|-------|-------------|
| `NAME` | nome do pacote (= nome do diretório) |
| `VERSION` | versão upstream, literal |
| `KIND` | `binary` (mundo A), `source` (mundo B) ou `meta` (meta-receita: só agrega `DEPS`, sem `SRC`/`build` — ex.: `base`, SPEC-0008 §3) |
| `SRC` | URL(s) do(s) artefato(s), separadas por espaço; HTTPS (não se aplica a `KIND=meta`) |
| `SHA256` | hash(es) na mesma ordem de `SRC` (não se aplica a `KIND=meta`) |

Opcionais:

| Campo | Significado |
|-------|-------------|
| `DEPS` | dependências de runtime (nomes de receitas) |
| `BUILD_DEPS` | dependências só de build (mundo B) |
| `LINKS` | mundo A: comandos a expor, `nome=caminho/relativo/no/prefix`; default: todo executável em `bin/` do prefix |
| `REQUIRES_GLIBC` | `1` ⇒ só instala após o Estágio 2 (SPEC-0005) |
| `ABOUT` | uma linha: o que é / justificativa de classificação |
| `LICENSE` | identificador SPDX |
| `SIG` | URL(s) de assinatura destacada, uma por artefato, na ordem de `SRC` (§5) |
| `SIGSUMS` | alternativa a `SIG`: URL única de lista de checksums assinada que cobre os artefatos (§5) |
| `SIGKEY` | chave pública pinada: uma linha base64 (minisign/signify) ou caminho `files/*.asc` (OpenPGP) |
| `SIGKEY_FP` | OpenPGP: fingerprint da chave — este é o pino de fato; o `.asc` é só transporte |
| `EPOCH` | `SOURCE_DATE_EPOCH` da receita (unix ts); sobrepõe o default do projeto p/ builds reprodutíveis (§3, SPEC-0010) |
| `REPROCORR` | mundo B: sha256 do **tar normalizado** reprodutível (saída de `minitrue pack`); raiz de confiança única da corroboração de canal (SPEC-0009 §6, SPEC-0010 §4) |
| `PROVISIONAL` | `1` ⇒ pacote-semente que cede o caminho a um homônimo real sem *doublethink* (ex.: busybox → coreutils/binutils; SPEC-0003 §3) |

Funções:

- `KIND=binary` DEVE definir `install_pkg()` — popula `$PREFIX`.
- `KIND=source` DEVE definir `build()` — compila e instala em `$STAGE`.
- `KIND=meta` NÃO define função nem `SRC`/`SHA256`: é só um nó de `DEPS`
  (ex.: `base`) que agrega um conjunto; instalar o meta = instalar as suas
  `DEPS`. Resolve o "conjunto mínimo" do instalador sem lógica no minipax.

## 3. Contrato de execução

O minitrue executa a função da receita via `sh -e`, com:

| Variável | Conteúdo |
|----------|----------|
| `DL`, `DL_2`, … | caminho no cache de cada artefato de `SRC`, já verificado |
| `WORK` | diretório de trabalho temporário (cwd inicial) |
| `PREFIX` | mundo A: staging de `/opt/<nome>/<versão>` |
| `STAGE` | mundo B: DESTDIR de staging |
| `JOBS` | paralelismo |
| `CC`, `CXX`, `AR`, `RANLIB` | toolchain corrente. Pré-E2: `zig cc -target x86_64-linux-musl` etc. — o `-target` explícito é obrigatório (spike 2026-07-19: sem ele o zig mira o host, glibc). Pós-E2: gcc |
| `ROOT` | raiz alvo (para casos raros e legítimos de leitura) |
| `SOURCE_DATE_EPOCH` | timestamp fixo p/ builds reprodutíveis (SPEC-0010); do campo `EPOCH` da receita ou o default do projeto |
| `LC_ALL`/`LANG`/`TZ` | `C`/`C`/`UTC` — impostos p/ determinismo (SPEC-0010) |

O ambiente é **determinístico** (SPEC-0010): além do acima, `umask 022` e
caminho de build canônico. A receita herda tudo; só precisa evitar
não-determinismo próprio (gravar a data corrente etc.). Campo opcional
`EPOCH=<unix ts>` sobrepõe o default.

Proibições (contrato; sandbox é dívida registrada em SPEC-0003 §8):

1. NÃO acessar rede — todo insumo entra por `SRC`.
2. NÃO escrever fora de `WORK`, `PREFIX`, `STAGE`.
3. NÃO executar maintainer scripts de pacotes embalados (`.deb`/`.rpm`).
4. NÃO usar `sudo`, `su`, nem tocar em serviços.

Convenções pré-E2, verificadas no spike (SPEC-0005 §8): o ambiente de
build oferece `/bin/ld` como shim para `zig ld.lld` (macros de configure
exigem um `ld` no PATH), e receitas autotools DEVERIAM passar
`--disable-nls --disable-dependency-tracking` (sem gettext no mundo musl
inicial; rastreio de dependências pressupõe um make que ainda não existe).

Nota sobre `/etc`: a receita instala defaults em `$STAGE/etc` normalmente;
é o minitrue que desvia esse conteúdo para `/usr/share/factory/etc/` e
aplica a política de `/etc`-do-administrador (SPEC-0002 §6, SPEC-0003 §3).
Receita não gerencia `/etc` — nunca.

## 4. Exemplos normativos (dados reais, verificados em 2026-07-18)

### 4.1 Mundo A — tarball simples (Zig; hash do índice oficial ziglang.org)

```sh
NAME=zig
VERSION=0.16.0
KIND=binary
ABOUT="toolchain Zig; fornece zig cc, o compilador C do mundo-fonte pré-E2"
SRC="https://ziglang.org/download/$VERSION/zig-x86_64-linux-$VERSION.tar.xz"
SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
SIG="$SRC.minisig"
SIGKEY="RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
LINKS="zig=zig"

install_pkg() {
    tar -xJf "$DL" --strip-components=1 -C "$PREFIX"
}
```

### 4.2 Mundo A — binário estático musl (ripgrep, GitHub Releases oficial)

```sh
NAME=ripgrep
VERSION=15.2.0
KIND=binary
ABOUT="grep moderno; upstream publica musl estático — roda desde o E0"
SRC="https://github.com/BurntSushi/ripgrep/releases/download/$VERSION/ripgrep-$VERSION-x86_64-unknown-linux-musl.tar.gz"
SHA256=@PINAR@
LINKS="rg=rg"

install_pkg() {
    tar -xzf "$DL" --strip-components=1 -C "$PREFIX"
}
```

### 4.3 Mundo B — fonte com bootstrap sem make (GNU make)

```sh
NAME=make
VERSION=4.4.1
KIND=source
ABOUT="GNU não publica binário; primeiro build do mundo-fonte. build.sh existe exatamente para compilar make sem make"
SRC="https://ftp.gnu.org/gnu/make/make-$VERSION.tar.gz"
SHA256=@PINAR@
SIG="$SRC.sig"
SIGKEY="files/gnu-make.asc"
SIGKEY_FP=@PINAR@

build() {
    tar -xzf "$DL" --strip-components=1
    ./configure --prefix=/usr --disable-nls --disable-dependency-tracking
    ./build.sh
    ./make -j"$JOBS"
    ./make install DESTDIR="$STAGE"
}
```

### 4.4 Mundo A — `.deb` do vendor como embalagem (Google Chrome)

```sh
NAME=google-chrome
VERSION=stable
KIND=binary
REQUIRES_GLIBC=1
ABOUT=".deb oficial do vendor tratado como envelope: extrai, nunca executa scripts"
SRC="https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
SHA256=@PINAR@   # vendor não versiona a URL; pinar congela a versão corrente
LINKS="google-chrome=opt-interno/google/chrome/google-chrome"

install_pkg() {
    ar x "$DL"                       # → data.tar.xz (+ scripts, ignorados)
    mkdir -p "$PREFIX/opt-interno"
    tar -xJf data.tar.xz -C "$WORK/extraido"
    cp -a "$WORK/extraido/opt/." "$PREFIX/opt-interno/"
    cp -a "$WORK/extraido/usr/share" "$PREFIX/share"
}
```

### 4.5 Mundo A — dependente de glibc e de stack gráfico (Firefox)

```sh
NAME=firefox
VERSION=146.0
KIND=binary
REQUIRES_GLIBC=1
DEPS="gtk3"        # mundo B; a Longa Marcha do Estágio 4b (SPEC-0005)
ABOUT="tarball oficial Mozilla; dinâmico contra glibc + GTK"
SRC="https://download.mozilla.org/…linux-x86_64…$VERSION….tar.xz"
SHA256=@PINAR@
LINKS="firefox=firefox/firefox"

install_pkg() {
    tar -xJf "$DL" -C "$PREFIX"
}
```

`@PINAR@` marca hash a pinar no momento de criar a receita de verdade (o
minitrue recusa receita sem hash, salvo `--tofu`; SPEC-0003 §2).

## 5. Assinaturas upstream

Quando o mantenedor assina o que publica, a receita pina a assinatura junto
com o hash. Papéis distintos: o **SHA-256 congela o artefato exato** que o
autor da receita viu; a **assinatura prova a autoria upstream** — inclusive
do artefato *novo* no momento de atualizar a versão. É a repinagem que a
assinatura protege: com `--tofu` o hash é recalculado, mas a chave pinada
continua exigindo que o artefato venha de quem sempre veio.

1. `SHA256` é obrigatório **sempre**; assinatura complementa, não
   substitui (o cache é verificável offline e sem esquema criptográfico
   variável).
2. Upstream assina ⇒ a receita DEVERIA pinar. Pacotes da base (estágios
   0–3, SPEC-0005) DEVEM pinar quando a assinatura existir.
3. A chave pública vive **na árvore newspeak**, versionada e revisável em
   diff. Buscar chave em keyserver ou URL em tempo de instalação é
   proibido (SPEC-0001 P6).
4. Esquemas do v0: **minisign** e **signify** (Ed25519; chave é uma linha
   base64 em `SIGKEY`) e **OpenPGP destacado** (`.sig`/`.asc`; bloco de
   chave em `files/*.asc`, com `SIGKEY_FP` obrigatório como pino real).
   O esquema é detectado pelo formato de `SIGKEY`.
5. `SIG` cobre assinatura por artefato; `SIGSUMS` cobre o padrão
   "lista de checksums assinada" (ex.: `SHASUMS256.txt.asc` do Node.js) —
   nesse modo o artefato DEVE constar na lista **e** bater com o `SHA256`
   pinado. Uma receita usa um esquema ou o outro, não ambos.
6. Falha de assinatura ⇒ erro 7 (SPEC-0003 §9), sem contorno.
7. Rotação de chave do upstream é evento auditável: o commit que troca
   `SIGKEY`/`SIGKEY_FP` DEVE justificar no corpo (link do anúncio).

Cobertura real: **todo o ftp.gnu.org publica `.sig`** (o mundo B da base
inteiro é verificável por OpenPGP); Zig publica `.minisig` (chave acima,
copiada da página oficial em 2026-07-18); Node assina `SHASUMS256.txt`.

## 6. Convenções da árvore

- Um pacote por diretório; `NAME` = nome do diretório; erro caso divirjam.
- Atualização = mudar `VERSION` e `SHA256` no mesmo commit; título de
  commit: `<nome>: <versão>`.
- A árvore newspeak num dado commit é o conjunto consistente do sistema —
  não existem ranges de versão (SPEC-0001 P1).
- Comentários na receita são bem-vindos quando registram uma decisão de
  classificação (por que este binário é elegível, por que este build é
  estranho).
- A árvore DEVE passar `minitrue lint` antes de publicar (local e no CI
  do repositório). O lint confere: `NAME` = nome do diretório; campos
  obrigatórios presentes e bem-formados; `SRC` só https; um `SHA256` de
  64 hex por artefato de `SRC`; `SIGKEY_FP` presente quando `SIGKEY` é
  bloco OpenPGP; `LINKS` só com caminhos relativos; a função exigida pelo
  `KIND` definida (`install_pkg`/`build`). Receita reprovada não entra na
  árvore oficial.

## 7. Questões em aberto

- Hash da árvore `files/` (patches) dentro do registro do pacote, para
  `verify` cobrir insumos locais.
- Receitas com variantes por arquitetura (`SRC_x86_64` / `SRC_aarch64` ou
  interpolação de `$ARCH`): decidir quando aarch64 entrar.
- Versões "rolantes" de vendor sem URL versionada (caso Chrome §4.4):
  formalizar procedimento de repinagem.
