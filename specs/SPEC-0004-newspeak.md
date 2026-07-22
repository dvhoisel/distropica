# SPEC-0004 — newspeak, o formato das receitas

**Status:** rascunho v0.6 · 2026-07-22
**Depende de:** SPEC-0001 (elegibilidade), SPEC-0003 (contrato de execução).

Newspeak é o vocabulário mínimo: uma receita diz **de onde vem, como se
confere e onde se encaixa** — e nada mais. Toda expressividade extra foi
removida do idioma.

## 1. Forma

Uma receita é um diretório `newspeak/<nome>/` contendo um arquivo `recipe`:
shell POSIX puro, avaliável por `busybox sh`. Opcionalmente `files/` com
patches e auxiliares (copiados para `$WORK` antes do build).
O nome `files/recipe` é reservado: o executor usa `$WORK/recipe` para o
snapshot exato da receita e recusa arquivo, symlink ou hardlink com esse nome.
O protótipo também recusa qualquer symlink dentro de `files/`: o build não pode
seguir um alvo mutável que ficou fora do fingerprint autocontido.

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

Obrigatórios em toda receita:

| Campo | Significado |
|-------|-------------|
| `NAME` | nome do pacote (= nome do diretório) |
| `VERSION` | versão upstream, literal e componente canônico (`[A-Za-z0-9][A-Za-z0-9._+~-]*`, sem `..`) |
| `KIND` | `binary` (mundo A), `source` (mundo B) ou `meta` (mundo M: meta-receita que só agrega `DEPS`, sem payload — ex.: `miniplenty-buildbase`) |

Condicionais:

| Campo | Significado |
|-------|-------------|
| `SRC` | URL(s) HTTPS dos artefatos, separadas por espaço. Obrigatório em `KIND=binary` e nas receitas `source` respaldadas por artefato upstream; omitido em receitas `source` de montagem e em `KIND=meta` |
| `SHA256` | um hash por item de `SRC`, na mesma ordem. É obrigatório quando `SRC` existe no contrato pinado; `SRC` e `SHA256` são ambos omitidos numa receita de montagem e proibidos em `KIND=meta` |

Uma receita `source` sem `SRC` é uma receita de **montagem**: seu `build()`
gera o payload apenas de conteúdo versionado com a própria receita. Ela não
pode declarar `SHA256` nem `SIG` sem um artefato a que esses campos se refiram.
O modo explícito `--tofu` continua sendo apenas o fluxo excepcional para obter
e revisar um hash ainda não pinado; não torna `SHA256` opcional na árvore
publicada.

Opcionais:

| Campo | Significado |
|-------|-------------|
| `DEPS` | dependências de runtime (nomes canônicos de receitas) |
| `BUILD_DEPS` | dependências só de build (mundo B; nomes canônicos) |
| `LINKS` | mundo A: comandos a expor, `nome=caminho/relativo/no/prefix`, sem `/`, `.` ou `..` nos componentes; default: todo executável em `bin/` do prefix |
| `REQUIRES_GLIBC` | `1` ⇒ só instala após o Estágio 2 (SPEC-0005) |
| `ABOUT` | uma linha: o que é / justificativa de classificação |
| `LICENSE` | expressão SPDX do **payload instalado**, ou `NOASSERTION` quando um bundle de terceiros ainda aguarda inventário conclusivo. Não relicencia o arquivo `recipe`: a implementação autoral da receita segue a licença do repositório, enquanto o software de terceiros conserva a licença upstream. `NOASSERTION` é conservador, não dispensa preservar avisos nem o SBOM antes da publicação |
| `SIG` | URL(s) de assinatura destacada, uma por artefato, na ordem de `SRC` (§5) |
| `SIGSUMS` | norma do Marco 0.2: URL única de lista de checksums assinada; parser atual reconhece, executor ainda recusa (§5) |
| `SIGKEY` | hoje: chave minisign/signify pinada em uma linha base64; caminho `files/*.asc` pertence ao OpenPGP futuro |
| `SIGKEY_FP` | norma futura OpenPGP: fingerprint da chave — o `.asc` será só transporte |
| `EPOCH` | `SOURCE_DATE_EPOCH` da receita (unix ts); sobrepõe o default do projeto p/ builds reprodutíveis (§3, SPEC-0010) |
| `REPROCORR` | mundo B: sha256 do **tar normalizado** reprodutível (saída de `minitrue pack`); raiz de confiança única da corroboração de canal (SPEC-0009 §6, SPEC-0010 §4) |
| `PROVISIONAL` | `1` ⇒ pacote-semente/scaffolding que **cede** seus caminhos ao sucessor que os reivindique, sem *doublethink* (SPEC-0003 §3). Dois usos: (a) busybox → coreutils/binutils; (b) o toolchain-semente musl do E2 (gmp/mpfr/mpc/binutils/gcc) → os rebuilds-glibc, SPEC-0005 §4 |
| `SUPERSEDES` | lista de pacotes `PROVISIONAL` cujos caminhos esta receita tem **licença** de tomar (SPEC-0003 §7). A supersessão é **declarativa**: colidir com um provisional NÃO listado aqui é *doublethink*, não cessão. Ex.: `mathlibs-glibc` pina `SUPERSEDES="gmp mpfr mpc"` |
| `TOOLCHAIN` | perfil de toolchain do build (SPEC-0005): `none` (receita de montagem, sem compilador), `seed` (zig cc -target musl; **default**), `cross` (`x86_64-distropica-linux-gnu-*`: gcc passada 1 + binutils-cross), `native` (gcc nativo, pós-E2). Em `KIND=source`, `seed` e `cross` implicam `zig` como dependência só de build; não é necessário repetir em `BUILD_DEPS` |
| `RETRIES` | nº de reexecuções que a função `retry` do build tolera (§3), para o ICE flaky do gcc-passada-1 (SPEC-0005/0010). Default `0` |

Funções:

- `KIND=binary` DEVE definir `install_pkg()` — popula `$PREFIX`.
- `KIND=source` DEVE definir `build()` — compila e instala em `$STAGE`.
- `KIND=meta` NÃO define função nem carrega payload: é um nó
  declarativo que agrega um conjunto por `DEPS`. Instalar o meta = instalar
  suas dependências e registrar a intenção, sem ensinar esse conjunto ao
  Minipax.

O parser implementa `KIND=meta` com validação fechada. `DEPS` precisa conter
ao menos uma receita; `TOOLCHAIN` deve ser omitido ou `none`; `SRC`, `SHA256`,
`BUILD_DEPS`, `LINKS`, `SIG`, `SIGSUMS`, `SIGKEY`, `REPROCORR`,
`REQUIRES_GLIBC`, `PROVISIONAL`, `SUPERSEDES`, `EPOCH`, `RETRIES`, `files/`,
`build()` e `install_pkg()` são proibidos. `NAME`, `VERSION`, `KIND`, `DEPS` e
os metadados descritivos continuam sujeitos às validações gerais. O primeiro
meta oficial é `miniplenty-buildbase`; `base` permanece uma receita
`KIND=source`, pois materializa o esqueleto real do sistema.

## 3. Contrato de execução

O minitrue executa a função da receita via `sh -e`, com:

| Variável | Conteúdo |
|----------|----------|
| `DL`, `DL_2`, … | caminho no cache de cada artefato de `SRC`, já verificado |
| `WORK` | diretório de trabalho temporário (cwd inicial) |
| `PREFIX` | mundo A: staging de `/opt/<nome>/<versão>` |
| `STAGE` | mundo B: DESTDIR de staging |
| `JOBS` | paralelismo |
| `CC`, `CXX`, `AR`, `RANLIB`, `NM`, `LD` | toolchain do perfil `TOOLCHAIN` (§2, SPEC-0005): `none` ⇒ `false` (uso acidental falha); `seed` ⇒ shims `zig cc -target x86_64-linux-musl` (o `-target` é obrigatório — sem ele o zig mira o host, glibc); `cross` ⇒ `x86_64-distropica-linux-gnu-*` (com os shims seed ainda no PATH, p/ `BUILD_CC`); `native` ⇒ `gcc`/`g++` |
| `retry <cmd>` | função shell injetada: reexecuta `<cmd>` até `RETRIES` vezes (§2). Envolve o comando sujeito ao ICE flaky do gcc-passada-1 (ex.: `retry make -j"$JOBS"`); o `make` incremental resume a cada tentativa (SPEC-0005/0010) |
| `ROOT` | raiz alvo (para casos raros e legítimos de leitura) |
| `SOURCE_DATE_EPOCH` | timestamp fixo p/ builds reprodutíveis (SPEC-0010); do campo `EPOCH` da receita ou o default do projeto |
| `LC_ALL`/`LANG`/`TZ` | `C`/`C`/`UTC` — impostos p/ determinismo (SPEC-0010) |

Para receitas `KIND=source`, `TOOLCHAIN=seed|cross` cria uma aresta implícita
para a receita `zig`. Ela participa do fingerprint transitivo mesmo sem a
repetição em `BUILD_DEPS`, e o Minitrue materializa Zig antes de executar
`build()` quando escolhe compilação local. Se um artefato de canal satisfaz o
pacote, nenhum build ocorre e Zig não é instalado. `KIND=binary` e os perfis
`none`/`native` não recebem essa dependência; `KIND=meta` também nunca a recebe,
mesmo quando agrega receitas fonte. Por ser dependência, e não pedido
explícito, Zig não entra em `/etc/minitrue/world`.

O ambiente é **determinístico** (SPEC-0010): além do acima, `umask 022` e
caminho de build canônico. A função recebe apenas o contrato; ainda precisa evitar
não-determinismo próprio (gravar a data corrente etc.). Campo opcional
`EPOCH=<unix ts>` sobrepõe o default.

A tabela descreve o ambiente da função. A avaliação top-level que coleta os
campos é uma execução separada, também com `env_clear` e locale/`TZ` fixos; o
mundo A recebe `WORK`/`PREFIX`, enquanto o mundo B recebe `WORK`/`STAGE` e a
toolchain. Em rootfs alternativo, só o `build()` mundo B ganha bwrap e rede
isolada; o rootfs ainda é gravável (SPEC-0003 §8).

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

## 4. Exemplos normativos

Os pinos upstream abaixo foram verificados em 2026-07-18; o meta e o grafo de
toolchain foram atualizados em 2026-07-22.

### 4.1 Mundo M — ambiente-base de produção

```sh
NAME=miniplenty-buildbase
VERSION=1
KIND=meta
DEPS="base make gcc-pass2"
ABOUT="O conjunto-base de produção da Distrópica: shell e utilitários essenciais, GNU Make, headers Linux, binutils nativo e GCC final para C e C++. O nome remete ao Ministry of Plenty de 1984; por ser meta, não instala payload próprio."
```

O grafo instalado é deliberadamente de **runtime final**:
`miniplenty-buildbase` agrega `base`, `make` e `gcc-pass2`; `base` traz
`busybox`; e `gcc-pass2` traz `linux-headers`, `glibc`, `mathlibs-glibc` e
`binutils-glibc`. Assim o perfil oficial entrega shell, Make, headers,
assembler/linker e GCC/G++ nativos, sem promover `gcc`, `binutils-cross` ou
`libstdcxx` provisórios a dependências de runtime. Estes continuam
`BUILD_DEPS` do fechamento do Estágio 2 e só são materializados quando esse
fechamento é compilado localmente.

O meta não tem artefato nem entra em canal. Sob instalação oficial
`--only-binary`, suas receitas `KIND=source` são atendidas pelos respectivos
artefatos assinados, e somente o grafo de runtime acima chega ao alvo. Na
compilação local, cada receita `seed`/`cross` ainda ganha sua aresta de build
implícita para Zig; isso faz parte da identidade transitiva, mas não transforma
Zig em componente do meta nem em desejo do `world`.

### 4.2 Mundo A — tarball simples (Zig; hash do índice oficial ziglang.org)

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

### 4.3 Mundo A — binário estático musl (ripgrep, GitHub Releases oficial)

```sh
NAME=ripgrep
VERSION=15.2.0
KIND=binary
ABOUT="grep moderno; upstream publica musl estático — roda desde o E0"
SRC="https://github.com/BurntSushi/ripgrep/releases/download/$VERSION/ripgrep-$VERSION-x86_64-unknown-linux-musl.tar.gz"
SHA256=33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c
LINKS="rg=rg"

install_pkg() {
    tar -xzf "$DL" --strip-components=1 -C "$PREFIX"
}
```

### 4.4 Mundo B — fonte com bootstrap sem make (GNU make)

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

### 4.5 Mundo A — `.deb` do vendor como embalagem (Google Chrome)

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

### 4.6 Mundo A — dependente de glibc e de stack gráfico (Firefox)

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

1. `SHA256` é obrigatório para **cada `SRC`**; assinatura complementa, não
   substitui (o cache é verificável offline e sem esquema criptográfico
   variável). Receitas de montagem e metas omitem ambos porque não possuem
   artefato upstream.
2. Upstream assina ⇒ a receita DEVERIA pinar. Pacotes da base (estágios
   0–3, SPEC-0005) DEVEM pinar quando a assinatura existir.
3. A chave pública vive **na árvore newspeak**, versionada e revisável em
   diff. Buscar chave em keyserver ou URL em tempo de instalação é
   proibido (SPEC-0001 P6).
4. Implementação v0.1: **minisign/signify** por artefato (Ed25519; chave em uma
   linha base64 de `SIGKEY`). OpenPGP destacado (`.sig`/`.asc`, chave em
   `files/*.asc`, `SIGKEY_FP`) é norma do Marco 0.2 e hoje falha explicitamente.
5. `SIG` cobre assinatura por artefato e está implementado; `SIGSUMS` cobrirá o padrão
   "lista de checksums assinada" (ex.: `SHASUMS256.txt.asc` do Node.js) —
   nesse modo o artefato DEVE constar na lista **e** bater com o `SHA256`
   pinado. Uma receita usa um esquema ou o outro, não ambos.
6. Falha de assinatura ⇒ erro 7 (SPEC-0003 §9), sem contorno.
7. Rotação de chave do upstream é evento auditável: o commit que troca
   `SIGKEY`/`SIGKEY_FP` DEVE justificar no corpo (link do anúncio).

Disponibilidade upstream: **todo o ftp.gnu.org publica `.sig`**, Zig publica
`.minisig` (chave acima, copiada da página oficial em 2026-07-18) e Node assina
`SHASUMS256.txt`. Hoje o minitrue valida o caso Zig/minisign; a cobertura GNU e
Node depende de OpenPGP/`SIGSUMS` no Marco 0.2.

## 6. Convenções da árvore

- Um pacote por diretório; `NAME` = nome do diretório; erro caso divirjam.
- Em receita com `SRC`, atualização = mudar `VERSION` e `SHA256` no mesmo
  commit; título de commit: `<nome>: <versão>`.
- A árvore newspeak num dado commit é o conjunto consistente do sistema —
  não existem ranges de versão (SPEC-0001 P1).
- Comentários na receita são bem-vindos quando registram uma decisão de
  classificação (por que este binário é elegível, por que este build é
  estranho).
- A árvore DEVERÁ passar `minitrue lint` antes de publicar quando o comando do
  Marco 0.2 existir (local e no CI do repositório). O lint conferirá: `NAME` = nome do diretório; campos
  obrigatórios presentes e bem-formados; `SRC` só https; um `SHA256` de
  64 hex por artefato de `SRC`; ausência conjunta de `SRC`/`SHA256` apenas em
  montagem `source` ou meta; `SIGKEY_FP` presente quando `SIGKEY` é
  bloco OpenPGP; `VERSION`, dependências e `LINKS` canônicos; ausência do nome
  reservado `files/recipe`; a função exigida pelo
  `KIND` definida (`install_pkg`/`build`) ou, para `meta`, `DEPS` não vazio e
  ausência dos campos, funções e `files/` proibidos no §2. Receita reprovada
  não entra na árvore oficial.

## 7. Questões em aberto

- Receitas com variantes por arquitetura (`SRC_x86_64` / `SRC_aarch64` ou
  interpolação de `$ARCH`): decidir quando aarch64 entrar.
- Versões "rolantes" de vendor sem URL versionada (caso Chrome §4.5):
  formalizar procedimento de repinagem.
