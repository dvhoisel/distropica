# SPEC-0004 — newspeak, o formato das receitas

**Status:** rascunho v0.13 · 2026-08-11
**Depende de:** SPEC-0001 (elegibilidade), SPEC-0003 (contrato de execução).
**Complementado por:** SPEC-0013 (semântica tipada e validação da closure).

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
| `LICENSE` | obrigatório e não vazio em `KIND=binary` e `KIND=source`; proibido em `KIND=meta`. Contém uma expressão SPDX do **payload instalado**, ou `NOASSERTION` quando um bundle de terceiros ainda aguarda inventário conclusivo. Deve ocupar uma única linha, sem caracteres de controle; o parser valida essa forma segura, não toda a gramática SPDX. Não relicencia o arquivo `recipe`: a implementação autoral da receita segue a licença do repositório, enquanto o software de terceiros conserva a licença upstream. `NOASSERTION` é conservador, não dispensa preservar avisos nem o SBOM antes da publicação |

Uma receita `source` sem `SRC` é uma receita de **montagem**: seu `build()`
gera o payload apenas de conteúdo versionado com a própria receita. Ela não
pode declarar `SHA256` nem `SIG` sem um artefato a que esses campos se refiram.
O modo explícito `--tofu`, compilado somente na variante de autoria
(`bootstrap/build-minitrue.sh --authoring`), continua sendo apenas o fluxo
excepcional para obter e revisar um hash ainda não pinado; não torna `SHA256`
opcional na árvore publicada.

Opcionais:

| Campo | Significado |
|-------|-------------|
| `DEPS` | dependências diretas de runtime (nomes canônicos de receitas); requisitos ELF externos precisam alcançar seu provedor por uma aresta direta, conforme SPEC-0013 §4 |
| `BUILD_DEPS` | dependências só de build (mundo B; nomes canônicos), materializadas apenas quando houver compilação local; SPEC-0013 §2 |
| `LINKS` | mundo A: comandos a expor, `nome=caminho/relativo/no/prefix`, sem `/`, `.` ou `..` nos componentes; default: todo executável em `bin/` do prefix |
| `REQUIRES_GLIBC` | `1` ⇒ só instala após o Estágio 2 (SPEC-0005) |
| `ABOUT` | uma linha: o que é / justificativa de classificação |
| `SIG` + `SIGKEY` | minisign/signify legado: URL HTTPS literal da assinatura e chave pública base64 em uma linha (§5) |
| `SIG_n` + `SIG_EPOCH_n` + `SIGKEY_n` + `SIGKEY_FP_n` | OpenPGP destacado do artefato `SRC_n`: URL HTTPS literal, instante criptográfico explícito, transporte `files/*.asc` e fingerprint da chave primária (§5) |
| `SIGSUMS` + `SIGSUMS_EPOCH` | URL HTTPS literal de uma lista de SHA-256 clearsigned OpenPGP e instante criptográfico explícito; usa `SIGKEY_1` + `SIGKEY_FP_1` (§5) |
| `SIGSUMS_SIG` | URL HTTPS literal opcional da assinatura destacada de `SIGSUMS` (padrão CMake); omitida no Cleartext Signature Framework (§5) |
| `SIG_UNSAFE_WAIVER` | transporte literal `files/assinatura-insegura` da renúncia auditável quando a única assinatura upstream é recusada pela política; nunca relaxa o motor (§5) |
| `SIG_UNSAFE_WAIVER_n` | forma indexada `files/assinatura-insegura-n` para o `SRC_n` de uma receita multi-SRC; pode coexistir apenas com quádruplas OpenPGP normais de outros índices (§5) |
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
`LICENSE`, `BUILD_DEPS`, `LINKS`, qualquer campo `SIG*`/`SIGKEY*`, `REPROCORR`,
`REQUIRES_GLIBC`, `PROVISIONAL`, `SUPERSEDES`, `EPOCH`, `RETRIES`, `files/`,
`build()` e `install_pkg()` são proibidos. `NAME`, `VERSION`, `KIND`, `DEPS` e
`ABOUT` continuam sujeitos às validações gerais. Como o meta não possui
payload, seu inventário de licenças é o fechamento das suas `DEPS`, não uma
licença atribuída ao nó agregador. O primeiro
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
toolchain. Em rootfs alternativo, só o `build()` mundo B ganha bwrap, rede
isolada e raiz somente-leitura; `WORK`/`STAGE` e o cache do Zig são os únicos
binds graváveis (SPEC-0003 §8).

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
LICENSE=NOASSERTION
SRC="https://ziglang.org/download/$VERSION/zig-x86_64-linux-$VERSION.tar.xz"
SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
SIG="https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz.minisig"
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
LICENSE=MIT
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
LICENSE="GPL-3.0-or-later AND GFDL-1.3-invariants-or-later"
SRC="https://ftp.gnu.org/gnu/make/make-$VERSION.tar.gz"
SHA256=@PINAR@
SIG_1="https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz.sig"
SIG_EPOCH_1=@PINAR_INSTANTE_DE_REVISAO@
SIGKEY_1="files/gnu-make.asc"
SIGKEY_FP_1=@PINAR_FINGERPRINT_PRIMARIO@

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
LICENSE=NOASSERTION
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
LICENSE=NOASSERTION
SRC="https://download.mozilla.org/…linux-x86_64…$VERSION….tar.xz"
SHA256=@PINAR@
LINKS="firefox=firefox/firefox"

install_pkg() {
    tar -xJf "$DL" -C "$PREFIX"
}
```

`@PINAR@` marca hash a pinar no momento de criar a receita de verdade (o
Minitrue distribuído recusa receita sem hash; a variante explícita de autoria
pode usar `--tofu`; SPEC-0003 §2).

## 5. Assinaturas upstream

Quando o mantenedor assina o que publica, a receita pina a assinatura junto
com o hash. Papéis distintos: o **SHA-256 congela o artefato exato** que o
autor da receita viu; a **assinatura prova a autoria upstream** — inclusive
do artefato *novo* no momento de atualizar a versão. É a repinagem que a
assinatura protege: na variante de autoria, com `--tofu`, o hash é recalculado,
mas a chave pinada continua exigindo que o artefato venha de quem sempre veio.

1. `SHA256` é obrigatório para **cada `SRC`**; assinatura complementa, não
   substitui (o cache é verificável offline e sem esquema criptográfico
   variável). Receitas de montagem e metas omitem ambos porque não possuem
   artefato upstream.
2. Upstream assina ⇒ a receita DEVERIA pinar. Pacotes da base (estágios
   0–3, SPEC-0005) DEVEM pinar quando existir assinatura que passe a política.
   Se o upstream publicar **somente** assinatura criptograficamente recusada,
   a receita não pode relaxar o motor: usa exclusivamente
   `SIG_UNSAFE_WAIVER="files/assinatura-insegura"`, mantém o SHA-256 e registra
   uma renúncia explícita à prova de autoria. O arquivo é UTF-8/LF canônico,
   preso no fingerprint, e contém exatamente data/epoch da revisão (a data
   precisa ser o dia UTC do epoch), pacote/versão, URL+SHA-256 do artefato,
   URL+SHA-256+epoch da assinatura, fingerprint primária, algoritmo/hash e
   motivo. A forma não indexada exige exatamente um `SRC` e não pode se
   misturar com outro campo de assinatura. Uma receita multi-SRC usa
   `SIG_UNSAFE_WAIVER_n="files/assinatura-insegura-n"`: cada índice contém
   **ou** esse waiver **ou** a quádrupla OpenPGP normal, nunca ambos, e todo
   `SRC` precisa ser coberto exatamente uma vez. Os formatos aceitos são
   fechados e factualmente distintos:

   - `minitrue-insecure-upstream-signature-v1` é renúncia sem prova de autoria
     e cobre somente `DSA-1024` + `SHA1_DATA_REJECTED`. Prende URL+SHA-256 dos
     bytes-fonte da chave, regra de extração e SHA-256 do certificado extraído;
     assim uma página HTML ou keyring multi-cert nunca finge que seu hash é o
     do certificado. Assinatura, fonte e certificado extraído são arquivos
     distintos no snapshot `files/`: o runtime coteja seus hashes, reproduz a
     extração, exige packet binário DSA p=1024/q=160 + SHA-1, issuer/creation
     time exatos e prova que o motor normal recusa a assinatura sobre o mesmo
     fd do artefato. Isso documenta factualmente a renúncia, sem transformar a
     assinatura fraca em prova de autoria.
   - `minitrue-expired-signer-endorsement-v2` cobre somente uma assinatura de
     dados moderna (`RSA-2560`/`SHA512`) que era válida em seu creation time,
     mas cujo certificado expirou antes do `REVIEW_EPOCH`. `VALIDATION_EPOCH`
     DEVE ser exatamente o creation time autenticado da assinatura; a
     selfsig/binding selecionada DEVE já existir e estar vigente nesse instante,
     e sua expiração DEVE anteceder a revisão. Bytes de uma página HTTPS
     oficial, observados e pinados no `REVIEW_EPOCH` posterior à expiração,
     DEVEM continuar reendossando o fingerprint exato. Quando o próprio
     conteúdo declara uma data, ela é registrada como `PAGE_DATE`, nunca
     apresentada como header HTTP autenticado. Assinatura,
     resposta-fonte do certificado, certificado mínimo e página oficial vivem
     no snapshot `files/`; seus hashes são cotejados, o certificado mínimo é
     provado packet-a-packet como subconjunto da fonte, o fingerprint é extraído
     pela regra fechada da página e a assinatura é verificada sobre o mesmo fd
     do artefato. O motor normal também precisa provar que a assinatura falha no
     `REVIEW_EPOCH`; portanto o v2 não retrodata `SIG_EPOCH`.
   - `minitrue-legacy-dsa-data-math-v3` cobre exclusivamente
     `DSA-2048-Q256`/`SHA256`. O motor normal continua recusando DSA sobre
     dados. Uma API separada, acessível somente pelo parser v3, verifica
     matematicamente a assinatura sobre o mesmo fd e exige que emissor e chave
     sejam exatamente a primária pinada com p=2048/q=256. Duas páginas oficiais
     congeladas precisam prender, respectivamente, a release+sidecar+chave e o
     fingerprint+email exatos; o certificado transportado apenas fornece os
     MPIs da primária e não cria confiança temporal.

   Novo motivo, algoritmo, regra de extração ou semântica exige novo formato
   normativo; nunca se amplia silenciosamente v1/v2/v3.
3. A chave pública vive **na árvore newspeak**, versionada e revisável em
   diff. Buscar chave em keyserver, trustdb, WKD ou URL em tempo de instalação
   é proibido (SPEC-0001 P6). `files/*.asc` é apenas transporte congelado no
   fingerprint; `SIGKEY_FP_n` é a âncora primária e precisa ser hexadecimal
   maiúscula canônica (40 ou 64 dígitos). O transporte contém exatamente um
   certificado público, sem material secreto. A chave/subchave emissora precisa
   pertencer a essa primária e ser válida sob a política no instante pinado.
   Quando bytes do certificado só existem por transporte não confiável, esse
   transporte não cria identidade. O caso Flex prende no mesmo snapshot os
   bytes das APIs oficiais de tag/release, verifica a assinatura da tag pela
   mesma primária e coteja tagger, email, uploader, nomes/URLs/tamanhos do tar e
   sidecar; certificado e assinatura normal continuam inputs autenticados do
   `PLAN_LOCK`.
   Um objeto de transporte oficial pode conter certificações WoT adicionais
   dentro do mesmo certificado (caso WKD da glibc). Isso não é um keyring nem
   `export-minimal`: o parser ainda exige exatamente **um** `Cert`, a primária
   exata e a signing key pertencente a ela sob a policy/epoch pinados;
   certificações externas não criam outra âncora nem ampliam signers aceitos.
4. Minisign/signify continua usando os nomes não indexados `SIG` + `SIGKEY`.
   OpenPGP destacado usa, para **cada** `SRC_n`, a quádrupla completa e contígua
   `SIG_n` + `SIG_EPOCH_n` + `SIGKEY_n` + `SIGKEY_FP_n`, salvo quando aquele
   índice usa `SIG_UNSAFE_WAIVER_n`. Índice zero, buraco, campo sobrando,
   sobreposição waiver/quádrupla ou mistura com minisign/`SIGSUMS` falha
   fechado. Os inputs autenticados de waiver indexado carregam o mesmo índice
   em seus identificadores; isso impede colisão entre evidências de dois SRC.
5. `SIGSUMS` cobre a lista de checksums assinada. Sem `SIGSUMS_SIG`, a lista
   precisa usar o OpenPGP Cleartext Signature Framework; com `SIGSUMS_SIG`, a
   assinatura é destacada. Em ambos os casos exige `SIGSUMS_EPOCH`, `SIGKEY_1`
   e `SIGKEY_FP_1`; cada artefato deve aparecer uma única vez como basename
   canônico e seu SHA-256 deve coincidir exatamente com `SHA256`. Linha
   malformada, path, duplicata ou separador ambíguo invalida toda a lista. Uma
   receita usa OpenPGP destacado por artefato ou `SIGSUMS`, nunca ambos.
6. `SIG_EPOCH_n`/`SIGSUMS_EPOCH` é Unix decimal canônico obrigatório, limitado
   ao horizonte `u32` do OpenPGP. Representa o instante pinado de
   verificação/revisão: deve ser igual ou posterior à criação da assinatura e
   cair dentro da validade aplicável do certificado/chave. Não é o relógio da
   máquina, não tem default e **nunca** é `EPOCH`/`SOURCE_DATE_EPOCH`, que rege
   somente a reprodutibilidade do build. O epoch criptográfico entra no
   fingerprint da receita e no namespace do cache.
7. Antes de executar `source` da receita, o Minitrue coleta **todo nome que
   começa por `SIG`** como atribuição literal no cabeçalho. `$VAR`, `$()`,
   backticks, escapes, operadores shell, duplicatas e campos após as funções
   são recusados; portanto URLs como `SIG="$SRC.minisig"` não são válidas.
   O plano tipado usa só esse mapa literal, nunca valores de assinatura
   impressos pelo shell.
8. A verificação é hermética: Sequoia OpenPGP com backend Rust e política
   versionada no formato do motor (`OPENPGP_ENGINE_FORMAT=3`), tempo explícito
   tanto no parser quanto na própria política e certificado local pinado;
   nenhuma consulta de rede, GnuPG externo ou trustdb. Para certificados
   legados, SHA-1 é aceito somente quando Sequoia exige resistência à segunda
   pré-imagem (selfsig/binding), e DSA-1024 somente para validar a certificação
   ou binding de uma subchave. O helper exige que a assinatura efetiva dos
   dados e sua chave emissora não sejam DSA e recusa SHA-1 explicitamente;
   SHA-1 também continua recusado pela política nos contextos que exigem
   resistência a colisão. Assim, uma primária DSA histórica pode ligar uma
   subchave RSA/SHA-256, mas nunca assinar artefato ou manifesto.
   Assinatura destacada de `SRC` ou manifesto DEVE ser do tipo OpenPGP Binary,
   pois Text canonicaliza EOL e não prova os bytes exatos. Somente o ramo
   declarado do Cleartext Signature Framework aceita Text, antes de interpretar
   sua lista autenticada de checksums.
   Assinatura e `SIGSUMS` são objetos pequenos e limitados.
   O artefato (até 16 GiB) é transmitido pelo mesmo descritor regular
   `O_NOFOLLOW`, `nlink=1` usado para seu SHA-256; metadados são comparados
   antes/depois. Objetos auxiliares conservam o mesmo fd/snapshot da leitura à
   publicação, são reverificados inclusive em `--offline` e publicados num
   diretório pertencente ao uid efetivo e sem escrita por grupo/outros, com
   `RENAME_NOREPLACE` + `fsync`, sem aceitar symlink/hardlink. Um swap aborta;
   limpeza pós-falha só remove o inode exato que acabou de ser publicado.
9. Falha criptográfica, auxiliar ausente/inválido em `--offline` ou assinatura
   cacheada que não revalida ⇒ erro 7 (SPEC-0003 §9), sem contorno.
10. Rotação de chave do upstream é evento auditável: o commit que troca
    `SIGKEY_n`/`SIGKEY_FP_n` DEVE justificar no corpo (link do anúncio).

O motor autentica somente os bytes exatos de `SRC` ou o SHA-256 desses bytes
num `SIGSUMS`. Assinaturas sobre uma transformação implícita (por exemplo, o
WireGuard assina o TAR depois de `xz -dc`, não o `.tar.xz`) permanecem
bloqueadas até existir um transformador autenticado explícito no schema.

## 6. Convenções da árvore

- Um pacote por diretório; `NAME` = nome do diretório; erro caso divirjam.
- Em receita com `SRC`, atualização = mudar `VERSION`, `SHA256` e, quando
  aplicável, URL/epoch da assinatura no mesmo commit; título de commit:
  `<nome>: <versão>`.
- A árvore newspeak num dado commit é o conjunto consistente do sistema —
  não existem ranges de versão (SPEC-0001 P1).
- Comentários na receita são bem-vindos quando registram uma decisão de
  classificação (por que este binário é elegível, por que este build é
  estranho).
- A árvore DEVERÁ passar `minitrue lint` antes de publicar (local e no CI do
  repositório). O lint confere: `NAME` = nome do diretório; campos
  obrigatórios presentes e bem-formados; `SRC` só https; um `SHA256` de
  64 hex por artefato de `SRC`; ausência conjunta de `SRC`/`SHA256` apenas em
  montagem `source` ou meta; quádruplas OpenPGP/SIGSUMS completas, literais e
  indexadas; `VERSION`, dependências e `LINKS` canônicos; ausência do nome
  reservado `files/recipe`; `LICENSE` presente, não vazio e em uma única linha
  sem controles em `binary`/`source`, e ausente em `meta`; a função exigida pelo
  `KIND` definida (`install_pkg`/`build`) ou, para `meta`, `DEPS` não vazio e
  ausência dos campos, funções e `files/` proibidos no §2. Receita reprovada
  não entra na árvore oficial.

## 7. Questões em aberto

- Receitas com variantes por arquitetura (`SRC_x86_64` / `SRC_aarch64` ou
  interpolação de `$ARCH`): decidir quando aarch64 entrar.
- Versões "rolantes" de vendor sem URL versionada (caso Chrome §4.5):
  formalizar procedimento de repinagem.
