# SPEC-0005 — Bootstrap em estágios

**Status:** rascunho v0.5 · 2026-07-22
**Depende de:** todas as anteriores.

## 1. A tese do bootstrap

Dos toolchains C, o único que o próprio upstream distribui como binário
Linux autocontido é o **Zig**: um tarball estático que embute clang, lld e
os headers/fontes da musl (`zig cc` compila e linka C/C++ sem nada
instalado no sistema). Já a **glibc não tem binário upstream e só compila
com GCC** — que também não tem binário upstream.

Logo, a ordem do mundo é forçada pela premissa:

1. O sistema **nasce musl-estático**, com `zig cc` como compilador semente
   (custo de compilação inicial ≈ zero).
2. A glibc é **conquistada por compilação** no Estágio 2 (binutils → GCC →
   glibc, à la LFS, com `zig cc` como toolchain hospedeira).
3. Só então os binários vendor dinâmicos (neovim, chrome, vscode, firefox…)
   passam a rodar — eles são todos linkados contra glibc.

Consequência assumida e documentada: entre E0 e E2, `REQUIRES_GLIBC=1`
recusa instalação com erro 5 (SPEC-0003 §3.2).

### 1.1 Decisão: o seed é upstream pinado, NÃO o gcc do host

Poder-se-ia — e seria **muito mais fácil** — usar o gcc da distro
hospedeira (o gcc do Kubuntu, digamos) para erguer a toolchain, como o LFS
faz. Não há impossibilidade técnica: gcc compilando gcc é o caso normal, e
um gcc glibc do host construiria o gcc da Distrópica sem o atrito
musl×glibc que o `zig cc` impôs (os ICEs flaky, os 58 decls mis-detectados,
o `rlim_t`, as mathlibs vazando a glibc — SPEC-0005 §4 — **são todos preço
da escolha do seed**).

A Distrópica **rejeita deliberadamente** essa muleta. O seed é o binário
**oficial e pinado por hash** do Zig (SPEC-0004), nunca o gcc que o builder
por acaso tem. Razões, em ordem de peso:

1. **Entradas pinadas ⇒ reprodutibilidade entre builders.** O gcc do host
   é "o que o `apt` instalou": versão, patches Debian/Ubuntu, flags e glibc
   variam de máquina para máquina — entrada **não pinada**. O zig é
   definido e verificável. É isso que faz o artefato depender só de insumos
   pinados e, portanto, o binário de canal ser verificável por reprodução
   (SPEC-0009/0010). Com o gcc do host como seed, os artefatos variariam
   por builder e o modelo de confiança dos canais ruiria.
2. **Independência de distro (P1).** "Só construível sobre o Ubuntu" é
   dependência permanente do Ubuntu. Bootstrapar de um seed mínimo e oficial
   estabelece a autossuficiência: a Distrópica se reconstrói de fontes
   upstream + ferramentas próprias, sem terceira distro.
3. **Base confiável mínima (trusting-trust).** Partir de um seed pequeno e
   auditável reduz o que se herda cego de um compilador alheio.

Alternativa rejeitada e por quê: usar o gcc do host como **muleta de
bootstrap única** (estilo LFS) daria um bootstrap sem dor e ainda terminaria
self-hosted — mas abre mão da reprodutibilidade-entre-builders do primeiro
estágio. A dor do seed puro é aceita como o preço da pureza (e, convém
notar, é temática). Decisão do mantenedor, 2026-07-19: **continua como está.**

### 1.2 Um pipeline, três entradas públicas

A ISO oficial não é a fonte privilegiada da distribuição. A fonte é o
conjunto formado por **perfil + worlds + árvore newspeak + insumos pinados +
lock**. O `minipax` resolve esse conjunto uma vez e entrega a mesma árvore a
três entradas públicas:

| Entrada | Contrato | Saída |
|---------|----------|-------|
| **Mídia oficial mínima** | iniciar a futura ISO/IMG publicada e executar o `minipax` contido nela | sistema instalado; os demais programas continuam sendo instalados pelo `minitrue` |
| **Instalação direta num host Linux** | `./bootstrap/distropica-bootstrap install --profile profiles/official --target /mnt --offline --cache CACHE --only-binary` | interface implementada; materializa a raiz já montada quando recebe um cache assinado que feche o world |
| **Construção de mídia** | `./bootstrap/distropica-bootstrap media build --profile profiles/official --mode offline --cache CACHE --format iso --boot-efi BOOTX64.EFI --output distropica.iso` | ISO ou imagem de disco gerada localmente a partir do mesmo perfil |

`install --target` **não particiona** e nunca interpreta `/mnt` como nome
mágico: o operador precisa preparar e montar o destino. A escrita destrutiva
num disco inteiro pertence ao fluxo interativo do instalador (SPEC-0008), com
alvo resolvido e confirmação explícita. A construção de mídia, por sua vez,
só escreve um arquivo de saída novo.

O perfil `official`, sem overrides, com o lock de release e a mesma época,
define a tentativa de reproduzir a mídia oficial byte a byte. Trocar `world`,
`live-world` ou `overlay` é uma operação suportada, mas classifica a saída
como **custom**, muda seu lock e seus hashes e não lhe concede a assinatura nem
o nome de artefato oficial do projeto.

No estado atual, `profiles/official` declara `INSTALL_READY=yes` e
`STATUS=development`. A prontidão afirma que o world mínimo pode ser instalado
num target vazio com o cache/canal correto; **não** afirma que já exista canal,
bundle ou mídia oficial publicada, nem muda a classe de desenvolvimento para
release.

### 1.3 Usuário normal e reprodutor

As três entradas acima admitem duas políticas de obtenção, sem criar dois
instaladores:

- o **usuário normal** consome, sob um snapshot/lock imutável, os binários
  assinados dos canais para o mundo B e os binários upstream elegíveis para o
  mundo A. O consumidor de canal, `--only-binary` e o
  `CHANNEL_LOCK_FORMAT=2` estão implementados: ele monta a distribuição
  localmente, mas não recompila glibc e GCC;
- o **reprodutor** pede `--from-source`: o mesmo grafo recusa binários de canal,
  reconstrói o mundo B a partir das fontes pinadas e compara os artefatos com
  `REPROCORR`/attestations (SPEC-0009/0010). É a prova deliberadamente cara,
  não o caminho obrigatório de instalação.

`install --from-source` já é a forma da interface de desenvolvimento. O mesmo
modificador para `media build` permanece **contrato futuro**, embora a
resolução de canais já exista: falta encadear a construção local de todo o
conteúdo fechado pelo lock antes de empacotar a mídia. Sem a opção, reproduzir
a ISO oficial significa reproduzir sua composição a partir dos artefatos
canônicos, e não necessariamente recompilar cada um deles.

### 1.4 Entrada estática e estado de implementação

A entrada pública de release DEVE ser um pequeno bundle verificável, baixado
como arquivo e conferido antes da execução — **não** `curl | sh`. Ele conterá
`distropica-bootstrap`, `minipax` e `minitrue` estáticos, a chave pública/pinos
necessários e instruções curtas de verificação. Assim o host não precisará de
Rust, GCC nem bibliotecas da distribuição hospedeira.

**Estado em 2026-07-21:** existe a casca `bootstrap/distropica-bootstrap` e o
envelope Rust do `minipax` para perfil, lock, instalação em raiz alternativa e
montagem determinística de ISO/IMG. O consumidor de canal assinado, o lock v2,
`--only-binary` e `channel emit` existem. `bootstrap/live/build-efi` produz o
`BOOTX64.EFI` EFI-stub (que continua sendo a entrada explícita do compositor de
mídia), e o initramfs vivo implementa a instalação destrutiva num disco
explicitamente autorizado. Em desenvolvimento, a casca compila por padrão
`minipax` e `minitrue` com Cargo para `x86_64-unknown-linux-musl`, confere que
os resultados não contêm segmento `INTERP` e também aceita executáveis
fornecidos por `MINIPAX`/`MINITRUE`. Estes últimos continuam sendo insumos do
usuário: a casca não lhes atribui linkagem estática, assinatura ou proveniência.

Uma ISO offline de desenvolvimento instalou em QEMU/OVMF um disco raw vazio e
o reiniciou sem a ISO até `rcS`/getty. Esse aceite automatizado final-v10 usa
uma variante construída com `--install-device /dev/vda` e
`distropica.test=1`; ele permanece separado do caminho humano e cobre também a
recusa fail-before-wipe de um `profile.lock` incoerente com `media.meta`.

A variante humana, construída sem `--install-device`, também passou num aceite
local real sob VirtualBox 7.2.6: exibiu no framebuffer os prompts de senha e de
disco, recebeu `/dev/sda`, teve a ISO ejetada depois do preflight integral em
`/run` e antes do wipe, instalou e reiniciou pelo VDI sem ISO com o cabo da NIC
desconectado e aceitou login de `root`. Num terceiro boot, o cabo VirtIO/NAT foi
conectado e a base configurou automaticamente DHCP IPv4, rota default e DNS; o
runner validou somente o resolvedor local e o gateway da NAT, sem depender da
Internet. Em seguida, o cabo foi desconectado outra vez: `ripgrep` 15.2.0,
inicialmente ausente, foi instalado por `minitrue --offline rectify ripgrep`, e
o `verify` posterior terminou limpo. Esse resultado é a evidência histórica
network-v1, anterior ao perfil que instala ripgrep por padrão e declara Make e
Zig em `cache.world`. Seu console usa simpledrm/fbcon e a cmdline
`console=ttyS0,115200 console=tty0 panic=-1 rdinit=/init`, com `tty0` por
último para ser o console interativo primário. Ainda faltam o bundle estático
assinado de release, endpoint/chave/pool de canal oficial, `channel refresh`
auditável, pinos e manifesto externo de release, uma ISO/IMG oficial
publicada, reprodução oficial por builders independentes e testes em hardware
real. Portanto, os comandos acima são o contrato público em construção e uma
implementação funcional de desenvolvimento, não a promessa de uma release já
publicada.

## 2. Estágio 0 — do host ao chroot (musl-estático)

**Entregável:** rootfs FHS mínimo, habitável via chroot sem privilégio.

Requisitos do host na entrada de desenvolvimento: `sh`, `tar`, `sha256sum`,
`curl` ou `wget`, ~300 MB livres, Cargo/Rust com o alvo
`x86_64-unknown-linux-musl`, um compilador C compatível (`clang` ou gcc musl) e
`readelf` para construir e validar os executores (a entrada de release usará o
bundle estático de §1.4 — SPEC-0003 §10) e
**bubblewrap (`bwrap`) para a entrada rootless** — na falta dele, `sudo
chroot` clássico.

Insumos (todos elegíveis por SPEC-0001 §2; hashes pinados nas receitas):

| Artefato | Origem | Nota |
|----------|--------|------|
| busybox 1.35.0 estático | `busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/` | oficial porém de 2022; recompilado da fonte no E1 |
| zig 0.16.0 | `ziglang.org/download` (sha no índice oficial) | 55 MB; o compilador C inteiro |
| minitrue estático | construído no host | o buscador/verificador |
| árvore newspeak | cópia do repositório | atualizável depois como pacote |

Passos (executados por `bootstrap/stage0.sh`, futuro):

1. Esqueleto FHS (SPEC-0002): diretórios, usr-merge, `/etc` mínimo
   (`passwd`, `group`, `hosts`, `os-release`, `resolv.conf` copiado do
   host), hostname `airstrip1`.
2. `minitrue --root <rootfs> rectify busybox zig` — o próprio minitrue
   popula o rootfs (dogfooding desde o primeiro minuto). A receita do
   busybox gera os links de applets (`busybox --list`).
3. Entrada sem root via **bwrap** (script `enter.sh`):
   `bwrap --bind <rootfs> / --proc /proc --dev /dev --unshare-pid …`.
   O plano original (`unshare -rmpf` + chroot) está **morto em hosts
   modernos**: com `apparmor_restrict_unprivileged_userns=1` (padrão
   Ubuntu/Debian recentes) o `unshare -r` recebe EPERM, enquanto o bwrap
   tem perfil AppArmor de fábrica (verificado no spike, ver Registro).
   Fallback documentado: `sudo chroot`.

**Critérios de aceite:**
- `busybox sh` interativo dentro do chroot;
- `zig cc -target x86_64-linux-musl hello.c` produz binário estático que roda;
- `minitrue rectify ripgrep` **dentro** do chroot baixa, verifica e instala
  (rede funciona via userns; TLS via raízes embutidas no minitrue).

Estes três critérios, ratificados em 2026-07-19, são o **Marco 0.1** do
projeto.

## 3. Estágio 1 — autossuficiência do mundo-fonte

**Entregável:** chroot capaz de `./configure && make` com
`CC="zig cc -target x86_64-linux-musl"` (o `-target` explícito é
obrigatório: sem ele o zig mira o host — glibc dinâmica).

- `make` da fonte — o primeiro build do mundo B, usando o truque histórico
  `./build.sh` do próprio tarball do GNU make (compilar make sem make).
- busybox recompilado da fonte na versão corrente (o binário oficial é
  1.35.0/2022) — valida `zig cc` + make num build real e tira a base da
  versão congelada.
- `pkgconf` da fonte.
- Utilitários de conveniência do mundo A que já rodam (musl-estáticos):
  ripgrep, uutils-coreutils (opcional, SPEC-0007 §4), sqlite.

**Critério de aceite:** um pacote autotools arbitrário simples compila e
instala via receita mundo B de ponta a ponta (staging → manifesto →
`memoryhole` limpo).

**Riscos:** scripts `configure` que assumem gcc real; incompatibilidades
pontuais do clang embutido. Mitigação: `zig cc` é clang — casos rebeldes
ganham patch em `files/` com justificativa. O caminho feliz foi provado no
spike com o próprio make (ver Registro): shim `/bin/ld → zig ld.lld` +
`--disable-nls --disable-dependency-tracking` bastaram.

## 4. Estágio 2 — a Grande Compilação (glibc)

**Entregável:** ABI glibc completa; binários vendor dinâmicos rodam.

Ordem (essencialmente o capítulo de cross-toolchain do LFS, com `zig cc`
no papel de toolchain hospedeira):

1. `linux-headers` (`make headers_install`);
2. pré-requisitos de build da glibc, da fonte: `m4`, `bison`, `gawk`,
   `python` (mínimo, sem módulos de rede — a ironia de compilar Python
   está registrada em SPEC-0007);
3. `binutils`;
4. `gcc` passada 1 (só C, `--without-headers`, cross para
   `x86_64-distropica-linux-gnu`);
5. `glibc` (compilada com o gcc da passada 1);
6. `gcc` passada 2 (C/C++ completo, hospedado na glibc nova) +
   `libstdc++`;
7. `ldconfig`, `/etc/ld.so.conf`, e `/lib64/ld-linux-x86-64.so.2`
   resolvendo (usr-merge, SPEC-0002 §4).

**A cadeia codificada — toolchain por estágio (2026-07-20).** Até aqui o E2
era *demonstrado à mão* (scripts ad-hoc). Agora o executor a codifica: cada
receita declara `TOOLCHAIN` (SPEC-0004 §2) e o `minitrue` injeta o compilador
certo por estágio, em vez de tudo cair no zig/musl:

- **`seed`** (default) — `zig cc -target x86_64-linux-musl`. A semente que
  constrói a base E0/E1 e o **gcc passada 1** (que é seed: feito pelo zig).
- **`cross`** — `x86_64-distropica-linux-gnu-{gcc,g++,ar,ranlib,nm,ld}`, do
  gcc passada 1 + do **`binutils-cross`** (receita nova: binutils `--target=`
  que dá as ferramentas prefixadas por nome, exigidas pelo build cross). A
  **glibc** é `cross`; os shims seed seguem no PATH para o `BUILD_CC` dela.
- **`native`** — `gcc`/`g++` nativo, hospedado na glibc. A **passada 2** e
  tudo pós-E2.

Em toda receita `KIND=source`, os perfis `seed` e `cross` implicam a receita
`zig` como dependência só de build, mesmo sem `BUILD_DEPS=zig`. Essa aresta
participa do fingerprint transitivo; alterar a receita da semente invalida os
pacotes produzidos por esses perfis. O Minitrue só materializa Zig quando o
plano escolhe compilação local. Um pacote atendido por canal não expande essa
aresta, e `TOOLCHAIN=none|native` também não instala Zig. Como dependência
implícita, a semente não entra no `world` salvo se for solicitada diretamente.

O ICE flaky do gcc-passada-1 vira contrato: a receita declara `RETRIES` e
envolve o comando em `retry` (SPEC-0004 §3); o `make` incremental resume a
cada tentativa até fechar. A `glibc` e o `gcc` já declaram `RETRIES=50`.

**O runner com rede e ambiente isolados (2026-07-20).** O executor roda os builds mundo-B de um
rootfs (`--root` != `/`) **dentro** dele, via `bwrap`: o rootfs montado em
`/`, `--clearenv` (só as variáveis do contrato — fim do vazamento do ambiente
do host) e `--unshare-net` (nenhum insumo pela rede; o fetch é no host —
SPEC-0004 §3.2). É necessário para o perfil `native` (o gcc da passada 2 é
**dinâmico** e usa o loader/libs glibc do rootfs em `/lib64`,`/usr/lib`
absolutos, que só são os do rootfs sob chroot); o `cross` (estático, e o gcc é
relocável) rodaria fora também, mas o runner o roda no mesmo ambiente limpo. O
rootfs ainda é montado **gravável**, portanto isto não é hermeticidade completa:
uma receita confiável continua obrigada a escrever só em WORK/STAGE. Smoke
verificado: sob `bwrap`, o `x86_64-distropica-linux-gnu-gcc` compila
in-chroot achando o `cc1`, e a rede fica isolada. No próprio sistema
(`--root /`) o build roda direto (o alvo já é `/`; sandbox de rede lá é dívida
de SPEC-0003 §8).

**Estado do E2:** a execução ponta-a-ponta e as receitas de passada 2 +
libstdc++ já foram concluídas pelo `rectify`, inclusive numa execução a frio;
o registro de aceite e das correções encontradas está ao fim desta seção. Falta
repetir o E2-clean num segundo ambiente independente e versionar as evidências.

A partir daqui `CC` do contrato de receitas (SPEC-0004 §3) passa a ser o
gcc nativo; `zig cc` permanece disponível como pacote comum.

**Critério de aceite:** `minitrue rectify neovim` (tarball oficial,
linkado contra glibc — verificado em 2026-07-18) instala e `nvim --version`
roda.

**Riscos (os maiores do projeto, fora o 4b):**
- GCC hospedado por clang/zig-cc: sabidamente possível, mas com atrito de
  flags — reservar tempo;
- versões glibc↔GCC precisam ser compatíveis entre si (matriz a fixar na
  receita);
- Python mínimo da fonte antes da glibc (o build da glibc exige Python):
  validar que o Python de bootstrap compila contra musl com zig cc.

**Conjunto de versões fixado (2026-07-19):** linux-headers 6.12.96,
m4 1.4.21, binutils 2.45, gmp 6.3.0, mpfr 4.2.2, mpc 1.3.1, bison 3.8,
gawk **5.3.2** (não 5.4.1 — regressão de array não-inicializado que quebra o
`optc-gen.awk` do gcc; ver adiante neste §), gcc 15.3.0, glibc 2.42 — todos
com SHA256 real pinado.

**Registro da fundação do Estágio 2 (2026-07-19).** Compilados com
`zig cc` DE DENTRO do chroot e encadeados por DEPS/BUILD_DEPS:
- **verificados de ponta a ponta:** linux-headers, m4, binutils, gmp,
  mpfr, mpc, bison, gawk. Achados que viraram desenho:
  - `make` é a ferramenta essencial do E1 (todo build de fonte a invoca),
    mas o E1 ainda não tem make — então uma **semente de make entra no E0**
    (`stage0`); o GNU make de verdade é (re)compilado da fonte no início do
    E1 pelo truque `./build.sh` (compila make sem make). Semente provisória
    no E0 → make real da fonte no E1;
  - o **busybox virou PROVISIONAL** (SPEC-0003): binutils tomou `ar`/
    `strings`, gawk tomou `awk`, sem doublethink — pré-condição para
    instalar qualquer GNU homônimo de applet;
  - binutils exige `--disable-gprofng` (o profiler assume glibc:
    `dlvsym`, `GLIBC_2.17`);
  - o gmp precisa de `m4` (asm) **e** do `nm` do binutils (configure) —
    daí `binutils` antes de `gmp`;
  - `zig cc` não busca `/usr/include`; mpfr/mpc/gcc acham as libs via
    `--with-gmp`/`--with-mpfr`/`--with-mpc` apontando `$ROOT/usr`.
- **fronteira ainda aberta (gcc + glibc):** a passada 1 do gcc estilo
  LFS usa triplet próprio `x86_64-distropica-linux-gnu`, o que exige
  **binutils-pass1 com o mesmo triplet** (hoje só há binutils nativo;
  aliases cross foram um paliativo de teste) e um modelo de **sysroot**
  que difere do "instala em /usr" do minitrue. A transição musl→glibc é
  o nó real. Falta ainda `python` (prereq da glibc). Recipes `gcc`/
  `glibc` commitadas como esqueleto marcado, não como build fechado.
- **Sinal do gcc (teste `make all-gcc`, 2026-07-19):** o `zig cc`
  compilou a **maior parte do GCC 15.3.0** — libcpp, libiberty, o
  frontend C e quase todos os passes de otimização, ~62 mil linhas de
  log, centenas de `.cc`, **sem erro** — e parou no `options.o` com
  `#error 0Wimplicit-function-declaration does not have a Var() flag`.
  Conclusão importante: o atrito NÃO está em compilar o compilador (que
  passou), mas na **geração das opções por awk**.
- **Causa-raiz do `options.o` (destravado em 2026-07-19):** era uma
  **regressão do gawk 5.4.1**, não do zig cc. Em 5.4.1, um elemento de
  array **não-inicializado**, comparado a `""` e depois concatenado,
  vira `"0"` em vez de `""` (reproduz até em `-O0`, logo não é
  miscompilação). O `optc-gen.awk` do gcc usa exatamente esse idioma
  (`if (enables[x]=="") …; enables[x]=enables[x] opt ";"`), gerando
  nomes de opção com `0` colado → `#error` espúrio. **Conserto durável:
  pinar gawk 5.3.2** (sadio, verificado no mesmo caso) em vez de remendar
  cada script awk do gcc/glibc — cura a doença na origem. Lição de
  método: fixar versões de ferramenta de bootstrap com cuidado, e
  desconfiar de releases muito novos (o 5.4.1 é de 2026).
- **Confirmação (build limpo com gawk 5.3.2):** o `options.cc` sai sem
  `#error` e o `all-gcc` avança **~7 mil linhas além** do antigo ponto de
  parada — o **compilador propriamente dito (cc1) compila por inteiro**
  sob zig cc (frontend + otimizadores + analisador, 57 mil linhas). O
  novo (e distinto) muro é auxiliar: `libgcov-driver-tool.o`
  (`gcov-tool`) compila como C mas inclui headers C++ do gcc (`unknown
  type name 'class'`) — não é musl, é uma diferença de driver: `g++`
  força C++ em `.c`, o `zig c++` (clang) respeita a extensão.
- **gcov-tool isolado (2026-07-19):** retirado de `LANGUAGES` via sed no
  `Makefile.in` (gcov e gcov-dump ficam). Com isso o `all-gcc` **constrói
  o compilador inteiro sob zig cc**: `cc1` (237 MB) e `xgcc` (12 MB)
  compilam e **linkam**. Marco real: o GCC 15.3.0 compila de ponta a
  ponta com a toolchain semente.
- **cc1 estático + self-test desligado (2026-07-19) — a passada 1 do gcc
  FUNCIONA:** o `cc1` saía dinâmico contra a musl (interpretador
  `/lib/ld-musl-x86_64.so.1`, ausente no rootfs), então o self-test do
  `all-gcc` não conseguia executá-lo. Conserto: `LDFLAGS=-static` (linka
  `cc1`/`xgcc` estáticos — as libs matemáticas têm `.a` em /usr/lib) e
  `SELFTEST_TARGETS=` (esvazia `selftest`, que é prereq de `all.internal`;
  a passada 1 não roda self-test, à la LFS). Resultado verificado: o
  `all-gcc` completa, o `cc1` é estático e **roda no rootfs**, e
  `xgcc`+`cc1` **compilam um `.c` em `.s`**. Marco: há um GCC 15.3.0
  executável, construído por zig cc, no rootfs musl. O nó final continua
  sendo a transição musl→glibc: falta este gcc **produzir glibc** (hoje
  ele mira musl); daí a passada 1 de verdade (`--without-headers` já está)
  seguida da glibc e da passada 2.
- **A GLIBC 2.42 COMPILA com o gcc da passada 1 (2026-07-19) — a barreira
  central do E2 caiu, mas o E2 ainda não fechou: falta a passada 2.** A
  `configure` da glibc declarou o
  `x86_64-distropica-linux-gnu-gcc` "sufficient to build libc", e o build
  produziu `libc.so.6` (11,6 MB, SONAME e a string "GNU C Library … 2.42"
  confirmados), o carregador `ld-linux-x86-64.so.2`, e `libm`/`libpthread`/
  `libdl`/`libmvec` — ELFs válidos. Prereqs resolvidos no caminho:
  - **python** (receita nova): a glibc o exige; python.org não publica
    binário. Dois consertos — `-Wno-error=date-time` (zig cc barra
    `__DATE__`/`__TIME__`) e `MODULE_BUILDTYPE=static` (Python estático
    precisa dos módulos embutidos, sem dlopen);
  - **gcc `--disable-lto`**: o `ld` estático não faz dlopen do
    `liblto_plugin.so`;
  - `CC=…-gcc -fno-use-linker-plugin`, `--with-headers=/usr/include`,
    `--host=…distropica…` != `--build`.
  - **Instabilidade do gcc-passada-1 (achado importante):** o gcc, por ser
    construído por zig cc/clang, **segfalta aleatoriamente** (ICE flaky) em
    arquivos complexos da math (`_FloatNx`). Não é determinístico — um loop
    de `make` (incremental) atravessa: os ~3800 objetos e todas as libs
    saíram assim. É a "atrito de clang" do §4 na forma mais aguda; o
    remédio próprio é um gcc mais estável (bootstrap/`-O` menor), mas a
    passada 2 (gcc nativo, hospedado na glibc nova) já tende a curar isso.
  - Único bloqueio restante do `make all`: `links-dso-program.cc`, um
    **helper de teste C++**, que o gcc-passada-1 (só C) não compila —
    irrelevante para a libc, resolve-se na passada 2 (que traz C++).
  Falta fechar: `make install` da glibc no rootfs, os symlinks de ld.so, e
  a passada 2 do gcc — mas a barreira central do projeto (produzir glibc a
  partir de um mundo musl com toolchain semente zig) **caiu**.
- **GLIBC INSTALADA E RODANDO NO ROOTFS (2026-07-19) — o sistema tem a ABI
  glibc.** `make install DESTDIR=` da glibc (não depende do
  `links-dso-program`), mesclado no rootfs respeitando o usr-merge
  (`/sbin`→`usr/bin`, loader em `/usr/lib` visível via `/lib64`), e
  `ldconfig` montou o cache (38 libs). Prova definitiva: um programa
  **dinâmico** compilado contra a glibc — interpretador
  `/lib64/ld-linux-x86-64.so.2`, `NEEDED libc.so.6` — **executou** e
  `gnu_get_libc_version()` retornou `2.42`. O rootfs deixou de ser
  musl-estático puro: binários dinâmicos glibc agora rodam. É o momento
  que o Estágio 2 perseguia desde o início (vendor dinâmico vira viável).
- **Passada 2 do gcc — nota de método:** a passada 2 pura (gcc estável)
  exige um gcc-passada-1 **com C++** para compilar o código C++ do GCC; o
  nosso foi `--enable-languages=c` (bastava para a glibc, que é C). Como o
  único compilador C++ à mão é o `zig c++`, a passada 2 aqui é um gcc
  nativo c,c++ hospedado na glibc, construído por zig c++ (dá gcc/g++ +
  libstdc++ sobre a glibc). Estabilidade plena do gcc só com um bootstrap
  self-hosted (gcc compilando a si mesmo) — trabalho seguinte.
- **Tentativa de pass-2 (2026-07-19) — muro caracterizado, não vencido.**
  Três causas-raiz atacadas em sequência: (1) os shims `cc/c++` do zig
  precisam responder opções do driver gcc (`-print-multi-os-directory`);
  (2) `zig cc -target …-musl` traz headers **musl** que conflitam com as
  premissas glibc do `system.h` do GCC → trocar para `-target …-gnu`
  (headers glibc) resolve; (3) o zig **não linka glibc estático** → os
  binários do gcc saem dinâmicos (rodam, pois a glibc está instalada —
  verificado: um exe zig-gnu dinâmico executou). Restou o muro de fundo:
  a **`configure` do GCC, sondada por zig cc, mis-detecta** `rlim_t`,
  `sbrk`, `strsignal` e gera um `auto-host.h` cujas definições-fallback
  **conflitam com os headers glibc reais** (`typedef __rlim_t long` etc.).
  Ou seja: um gcc glibc nativo construído pela semente clang esbarra na
  auto-detecção do próprio GCC. Saídas: (a) o caminho LFS correto — um
  **gcc-passada-1 COM C++** (rebuild do pass-1 com `c,c++`, que aí compila
  libstdc++ e depois o pass-2 com headers glibc coerentes), ou (b) patch/
  ajuste da `configure`/`auto-host.h`. Ambas são trabalho substancial; a
  passada 2 fica como a próxima fronteira, com o diagnóstico já feito.
- **Rebuild do pass-1 com c,c++ (2026-07-19) — bloqueado pelo MESMO muro,
  e a causa é estrutural.** A receita foi atualizada para
  `--enable-languages=c,c++` (config correta). Mas o build agora falha no
  `build/gengenrtl.o` com exatamente o conflito do pass-2: `auto-host.h`
  define `#define rlim_t` (fallback bogus da configure) que colide com o
  `typedef` da musl, mais `sbrk`/`strsignal`. **Chave:** o build C-only do
  pass-1 funcionou **antes** da glibc estar instalada; depois de instalá-la
  em `/usr/include`, a `configure` do GCC — mesmo no build cross com zig cc
  -target musl — mis-detecta esses tipos e gera o `auto-host.h` quebrado.
  Ou seja, **instalar a glibc contaminou o ambiente de build do
  gcc-por-zig-cc**. É a separação de sysroot que o LFS mantém (ferramentas
  temporárias isoladas do sistema final) e que o nosso modelo de rootfs
  único não faz. [Teoria depois CORRIGIDA — ver abaixo.]
- **CORREÇÃO do diagnóstico (2026-07-19) — NÃO é sysroot nem glibc.** Ao
  investigar para isolar a toolchain num sysroot, o mecanismo real apareceu
  e desmentiu a teoria acima. Fatos verificados: o
  `x86_64-distropica-linux-gnu-gcc` tem `-print-sysroot` **vazio** e a lista
  de includes **não contém `/usr/include`** — o compilador **não enxerga a
  glibc do sistema**. Logo, isolar um sysroot **não resolveria nada**. O
  muro real é um conflito **musl × `system.h` do GCC**: o `system.h`
  declara `extern void *sbrk(int)` (e um análogo p/ `strsignal`) como
  fallback quando a `configure` reporta `HAVE_DECL_SBRK=0`, mas a musl
  declara `sbrk(intptr_t)` (`unistd.h:164`) — `int` vs `intptr_t` colide
  nas ferramentas `build/` (gengenrtl, genhooks). A `configure` mis-detecta
  `HAVE_DECL_SBRK/STRSIGNAL=0` (o teste roda sem o feature-macro que a musl
  exige p/ declará-los), e o `auto-host.h` é **regenerado pelo
  `config.status` durante o `make`** — então corrigir o arquivo à mão não
  gruda (só os `libiberty/config.h` de subdir mantiveram o patch; o
  `auto-host.h` voltou a 0). O conserto tem de ser no nível da `configure`:
  o cache var certo (`ac_cv_have_decl_sbrk=yes` tentado não pegou no subdir
  `gcc/` — nome/propagação a investigar) ou um patch em `system.h`/config.
  É atrito **conhecido** de "GCC sobre musl" (Alpine e musl-cross-make
  compilam GCC com/para musl usando config de triplet musl próprio). A
  próxima fronteira é essa correção pontual GCC×musl — **não** a
  reestruturação de sysroot que a teoria anterior sugeria. Fica registrado
  para não repetir o caminho errado.
- **CACHE VAR ACHADO + muro das ferramentas de build QUEBRADO (2026-07-19).**
  O `ac_cv_have_decl_sbrk` não pegava porque o GCC usa macro **própria**
  (`gcc_AC_CHECK_DECL`, em `gcc/acinclude.m4:27`) que cacheia em
  **`gcc_cv_have_decl_<fn>`** — não no `ac_cv_` padrão. Além disso, a
  configure do subdir `gcc/` roda **durante o `make`**, então o cache var
  tem de estar **exportado no ambiente do make**. Com
  `gcc_cv_have_decl_sbrk=yes gcc_cv_have_decl_strsignal=yes` exportados +
  um patch no `gcc/configure` neutralizando o fallback `#define rlim_t long`
  (esse check é `AC_TRY_COMPILE` inline, sem cache var), o `auto-host.h`
  passou a ter `HAVE_DECL_SBRK/STRSIGNAL 1`, o `rlim_t` sumiu, e as
  ferramentas `build/` (gengenrtl, genhooks) **compilaram** — o build
  avançou ~5,5 mil linhas, para dentro do GCC de verdade (c-lang.o). Muro
  antigo derrubado.
- **A cauda que resta (por que o c,c++ ainda não fecha).** Dois fatores
  independentes:
  1. **Cascata de decls:** são **58** `HAVE_DECL_*=0` mis-detectados (a
     configure roda os checks em C++ e não vê as declarações GNU da musl).
     A maioria é inofensiva (fallback = protótipo da musl), mas
     `sbrk`/`strsignal`/`vasprintf`/… conflitam. Forçar **todos** a `yes`
     em massa gera erro NOVO (`functions that differ only in their return
     type`) em outros (`getwd` etc.) — precisa ser **cirúrgico**, só nos
     que de fato colidem. Cache vars nos dois prefixos:
     `gcc_cv_have_decl_*` (gcc/) e `ac_cv_have_decl_*` (libiberty).
  2. **libc++ × glibc em /usr/include:** aqui a glibc instalada MORDE de
     verdade — não pelo sysroot do compilador, mas porque
     `--with-gmp=/usr` injeta `-I/usr/include`, e agora essa pasta tem o
     `stdio.h` da glibc, que vem **antes** do `<stdio.h>` do libc++ do zig
     → `<cstdio>` do libc++ quebra ("header search paths not configured").
     Conserto: instalar/apontar as libs matemáticas num include **isolado**
     da glibc (`--with-gmp=<dir só das mathlibs>`), ou `-isystem`.
  Conclusão prática: o caminho limpo é a **configuração musl sistemática**
  (patches/`t-musl` à la Alpine/musl-cross-make) + separar os headers das
  mathlibs da glibc — não overrides ad-hoc, que revelam camada após camada.
  O cache var (a pergunta) está respondido: **`gcc_cv_have_decl_<fn>`**,
  exportado no ambiente do make.
- **RESOLVIDO — a passada 1 com C++ COMPILA (2026-07-19).** Correção
  cirúrgica dos decls + isolamento das mathlibs fecharam o build. As quatro
  peças, todas na receita `gcc`: (1) patch no `gcc/configure` neutralizando
  `#define rlim_t long`; (2) cache vars `gcc_cv_have_decl_*`/`ac_cv_have_decl_*=yes`
  para os ~55 decls que a musl declara (exceto glibc-only mallinfo/mallinfo2/
  ldgetname) — a `getwd`/`strstr` NÃO davam return-type-conflict de verdade,
  era cascata do `<cstdio>` quebrado; (3) mathlibs copiadas p/ um prefixo
  isolado (`$WORK/mathlibs`) e `--with-gmp=` apontando lá, tirando o
  `-I/usr/include` da glibc do caminho do libc++; (4) gcov-tool fora de
  LANGUAGES. Resultado: o build completou 66 mil linhas e produziu **`cc1`
  (242 MB), `cc1plus` (256 MB), `xgcc`, `xg++`**. Instalado; o
  `x86_64-distropica-linux-gnu-g++` **compila C++ → assembly** (cc1plus
  funciona). O `libstdc++` ainda não (é `--without-headers`; vem com a
  glibc). Com o cc1plus pronto, a **passada 2 destrava**: agora há um gcc
  real (não zig cc) capaz de compilar o código C++ do GCC contra a glibc.
- **libstdc++ construída (2026-07-20).** Do subdir `libstdc++-v3` do fonte do
  gcc, pelo pass-1 (perfil cross), agora com a glibc. É o elo entre pass-1
  (`--without-headers`: tem cc1plus, nenhuma libstdc++) e pass-2 — sem ela o
  g++ compila C++ mas não linka. Muro: o pass-1 gcc não conhece `/usr`
  (headers nem startfiles). Conserto: `-isystem /usr/include -B/usr/lib
  -L/usr/lib`. Produziu `libstdc++.so.6.0.34`. (receita `libstdcxx`.)
- **PASSADA 2 — o compilador construído, e o achado profundo do E2
  (2026-07-20).** O gcc nativo c,c++ (build=host=target=distropica, hospedado
  na glibc, feito pelo pass-1) foi levado até **cc1+cc1plus construídos e
  funcionais** (1586 objetos, `all-gcc` fechado, selftest passou). Oito muros,
  cada um diagnosticado:
  1. `C++14 required` → build nativo puro (build=host=target), não cross;
  2. `build-libiberty` sem `<stdlib.h>` → **shims** do cross gcc/g++ que
     injetam os paths `/usr` (não flag-por-fase, um poço sem fundo);
  3. `obstack.h` da glibc sombreava o da libiberty → **`-isystem`** (buscado
     após os `-I` do pacote), não `-I`;
  4. selftest falhava porque o **cc1 não carregava** — não era o selftest;
  5. `cc1: /usr/lib/libc.so: invalid ELF header` → os **mathlibs eram musl**
     (`NEEDED libc.so`); um cc1 glibc não os carrega;
  6. gmp configure: `g()` = 0 args (**C23** mudou `()`) → `-std=gnu17`;
  7/8. `ld: liblto_plugin.so: dynamic loading not supported` — o `ld`/`ar` da
     **semente são estáticos musl** e não fazem `dlopen`; nem `--disable-lto`
     resolve, pois o `ar` é configurado com `--plugin`.

  **A lição do E2 (que o LFS não vê, pois lá nada é musl):** *todo o
  toolchain-semente construído musl/estático pelo zig precisa ser
  reconstruído como glibc antes da passada 2* — os **mathlibs** (senão o cc1
  glibc não os carrega) e os **binutils** (senão o ld/ar estático não faz
  dlopen do plugin). Ordem revisada do E2: pass-1 → glibc → **mathlibs-glibc**
  → libstdc++ → **binutils-glibc** → pass-2. Os mathlibs-glibc já foram
  reconstruídos (gmp/mpfr/mpc, `NEEDED libc.so.6`, com `-std=gnu17`); os
  binutils-glibc são o próximo passo, e então a passada 2 fecha as target-libs
  (libgcc + libstdc++ do alvo).
- **PASSADA 2 FECHADA — O ESTÁGIO 2 ESTÁ VENCIDO (2026-07-20).** Com os
  binutils-semente reconstruídos como glibc (dinâmicos → `ld`/`ar` fazem
  `dlopen`), o muro do `libgcc_s.so` caiu, a libgcc e a **libstdc++ do alvo**
  compilaram, e `make install` produziu `gcc`/`g++` **nativos** (11 MB cada,
  GCC 15.3.0, dinâmicos glibc). Prova (sem shims, sem flags, só `PATH=/usr/bin`):
  - `gcc` compila **C** e roda (`self-host ok`);
  - `g++` compila **C++/STL** (vector/string/unique_ptr) e roda — binário
    dinâmico `NEEDED libstdc++.so.6, libc.so.6`, interpretador
    `/lib64/ld-linux-x86-64.so.2`.
  Detalhes de fechamento: o `liblto_plugin.so` herdado do pass-1 tinha `NEEDED
  libc.so` (musl) e falhava ao carregar — substituído pelo do pass-2 (glibc);
  `libgcc_s.so.1` e a `libstdc++.so.6.0.34` do pass-2 (com symbol versioning)
  instalados em `/usr/lib`. LTO fica desligado por opção (`--disable-lto`), o
  que é coerente com o pass-1. **O objetivo central do projeto — produzir uma
  glibc E um gcc nativo a partir de um mundo musl com semente zig — está
  cumprido.**
- **Transcrição em receitas (2026-07-20).** A investigação (feita via bwrap
  direto) virou receitas versionadas em `newspeak/`, cada uma codificando os
  consertos provados: `libstdcxx`, `mathlibs-glibc` (gmp+mpfr+mpc glibc,
  `-std=gnu17`), `binutils-glibc` (`--enable-plugins`), `gcc-pass2` (triple
  nativo, shims `-isystem` do pass-1, `--disable-lto`, `SELFTEST_TARGETS=`,
  reconciliação lib64→lib). A **ordem do E2** fica no grafo de DEPS:
  `rectify gcc-pass2` puxa `glibc → mathlibs-glibc → libstdcxx →
  binutils-glibc → gcc-pass2` (com `gcc` pass-1 e `binutils-cross` como
  BUILD_DEPS). Validadas: sintaxe (`sh -n`) e carga (campos + DEPS).

  **O gap que a transcrição expôs — supersessão / fingerprint de build.** Os
  rebuilds-glibc instalam nos **mesmos caminhos** dos seus equivalentes
  semente (mathlibs-glibc × gmp/mpfr/mpc; binutils-glibc × binutils;
  gcc-pass2 × gcc). No `rectify`, isso dispara *doublethink* (SPEC-0003 §7),
  porque o modelo hoje trata "mesmo caminho, dono diferente" como colisão. É
  o E2 é uma **sequência de substituições** — reconstruir o mesmo software com
  um toolchain melhor, in-place.

  **As duas metades do executor — fechadas (2026-07-20).**
  1. *Fingerprint de build* (SPEC-0011 §4): o registro guarda `FINGERPRINT` e o
     `rectify` re-builda quando a receita muda sem bump de versão. Resolve o
     rebuild-in-place da **mesma** receita.
  2. *Supersessão provisional* (SPEC-0003 §3): os builds-semente
     (gmp/mpfr/mpc/binutils/gcc) foram marcados `PROVISIONAL=1` — cedem seus
     caminhos aos rebuilds-glibc (mathlibs-glibc/binutils-glibc/gcc-pass2) sem
     *doublethink*, como o busybox cede a coreutils. Resolve a colisão entre
     receitas de **nomes distintos** que se substituem.

  Com as duas, o executor tem tudo para rodar a cadeia do E2 pelo `rectify`.

  **Exercido pelo `rectify` (2026-07-20).** `minitrue rectify gcc-pass2` (com
  `--root <rootfs>`) resolveu e construiu a cadeia pela ferramenta —
  **15 de 16** pacotes retificados na ordem do grafo, cada um dirigido em
  bwrap: toda a base seed, o **gcc pass-1** (o build flaky, limpo), a **glibc**
  (perfil **cross**), e os rebuilds-glibc (`mathlibs-glibc`, `binutils-glibc`,
  `libstdcxx`) com a **supersessão provisional** funcionando de fato (as linhas
  `assume o controle de … (provisório)` no log). O `FINGERPRINT` é gravado em
  cada registro. Rodar pela ferramenta **expôs quatro bugs que o build manual
  mascarava** (a ordem real do grafo + o ambiente hermético), todos corrigidos
  nas receitas:
  1. `gmp --enable-cxx` exigia libstdc++ que ainda não existe nesta ordem
     (mathlibs-glibc precede libstdcxx) → removido (o gcc usa a API C do gmp);
  2/3. *doublethink* de arquivos compartilhados: `binutils-cross` × `binutils-
     glibc`, e a libstdc++ do `gcc-pass2` × `libstdcxx` → marcar os scaffoldings
     `binutils-cross` e `libstdcxx` como `PROVISIONAL`;
  4. o teste de gmp/mpfr/mpc da `configure` do gcc falhava: o ld do cross gcc
     não resolve o dep **transitivo** `libmpc → libm.so.6` (o `-L` cobre só o
     `-l` direto) → `-Wl,-rpath-link,/usr/lib` no shim do `gcc-pass2`.

  A **lição**: todo scaffolding superseder por um build glibc/nativo é
  `PROVISIONAL` (a cadeia de cessão seed→cross→glibc é o que faz o bootstrap
  caber no modelo de pacotes), e o cross gcc precisa de `-rpath-link` para os
  deps transitivos das mathlibs.

  **E2 FECHADO COMO FLUXO (2026-07-20).** Com os quatro consertos,
  `rectify gcc-pass2` rodou os **16 pacotes** até o fim pela ferramenta
  (`gcc-pass2 … compilado e retificado`, `FINGERPRINT` gravado, gcc-pass2
  cedendo do gcc-semente provisional). O gcc **nativo produzido pelo rectify**
  (não por scripts) compila e roda **C** (`self-host ok`) e **C++/STL**
  (`libstdc++.so.6, libc.so.6` — dinâmico glibc), sem shims.

  **E2-CLEAN — reproduzível a frio (2026-07-20).** A primeira prova rodou num
  rootfs trabalhado; agora foi refeita **do zero**. Um rootfs **novo**
  (`rootfs-clean`), semeado só com o E0/E1 (busybox, zig, make — verificado:
  registros = exatamente esses três, zero resíduo do E2) e o cache de fontes,
  rodou `rectify gcc-pass2 --offline` e construiu os **16 pacotes** de ponta a
  ponta, com o grafo corrigido. Resultado: o `gcc`/`g++` **nativos** compilam e
  rodam **C** (`self-host ok`) e **C++/STL**, e a **`libstdc++` final está em
  `/usr/lib`** (não a intermediária em lib64) — as libs finais são as
  selecionadas.

  Rodar a frio **expôs dois bugs que o rootfs trabalhado mascarava**, ambos
  corrigidos: (1) `doublethink: /usr/bin/ar já pertence a busybox` — a
  supersessão declarativa (`SUPERSEDES`, SPEC-0003 §7) não cobria seed→busybox;
  `binutils`/`gawk` passaram a declarar `SUPERSEDES="busybox"`; (2) o híbrido
  `libstdc++` em `/usr/lib64` × o shim `-L/usr/lib` (o gcc x86_64 instala em
  lib64, o sistema é /usr/lib) — `libstdcxx` reconcilia lib64→lib e o `stage0`
  faz `/usr/lib64 → lib` (usr-merge). Também a aresta `gcc → binutils-cross`
  (que faltava) foi confirmada na ordem: binutils-cross **antes** de gcc.

  **Falta para "reproduzível ×2":** repetir num **segundo** ambiente limpo
  independente (a reprodutibilidade *de artefato* — byte-a-byte — já está
  provada para gcc e glibc em SPEC-0010 §6; o cotejo do artefato do E2-clean
  completo é o passo restante). Os scripts hoje transitórios em
  `rootfs/tmp/*.sh` DEVEM ser promovidos, junto com hashes e logs, para
  `proofs/e2/` versionado; o rootfs em si continua fora do repositório.

## 5. Estágio 3 — boot de verdade

**Entregável:** Distrópica dá boot em hipervisor UEFI até login.

- Kernel da fonte, configuração mínima virtio e drivers indispensáveis ao
  instalador embutidos;
- kernel **EFI-stub** com initramfs BusyBox e o `init` vivo legível, gerado por
  `bootstrap/live/build-efi` como `BOOTX64.EFI`;
- a variante humana DEVE ter simpledrm e fbcon built-in
  (`CONFIG_SYSFB_SIMPLEFB`, `CONFIG_DRM_SIMPLEDRM`,
  `CONFIG_DRM_FBDEV_EMULATION`, `CONFIG_DRM_CLIENT_DEFAULT_FBDEV` e
  `CONFIG_FRAMEBUFFER_CONSOLE`) e deixar `console=tty0` como o último console
  da cmdline, para que prompts e teclado funcionem no framebuffer UEFI;
- **sem bootloader separado no v0:** OVMF/UEFI carrega o mesmo EFI-stub da
  mídia e da ESP instalada. Sem mídia, o initramfs localiza a raiz por
  `LABEL=DISTROPICA_ROOT` e faz `switch_root`;
- na mídia, o PID 1 chama primeiro
  `minipax install-media --only-binary --export-boot-efi`, materializa closure
  e EFI em `/run` e os verifica sem ter pedido disco algum. Só então exige que
  o disco inteiro seja autorizado explicitamente, protege o dispositivo da
  própria mídia, cria ESP FAT32 + raiz ext2, copia e verifica o root preparado,
  instala o snapshot EFI, publica o marcador completo por último e reinicia;
- runit como PID 1 + mdev permanece o contrato do sistema final (SPEC-0006).
  O target mínimo de desenvolvimento aceito hoje usa o `/sbin/init` disponível
  e chegou a `rcS`/getty.

**Estado de implementação (2026-07-22):** há dois aceites deliberadamente
separados. `bootstrap/live/accept-qemu` passou offline, sem NIC, com a variante
automatizada (`/dev/vda` + `distropica.test=1`): ISO → disco raw vazio, boot
sem ISO até `rcS`/getty e probe negativo fail-before-wipe. A variante humana,
sem `--install-device`, passou em `bootstrap/live/accept-virtualbox` com
EFI64/VMSVGA/SATA: prompts gráficos de senha e disco, alvo `/dev/sda`, ejeção
da ISO depois do preflight e antes do wipe, reboot pelo VDI sem ISO, getty e
login `root` comprovado como uid 0. Instalação e segundo boot ocorreram com o
cabo NAT desconectado. Um terceiro boot, agora com o cabo conectado, comprovou
DHCP IPv4 automático, rota, DNS local via resolvedor da NAT e acesso ao gateway;
depois de desligar novamente o link, instalou `ripgrep` 15.2.0 do objeto extra
do cache com `--offline` e terminou com `minitrue verify` limpo. Essa é a
evidência histórica network-v1; ela está
em `target/vbox-acceptance-network-v1/evidence/acceptance.meta`. Duas composições
locais dessa ISO humana foram byte a byte idênticas, com SHA-256
`3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d`; o EFI
medido foi
`71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88`.
O cache continua sendo um override `custom`, e o ensaio não comprova Internet,
hardware real, reprodução entre builders independentes nem uma ISO oficial
publicada.

O runner atual foi adaptado ao novo contrato: ripgrep 15.2.0 deve estar
presente desde o primeiro boot; Zig e GNU Make começam ausentes; depois de
desconectar a rede, `minitrue --offline --no-binary rectify make` deve compilar
GNU Make 4.4.1, instalando Zig 0.16.0 automaticamente como dependência de build.
O aceite exige `make` no `world`, Zig fora dele e `minitrue verify` limpo. Essa
nova prova ainda depende de recompor a mídia e executar o runner no VirtualBox.

**Critério normativo de aceite do estágio completo:** boot UEFI chega a getty;
login root; `minitrue verify` limpo. O aceite VirtualBox fecha os três pontos em
hipervisor, inclusive o `verify` executado depois do login e da instalação
offline de um pacote adicional. Continuam abertas as dívidas de runit e o
aceite em hardware real.

## 6. Estágio 4 — userland vendor

**4a — console (barato):** node, go, rustup, bun, deno, jq, vscode-server,
sqlite… — praticamente tudo cai pronto do mundo A após o E2.

**4b — GUI (a Longa Marcha):** o Firefox oficial precisa de GTK3, que
precisa de glib/pango/cairo/harfbuzz, que precisam de wayland + **mesa** —
nada disso tem binário upstream elegível. É o maior custo de compilação do
projeto inteiro, e fica explicitamente fora do caminho crítico dos
estágios 0–4a. Compositor alvo mínimo (labwc? cage?) e escopo exato: spec
futura própria.

## 7. Resumo

| Estágio | Entregável | Risco dominante |
|---------|-----------|-----------------|
| E0 | chroot musl-estático habitável | baixo |
| E1 | `./configure && make` funciona | atrito zig-cc×autotools |
| E2 ✅ | ABI glibc + gcc nativo (pass-2) — **E2-clean: reproduzido a frio** de um rootfs novo (16 pacotes, libs finais selecionadas) 2026-07-20 | GCC hospedado por clang; matriz glibc↔GCC; toolchain-semente musl→glibc |
| E3 🟡 | EFI-stub + instalação offline; QEMU automatizado cobre segundo boot e fail-before-wipe, e o VirtualBox network-v1 histórico cobre prompts, `/dev/sda`, reboot sem ISO, login root, DHCP/DNS/gateway VirtIO NAT, instalação posterior de ripgrep com link desligado e `verify` limpo. O novo aceite ripgrep-default + build offline de Make/Zig ainda precisa ser executado; runit segue aberto | hardware real e política final de init |
| E4a | userland vendor console | baixo |
| E4b | GUI + Firefox | volume brutal de fonte (mesa/GTK) |

## 8. Registro do spike E0/E1 (2026-07-19)

Provas executadas em host real (kernel 7.0, AppArmor com userns restrito),
rootfs de rascunho montado à mão — cada linha sustenta um claim desta spec:

- **busybox 1.35.0 oficial**: roda; 402 applets; sha256
  `6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348`
  (pinar na receita).
- **Entrada rootless**: `unshare -r` bloqueado pelo AppArmor do host (sem
  perfil para o unshare); `bwrap` 0.11 funcionou com perfil de fábrica —
  §2 atualizado. DNS e rede ok lá dentro.
- **busybox wget**: NÃO completa handshake TLS moderno com ziglang.org
  (falha até com `--no-check-certificate`) — o minitrue é o único
  buscador viável do E0, agora por necessidade e não só por desenho.
- **zig cc**: hello musl-estático compilado e executado num rootfs sem
  `/lib` algum. `-target x86_64-linux-musl` explícito é obrigatório.
- **GNU make 4.4.1** (`./configure && ./build.sh` sob busybox ash):
  ok com o shim de `ld` e as flags acima; o make resultante executa
  Makefiles e **recompila a si mesmo** dentro do rootfs.
- **Rust musl estático** (ensaio do minitrue): `ureq`/rustls buscou HTTPS
  **sem `/etc/ssl` no sistema** (raízes Mozilla embutidas confirmadas);
  `minisign-verify` validou o tarball real do Zig contra a chave pinada;
  binário `static-pie` de 2,4 MB (alvo < 5 MB da SPEC-0003 respeitado).
  Crates com C (ring) exigem wrapper de `CC` traduzindo o triple LLVM
  (`x86_64-unknown-linux-musl`) para o do zig (`x86_64-linux-musl`).
- **Fluxo P6**: o sha256 pinado do Zig conferiu no download; a cadeia
  pino → fetch → recusa/aceite foi exercitada de ponta a ponta.

## 9. Questões em aberto

- Publicar o rootfs E0 pronto como tarball de release (bootstrap sem host
  com Rust)?
- aarch64: repetir E0–E2 ou cross-compilar do x86_64 com zig?
- Ponto de corte para trocar `CC` default para gcc (E2 §4): global ou por
  receita?
