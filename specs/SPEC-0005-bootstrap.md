# SPEC-0005 — Bootstrap em estágios

**Status:** rascunho v0.2 · 2026-07-19
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

## 2. Estágio 0 — do host ao chroot (musl-estático)

**Entregável:** rootfs FHS mínimo, habitável via chroot sem privilégio.

Requisitos do host: `sh`, `tar`, `sha256sum`, `curl` ou `wget`, ~300 MB
livres, cargo/rustup para construir o minitrue (ou, futuramente, o
binário estático publicado nos releases do projeto — SPEC-0003 §10) e
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
gawk 5.4.1, gcc 15.3.0, glibc 2.42 — todos com SHA256 real pinado.

**Registro da fundação do Estágio 2 (2026-07-19).** Compilados com
`zig cc` DE DENTRO do chroot e encadeados por DEPS/BUILD_DEPS:
- **verificados de ponta a ponta:** linux-headers, m4, binutils, gmp,
  mpfr, mpc, bison, gawk. Achados que viraram desenho:
  - `make` é a ferramenta essencial do E1 — entrou no `stage0` (todo
    build de fonte a invoca);
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
- **A GLIBC 2.42 COMPILA com o gcc da passada 1 (2026-07-19) — o Estágio 2
  está essencialmente vencido.** A `configure` da glibc declarou o
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

## 5. Estágio 3 — boot de verdade

**Entregável:** Distrópica dá boot em QEMU até login.

- Kernel da fonte (gcc do E2), configuração mínima virtio;
- initramfs de busybox (script `init` de uma tela — legível inteiro,
  premissa P4);
- runit como PID1 + mdev (SPEC-0006);
- **Sem bootloader no v0:** QEMU com `-kernel bzImage -initrd …` direto.
  Hardware real também dispensa bootloader: kernel com EFI stub, decidido
  na SPEC-0008 (instalador). O initramfs localiza a raiz por
  `LABEL=distropica-root`, então nenhuma cmdline é necessária.

**Critério de aceite:** `qemu-system-x86_64 -kernel … -initrd …` chega a
getty; login root; `minitrue verify` limpo.

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
| E2 | ABI glibc; vendor dinâmico roda | GCC hospedado por clang; matriz glibc↔GCC |
| E3 | boot QEMU até login | config de kernel |
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
