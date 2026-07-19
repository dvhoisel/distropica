# SPEC-0005 — Bootstrap em estágios

**Status:** rascunho v0.1 · 2026-07-18
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
livres, e cargo/rustup para construir o minitrue (ou, futuramente, o
binário estático publicado nos releases do projeto — SPEC-0003 §10).

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
3. Entrada sem root: `unshare -r -m -p -f` + mount de `/proc` + binds
   mínimos de `/dev` + `chroot` (script `enter.sh`; exige userns não
   privilegiado habilitado no kernel do host).

**Critérios de aceite:**
- `busybox sh` interativo dentro do chroot;
- `zig cc -target x86_64-linux-musl hello.c` produz binário estático que roda;
- `minitrue rectify ripgrep` **dentro** do chroot baixa, verifica e instala
  (rede funciona via userns; TLS via raízes embutidas no minitrue).

## 3. Estágio 1 — autossuficiência do mundo-fonte

**Entregável:** chroot capaz de `./configure && make` com `CC="zig cc"`.

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
pontuais do clang embutido. Mitigação: `CC="zig cc"` é clang — casos
rebeldes ganham patch em `files/` com justificativa.

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

## 8. Questões em aberto

- Publicar o rootfs E0 pronto como tarball de release (bootstrap sem host
  com Rust)?
- aarch64: repetir E0–E2 ou cross-compilar do x86_64 com zig?
- Ponto de corte para trocar `CC` default para gcc (E2 §4): global ou por
  receita?
