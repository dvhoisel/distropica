# SPEC-0007 — Censo de binários upstream

**Status:** rascunho v0.4 · 2026-07-19
**Método:** coluna "verificado" = checagem direta na data indicada (URL do
canal oficial consultada); "notório" = sabidamente publicado, a re-verificar
no momento de escrever a receita. Elegibilidade conforme SPEC-0001 §2.

## 1. A leitura distópica

O padrão empírico que batiza a distribuição: **o mundo novo distribui
binários; o mundo antigo exige compilação dos manuscritos.** Toolchains
modernas (Zig, Go, Rust), utilitários reescritos em Rust e os aplicativos
das corporações caem prontos do céu. A base GNU/C que sustenta tudo —
glibc, coreutils, make, bash — não tem binário oficial de espécie alguma.

Implicação estratégica: **o caro na Distrópica é a base, não o desktop.**
Por isso o bootstrap (SPEC-0005) gira em torno de conquistar a glibc, e o
custo GUI (mesa/GTK) é isolado no Estágio 4b.

## 2. Mundo A — publicam binário Linux oficial (✓)

| Pacote | Formato oficial | Verificado | Nota |
|--------|-----------------|-----------|------|
| zig 0.16.0 | tar.xz + sha256 em índice JSON + minisig | 2026-07-18 | o compilador semente (E0) |
| busybox 1.35.0 | binário estático solto | 2026-07-18 | oficial porém 2022; recompilar no E1 |
| ripgrep 15.2.0 | tar.gz musl estático + .sha256 | 2026-07-18 | roda desde o E0 |
| uutils-coreutils 0.9.0 | tar.gz musl estático | 2026-07-18 | coreutils sem compilar (§4) |
| neovim v0.12.4 | tar.gz | 2026-07-18 | glibc ⇒ pós-E2; aceite do E2 (AppImage oficial existe, mas é inelegível) |
| sqlite tools 3.53 | zip de binários | 2026-07-18 | |
| go | tar.gz (go.dev/dl) | notório | glibc-free na prática |
| rust | rustup + toolchains oficiais | notório | motor do próprio minitrue |
| node | tar.xz (nodejs.org) | notório | glibc |
| bun / deno | zip/tar (releases oficiais) | notório | |
| jq / fd / fzf / shellcheck / pandoc | releases oficiais | notório | vários estáticos |
| firefox / thunderbird | tar.xz (Mozilla) | notório | glibc + GTK ⇒ E4b |
| blender | tar.xz | notório | glibc + GL |
| vs code | tar.gz oficial | notório | glibc |
| google chrome | .deb do vendor (embalagem) | notório | SPEC-0004 §4.4 |
| libreoffice | tar.gz contendo .deb/.rpm (embalagem) | notório | |
| telegram / discord | tar.xz / tar.gz | notório | proprietários; política própria? (§5) |
| obsidian 1.12.7 | tar.gz (há também .deb) | 2026-07-18 | sobrevive ao banimento de AppImage: tar.gz oficial existe |

## 3. Mundo B — sem binário oficial (✗ ⇒ fonte)

| Pacote | Situação | Papel na Distrópica |
|--------|----------|---------------------|
| glibc | só fonte; exige GCC | a conquista do E2 |
| gcc / binutils | só fonte | E2 |
| gnu make | só fonte | primeiro build (truque `build.sh`) |
| bash | só fonte | adiável: `busybox ash` cobre o começo |
| gnu coreutils | só fonte | ou uutils (§4) |
| curl | **sem binário oficial Linux** (verificado 2026-07-18: página oficial só lista pacotes de distros) | dispensável: quem busca é o minitrue |
| wget / wget2 | **só fonte** (verificado 2026-07-18: ftp.gnu.org tem apenas tar.gz/lz/bz2 + .sig) | dispensável como o curl: quem busca é o minitrue — **obrigatoriamente**: o applet `wget` do busybox 1.35 nem completa handshake TLS moderno (spike 2026-07-19, SPEC-0005 §8) |
| git | só fonte (https exige libcurl+tls ⇒ build pesado) | adiável: newspeak atualiza por tarball (SPEC-0003 §11) |
| python | **só fonte** (python.org não publica binário Linux) | pré-requisito do build da glibc; a ironia registrada |
| perl, openssh, tmux, vim, htop | só fonte | conforme demanda |
| mandoc | só fonte (BSD, minúsculo) | formata os manuais da base; man page é contrato (SPEC-0001 P4) |
| kernel linux | só fonte | E3 |
| wayland / mesa / gtk | só fonte | a Longa Marcha (E4b) |
| inkscape, krita | único binário oficial é AppImage ⇒ inelegível (SPEC-0001 §2) | mundo B, por consequência do banimento de AppImage |
| ffmpeg | caso-limite: site oficial aponta builds de CI de terceiro (BtbN) | classificação pendente (SPEC-0001 §5) |

## 4. O dilema coreutils

Dois caminhos para `ls`, `cp`, `sha256sum`:

1. **GNU coreutils da fonte** — tradição, cobertura total; custo: build
   mundo B cedo no ciclo.
2. **uutils-coreutils binário oficial musl estático** — zero compilação,
   coerência máxima com P2; custo: compatibilidade ~quase-completa e a
   constatação de que até o `ls` agora vem do mundo novo.

O busybox cobre o E0–E1 de qualquer forma. Decisão fica para a receita
`coreutils`, com `ABOUT` justificando. Tendência assumida pela premissa:
uutils (binário elegível existe ⇒ P2 manda usá-lo). Contra-argumento a
registrar: coreutils é base crítica e a versão GNU é a referência.

## 5. Questões em aberto

- Proprietários (chrome, discord, obsidian): premissa P2 os aceita sem
  cerimônia — criar campo `NONFREE=1` para o usuário poder filtrar?
- ffmpeg/BtbN e casos "CI endossada pelo site oficial": critério formal.
- Re-verificação periódica do censo: as colunas "notório" devem virar
  "verificado" à medida que as receitas forem escritas.
