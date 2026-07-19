# SPEC-0001 — Premissas e política de elegibilidade

**Status:** rascunho v0.5 · 2026-07-18
**Palavras-chave normativas:** DEVE / NÃO DEVE / DEVERIA / PODE (interpretação análoga à RFC 2119).

## 1. Premissas fundadoras

### P1 — Nenhum gerenciador de pacotes existente

A Distrópica NÃO DEVE adotar, embutir ou depender de apt, dnf, pacman, apk,
xbps, portage, nix, guix, flatpak, snap, homebrew ou equivalentes — nem como
mecanismo interno, nem como fonte de artefatos.

A ferramenta própria (`minitrue`, SPEC-0003) existe, mas é deliberadamente
menor que um gerenciador clássico:

- sem solver de dependências com versões (uma versão ativa por pacote; a
  árvore de receitas em um dado commit É o conjunto consistente);
- sem protocolo de repositório próprio (transporte = HTTPS simples);
- sem banco de dados opaco (estado = arquivos-texto em `/var/lib/minitrue`,
  legíveis com `cat`).

**Fronteira com gerenciadores de linguagem** (pip, cargo, npm, gem…),
inspirada no conceito *Aliens* do GoboLinux: são ferramentas de
desenvolvimento **do usuário**, não do sistema. Regras: (a) operam
estritamente per-user, em `$HOME` (venvs, `~/.cargo`, prefixo npm do
usuário) — NUNCA em caminho de sistema; (b) nenhum pacote da Distrópica
PODE depender deles em runtime; (c) necessidades internas de build (ex.:
o Python que compila a glibc) são resolvidas por receitas do mundo B,
invisíveis ao usuário.

### P2 — Binário do mantenedor original primeiro

Para cada pacote, se existir **binário elegível** (§2), a receita DEVE usá-lo.
Compilar algo que o mantenedor já distribui pronto é considerado desperdício
e desvio de premissa.

### P3 — Fonte apenas na falta

O que não tem binário elegível é compilado da fonte oficial do projeto.
Builds do mundo-fonte DEVERIAM usar toolchain que é ela mesma binário
upstream (`zig cc` — ver SPEC-0005) e DEVERIAM preferir linkagem estática
quando razoável, para reduzir o grafo de dependências em runtime.

### P4 — Sem systemd

O sistema NÃO DEVE conter systemd nem seus satélites (journald, logind,
udevd do systemd, timers) e NÃO DEVE exigir dbus para funções básicas.
Racional e desenho do init: SPEC-0006. Princípio orientador: **devolver a
simplicidade ao usuário** — qualquer mecanismo do sistema base deve ser
explicável em uma página e inspecionável com ferramentas de texto.

A forma concreta dessa promessa é a página de manual, na tradição OpenBSD:
todo componente do projeto DEVE entregar a sua — `minitrue(1)`,
`newspeak(5)`, `minipax(8)` — e **a página é o contrato de comportamento**
da ferramenta instalada. O formatador da base é o `mandoc` (fonte pequena,
mundo B).

### P5 — FHS 3.0

O layout DEVE seguir o Filesystem Hierarchy Standard 3.0 (SPEC-0002). Os
binários de vendor vivem em `/opt/<nome>` (previsto pelo próprio FHS); o
mundo compilado vive em `/usr`; estado da ferramenta em `/var`. Nada de
hierarquias exóticas.

### P6 — A rede nunca decide o que é verdade

Todo artefato baixado DEVE ser conferido contra hash SHA-256 pinado na
receita **antes** de qualquer uso. Hash divergente ⇒ recusa imediata
(*crimestop*), sem opção de contorno por flag de força. O registro (a
receita versionada) é a fonte de verdade; a rede é só transporte.

Quando o upstream publica assinaturas (minisign, signify, OpenPGP), a
receita DEVERIA piná-las — e DEVE, nos pacotes da base (estágios 0–3) —
com a chave pública versionada na própria árvore (SPEC-0004 §5). A
assinatura **complementa** o hash, nunca o substitui: o hash congela o
artefato exato que o autor da receita viu; a assinatura protege o momento
da **repinagem** (troca de versão), provando que o artefato novo veio de
quem sempre veio. Chaves NÃO DEVEM ser buscadas em keyservers ou URLs em
tempo de instalação.

## 2. O que conta como "binário do mantenedor original"

Um artefato é **elegível** quando TODAS as condições valem:

1. Publicado pelo próprio projeto ou vendor em canal oficial: site do
   projeto, GitHub/GitLab Releases do repositório oficial, ou CDN do vendor.
2. Formato de **embalagem passiva**: tarball, zip, binário solto.
3. `.deb`/`.rpm` publicados **pelo vendor** (ex.: Google Chrome, VS Code,
   Discord) são elegíveis **como embalagem**: o conteúdo é extraído
   (`ar`/`bsdtar`); maintainer scripts (pre/postinst) NÃO DEVEM ser
   executados em hipótese alguma. O formato é só o envelope.

NÃO são elegíveis:

- repositórios de qualquer distribuição (Debian, Fedora, Alpine, AUR, PPA…);
- imagens de contêiner (as camadas embutem userland de outra distro);
- Flathub e Snapcraft, **mesmo quando o publicador é o próprio upstream** —
  consumi-los exigiria adotar o gerenciador deles, violando P1;
- AppImages, ainda que publicadas pelo upstream — embutem um userland de
  bibliotecas construído sobre outra distro e dependem de FUSE ou de
  auto-extração; estão mais para imagem de contêiner do que para binário
  limpo do vendor. Quando o AppImage for o **único** formato oficial
  (ex.: Inkscape, Krita), o pacote vai para o mundo-fonte;
- binários "famosos porém de terceiros" (ex.: builds estáticos de ffmpeg de
  johnvansickle). Caso o site oficial do projeto endosse explicitamente um
  build de terceiro, a classificação é decidida caso a caso na receita, com
  a justificativa registrada (`ABOUT`) — ver questões em aberto.

## 3. Tema e tom (1984)

Vocabulário oficial: `minitrue` (ferramenta), `rectify` (instalar/atualizar),
`memoryhole` (remover), `newspeak` (árvore de receitas), `room101` (logs de
builds falhos), `minipax` (instalador — SPEC-0008), *crimestop* (recusa por
hash ou assinatura), *doublethink* (colisão de arquivos), *thinkpol*
(verificação).

Regra de tom: mensagens PODEM ser temáticas, mas o diagnóstico técnico vem
primeiro. Um erro DEVE conter causa, caminho e ação sugerida; a piada é
acabamento, nunca substituto de informação.

## 4. Não-objetivos (v0)

- Múltiplas arquiteturas: alvo inicial é **x86_64**; receitas DEVERIAM ser
  estruturadas para acomodar aarch64 depois, sem compromisso de prazo.
- Reprodutibilidade bit-a-bit: aspiração, não requisito.
- Multilib/i686: fora.
- Sandbox forte de builds: desejado, mas não bloqueia o v0 (SPEC-0003 §8).
- Secure boot, instalador gráfico, suporte a hardware exótico: fora.
  (Instalador de **texto** existe e tem spec própria: `minipax`,
  SPEC-0008 — alvo UEFI x86_64, sem bootloader.)

## 5. Questões em aberto

- Critério formal para builds "endossados pelo site oficial" (caso ffmpeg →
  builds BtbN linkados por ffmpeg.org): elegível ou não? Proposta pendente.
- GNU coreutils da fonte vs. uutils-coreutils (Rust) que publica binário
  oficial musl estático: a escolha filosófica fica para a receita `coreutils`
  (ver SPEC-0007 §4).
