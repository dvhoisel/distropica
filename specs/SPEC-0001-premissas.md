# SPEC-0001 — Premissas e política de elegibilidade

**Status:** rascunho v0.6 · 2026-07-23
**Palavras-chave normativas:** DEVE / NÃO DEVE / DEVERIA / PODE (interpretação análoga à RFC 2119).

## 1. Premissas fundadoras

### P0 — Pragmatismo acima de ideologia

A Distrópica é **pragmática acima de ideológica**. As premissas abaixo
(P1–P6) NÃO são dogmas: cada uma existe por um **fim prático** —
simplicidade inspecionável, controle do usuário, não reinventar o que o
upstream já entrega. Quando a *letra* de uma regra colidir com o *fim* que
a justifica, o fim vence, e a regra é emendada — estas specs são rascunhos
versionados, não escritura. Não se recusa uma solução por ela ser "impura";
recusa-se por ela ser pior para o usuário. Toda premissa DEVERIA poder
responder "que problema concreto do usuário isto resolve?"; a que não
responder é candidata a corte.

Exemplos já no corpo destas specs, de pragmatismo sobre purismo:

- vendorizar um `.deb`/`.rpm` do mantenedor como **envelope passivo**
  (extrair o conteúdo, jamais rodar os scripts) em vez de exigir tarball —
  aproveita o binário upstream sem adotar o formato (§2, SPEC-0007);
- semear o mundo-fonte com o `zig cc` — um toolchain **gordo** (Clang+LLD+
  fontes de libc), o oposto do minimalismo —, porque é um binário upstream
  único e reprodutível que destrava todo o resto (SPEC-0005);
- uma versão ativa por pacote em vez de um solver de versões: menos poder,
  mas explicável com `cat` (P1).

**A ressalva — "a ideologia que vale é a dela mesma".** Há exatamente uma
coisa que a Distrópica NÃO troca por conveniência: a própria identidade — a
coerência do sistema, o mandato de inspecionabilidade ("explicável em uma
página", P4) e o caráter Newspeak que a nomeia. Tudo o mais é meio, e meios
se escolhem pelo que funciona; esse núcleo é o fim. É o único dogma, e é o
dela: **não há purismo herdado que a governe, só a sua própria coerência.**

**O que o pragmatismo NÃO flexibiliza.** P0 governa *meios*, e jamais serve
de desculpa para afrouxar em silêncio o que é *fim*. Três coisas nunca cedem
a uma "conveniência", porque são a própria identidade que P0 protege:

- **P6** — nada é usado sem hash pinado; nenhum atalho o dispensa (a única
  exceção, `--tofu`, *cria* o pino, não o remove — P6);
- **rastreabilidade** — toda instalação é auditável na sua proveniência
  (`ORIGIN`/`TRUST`, SPEC-0009 §8); nenhum caminho pode apagar a trilha ou
  registrar menos do que fez;
- **consentimento** — decisão de confiança (samizdat `builder`, TOFU,
  remoção com perda) exige opt-in explícito e gritante, nunca um default
  silencioso.

Um "pragmatismo" que enfraquece qualquer um destes está negociando a
identidade, não um meio — e aí P0 se volta contra si mesmo. Se a praticidade
e um destes colidirem, o fim vence e o atalho é recusado, com a razão dita
em voz alta.

O eco distópico é proposital. No romance, o Partido não serve a doutrina
nenhuma além da perpetuação de si mesmo — "o objetivo do poder é o poder".
A Distrópica inverte a piada a favor do usuário: nenhuma ortodoxia externa
a comanda, e ainda assim a forma é a mesma — **a única lealdade é à casa.**

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

Aplicada recursivamente, P2 resolve o mundo B: o que não tem binário
upstream a Distrópica compila **uma vez** e publica como binário do
próprio projeto (o **canal binário**, SPEC-0009). A partir daí existe um
binário elegível, e P2 manda preferi-lo à fonte — então o usuário final
não recompila a base. Compilar de fonte na máquina do usuário vira o
último recurso, só para o que nem o upstream nem nenhum canal confiável
publica.

### P3 — Fonte apenas na falta

O que não tem binário elegível é compilado da fonte oficial do projeto.
Builds do mundo-fonte DEVERIAM usar toolchain que é ela mesma binário
upstream (`zig cc` — ver SPEC-0005) e DEVERIAM preferir linkagem estática
quando razoável, para reduzir o grafo de dependências em runtime.

P2 e P3 definem a preferência de origem, não dispensam o fechamento. Toda
origem precisa satisfazer o mesmo grafo tipado de runtime, build, toolchain e
ABI especificado na SPEC-0013.

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

**A única exceção — `--tofu` — e por que não fere P6.** Escrever uma receita
nova exige obter, uma vez, o hash que ainda não existe. `minitrue --tofu`
(SPEC-0003 §2) faz isso: baixa, calcula e **imprime a linha `SHA256=…` para
o autor colar** na receita e commitar. É um *aid de autoria* que **cria** o
pino — não um bypass que o dispensa. Depois disso, todo uso (o do autor e o
de qualquer outro) confere contra o hash pinado, como manda P6; a árvore
versionada continua sendo a fonte de verdade. As três amarras que o mantêm
dentro de P6: (a) se a receita pina `SIGKEY`, a assinatura é exigida **mesmo
em TOFU** — nem o primeiro fetch é cego; (b) `--tofu` existe somente no build
explícito de autoria (`bootstrap/build-minitrue.sh --authoring`, feature Cargo
`tofu-authoring` sem default) e não é compilado na interface distribuída; (c)
nada é instalado num sistema alheio a partir de hash não-pinado — o pino nasce na máquina do
autor e chega aos outros já congelado no commit. TOFU é como um pino passa a
existir, não uma licença para viver sem ele.

### P7 — Edge: sempre o estável mais recente

A Distrópica é **edge**: para cada componente, a árvore newspeak pina a
**versão estável mais recente** do upstream — a começar pelo **kernel**, que
acompanha o *stable* mais novo do kernel.org, não um LTS antigo.

**Edge é o estável mais recente, não *bleeding edge*.** Nada de release
candidates, betas, nightlies ou snapshots de git — é a fronteira do que já é
estável, não do que ainda não é. (Distingue-se do "edge" do Alpine, que
nomeia o ramo *instável*; o edge da Distrópica é o oposto — o estável na sua
borda mais nova.)

Edge é **política de versão** (qual versão a árvore pina); o **rolling**
(SPEC-0011) é o **mecanismo** (como a árvore se move e o sistema converge). Os
dois casam: a árvore é continuamente reapontada para o estável-mais-novo, e
`rectify --sync` retifica o sistema a ela. Seguir o binário do mantenedor
(P2) passa a significar seguir o **último estável** dele — a segurança vem do
rollback e da reprodução (SPEC-0011, SPEC-0010), não de ficar para trás.

**Ressalva pragmática (P0).** Edge é o **default**, não um absoluto: quando o
estável-mais-novo regride, a receita PODE pinar uma versão anterior sã, com o
motivo registrado. Precedente do próprio bootstrap: **gawk 5.3.2**, porque o
5.4.1 tinha uma regressão que quebrava o gcc (SPEC-0005). Edge nunca embarca o
comprovadamente quebrado — o fim (um sistema que funciona) vence a letra (a
versão mais nova).

**Como isto é FEITO CUMPRIR.** A P7 é verificável e foi violada em silêncio: a
0.12 saiu com o kernel 7.1.4 enquanto o kernel.org já publicava o 7.1.8. Nada na
árvore acusou, porque nenhum guarda olhava para fora dela — a receita não sabe
que existe versão mais nova, os aceites provam que a mídia instala e não que
está atual, e o `channel emit` audita fechamento de dependências, não idade.
Desde então, conferir a versão de TODO software empacotado é exigência de
publicação, e não etapa opcional: SPEC-0011 §7.1.

Tema: o **presente eterno**. Não se cultua a versão "antiga, estável e
testada" — isso seria preservar o passado. Retifica-se para o agora.

### P8 — Opinativa: uma escolha canônica por função

Para muitas funções há mais de um software (editor, shell, coreutils, servidor
de DNS…). A Distrópica **escolhe**: o conjunto default é **curado e singular**
— uma ferramenta canônica por função, não um cardápio de equivalentes com um
sistema de "alternativas" a configurar.

É **Newspeak aplicado ao sistema**: assim como a árvore newspeak dá um nome sem
ambiguidade a cada pacote (SPEC-0004), a instalação default dá uma resposta sem
ambiguidade a cada necessidade. Menos escolha imposta ao usuário, menos
superfície de teste, menos fadiga de decisão — a simplicidade que P4 promete,
estendida do mecanismo ao conteúdo. O precedente já está no projeto: **runit**
como init (não systemd, não OpenRC, não s6 — P4/SPEC-0006) é uma escolha
opinativa, não um default entre iguais; P8 generaliza a postura para o conjunto
base.

**Opinativa não é trancada (P0, controle do usuário).** A curadoria decide o
que vem **por default** em `target.world` — hoje `base`, `linux`, `ripgrep`,
`vim` e o metapacote `miniplenty-buildbase` (SPEC-0008 §2 e §4.2) —, não o que
é **permitido**. `base` não é meta: é uma receita `KIND=source` de montagem que
materializa configuração real; `miniplenty-buildbase` é que agrega Make e a
toolchain final sem payload próprio. Vim é o editor canônico já instalado e
ncurses entra apenas como sua dependência transitiva. Alternativas que valham a
pena vivem na árvore e o usuário as instala com um `rectify`; elas só não são a
resposta default. A liberdade que importa — trocar a ferramenta — fica; a que
se remove — ter de escolher tudo antes de começar — é atrito, não liberdade.

Disponibilidade offline tampouco é escolha default. O `cache.world` atual exige
`jq`, `make`, `tree` e `zig`, mas jq e tree começam ausentes do sistema
instalado: o primeiro prova o consumo offline de um binário upstream elegível;
o segundo prova a compilação offline da fonte oficial com a toolchain nativa.
Só um pedido explícito ao Minitrue transforma cada um em intenção e fato.

Critério da escolha: coerência com as premissas (binário upstream elegível, P2;
explicável e inspecionável, P4; sem arrastar dependências que firam P1) e, entre
os que passam, o de menor peso e maior clareza. A escolha e o porquê ficam na
árvore (o `ABOUT` da receita), auditáveis.

Tema: o Partido decide qual é a palavra certa — aqui, a favor do usuário. A
escolha é feita uma vez, com transparência, para que ninguém precise refazê-la
a cada instalação.

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
- Reprodutibilidade bit-a-bit: começou como aspiração, mas virou
  **mecanismo de segurança** dos canais binários (SPEC-0010): é o que faz
  o binário de canal ser verificável por reprodução (SPEC-0009 §6). Há provas
  históricas para m4, gmp, gcc e glibc nos artefatos então medidos; a receita
  atual de `gcc-pass2` com `install-strip` e a closure completa ainda precisam
  de nova reprodução.
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
