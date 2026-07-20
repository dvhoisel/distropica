# Distrópica

> Uma distribuição Linux distópica. Não instala pacotes: **retifica registros**.

A Distrópica parte de uma observação desconfortável sobre o mundo atual: os
projetos novos (Zig, Go, Rust, os aplicativos das corporações) distribuem
binários oficiais prontos, enquanto o mundo antigo (GNU, glibc, o núcleo do
que chamamos de "sistema") exige compilação a partir dos manuscritos. A
Distrópica abraça essa distopia em vez de escondê-la: **usa o binário do
mantenedor original sempre que ele existir, e compila da fonte apenas o que
ninguém mais se dá ao trabalho de distribuir**.

Não há gerenciador de pacotes herdado — nem apt, nem pacman, nem flatpak. Há
o `minitrue`, uma ferramenta mínima que busca, verifica, registra e apaga.
Quando algo é removido, ele nunca existiu.

É uma *rolling release* **edge**: a árvore aponta sempre para a versão estável
mais recente do upstream, e o sistema é continuamente retificado para o
presente — nunca um release congelado. O passado é reescrito para bater com o
agora.

## Premissas

Acima de todas, uma lente (**P0**): a Distrópica é **pragmática acima de
ideológica** — cada premissa existe por um fim prático, não por dogma, e a
única ideologia inegociável é a coerência da própria casa.

1. **Nenhum gerenciador de pacotes existente.** A ferramenta própria
   (`minitrue`) é deliberadamente pequena: sem solver, sem protocolo de
   repositório, sem banco de dados opaco. O estado é o filesystem.
2. **Binário do mantenedor original primeiro.** Se o projeto publica binário
   oficial para Linux, é ele que entra — verificado por hash.
3. **Fonte só na falta.** O que não tem binário elegível é compilado, de
   preferência com uma toolchain que é ela mesma um binário upstream
   (`zig cc`).
4. **Sem systemd.** PID1 mínimo e inspecionável. Devolver a simplicidade ao
   usuário: todo mecanismo do sistema deve ser explicável em uma página.
5. **FHS 3.0.** Nada de hierarquias exóticas: vendors em `/opt`, mundo
   compilado em `/usr`, estado em `/var`.
6. **A rede nunca decide o que é verdade.** Todo artefato é conferido contra
   o hash pinado na receita. Divergência é *crimestop*.
7. **Edge — sempre o estável mais recente.** A árvore pina a versão estável
   mais nova do upstream (a começar pelo kernel); *edge* é o estável na sua
   borda, não *bleeding edge*. Rolling: não há versão-do-sistema nem release
   congelado.

## Especificações

| Spec | Assunto |
|------|---------|
| [SPEC-0001](specs/SPEC-0001-premissas.md) | Premissas, política de elegibilidade de binários, tema |
| [SPEC-0002](specs/SPEC-0002-hierarquia-fhs.md) | Hierarquia de arquivos (FHS 3.0, os dois mundos) |
| [SPEC-0003](specs/SPEC-0003-minitrue.md) | `minitrue` — a ferramenta (CLI, fluxos, registros) |
| [SPEC-0004](specs/SPEC-0004-newspeak.md) | `newspeak` — formato das receitas |
| [SPEC-0005](specs/SPEC-0005-bootstrap.md) | Bootstrap em estágios (E0 chroot → E4 desktop) |
| [SPEC-0006](specs/SPEC-0006-init.md) | Init e serviços sem systemd (busybox init → runit) |
| [SPEC-0007](specs/SPEC-0007-censo-binarios.md) | Censo de binários upstream (quem publica o quê) |
| [SPEC-0008](specs/SPEC-0008-instalador.md) | `minipax` — o instalador (mídia viva, EFI stub sem bootloader) |
| [SPEC-0009](specs/SPEC-0009-canais-binarios.md) | Canais binários (oficial e samizdat) — o usuário não compila a base |
| [SPEC-0010](specs/SPEC-0010-reprodutibilidade.md) | Builds reprodutíveis — a raiz de confiança dos canais |
| [SPEC-0011](specs/SPEC-0011-release-rolling.md) | Modelo de release: rolling *edge* — sempre o estável mais recente |

## Estado

A barreira técnica que justificava o projeto — compilar o "mundo antigo" a
partir de nada além de binários upstream — está **vencida**.

- **Bootstrap (Estágio 2) — vencido.** A partir de um mundo musl semeado
  apenas pelo binário oficial do Zig (`zig cc`), a Distrópica compila uma
  **glibc** e um **gcc nativo** (C e C++) — sem toolchain de nenhuma outra
  distro. O gcc final, hospedado na glibc, compila e roda C e C++/STL
  (SPEC-0005).
- **`minitrue` — implementado** (Rust): mundo A (binários vendor em `/opt`) e
  mundo B (compilação para `/usr`), verificação por hash + assinatura
  (minisign), registros em texto, empacotamento determinístico (`pack`),
  toolchain por estágio e um runner de build hermético (bwrap). Com os
  primeiros testes automatizados.
- **Reprodutibilidade — provada.** Dois builds independentes de m4, gmp, gcc e
  glibc produzem artefato byte-a-byte idêntico — a raiz de confiança dos
  canais binários (SPEC-0010).

Ainda em design ou não implementados: o instalador (`minipax`), o init
(runit), os canais binários, e a execução **ponta-a-ponta** do bootstrap pelo
próprio `minitrue` — hoje as receitas do Estágio 2 existem, mas a cadeia foi
provada por experimentos diretos; fechá-la pelo `rectify` depende do
*fingerprint de build* (SPEC-0011 §4).

Alvo inicial: **x86_64**.

## Vocabulário

| Termo | Significado |
|-------|-------------|
| `minitrue` | A ferramenta central (Ministério da Verdade) |
| `minipax` | O instalador (Ministério da Paz — anexa territórios novos) |
| `rectify` | Instalar/atualizar — retificar os registros |
| `memoryhole` | Remover — o pacote nunca existiu |
| `newspeak` | A árvore de receitas — vocabulário mínimo, sem ambiguidade |
| `room101` | `/var/log/room101/` — para onde vão os logs de builds que quebraram |
| `unperson` | Pacote desativado sem remoção: segue em `/opt`, mas some de todos os registros visíveis |
| `samizdat` | Canal binário não oficial porém confiável (SPEC-0009) — o livro clandestino, circulado fora do canal oficial |
| *crimestop* | Recusa automática de artefato com hash divergente |
| *doublethink* | Colisão: dois pacotes reivindicando o mesmo arquivo |
