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
8. **Opinativa — uma escolha canônica por função.** Onde há vários softwares
   para o mesmo fim, a Distrópica escolhe: o conjunto default é curado e
   singular — Newspeak aplicado ao sistema, uma resposta por necessidade. Não
   trancada: alternativas vivem na árvore, só não são o default.

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
| [SPEC-0008](specs/SPEC-0008-instalador.md) | `minipax` — instalação direta e composição determinística de mídia pelo mesmo perfil |
| [SPEC-0009](specs/SPEC-0009-canais-binarios.md) | Canais binários (oficial e samizdat) — o usuário não compila a base |
| [SPEC-0010](specs/SPEC-0010-reprodutibilidade.md) | Builds reprodutíveis — a raiz de confiança dos canais |
| [SPEC-0011](specs/SPEC-0011-release-rolling.md) | Modelo de release: rolling *edge* — sempre o estável mais recente |
| [SPEC-0012](specs/SPEC-0012-ministerios.md) | Os quatro ministérios — fronteiras de responsabilidade das ferramentas |

## Estado

Um **protótipo sério de engenharia de sistemas** — ainda um laboratório, não
uma distribuição pronta para usuários. A matriz precisa do que está feito,
testado e futuro vive em **[STATUS.md](STATUS.md)**.

A barreira técnica que justificava o projeto — compilar o "mundo antigo" a
partir de nada além de binários upstream — foi **demonstrada**:

- **Bootstrap (Estágio 2) — executado pelo `rectify`.** A partir de um mundo
  musl semeado apenas pelo binário oficial do Zig (`zig cc`), o `minitrue
  rectify gcc-pass2` construiu os 16 pacotes até um **gcc nativo** (C e C++)
  hospedado na **glibc**, sem toolchain de outra distro. O **E2-clean** já foi
  executado uma vez, a frio, num rootfs novo com o grafo corrigido; falta uma
  segunda execução em ambiente independente para a prova forte (SPEC-0005 §4).
- **`minitrue` — implementado** (Rust): mundo A (`/opt`) e mundo B (`/usr`),
  hash + assinatura (minisign), registros em texto com **fingerprint de build**
  e **manifesto v2** (conteúdo + tipo, alvo de symlink e árvore mundo A),
  empacotamento determinístico (`pack`), imagem de STAGE selada, attestations
  Ed25519 sem replay histórico, toolchain por estágio, journal transacional com
  recuperação global no mundo B, runner de build em rootfs via bwrap e
  **`explain`/`why`** (a proveniência como comando).
  Há uma suíte local automatizada; a matriz de cobertura vive no `STATUS.md`.
- **`minipax` — núcleo implementado** (Rust): resolve um perfil comum, sela
  seus insumos num `profile.lock`, materializa o sistema em um `--target` e
  compõe mídias determinísticas nos formatos GPT/FAT32 (`.img`) e ISO9660
  UEFI (`.iso`). Instalação direta e geração de mídia usam o mesmo
  `target.world`, `live.world`, overlay, árvore Newspeak e cache fechado.
  Perfil, mídia e instalação recebem classes separadas que descrevem apenas
  quais **insumos** foram pinados — nunca se autoatribuem a condição de
  reprodução oficial.
  Isso ainda não equivale a uma mídia oficial inicializável: o perfil oficial
  continua marcado como desenvolvimento e o `BOOTX64.EFI` precisa ser
  fornecido pronto ao compositor.
- **Bootstrap (Estágio 3) — smoke parcial.** O kernel compilado pelo gcc nativo
  boota em QEMU com raiz 9p somente-leitura e `busybox init`. O login foi
  observado num rootfs com `/etc/shadow` previamente provisionado; initramfs,
  runit e o caminho UKI/EFI do sistema instalável ainda não foram fechados.
- **Reprodutibilidade — provada.** Dois builds independentes de m4, gmp, gcc e
  glibc produzem artefato byte-a-byte idêntico (SPEC-0010).

Ainda não fechados: o instalador interativo e destrutivo de disco, o init
(runit), o kernel EFI com initramfs da mídia viva, os canais binários, o
`--sync` e o rollback retido do mundo B entre versões ou de uma sincronização
inteira. O mundo A ainda não tem transação de conjunto e a durabilidade do
journal não cobre perda de energia (`fsync` é dívida). Ver
[STATUS.md](STATUS.md).

Alvo inicial: **x86_64**.

## Um perfil, três entradas

O contrato almejado faz da futura ISO mínima oficial, da instalação iniciada
de outra distribuição e da mídia gerada pelo próprio usuário três entradas
para o **mesmo pipeline**. A fonte da identidade dos insumos é o perfil
resolvido e seu `profile.lock`, que vincula os worlds do ambiente vivo e do
sistema-alvo, o overlay, a árvore Newspeak, o cache opcional, a arquitetura,
o `SOURCE_DATE_EPOCH` e a prontidão declarada para instalação.

O invólucro público de desenvolvimento pode ser usado assim:

```sh
# Forma da instalação direta numa raiz montada; não particiona discos.
./bootstrap/distropica-bootstrap install \
  --profile profiles/official --target /mnt

# Compor uma imagem de pendrive GPT/FAT32 a partir do mesmo perfil.
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode online --format img \
  --boot-efi caminho/BOOTX64.EFI --output distropica.img

# Compor a variante ISO9660 UEFI (requer xorriso).
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode online --format iso \
  --boot-efi caminho/BOOTX64.EFI --output distropica.iso
```

O perfil `profiles/official` ainda declara `INSTALL_READY=no`, pois hoje faltam
os canais/toolchain capazes de fechar `base` e `linux` num alvo vazio. Portanto
o primeiro comando documenta a interface e **recusa antes de tocar em `/mnt`
neste marco**; ele funciona para perfis de desenvolvimento que declarem
`INSTALL_READY=yes` e possuam um world materializável. As composições de mídia
continuam estruturais e exigem um EFI fornecido pelo chamador.

O modo `online` não incorpora cache e deixa a obtenção dos artefatos para a
instalação. O modo `offline` exige `--cache DIR` e leva esse snapshot fechado
na mídia; a instalação direta equivalente usa `--offline --cache DIR`.
`--world`, `--live-world` e `--overlay` criam uma variante personalizada,
identificada como `custom` no lock e nos manifestos. Saídas de mídia recebem
os sidecars `.sha256`, `.media.lock` e `.manifest`; cada nome é publicado sem
sobrescrita. O conjunto de quatro arquivos, contudo, ainda não é uma transação
única contra outros escritores: uma corrida pode deixar sidecars já publicados
sem a imagem final.

Um perfil de release precisa pinar três hashes:
`OFFICIAL_CONTENT_SHA256`, `OFFICIAL_BOOT_EFI_SHA256` e
`OFFICIAL_MINITRUE_SHA256`. `PROFILE_CLASS` confirma somente o primeiro;
`MEDIA_CLASS` acrescenta a conferência do EFI; `INSTALL_CLASS`, a do executável
`minitrue`. O valor máximo positivo é `official-inputs`, não “reprodução”. Uma
reprodução oficial só fica comprovada quando o SHA-256 final da mídia coincide
com um manifesto oficial externo e assinado.

Na instalação, o `minitrue` escolhido é copiado para um `memfd`, selado contra
escrita e executado sempre desse snapshot; seu hash entra no
`install.manifest`. Neste marco, cada árvore de Newspeak, overlay ou cache é
limitada a 128 MiB de conteúdo regular e 50 mil entradas. Streaming e uma
partição de dados própria para caches maiores continuam gates de release.

Neste marco, o script constrói os binários Rust quando Cargo está disponível,
ou aceita `MINIPAX` e `MINITRUE` já fornecidos. O bundle estático assinado, os
canais que alimentam uma instalação comum e o kernel vivo EFI ainda são gates
de release. Na variante ISO, versão e SHA-256 do `xorriso` são registrados e o
compositor recusa se o binário mudar durante a execução, mas a toolchain e o
bundle completos ainda não estão pinados. Por isso o repositório **não anuncia
uma ISO oficial pronta, instalável ou com boot comprovado**; o compositor
existente produz e descreve a mídia a partir de um executável EFI fornecido
explicitamente.

## Segurança e validação

O `minitrue` assume que a árvore sob `--root` pode conter estado hostil ou
incompleto. Nas operações do mundo B, cada mutação é precedida por uma intenção
em journal; um processo interrompido é recuperado antes da próxima retificação
ou remoção. Leituras, comparações e remoções sensíveis ficam confinadas ao
rootfs e recusam symlinks intermediários, arquivos especiais e metadados
ambíguos. O artefato verificado também permanece selado entre o hash e a
aplicação no sistema.

Receitas transitivas participam do fingerprint de build. Attestations Ed25519
incluem formato, versão e fingerprint da receita, portanto não podem ser
reaplicadas silenciosamente a outro build. Hashes e assinaturas de fontes são
revalidados mesmo quando o artefato vem do cache.

Essas garantias cobrem **crash de processo**, não falta de energia: ainda não há
uma disciplina completa de `fsync`. A transação de conjunto também é exclusiva
do mundo B; a troca de versões do mundo A continua sendo uma dívida explícita.
Por fim, uma attestation comprova concordância com o registro local — a
distribuição externa desse registro ainda pertence à futura infraestrutura de
canais. Os limites detalhados e a matriz de cobertura estão no
[STATUS.md](STATUS.md).

Os verificadores usados no desenvolvimento podem ser reproduzidos com:

```sh
(cd minitrue && cargo test --all-targets)
(cd minitrue && cargo clippy --all-targets -- -D warnings)
(cd minipax && cargo test --all-targets)
(cd minipax && cargo clippy --all-targets -- -D warnings)
(cd minitrue && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps)
(cd minipax && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps)
(cd minitrue && cargo fmt --check)
(cd minipax && cargo fmt --check)
sh -n bootstrap/distropica-bootstrap
```

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
