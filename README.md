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

## Licença

O código, os scripts, as receitas enquanto implementação autoral, os perfis e
a documentação próprios da Distrópica são licenciados sob a **GNU GPL versão
3 ou qualquer versão posterior** (`GPL-3.0-or-later`). O texto integral está
em [LICENSE](LICENSE), o aviso conciso em [NOTICE](NOTICE) e a delimitação
completa em [LICENSING.md](LICENSING.md).

Isso não relicencia o software de terceiros: Linux e BusyBox continuam
`GPL-2.0-only`, glibc conserva LGPL/GPL, e os demais componentes mantêm as
licenças declaradas pelos respectivos upstreams. O campo `LICENSE=` de uma
receita descreve o payload instalado; a ISO reúne componentes sob licenças
distintas, cujas obrigações precisam ser avaliadas componente a componente e
nas combinações efetivamente distribuídas.

Quando houver publicação de ISO, EFI, cache ou canal binário oficial, cada
artefato deverá vir acompanhado de acesso equivalente ao seu bundle de fontes
correspondentes: revisão da Distrópica, crates Rust vendorizadas, fontes
upstream exatas, configurações, patches, scripts, licenças e inventário. O
repositório público é a fonte do desenvolvimento, mas não substitui sozinho
esse conjunto por artefato. Gerar uma imagem para uso privado não exige
publicá-la; redistribuí-la transfere ao redistribuidor as obrigações das
licenças presentes.

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
  hospedado na **glibc**, sem toolchain de outra distro. Essa execução
  **E2-clean** é evidência histórica: ocorreu uma vez, a frio, num rootfs novo
  com o grafo então vigente. As receitas atuais com `install-strip` precisam de
  rebuild e, depois, comparação entre dois ambientes limpos para uma nova prova
  forte (SPEC-0005 §4).
- **`minitrue` — implementado** (Rust): mundo A (`/opt`), mundo B (`/usr`) e
  mundo M para metapacotes declarativos (`KIND=meta`, `WORLD=M`, sem payload),
  hash + assinatura (minisign), registros em texto com **fingerprint de build**
  e **manifesto v2** (conteúdo + tipo, alvo de symlink e árvore mundo A),
  empacotamento determinístico (`pack`), imagem de STAGE selada, attestations
  Ed25519 sem replay histórico, toolchain por estágio, journal transacional com
  recuperação global no mundo B, runner de build em rootfs via bwrap e
  **`explain`/`why`** (a proveniência como comando). O canal binário mínimo
  também está implementado: índice canônico v2 assinado por minisign, com o
  fingerprint da receita dentro da identidade autenticada, chave pinada,
  artefatos `.tar.zst` endereçados por conteúdo, lock imutável v2 da seleção e
  resolução `--no-binary`/`--only-binary` sem puxar dependências de build
  quando um artefato de canal é escolhido. `verify` coteja semanticamente a
  proveniência gravada com esse lock, inclusive caminho e fingerprint.
  Há uma suíte local automatizada; a matriz de cobertura vive no `STATUS.md`.
- **`minipax` — núcleo implementado** (Rust): resolve um perfil comum, sela
  seus insumos num `profile.lock`, materializa o sistema em um `--target` e
  compõe mídias determinísticas nos formatos GPT/FAT32 (`.img`) e ISO9660
  UEFI (`.iso`). Instalação direta e geração de mídia usam o mesmo
  `target.world`, `live.world`, `cache.world`, overlay, árvore Newspeak e cache
  fechado. O lock v2 autentica `cache.world` separadamente: ele declara
  disponibilidade offline verificável, não intenção de instalação.
  Perfil, mídia e instalação recebem classes separadas que descrevem apenas
  quais **insumos** foram pinados — nunca se autoatribuem a condição de
  reprodução oficial. O perfil de desenvolvimento declara `base`, `linux`,
  `ripgrep` e `miniplenty-buildbase` como target padrão. Esse último é um metapacote sem
  payload: suas dependências diretas são `base`, `make` e `gcc-pass2`, cuja
  closure final instala `linux-headers`, glibc, `mathlibs-glibc`,
  `binutils-glibc` e o GCC nativo. Assim, Make, `gcc`, `g++`, `as`, `ld`, `ar`
  e `ranlib` já fazem parte do sistema mínimo, vindos do canal em uma instalação
  `--only-binary`; Zig permanece apenas no cache e é materializado sob demanda
  quando uma compilação fonte `seed`/`cross` realmente ocorre. Antes de
  retificar o target, o Minipax confere os artefatos declarados em `cache.world`
  com `minitrue --offline cache verify`. `install-media` valida o payload antes
  de materializá-lo. O perfil fixa `MEDIA_SIZE_MIB=512` para dimensionar a
  saída IMG e registrar esse parâmetro no lock; a ISO cresce conforme o payload
  e não fica limitada nem preenchida até 512 MiB por esse campo.
- **Mídia viva UEFI — implementação inicial.**
  `bootstrap/live/build-efi` produz um kernel EFI-stub com initramfs,
  BusyBox, Minipax e Minitrue `static-pie` ligados com musl. O PID 1 encontra a
  mídia e, **antes de pedir ou apagar um disco**, materializa e verifica toda a
  closure em `/run`, configura a conta root e exporta para um snapshot medido o
  EFI validado pelo próprio `install-media`. Só então exige a escolha explícita
  do disco, cria ESP FAT32 + raiz ext2, copia o sistema preparado, executa
  `minitrue verify`, instala o EFI e publica por último o marcador de instalação
  completa. A execução final-v10 passou no aceite automatizado QEMU/OVMF e
  também recusou um `profile.lock` incoerente com `media.meta` antes de
  qualquer escrita no disco, cobrindo essa ordem *fail-before-wipe*. Uma ISO
  interativa separada passou no VirtualBox 7.2.6: exibiu os prompts no
  framebuffer, instalou em SATA (`/dev/sda`) e completou o segundo boot sem ISO
  e com o cabo de rede desligado. Num terceiro boot com VirtIO NAT, obteve DHCP,
  rota e DNS local; depois desligou novamente o cabo, instalou o `ripgrep 15.2.0`
  somente do cache com `minitrue --offline rectify` e terminou com `verify`
  limpo. Essa é evidência histórica da revisão network-v1. O runner atual foi
  alterado para exigir ripgrep e `miniplenty-buildbase` já no primeiro sistema
  instalado e, ainda sem rede, compilar, linkar e executar C, C++, uma biblioteca
  estática e um Makefile com a toolchain nativa; Zig precisa continuar ausente
  do sistema e disponível apenas no cache. A nova mídia ainda precisa passar por
  esse aceite. O kernel mantém
  `CONFIG_MODULES=y`, mas a mídia não distribui módulos:
  os drivers indispensáveis são built-in e o release
  `7.1.4-distropica-live` evita procurar acidentalmente os módulos `7.1.4` do
  target. Isso ainda não é uma ISO oficial publicada nem prova suporte a
  hardware UEFI genérico.
- **Bootstrap (Estágio 3) — smoke parcial.** O kernel compilado pelo gcc nativo
  boota em QEMU com raiz 9p somente-leitura e `busybox init`. O login foi
  observado num rootfs com `/etc/shadow` previamente provisionado. O caminho
  EFI/initramfs da mídia, separado desse smoke, passou no aceite funcional
  QEMU/OVMF; runit e a gestão completa do boot instalado seguem abertos.
- **Reprodutibilidade — prova histórica parcial.** Dois builds independentes
  produziram artefatos byte a byte idênticos de m4, gmp, gcc e glibc nas
  receitas e payloads então medidos (SPEC-0010). As receitas atuais de
  `gcc-pass2` e `binutils-glibc`, alteradas para solicitar `install-strip`,
  ainda precisam de rebuild repetido e nova comparação.

Ainda não fechados: publicação de um canal oficial e de um bundle estático
assinados, reprodução independente da mídia, cobertura de hardware UEFI real,
runit, a operação administrativa `channel refresh`, `--sync` e o rollback
retido do mundo B entre versões ou de uma sincronização inteira. O Journal
ainda usa caminhos entre validação e mutação e, portanto, não promete resistir
a um processo hostil concorrente alterando o mesmo rootfs; migrá-lo integralmente
para operações fd-relative é gate de release. O mundo A ainda não tem transação
de conjunto e a durabilidade do journal não cobre perda de energia (`fsync` é
dívida). Ver
[STATUS.md](STATUS.md).

Alvo inicial: **x86_64**.

## Um perfil, três entradas

O contrato faz da futura ISO mínima oficial, da instalação iniciada de outra
distribuição e da mídia gerada pelo próprio usuário três entradas para o
**mesmo pipeline**. A fonte da identidade dos insumos é o perfil
resolvido e seu `profile.lock`, que vincula os worlds do ambiente vivo, do
sistema-alvo e da disponibilidade de cache, o overlay, a árvore Newspeak, o
cache opcional, a arquitetura, o `SOURCE_DATE_EPOCH` e a prontidão declarada
para instalação. `target.world` é intenção de instalação; `cache.world` apenas
exige que artefatos possam ser verificados offline. O documento atual usa
`PROFILE_LOCK_FORMAT=2` e `PROFILE_CONTENT_FORMAT=2`; `CACHE_WORLD_SHA256`
prende a lista normalizada.

O caminho hoje fechado é o de desenvolvimento **offline**, com um cache de
canal assinado. Os exemplos abaixo supõem esse cache em `$CACHE` e privilégios
para escrever no target ou no disco.

### ISO interativa de desenvolvimento

Este é o caminho para uma pessoa e o candidato técnico à futura mídia oficial:
o EFI é construído **sem** `--install-device`. Ele não escolhe disco nem
autoriza destruição na linha de comando do kernel; depois de validar todo o
payload, o instalador pede uma senha e exige que a pessoa digite explicitamente
o dispositivo inteiro que será apagado. Enquanto perfil, canal, cache e
manifesto de release não forem publicados com pinos oficiais, a saída abaixo
continua sendo uma composição local `development`/`custom`, não uma ISO oficial.

```sh
# 1. Instalação direta numa raiz já montada; não particiona discos.
./bootstrap/distropica-bootstrap install \
  --profile profiles/official --target /mnt \
  --offline --cache "$CACHE" --only-binary

# 2. Constrói o ambiente vivo UEFI. Minipax/Minitrue precisam ser estáticos;
# o script pode compilá-los para x86_64-unknown-linux-musl.
bootstrap/live/build-efi --output target/BOOTX64.EFI

# 3. Compõe uma ISO instalável com o mesmo perfil e cache (requer xorriso).
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode offline --cache "$CACHE" \
  --format iso --boot-efi target/BOOTX64.EFI \
  --output target/distropica.iso

# A variante para pendrive usa o mesmo payload em GPT/FAT32.
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode offline --cache "$CACHE" \
  --format img --boot-efi target/BOOTX64.EFI \
  --output target/distropica.img
```

A ISO interativa pode ser exercitada de ponta a ponta no VirtualBox. O runner
cria uma VM efêmera com UEFI64, VMSVGA, SATA/AHCI e uma interface VirtIO NAT
inicialmente com o cabo desligado; por padrão, o VDI tem 4096 MiB e aparece no
guest como `/dev/sda`.
Depois que a closure já está validada em RAM, ele ejeta a ISO **antes** de enviar
a autorização de wipe, instala no VDI e comprova o segundo boot e o login de
root ainda sem rede. Nesse segundo boot, exige ripgrep 15.2.0, o registro
`KIND=meta`/`WORLD=M` de `miniplenty-buildbase`, GNU Make 4.4.1, binutils 2.45 e
GCC/G++ 15.3.0 já instalados. Ainda sem link, compila e executa programas C e
C++, cria e liga um arquivo estático e constrói outro programa por Makefile;
depois roda `minitrue verify`. Só então, num terceiro boot, conecta o cabo e
prova DHCP IPv4, rota padrão, `resolv.conf`, resolução de `localhost` pelo
resolvedor NAT e alcance do gateway do VirtualBox. Zig deve permanecer sem
binário e sem registro: ele é cache/semente sob demanda, não parte do target.

`miniplenty-buildbase` não carrega arquivos próprios. A receita declara
`DEPS="base make gcc-pass2"`; seu registro M e manifesto vazio representam o
conjunto solicitado, enquanto os pacotes da closure têm registros próprios.
Além de Make e GCC, a closure final traz `linux-headers`, glibc,
`mathlibs-glibc` e `binutils-glibc`. Como `base` e o metapacote são desejos
explícitos do perfil, ambos entram em `/etc/minitrue/world`; as dependências da
toolchain ficam instaladas sem se tornarem desejos top-level.

O `cache.world` do perfil declara GNU Make e Zig como disponibilidades
obrigatórias da mídia offline. Na instalação, o Minipax chama
`minitrue --offline cache verify make zig` antes de `rectify`: hashes e a
assinatura do Zig são conferidos sem download, registro ou instalação. Isso
mantém distintas a disponibilidade no cache, autenticada por
`CACHE_WORLD_SHA256`, e a intenção do `target.world`. Make acaba instalado por
ser dependência de `miniplenty-buildbase`, não por constar em `cache.world`;
Zig continua apenas disponível para futuras compilações fonte.

O núcleo desse percurso já foi exercitado separadamente numa cópia isolada do
target, antes da adoção do metapacote e sem atribuir a ele o aceite da ISO:
`cache verify make zig` conferiu os tarballs e a assinatura minisign do Zig; em
seguida,
`minitrue --offline --no-binary rectify make` partiu sem registros de Zig/Make,
instalou Zig 0.16.0 como dependência, compilou GNU Make 4.4.1, deixou somente
`make` no `world` e terminou com `minitrue verify` limpo. Essa continua sendo
uma evidência histórica válida do caminho fonte; o runner atual não recompila
Make e testa, em vez disso, a toolchain final já instalada.
O diretório de execução precisa ser novo:

```sh
bootstrap/live/accept-virtualbox \
  --iso target/distropica.iso \
  --run-dir target/acceptance-virtualbox
```

O cenário descrito acima ainda precisa ser validado com uma mídia recomposta.
As receitas de `gcc-pass2` e `binutils-glibc` passaram a solicitar
`make install-strip`, e o grafo final também mudou; portanto seus payloads e
fingerprints precisam ser reconstruídos, os pacotes precisam ser reemitidos no
canal e o índice/cache/lock/EFI/ISO precisam ser regenerados antes do aceite.
O perfil passou a `MEDIA_SIZE_MIB=512`, que dimensiona somente a saída IMG; a
ISO acompanha o tamanho real do payload. Os runners QEMU e VirtualBox usam
discos de 4096 MiB por padrão. Nada disso constitui uma nova execução. O
aceite anterior passou em 2026-07-21 com VirtualBox
`7.2.6_Ubuntur172322`. Duas composições da ISO a partir dos mesmos insumos
foram byte a byte idênticas. Os hashes abaixo registram a evidência histórica
da revisão funcional `7148ebd`, na qual ripgrep ainda começava ausente e era
instalado explicitamente. As revisões posteriores de licenciamento, do perfil e
da toolchain exigem novo canal/cache/lock/EFI/ISO antes que exista um novo pino
de mídia:

```text
EVIDENCIA_VIRTUALBOX_INTERATIVA=local-custom
ACCEPTANCE_META=target/vbox-acceptance-network-v1/evidence/acceptance.meta
VBOX_VERSION=7.2.6_Ubuntur172322
FIRMWARE=efi64
GRAPHICS=vmsvga
STORAGE=IntelAhci
GUEST_DISK=/dev/sda
NIC_TYPE=virtio
INSTALL_NETWORK=nat-cable-disconnected
THIRD_BOOT_NETWORK=nat-cable-connected
DNS_PROBE=localhost-via-vbox-nat-host-resolver
ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
REPEATED_ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
BOOT_EFI_SHA256=71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88
RUN_STATE=passed
ISO_EJECTED_BEFORE_WIPE=yes
INSTALL_AND_SECOND_BOOT_OFFLINE=yes
SECOND_BOOT_WITHOUT_ISO=yes
ROOT_LOGIN=yes
THIRD_BOOT_WITH_NAT=yes
THIRD_BOOT_GETTY=yes
THIRD_BOOT_ROOT_LOGIN=yes
DHCP_IPV4=yes
DEFAULT_ROUTE=yes
RESOLV_CONF_IPV4_NAMESERVER=yes
DNS_LOCALHOST=yes
NAT_GATEWAY_PING=yes
NETWORK_DISCONNECTED_BEFORE_OFFLINE_RECTIFY=yes
RIPGREP_INITIAL_ABSENT=yes
RIPGREP_EXTRA_OFFLINE_RECTIFY=yes
RIPGREP_VERSION=15.2.0
MINITRUE_VERIFY_AFTER_RIPGREP=yes
FINAL_RESULT=passed
```

Essa igualdade é uma prova local de composição determinística, não uma
reprodução independente nem um pino de release. A prova de rede limita-se ao
DHCP, resolvedor de `localhost` e gateway fornecidos pelo NAT do VirtualBox: ela
não afirma acesso à Internet. O cache continua sendo um insumo local `custom`;
o ensaio também não cobre hardware real nem reprodução em outro ambiente.

### ISO automatizada destrutiva — somente aceite QEMU

O aceite QEMU usa uma imagem EFI **diferente**, construída com
`--install-device /dev/vda`. Essa opção embute no kernel a autorização para
apagar `/dev/vda` e ativa `distropica.test=1`, que mantém a conta root bloqueada
para o ensaio automático. O artefato existe exclusivamente para uma VM
descartável criada pelo runner: **nunca distribua, publique, monte em hardware
real ou apresente essa variante como ISO instalável para pessoas**.

```sh
bootstrap/live/build-efi \
  --install-device /dev/vda \
  --output target/BOOTX64-test.EFI
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode offline --cache "$CACHE" \
  --format iso --boot-efi target/BOOTX64-test.EFI \
  --output target/distropica-test.iso
bootstrap/live/accept-qemu \
  --iso target/distropica-test.iso \
  --disk target/acceptance-disk.raw \
  --log-dir target/acceptance-logs
```

Por segurança, tanto o caminho de `--disk` quanto o de `--log-dir` precisam
ainda não existir; use nomes novos ao repetir o aceite. Essa restrição refere-se
ao runner QEMU acima; o runner VirtualBox impõe a mesma política ao `--run-dir`.

O aceite final-v10 foi executado em 2026-07-21, sem NIC e com aceleração TCG.
Ele instalou a ISO num disco raw vazio e iniciou esse disco novamente sem a
ISO. Uma segunda composição da mesma ISO foi byte a byte idêntica. No teste
negativo, uma ISO com `profile.lock` adulterado foi recusada antes da mensagem
de wipe; o disco de 256 MiB permaneceu byte a byte igual a um arquivo zerado.

```text
EVIDENCIA_FINAL_V10=local-development
ACCEPTANCE_META=target/qemu-acceptance-final-v10/acceptance.meta
RUN_STATE=completed
NETWORK=none
ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
REPEATED_ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
BOOT_EFI_SHA256=c8a884845aa1568c4e51756f2a26c1b21652969367957387c5efdfb616e3204c
INSTALL_LOG_SHA256=d94ad6d3abdb99d29674c383f11106a0a23774f91b153dc1cee1b03b64d61540
BOOT_LOG_SHA256=f3e3a80d76bffd7bbb6a995a9186d1d66c4ae8902e645e48db2e3421ef69f133
CORRUPT_ISO_SHA256=c13e3d42ccc6e2129e73f8fa8df629c17803fff2a6ede756519c86791786dcf8
CORRUPT_INSTALL_LOG_SHA256=5c1004263db4ca6323ae8630cf51ceb7a313350424ad40d1886b75deadd0ebb3
CORRUPT_DISK_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
ZERO_256_MIB_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
RESULT=pass
INCONSISTENT_PROFILE_LOCK_RESULT=refused-before-wipe
```

Essa evidência continuará sendo de desenvolvimento. Ela não será pino de
release, não substituirá um manifesto oficial assinado e não indicará que
endpoint, chave ou mídia oficial tenham sido publicados.

O perfil `profiles/official` declara `INSTALL_READY=yes`, mas continua com
`STATUS=development`. A prontidão significa que o world mínimo pode ser
materializado num alvo vazio quando o cache/canal correto é fornecido; não
significa release, endpoint público ou mídia oficial. O target atual inclui
`base`, `linux`, `ripgrep` e `miniplenty-buildbase`; o metapacote `KIND=meta`
fica no mundo M sem payload e agrega Make e a toolchain GCC final. Em
`--only-binary`, o metapacote é resolvido localmente, mas seus pacotes fonte
precisam existir como artefatos autenticados do canal: a instalação não deve
recompilar GCC no computador do usuário. O cache de desenvolvimento usado nos
testes não é versionado como release. Para registros
v2 íntegros, `minitrue channel emit --output DIR <pacotes...>` gera artefatos,
índice v2 e `emit.meta` com `CHANNEL_EMIT_FORMAT=2`; o índice ainda precisa ser
assinado externamente. Quando o registro veio de canal, o comando reutiliza o
tar autenticado do cache, revalidando os hashes de transporte e interno. Para
um build local, só reconstrói a partir das claims quando consegue provar
topologia, metadados e `ARTIFACT_HASH`; ambiguidade falha fechado. Um pipeline
de release deve emitir no próprio build e conservar o artefato autenticado, não
usar a reconstrução posterior como raiz de publicação.

O canal atual ainda não contém os novos artefatos prontos para essa closure.
Além da mudança de dependências, as receitas de `gcc-pass2` e
`binutils-glibc` passaram a solicitar `make install-strip` para reduzir o
footprint esperado. O efeito exato, a funcionalidade e a reprodutibilidade dos
novos payloads ainda precisam ser medidos em rebuilds; depois será necessário
reemiti-los, assinar o novo índice, recompor cache/lock/EFI/ISO e executar os
aceites. A ISO resultante não tem tamanho fixado por `MEDIA_SIZE_MIB`.

O outro caminho também foi exercitado com os executores musl estáticos: na
revisão anterior, a instalação direta `--offline --only-binary` materializou
`base` + `linux` a partir do canal assinado de desenvolvimento e terminou com
`minitrue verify`
sem divergências. O lock instalado teve SHA-256
`e08ef8c874478a6333f3af53ce4e2dd144ee6f3b144db9746d4cc57d12b0a534`;
isso é evidência local do fluxo, não um pino oficial.

`bootstrap/channel-from-rootfs` existe somente para migrar registros históricos
v1 e sempre produz `TRUST=builder`. Como os exemplos fornecem `$CACHE` por
override, seus locks são classificados como `custom`; um cache/bootstrap
versionado dentro do perfil preservaria a classe `development` enquanto o
`STATUS` continuar assim.

O modo `online` incorpora somente o bootstrap de canal fechado pelo lock:
`channel-config/<nome>` e o par assinado
`channels/<nome>/{index,index.minisig}`. Os artefatos não entram nessa mídia;
são obtidos da URL HTTPS pinada durante a instalação. O consumidor, a
validação minisign e o lock de canal já existem, mas o projeto **ainda não
publicou** URL, índice, chave e artefatos de um canal oficial. Por isso nenhum
`channel-bootstrap/` fictício é versionado no perfil oficial: a composição
online falha cedo até que um bootstrap real seja fornecido pelo perfil ou por
`--cache DIR`. O Minipax confere o layout e prende seus bytes no perfil; é o
Minitrue que valida criptograficamente `index.minisig` contra a chave pinada
antes da seleção. Cada linha v2 obrigatoriamente autentica
`NAME VERSION ARCH RECIPE_FINGERPRINT PATH SHA256 [REPROCORR]`; a seleção só é
aceita quando o fingerprint assinado coincide com a receita efetiva. A
existência de `/etc/minitrue/channels/` é uma decisão administrativa: se o
diretório estiver vazio, nenhum canal é carregado e a seed do cache não é
reativada. O modo `offline` exige o cache completo e leva seus objetos na mídia;
a instalação direta equivalente usa `--offline --cache DIR`.
`--world`, `--live-world`, `--overlay` e `--cache` explícito criam uma variante
personalizada, identificada como `custom` no lock e nos manifestos. Saídas de
mídia recebem os sidecars `.sha256`, `.media.lock` e `.manifest`; cada nome é
publicado sem
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

Na instalação, `minitrue` e `minipax` são copiados para snapshots medidos; o
Minitrue é executado de um `memfd` selado e ambos são persistidos em
`/usr/bin` no target. Seus hashes e a política `ONLY_BINARY` entram no
`install.manifest`. Para que esses executores funcionem no sistema mínimo,
use binários estáticos. Por padrão, a casca de desenvolvimento compila ambos
para `x86_64-unknown-linux-musl` e recusa uma saída que contenha `INTERP`;
executáveis passados explicitamente por `MINIPAX`/`MINITRUE` continuam sendo
insumos do usuário e não recebem dessa casca uma alegação de linkagem ou
proveniência. Neste marco, as árvores Newspeak e overlay são limitadas,
cada uma, a 128 MiB de conteúdo regular; a árvore de cache, a 384 MiB. Cada
árvore admite até 50 mil entradas, e o arquivo de entrada `cache.tar` é aceito
até 416 MiB. Conteúdo e tar normalizado ainda ficam simultaneamente em memória.
Os modos não dependem dos bits preservados pelo Git:
diretórios são normalizados para `0755` (com `root/` do overlay em `0700`),
`shadow`/`gshadow` e seus backups para `0600`, regulares executáveis para `0755`
e os demais para `0644`. Durante o consumo de canal, o snapshot `.tar.zst` e o
tar descompactado selado coexistem; o pico de RAM pode aproximar a soma dos
dois. Na instalação viva soma-se ainda a raiz preparada em `/run`, deliberada
para garantir validação completa antes do disco. Streaming e uma partição de
dados própria para caches maiores continuam gates de release.

Neste marco, a casca pública constrói os binários Rust estáticos quando o
toolchain Rust/musl, um compilador C compatível e `readelf` estão disponíveis,
ou aceita `MINIPAX` e `MINITRUE` já fornecidos. O construtor live exige
executores estáticos e também aceita os dois prontos. Para compilar o kernel,
ele requer ainda `make`, `gcc`, `flex`, `bison`, `pkg-config` e os headers de
`libelf`; a composição ISO requer `xorriso`. O aceite headless do VirtualBox
requer `VBoxManage` e `tesseract` e recusa iniciar se já houver um `VBoxSVC` do
mesmo usuário. Os dois runners de instalação reservam agora 4096 MiB para o
disco por padrão, coerentes com a toolchain instalada; isso não altera o disco
histórico de 256 MiB registrado nos blocos de evidência. O bundle estático
assinado e o canal oficial publicado ainda são gates de release. Na variante
ISO, versão e SHA-256 do `xorriso` são registrados e o
compositor recusa se o binário mudar durante a execução, mas a toolchain e o
bundle completos ainda não estão pinados. Por isso o repositório **não anuncia
uma ISO oficial publicada**. Ele já consegue construir o EFI vivo e compor a
mídia localmente. Boot, instalação offline em disco vazio, reboot sem a mídia
e recusa antes do wipe de um `profile.lock` incoerente com `media.meta` foram
comprovados pelo aceite final-v10 acima. A experiência interativa — console
gráfico, confirmação humana do disco SATA, reboot sem ISO e login — foi
comprovada separadamente no VirtualBox; nenhum dos dois ensaios promove o
perfil de desenvolvimento a release.

## Segurança e validação

O `minitrue` assume que a árvore sob `--root` pode conter estado hostil ou
incompleto. Nas operações do mundo B, cada mutação é precedida por uma intenção
em journal; um processo interrompido é recuperado antes da próxima retificação
ou remoção. Leituras, comparações e remoções sensíveis ficam confinadas ao
rootfs e recusam symlinks intermediários, arquivos especiais e metadados
ambíguos. O artefato verificado também permanece selado entre o hash e a
aplicação no sistema. Isso não equivale ainda a uma defesa completa contra um
mutador local concorrente: partes do Journal continuam baseadas em caminhos
após o preflight, sujeitas a TOCTOU apesar do `flock` cooperativo. O contrato
atual pressupõe controle administrativo exclusivo do rootfs durante a mutação;
converter o Journal inteiro a descritores confinados é gate de release.

Receitas transitivas participam do fingerprint de build; para receitas fonte
`TOOLCHAIN=seed|cross`, isso inclui a receita Zig implícita mesmo quando não há
`BUILD_DEPS=zig`. Attestations Ed25519
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
sh -n bootstrap/channel-from-rootfs bootstrap/live/build-efi \
  bootstrap/live/accept-qemu bootstrap/live/accept-virtualbox \
  bootstrap/live/init newspeak/base/files/udhcpc.script
```

## Vocabulário

| Termo | Significado |
|-------|-------------|
| `minitrue` | A ferramenta central (Ministério da Verdade) |
| `minipax` | O instalador (Ministério da Paz — anexa territórios novos) |
| `miniplenty-buildbase` | Metapacote do conjunto-base de produção (Ministério da Fartura): Make e toolchain nativa, sem payload próprio |
| `rectify` | Instalar/atualizar — retificar os registros |
| `memoryhole` | Remover — o pacote nunca existiu |
| `newspeak` | A árvore de receitas — vocabulário mínimo, sem ambiguidade |
| `room101` | `/var/log/room101/` — para onde vão os logs de builds que quebraram |
| `unperson` | Pacote desativado sem remoção: segue em `/opt`, mas some de todos os registros visíveis |
| `samizdat` | Canal binário não oficial porém confiável (SPEC-0009) — o livro clandestino, circulado fora do canal oficial |
| *crimestop* | Recusa automática de artefato com hash divergente |
| *doublethink* | Colisão: dois pacotes reivindicando o mesmo arquivo |
