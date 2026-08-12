# Perfil oficial (em desenvolvimento)

Este diretório é a entrada canônica do futuro release. Enquanto `STATUS` no
arquivo `profile` for `development`, o `minipax` rotula a resolução sem
overrides como `development`; qualquer override aplicável vira `custom`.
Nenhuma delas é oficial.

`live.world` descreve o ambiente incorporado no `BOOTX64.EFI` da mídia;
`target.world` descreve o sistema instalado; e o `cache.world` opcional declara
quais receitas precisam ter, no cache offline, todos os artefatos e as
assinaturas que estiverem pinadas. A árvore Newspeak, o overlay, os três worlds,
o cache e o bootstrap do canal entram no `profile.lock` por hashes separados.
O lock e sua identidade de conteúdo usam os formatos `PROFILE_LOCK_FORMAT=3`
e `PROFILE_CONTENT_FORMAT=3`; `CACHE_WORLD_SHA256` autentica a forma
normalizada de `cache.world` e `CHANNEL_BOOTSTRAP_SHA256` prende endpoint,
chave pública e seed assinada.

O canal oficial publicado em `https://distropica.com.br/canal/oficial/` tem
seu bootstrap versionado em `channel-bootstrap/`, com
`channel-config/oficial` e
`channels/oficial/{index,index.minisig}`. O arquivo `newspeak-origem` prende
separadamente `https://distropica.com.br/newspeak/` com a mesma chave do
projeto, para `rectify newspeak`. O endpoint e a chave minisign estão
pinados na mídia; o índice embarcado é uma seed assinada, não autoridade vinda
da rede. Em operações online o Minitrue busca o índice corrente, valida-o pela
mesma chave e só então, dentro da invocação explícita de `rectify`, substitui o
snapshot operacional preso no lock. Não há atualização em background;
`channel refresh` é a via auditável sem instalação. Em operação offline usa
exatamente a seed assinada disponível.

`INSTALL_READY=yes` declara que o world mínimo (`base` + `linux` + `e2fsprogs`
+ `ripgrep` + `vim` + `miniplenty-buildbase`) pode ser materializado num alvo
vazio. `e2fsprogs` entra porque a raiz instalada é ext4: um sistema que não
sabe verificar nem redimensionar o próprio disco não é um sistema. O último
item é uma receita `KIND=meta`: não contém payload, fica registrada como
`WORLD=M` com manifesto vazio e agrega `DEPS="base make gcc-pass2"`. A closure
de `gcc-pass2` instala ainda `linux-headers`, glibc, `mathlibs-glibc`, zlib e
`binutils-glibc`; o resultado mínimo já oferece GNU Make e a toolchain GCC
nativa para C e C++. Vim é outro desejo explícito e traz ncurses como
dependência transitiva; ncurses fica instalado, mas não entra no `world` como
desejo top-level. O caminho de instalação pretendido usa um canal assinado com
`--offline --only-binary`: o metapacote é resolvido localmente e os pacotes
fonte de sua closure, Vim e ncurses vêm como artefatos do canal, sem compilar
esses componentes no computador do usuário. O canal/cache local de
desenvolvimento com essa closure foi construído, assinado e aceito na mídia
`miniplenty-v1`; essa evidência histórica continua sendo de desenvolvimento,
embora endpoint, chave e índice oficiais já estejam publicados agora.

O cache fechado usado para compor a mídia offline é um insumo de build e entra
integralmente em `CACHE_SHA256` e `PROFILE_CONTENT_SHA256`. Em
`STATUS=release`, apenas os bytes exatos pinados por
`OFFICIAL_CONTENT_SHA256` conservam `official-inputs`; qualquer alteração no
`--cache` rebaixa a composição para `custom`. O cache não substitui o
`channel-bootstrap/`: ele é consumido para instalar sem rede e, antes do
primeiro reboot, endpoint, chave e seed oficiais do perfil são instalados no
alvo. O perfil
fixa `MEDIA_SIZE_MIB=1024` para dimensionar a saída IMG e registrar o valor no
lock. Esse campo não fixa o tamanho da ISO, que acompanha o payload.

O cache offline completo pode ser um superconjunto estrito da closure de
`target.world`. Objetos adicionais continuam presos por `CACHE_SHA256` e são
semeados em `/var/cache/minitrue`, mas não expressam intenção de instalação e
não acrescentam pacotes ao world por conta própria. `cache.world` torna
verificável uma parte desse superconjunto: antes de retificar o target, uma
instalação offline executa o equivalente a:

```sh
minitrue --offline cache verify jq make tree zig
```

Essa conferência valida o hash e, quando pinada, a assinatura dos artefatos já
presentes, sem rede e sem instalação. No perfil atual, jq 1.8.2, a fonte do GNU
Make 4.4.1, a fonte de tree 2.3.2 e Zig 0.16.0 são obrigatórios na
disponibilidade offline. A declaração em `cache.world`, por si, não instala
nenhum deles: Make é instalado porque `miniplenty-buildbase` depende dele; Zig
continua apenas no cache até que uma compilação `seed`/`cross` o exija; jq e
tree começam sem comando, registro ou entrada em `/etc/minitrue/world`. Depois
da instalação, `minitrue --offline rectify jq` deve consumir o executável
estático publicado pelo upstream, enquanto
`minitrue --offline rectify tree` deve compilar a fonte oficial com
a toolchain nativa já instalada. Ripgrep, Vim e o metapacote constam diretamente
em `target.world`; por isso `/usr/bin/rg`, `/usr/bin/vim`, `/usr/bin/vi`, Make e
a toolchain final devem existir desde o primeiro boot. Ncurses existe como
dependência de Vim, não como intenção top-level.

As receitas `yq` 4.53.2 e `nano` 9.1 também fazem parte da árvore, mas não de
nenhum dos três worlds. São provas online-only: `minitrue rectify yq` baixa o
binário estático oficial e registra `ORIGIN=vendor`; `minitrue rectify nano`
baixa o tarball oficial e compila com a toolchain nativa, registrando
`ORIGIN=fonte`. Nenhum dos dois payloads está no cache da mídia. A composição
`miniplenty-v2` leva somente as receitas; por isso requer rede no sistema
instalado para exercitá-las.

Quando uma receita `KIND=source` com `TOOLCHAIN=seed` ou `cross` precisa ser
compilada localmente, o Minitrue trata Zig como dependência de build implícita:
instala-o antes do build e prende sua identidade ao fingerprint do pacote. Um
artefato de canal evita a compilação e não instala Zig; receitas `none` ou
`native` também não o puxam. Como dependência implícita, Zig não entra no
`world`; somente o pacote solicitado explicitamente entra. Na toolchain do
perfil, o único desejo explícito é `miniplenty-buildbase`: Make e `gcc-pass2`
ficam registrados e instalados como dependências, mas não viram desejos
top-level. `base`, também alcançado pelo meta, já é listado diretamente ao lado
de `linux`, `ripgrep` e `vim`. O `--cache` participa da identidade pelos próprios
bytes: em desenvolvimento conserva a classe `development`; em release, só o
conteúdo exatamente pinado pode chegar a `official-inputs`.

O overlay fornece o estado mínimo de contas e boot: conta root inicialmente
bloqueada, `fstab`, `securetty`, `passwd` e `group`. A mídia viva pede uma senha
de root antes do primeiro boot; o modo automatizado de teste conserva a conta
bloqueada. Ao congelar as árvores, o Minipax aplica modos canônicos independentes
do Git: diretórios `0755`, `root/` do overlay `0700`, `shadow`/`gshadow` e seus
backups `0600`, executáveis `0755` e demais regulares `0644`.

`bootstrap/live/build-efi` implementa o kernel EFI-stub com initramfs do
instalador, e `minipax media build` compõe localmente IMG ou ISO a partir dele.
Antes de sequer pedir o disco, o initramfs materializa a closure em `/run`,
configura a conta, valida o root preparado e usa
`install-media --export-boot-efi` para capturar o EFI já conferido. Só depois
autoriza e particiona o disco, copia o root, executa `minitrue verify`, instala o
snapshot EFI e publica por último o marcador `disk-install.complete`.

Há duas classes de artefato vivo que não podem ser confundidas:

- A **ISO interativa de desenvolvimento**, construída sem
  `--install-device`, é o caminho humano e o candidato técnico à futura mídia
  oficial. Ela pede senha, valida todo o payload antes de oferecer o disco e
  exige que a pessoa digite o dispositivo inteiro a apagar. Hoje continua
  `development`/`custom`: não é uma release oficial.
- A **ISO automatizada destrutiva do aceite QEMU**, construída com
  `--install-device /dev/vda`, incorpora autorização para apagar esse disco e
  `distropica.test=1`. Ela serve somente à VM raw descartável criada por
  `bootstrap/live/accept-qemu`; **nunca deve ser distribuída, publicada nem
  usada em hardware real**.

A variante interativa pode ser aceita com:

```sh
bootstrap/live/accept-virtualbox \
  --iso target/media-output/distropica.iso \
  --run-dir target/acceptance-virtualbox
```

O runner cria uma VM efêmera UEFI64/VMSVGA/SATA com uma NIC VirtIO NAT. O cabo
permanece desligado durante a instalação e o segundo boot; por padrão o VDI tem
4096 MiB e é `/dev/sda` no guest. Com o payload já validado em RAM, a ISO é
ejetada antes da autorização do wipe. O contrato atual exige que o primeiro
sistema instalado já contenha ripgrep 15.2.0, Vim 9.2.0837 e
`miniplenty-buildbase` registrado como `KIND=meta`/`WORLD=M`, além de GNU Make
4.4.1, binutils 2.45 e GCC/G++ 15.3.0 vindos do canal. Ncurses deve estar
presente como dependência transitiva de Vim; Zig, jq e tree devem começar
ausentes. Ainda sem rede, o runner deve validar uma edição com Vim, compilar e
executar C e C++, criar e ligar uma biblioteca estática e construir por
Makefile. Em seguida deve instalar jq como binário upstream com
`minitrue --offline rectify jq` e compilar tree da fonte com
`minitrue --offline rectify tree`, terminando com
`minitrue verify` limpo e provando a persistência dos três num novo boot. Só
depois prova a rede local. Esse cenário ainda precisa ser executado no
VirtualBox com uma mídia recomposta; este texto não constitui evidência de
aceite.

Antes disso, os payloads e fingerprints alcançados pelas receitas atuais,
inclusive Vim e ncurses, precisam ser fechados; o canal deve ser reemitido, o
índice assinado e o cache/lock/EFI/ISO recompostos. Jq e tree precisam integrar
o cache offline verificado. O runner QEMU também passou a usar disco de 4096
MiB por padrão. Essas são mudanças de código e de contrato, não uma nova
evidência de execução.

O bloco abaixo preserva a **evidência histórica** network-v1, anterior ao
`target.world` e ao contrato de toolchain atuais. Naquela revisão, ripgrep era
um extra inicialmente ausente e foi instalado explicitamente. O fluxo passou
em 2026-07-21 no VirtualBox `7.2.6_Ubuntur172322`; duas composições a partir dos
mesmos insumos produziram ISO byte a byte idêntica:

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
ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
REPEATED_ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
BOOT_EFI_SHA256=71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88
RUN_STATE=passed
ISO_EJECTED_BEFORE_WIPE=yes
INSTALL_AND_SECOND_BOOT_OFFLINE=yes
SECOND_BOOT_WITHOUT_ISO=yes
ROOT_LOGIN=yes
THIRD_BOOT_WITH_NAT=yes
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

O aceite automatizado final-v10, preservado como evidência separada, passou em
QEMU/OVMF sem NIC: instalou em disco vazio, iniciou o disco sem a ISO e recusou
uma variante cujo `profile.lock` não correspondia ao hash de `media.meta` antes
de qualquer wipe. Duas composições locais dessa ISO de teste também foram byte
a byte idênticas:

```text
EVIDENCIA_FINAL_V10=local-development
ACCEPTANCE_META=target/qemu-acceptance-final-v10/acceptance.meta
RUN_STATE=completed
NETWORK=none
ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
REPEATED_ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
BOOT_EFI_SHA256=c8a884845aa1568c4e51756f2a26c1b21652969367957387c5efdfb616e3204c
CORRUPT_DISK_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
ZERO_256_MIB_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
RESULT=pass
INCONSISTENT_PROFILE_LOCK_RESULT=refused-before-wipe
```

Isso continua sendo desenvolvimento: os manifestos registraram
`PROFILE_CLASS=custom` e `MEDIA_CLASS=custom`; essa evidência não é
pino oficial e igualdade local não provará reprodução entre builders. O kernel
vivo cobre sobretudo o hardware virtual testado e o EFI contém
kernel+initramfs embutidos. `CONFIG_MODULES=n` fecha o carregador e a mídia não
contém `.ko`: os drivers do instalador são built-in. O sufixo
`-distropica-live` separa seu release do `7.1.8` instalado. O EFI ainda não
acompanha automaticamente atualizações de `/boot/vmlinuz-*`.

Para virar release faltam, entre outros, fechar e reconstruir os payloads do
canal, o bundle estático assinado, pinos oficiais do perfil/EFI/Minitrue, manifesto
externo assinado, runit, política final de contas e uid/gid, atualização
atômica do EFI e testes em hardware real. Também faltam Journal integralmente
fd-relative contra TOCTOU e streaming: durante
o consumo binário, o `.tar.zst` selado e o tar descompactado coexistem em RAM, e
o instalador vivo ainda mantém a raiz pré-validada em `/run` até concluir a
cópia segura para o disco.
