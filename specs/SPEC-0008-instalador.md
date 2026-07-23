# SPEC-0008 — minipax, instalação e mídia

**Status:** implementação inicial v0.8 · 2026-07-23

**Depende de:** SPEC-0003 (minitrue `--root`), SPEC-0005 (estágios),
SPEC-0006 (init), SPEC-0009 (canais) e SPEC-0010 (reprodutibilidade).
**Complementado por:** SPEC-0013 (closure resolvida e vínculo futuro do plan
lock ao perfil).

O Ministério da Paz cuida de territórios novos. Seu contrato não começa na
ISO: começa num **perfil resolvido**, que pode ser materializado diretamente
num filesystem ou empacotado como mídia de instalação.

## 1. Um pipeline, destinos diferentes

Estes três caminhos DEVEM convergir para os mesmos insumos e a mesma
identidade:

1. a mídia mínima inicia o ambiente vivo e instala o sistema;
2. `minipax install --target DIR` materializa o mesmo sistema a partir de
   outra distribuição Linux, sem exigir boot pela mídia;
3. `minipax media build` gera localmente uma `.img` ou `.iso` a partir de
   entradas canônicas ou personalizadas.

O núcleo comum resolve o perfil, normaliza os worlds, congela a árvore
Newspeak, o overlay e o cache opcional e calcula um `profile.lock`. Instalação
e mídia podem ter entregas diferentes, mas não podem reinterpretar o perfil.
O hash do lock é a chave que permite relacionar uma raiz instalada, uma mídia
e, no futuro, o artefato publicado pelo projeto.

Há duas camadas deliberadamente separadas:

- o **materializador não destrutivo**, já implementado em Rust, opera sobre
  um diretório montado e compõe arquivos de mídia novos;
- o **instalador de máquina**, implementado inicialmente no PID 1 da mídia
  viva, chama primeiro o materializador por `install-media` numa raiz de
  pré-validação em `/run`, configura a conta e captura o EFI medido. Só depois
  pede autorização, particiona o disco, copia/verifica a raiz e publica a
  conclusão.

Essa separação permite auditar e usar o pipeline numa distribuição hospedeira
sem conceder implicitamente permissão para alterar tabelas de partição.

## 2. Perfil e lock comuns

Um perfil v1 é um diretório com, no mínimo:

```text
perfil/
├── profile
├── live.world
├── target.world
├── cache.world           # opcional; disponibilidade exigida no cache offline
├── overlay/              # opcional
└── channel-bootstrap/    # opcional; somente bootstrap online
```

O arquivo `profile` declara `PROFILE_FORMAT=1`, `NAME`, `ARCH`,
`SOURCE_DATE_EPOCH`, `STATUS=development|release` e, opcionalmente,
`MEDIA_SIZE_MIB` e `INSTALL_READY=yes|no` (default `yes`). O marco atual aceita
somente `x86_64`; um perfil de release exige `INSTALL_READY=yes`. O perfil
`official` de desenvolvimento fixa atualmente `MEDIA_SIZE_MIB=512` para
dimensionar a saída IMG e registrar esse parâmetro no lock. O campo não
dimensiona o disco de instalação e não fixa o tamanho da ISO, que acompanha o
payload.

`STATUS=release` também exige três pinos SHA-256, em hexadecimal minúsculo:

- `OFFICIAL_CONTENT_SHA256`: conteúdo canônico resolvido do perfil;
- `OFFICIAL_BOOT_EFI_SHA256`: `BOOTX64.EFI` aceito para compor a mídia;
- `OFFICIAL_MINITRUE_SHA256`: executor aceito para a instalação direta.

A ausência de qualquer pino invalida um perfil de release. Um hash presente
não é autoridade por si só: o arquivo de perfil e, finalmente, o manifesto da
mídia ainda precisam de distribuição externa assinada.

- `live.world` descreve o ambiente que o `BOOTX64.EFI` precisa tornar
  disponível na mídia viva;
- `target.world` descreve os pacotes materializados no sistema instalado;
- `cache.world` declara receitas cujos artefatos e assinaturas precisam estar
  disponíveis e verificáveis numa instalação offline, sem pedir sua instalação;
- `overlay/` aplica a personalização final do filesystem;
- a árvore Newspeak vem de `--newspeak DIR` ou `DISTROPICA_NEWSPEAK`;
- `--cache DIR` acrescenta o cache completo para operação offline ou, no
  modo online, o bootstrap estrito de configuração+índice assinado do canal.

Os três worlds são normalizados de forma canônica; `cache.world` ausente
equivale à forma vazia. Árvores são recusadas quando
contêm tipos ou caminhos fora da política de cada snapshot. Seus modos também
são canônicos e não dependem do que o Git conserva: diretórios ficam em `0755`,
exceto `root/` do overlay em `0700`; `etc/shadow`, `etc/gshadow` e seus backups
ficam em `0600`; regulares executáveis ficam em `0755`, os demais em `0644` e
symlinks são representados como `0777`. No snapshot de cache, todos os regulares
ficam em `0644`. O `SOURCE_DATE_EPOCH` fixa timestamps dos arquivos empacotados.

O lock textual usa `PROFILE_LOCK_FORMAT=2`; sua identidade interna usa
`PROFILE_CONTENT_FORMAT=2`. Ele inclui hashes SHA-256 dos três worlds, overlay,
Newspeak e cache, além de nome, `PROFILE_CLASS`, arquitetura, epoch,
`INSTALL_READY`, o `PROFILE_CONTENT_SHA256` calculado e os três pinos oficiais.
`CACHE_WORLD_SHA256` prende a forma normalizada de `cache.world`, inclusive o
hash da forma vazia quando o arquivo opcional não existe. O lock pode ser
inspecionado sem construir ou instalar nada:

```sh
minipax lock --profile profiles/official --newspeak newspeak
minipax lock --profile profiles/official --newspeak newspeak \
  --output ./profile.lock
```

Saídas nunca são sobrescritas. Um lock identifica os bytes resolvidos; ele
não é, sozinho, uma assinatura nem uma declaração de que esses bytes vieram
do projeto. O envelope continua em `MEDIA_FORMAT=1`, mas o consumidor atual
aceita dentro dele somente `PROFILE_LOCK_FORMAT=2`; mídias com lock v1
permanecem evidência histórica, não entrada compatível com o fluxo atual.

### 2.1 Classes de perfil

- `development`: `NAME=official`, `STATUS=development` e nenhum override que
  force personalização;
- `official-inputs`: perfil chamado `official`, marcado `release`, sem
  override de `target.world`, `live.world`, overlay ou cache e cujo conteúdo
  resolvido coincide com `OFFICIAL_CONTENT_SHA256`;
- `custom`: qualquer outro nome ou o uso de `--world`, `--live-world` ou
  `--overlay` ou `--cache`; divergência do pino de conteúdo também rebaixa um
  perfil de release para esta classe.

A classe é gravada no lock e nos manifestos para impedir que uma variante se
apresente acidentalmente como entrada canônica. Alterações na árvore Newspeak
ou no cache mudam `PROFILE_CONTENT_SHA256`; num perfil de release isso causa
rebaixamento para `custom` até que o pino seja atualizado pela autoridade de
publicação.

Há três classificações relacionadas, mas não intercambiáveis:

| Campo | O que precisa coincidir para `official-inputs` |
|-------|------------------------------------------------|
| `PROFILE_CLASS` | conteúdo resolvido com `OFFICIAL_CONTENT_SHA256` |
| `MEDIA_CLASS` | `PROFILE_CLASS=official-inputs` e EFI com `OFFICIAL_BOOT_EFI_SHA256` |
| `INSTALL_CLASS` | `PROFILE_CLASS=official-inputs` e executor com `OFFICIAL_MINITRUE_SHA256` |

Nenhum desses campos usa o nome “reprodução oficial”. Eles descrevem somente
os insumos conferidos localmente. Uma mídia é uma reprodução comprovada apenas
quando o SHA-256 **final** coincide com o de um manifesto oficial externo e
assinado; a classe autoatribuída nunca substitui essa comparação.

## 3. Instalação direta em uma raiz

O comando implementado é:

```sh
minipax install --profile DIR --newspeak DIR --target DIR [opções]
```

Ele:

1. recusa antes de tocar no alvo quando `INSTALL_READY=no`;
2. recusa `/`, targets não vazios e ancestrais que não sejam diretórios
   reais; `lost+found` é a única entrada inicial tolerada;
3. abre o `minitrue` escolhido, copia seus bytes para um `memfd`, sela esse
   snapshot contra crescimento, redução e escrita e calcula seu SHA-256;
4. grava um marcador inicial na raiz, cria o esqueleto FHS/usr-merge (incluindo
   `/proc`, `/sys` e `/dev`) e promove o marcador a `profile.lock.pending`;
5. instala snapshots congelados da árvore Newspeak e do cache opcional;
6. no modo offline, antes de qualquer retificação, executa do mesmo `memfd`
   `minitrue --root DIR --offline cache verify <cache.world>` quando a lista
   não é vazia;
7. executa do mesmo `memfd` selado
   `minitrue --root DIR rectify <target.world>`;
8. executa do snapshot `minitrue verify`, aplica o overlay e verifica
   novamente;
9. persiste exatamente os snapshots medidos de `minitrue` e `minipax` em
   `/usr/bin`, grava `install.manifest` e promove o lock pendente para
   `/var/lib/minipax/profile.lock`.

`cache verify` impõe operação sem rede e confere SHA-256 e assinaturas pinadas,
mas não executa receitas, não instala pacotes e não altera o `world`. A falha de
qualquer entrada de `cache.world` interrompe a instalação antes de
`target.world`.

O perfil de desenvolvimento oficial declara `INSTALL_READY=yes`: o target
atual pede `base`, `linux`, `ripgrep`, `vim` e `miniplenty-buildbase`. O último
é `KIND=meta`, não possui payload e agrega `base`, GNU Make e `gcc-pass2`; sua
closure entrega headers Linux, glibc, mathlibs-glibc, zlib, binutils nativo e GCC/G++
final. Vim traz ncurses como dependência transitiva, sem transformar ncurses em
desejo top-level. Na instalação normal `--only-binary`, Vim, ncurses, Make e
toda essa toolchain vêm do canal. Jq, Make, tree e Zig constam em
`cache.world`: a fonte de Make permanece congelada e verificável para
rebuild/oferta offline, apesar de seu binário ser instalado por depender do
meta; Zig garante a semente de uma reconstrução local futura; jq conserva o
binário upstream e tree, a fonte oficial. Jq, tree e Zig não são instalados no
target inicial. O caminho anterior
foi exercitado de ponta a ponta numa raiz vazia com `--offline --only-binary`,
antes desse contrato do perfil. O cache veio de registros históricos e usa
`TRUST=builder`; não é um canal oficial publicado nem autoriza mudar
`STATUS=development` para `release`.

Nos registros v2, `minitrue verify` também exige a presença factual de todas as
`DEPS` de execução declaradas. Assim, um registro íntegro de `gcc-pass2` não
mascara a ausência posterior de headers, runtimes ou binutils da sua closure.

O caminho original do executável não volta a ser aberto entre `rectify` e os
dois `verify`: substituí-lo durante a operação não troca o programa que está
rodando. O ambiente é reconstruído por allowlist, com PATH fixo de sistema,
locale UTC, proxies opcionais e `NEWSPEAK_PATH`/`SOURCE_DATE_EPOCH` definidos
pelo perfil. O manifesto registra `PROFILE_CLASS`, `INSTALL_CLASS`,
`MINITRUE_SHA256`, versão e hash do executável `minipax` e os modos
`OFFLINE`/`FROM_SOURCE`/`ONLY_BINARY`. `INSTALL_CLASS=official-inputs` exige
que o hash do snapshot coincida com `OFFICIAL_MINITRUE_SHA256`.

Opções relevantes:

- `--minitrue ARQ` escolhe o binário; `MINITRUE` e depois `PATH` são os
  fallbacks;
- `--offline --cache DIR` exige cache não vazio e repassa a proibição de rede
  ao `minitrue`;
- `--from-source` repassa `--no-binary`, recusando artefatos de canal;
- `--only-binary` exige que todo pacote `KIND=source` seja atendido por um
  canal aceitável e falha em vez de expandir `BUILD_DEPS`/compilar;
- `--resume` somente retoma um target que já possua marcador pendente ou lock
  do `minipax`, e recusa um perfil divergente.

Exemplo a partir de outra distribuição Linux:

```sh
minipax install \
  --profile profiles/official \
  --newspeak newspeak \
  --minitrue ./minitrue \
  --offline --cache ./cache-fechado --only-binary \
  --target /mnt
```

`--target` **nunca particiona nem formata**. O overlay do perfil pode fornecer
`fstab` e estado inicial de contas, mas a montagem, o boot e a escolha do disco
pertencem ao chamador. Para uma máquina completa, use o fluxo da mídia viva de
§8 ou prepare filesystem e ESP externamente.

## 4. Geração de mídia

O compositor implementado usa o mesmo perfil:

```sh
minipax media build \
  --profile DIR \
  --newspeak DIR \
  --mode online|offline \
  --format img|iso \
  --boot-efi BOOTX64.EFI \
  --output ARQ
```

O payload contém:

- `EFI/BOOT/BOOTX64.EFI`, fornecido explicitamente;
- a representação canônica de `profile`, `profile.lock`, `live.world`,
  `target.world` e `cache.world` (vazio quando não declarado no perfil);
- snapshots determinísticos de Newspeak e overlay;
- `media.meta`, que vincula modo, perfil, lock, arquitetura e hash do EFI;
- `cache.tar`: cache completo na variante offline; na online, exclusivamente
  configuração pinada e snapshot assinado do canal, sem artefatos de pacote.

O compositor verifica que `--boot-efi` é um arquivo PE/COFF que declara o
subsistema EFI Application. Ele **não demonstra que esse executável contém um
kernel, um initramfs funcional ou o `minipax`, nem testa seu boot**. O hash do
arquivo é registrado em `media.meta` e no manifesto; `MEDIA_CLASS` só chega a
`official-inputs` quando `PROFILE_CLASS` já possui essa classe e o hash
coincide com `OFFICIAL_BOOT_EFI_SHA256`.

O caminho inverso é implementado por:

```sh
minipax install-media --source RAIZ-DA-MIDIA --target DIR \
  --minitrue ARQ [--only-binary|--from-source] [--resume] \
  [--export-boot-efi ARQ]
```

Antes da primeira mutação no target, ele lê controles com `O_NOFOLLOW` e
limites, confere o hash do EFI e do lock, exige coerência entre modo e presença
do cache, extrai as árvores sob políticas confinadas e reconstrói o perfil. Os
bytes de `profile.lock` recalculados precisam ser idênticos aos da mídia.
`--source` aponta para a raiz montada que contém `EFI/` e `distropica/`, não
para o subdiretório `distropica/`.

`--export-boot-efi ARQ` cria sem sobrescrever um snapshot `0600` dos mesmos
bytes de EFI cujo hash acabou de ser validado. Se a instalação do target falha,
esse arquivo é removido. O instalador vivo usa a opção para não reler o EFI da
mídia depois da autorização destrutiva.

### 4.1 Formatos

| Formato | Estrutura | Dependência adicional |
|---------|-----------|-----------------------|
| `img` | disco GPT reproduzível com uma ESP FAT32 e caminho de fallback UEFI | nenhuma ferramenta externa para composição |
| `iso` | ISO9660 híbrida com imagem ESP El Torito/UEFI e marcações GPT/MBR | `xorriso` |

O `.img` é o formato natural para pendrive e firmware UEFI. O `.iso` existe
para hipervisores, gravadores e fluxos que esperam ISO9660; ambos carregam o
mesmo payload lógico.

### 4.2 Online e offline

| Modo | Cache na mídia | Contrato |
|------|----------------|----------|
| `online` | bootstrap obrigatório | incorpora somente `channel-config/<nome>` + `channels/<nome>/{index,index.minisig}`; o ambiente vivo baixa os artefatos da URL HTTPS pinada |
| `offline` | obrigatório | incorpora o snapshot indicado por `--cache`; a instalação roda com rede proibida |

O builder vincula o cache completo em `CACHE_SHA256` e a lista normalizada de
disponibilidade em `CACHE_WORLD_SHA256`. Ele não prova por si só que o cache
fecha todo o grafo de `target.world`; na instalação offline, porém, o Minipax
exige `minitrue --offline cache verify` para cada nome de `cache.world` antes de
retificar o target. Essa operação confere os artefatos e suas assinaturas sem
baixar nem instalar. Um cache pode continuar sendo superconjunto estrito das
duas listas: bytes extras também ficam presos por `CACHE_SHA256`, mas não criam
registro, link ou intenção.

Antes de uma mídia oficial, essa limitação deve ser substituída pelo
`cache verify --closure` da SPEC-0013 §7.4: o Minipax receberá do Minitrue um
plan lock, prenderá seu hash ao `profile.lock` e falhará antes de compor a mídia
se a política offline não fechar `target.world`. O `cache verify` atual
continua conferindo somente os nomes explicitamente passados; não se deve
descrevê-lo como prova dessa closure futura.

Somente `target.world` expressa a instalação inicial. No perfil atual, `base`,
`linux`, `ripgrep`, `vim` e `miniplenty-buildbase` são desejos top-level e
devem existir desde o primeiro boot. O meta é registrado com `WORLD=M`,
`ORIGIN=meta` e manifesto canônico sem entradas; ele mantém suas dependências
instaladas sem possuir arquivos. `base`, também alcançado pelo meta, já é
listado diretamente. Entre os componentes da toolchain, apenas o meta é desejo
top-level: Make, headers Linux, glibc, mathlibs-glibc, zlib, binutils-glibc e
gcc-pass2 são componentes instalados da closure. Vim é top-level; ncurses é
somente sua dependência transitiva.

Jq, Make, tree e Zig estão em `cache.world`. A entrada de Make conserva sua
fonte verificada para rebuild/oferta offline; ela não é a razão de o binário
estar no target — isso decorre da dependência do meta. Receitas fonte
`TOOLCHAIN=seed|cross` materializam Zig automaticamente apenas quando o
Minitrue escolhe build local; canal/binário e `none|native` não o instalam.
Assim, no caminho `--only-binary`, Zig fica disponível no cache, mas sem
comando, registro ou entrada no `world`. Jq e tree também começam ausentes:
`minitrue --offline rectify jq` deve instalar o executável estático publicado
pelo upstream, enquanto `minitrue --offline rectify tree` deve compilar a fonte
oficial com a toolchain nativa do sistema instalado. Tree não integra o canal;
usar `--no-binary` seria incorreto porque aplicaria a política a toda a closure.

Para que essa closure represente o sistema final, `gcc-pass2` declara como
`DEPS` de execução `linux-headers`, glibc, mathlibs-glibc, zlib e binutils-glibc; gcc
passada 1, binutils-cross e o libstdcxx intermediário são `BUILD_DEPS`. O GCC
final supersede esse intermediário e fornece a libstdc++ definitiva. As
receitas de binutils-glibc e gcc-pass2 passaram a solicitar
`make install-strip` para reduzir o footprint esperado, motivadas pelo peso do
payload anterior sem strip. Os novos payloads ainda não foram reconstruídos:
o efeito exato, a preservação funcional e a identidade entre builds repetidos
precisam ser medidos antes de atribuir essa redução à mídia atual.

Historicamente, o cache de desenvolvimento network-v1 fechou o perfil mínimo e
carregou o objeto pinado de `ripgrep` sem acrescentá-lo ao antigo
`target.world`; esse resultado não prova o perfil atual. A capacidade online
existe no consumidor,
porém o projeto ainda não publicou endpoint, chave e índice de um canal
oficial. O perfil oficial não inventa esses valores: sem um diretório
`channel-bootstrap/` real ou um `--cache DIR` com esse layout estrito, a
composição online é recusada
antes de publicar a mídia. No target, o bootstrap vai para
`/var/cache/minitrue`; a existência de `/etc/minitrue/channels` continua
vencendo por inteiro, inclusive quando o diretório está vazio para desativar
explicitamente a seed. O Minipax valida aqui o layout e o vínculo pelo hash do
perfil; a assinatura minisign é validada pelo Minitrue contra a chave da
configuração antes de selecionar qualquer pacote.

### 4.3 Limites de escala deste marco

Cada árvore é coletada na memória. Newspeak e overlay são limitadas,
separadamente, a **128 MiB de conteúdo em arquivos regulares**; o cache, a
**384 MiB**. Cada árvore admite **50 mil entradas**. O arquivo de entrada
`cache.tar` possui ainda o teto de aceitação de **416 MiB**; arquivos de
perfil/world têm o limite de 1 MiB. Esses são limites explícitos de
desenvolvimento, não o tamanho pretendido de uma mídia offline final nem uma
prova de que o perfil atual caiba neles.

Ao consumir um artefato de canal, o transporte `.tar.zst` é selado antes do
uso e permanece vivo enquanto o tar descompactado é escrito noutro `memfd`
selado; o pico de RAM pode, portanto, aproximar a soma de **zst + tar**. No
instalador vivo, a raiz materializada em `/run` permanece até a cópia e a
verificação no disco, acrescentando ao pico o tamanho da closure preparada.

Antes de suportar caches maiores, o pipeline precisa empacotar e aplicar
árvores por streaming. Para `.img`, uma partição de dados separada da ESP
também permanece gate de release; o compositor atual põe o payload na FAT32.

### 4.4 Sidecars e não sobrescrita

Para `distropica.iso`, o compositor cria, em operação de sucesso:

```text
distropica.iso
distropica.iso.sha256
distropica.iso.media.lock
distropica.iso.manifest
```

O `.sha256` confere os bytes da mídia. O `.media.lock` preserva o perfil
resolvido. O `.manifest` vincula hashes da mídia e do payload lógico, hash do
lock, `PROFILE_CLASS`, `MEDIA_CLASS`, modo, formato, arquitetura, hash do EFI e
compositor empregado. Nenhum desses arquivos é hoje assinado automaticamente.
Cada imagem ou sidecar é publicado sem substituir um nome existente, inclusive
quando outro processo cria esse nome depois do preflight.

Essa garantia vale **por arquivo**, não pelo conjunto. Sidecars são publicados
antes da imagem e não há transação multi-arquivo contra escritores
concorrentes. Numa corrida, a operação pode falhar depois de publicar parte dos
sidecars; o operador deve conferir a presença e a consistência dos quatro
arquivos antes de distribuí-los.

Com os mesmos bytes de entrada, epoch e versão do compositor, `.img` deve ser
byte a byte reproduzível. A ISO também fixa datas, ownership e identificadores,
e resolve o executável `xorriso` antes de usá-lo. Sua versão e SHA-256 são
registrados no campo `TOOL`; o compositor confere novamente o hash e recusa a
saída se o binário mudar durante a execução. Isso melhora a proveniência, mas
não pina por si só a toolchain, bibliotecas ou ambiente do `xorriso`: o bundle
reproduzível completo e a validação entre ambientes independentes ainda são
gates de release.

Mesmo uma saída byte a byte estável no teste local só passa a ser reprodução
oficial após comparação de seu SHA-256 final com manifesto externo assinado.

## 5. Personalização sem um segundo instalador

Uma mídia personalizada não usa um pipeline paralelo. Ela substitui entradas
do perfil e, por isso, recebe outro lock e a classe `custom`:

```sh
minipax media build \
  --profile profiles/official \
  --newspeak newspeak \
  --world meu-target.world \
  --live-world meu-live.world \
  --overlay meu-overlay \
  --mode offline --cache cache-fechado \
  --format iso --boot-efi BOOTX64.EFI \
  --output minha-distropica.iso
```

A imagem oficial publicada será apenas uma conveniência assinada produzida
com o perfil canônico. `official-inputs` diz que o compositor recebeu os pinos
esperados; a prova de reprodução continuará sendo a comparação do SHA-256 da
imagem pronta com o manifesto oficial assinado. Isso será praticável quando
todos os gates de release e a toolchain de composição estiverem pinados. Uma
variante continua sendo Distrópica, mas não pode usar a identidade de artefato
oficial.

## 6. Bootstrap público

O repositório inclui `bootstrap/distropica-bootstrap` como casca de
desenvolvimento. Ela encaminha os mesmos comandos ao `minipax`, aponta a árvore
Newspeak do checkout e:

- usa cada executável fornecido por `MINIPAX` e/ou `MINITRUE` e compila com
  Cargo somente o que estiver ausente;
- para a compilação, usa `x86_64-unknown-linux-musl`, exige um compilador C
  compatível e `readelf`, e recusa resultado com segmento `INTERP`. A saída
  padrão é musl `static-pie`, não ligada ao host.

O contrato de release é distribuir essa entrada como um bundle pequeno,
estático e assinado, acompanhado de instruções para verificar antes de
executar. `curl | sh` não é o procedimento recomendado. O bundle de release
ainda não existe.

## 7. Boot sem bootloader

O alvo continua sendo UEFI x86_64 sem GRUB nem systemd-boot. O primeiro marco
bootável DEVE usar um kernel compilado com `CONFIG_EFI_STUB` e com o initramfs
incorporado durante o próprio build do kernel (`CONFIG_INITRAMFS_SOURCE`). O
`bzImage` EFI resultante pode então ser instalado como
`EFI/BOOT/BOOTX64.EFI`; este caminho não exige fabricar uma UKI com `objcopy`.

Uma UKI real permanece uma evolução possível. Nesse caso será necessário um
**stub EFI que saiba localizar e carregar** as seções `.linux`, `.initrd`,
`.cmdline` e `.osrel`. `objcopy` apenas acrescenta seções a um PE: ele não
fornece esse comportamento de boot. O projeto poderá adotar ou implementar um
stub mínimo sem depender do systemd, mas não deve chamar de UKI um `bzImage`
que recebeu seções sem um consumidor compatível.

`bootstrap/live/build-efi` implementa esse primeiro marco: pina Linux 7.1.4 e
o BusyBox estático, exige `minipax`/`minitrue` estáticos e incorpora os quatro
componentes e o PID 1 via `CONFIG_INITRAMFS_SOURCE`. No boot, o initramfs
localiza o payload, inicia `install-media` e, em boots posteriores, localiza a
raiz por `LABEL=DISTROPICA_ROOT`. O compositor continua recebendo o EFI pronto
e mede seus bytes; o construtor do EFI ainda não consome nem coteja
automaticamente `live.world`/`profile.lock`, dívida que precisa ser fechada
antes de release.

O kernel vivo conserva `CONFIG_MODULES=y`, porém seu initramfs não distribui
módulo algum: todos os drivers necessários para encontrar mídia, rede e disco
precisam estar built-in. `LOCALVERSION=-distropica-live` faz seu release ser
`7.1.4-distropica-live`, distinto do kernel `7.1.4` materializado no target.
Assim, depois do `switch_root`, a busca automática não reutiliza por acidente
`/lib/modules/7.1.4`; isso não amplia a cobertura estreita de drivers deste
marco.

A mídia destinada a pessoas DEVE ser construída sem `--install-device` e não
DEVE conter `distropica.test=1`. Sua cmdline atual é
`console=ttyS0,115200 console=tty0 panic=-1 rdinit=/init`: manter `tty0` por
último faz do framebuffer o console primário sem perder o log UART. Para que
esse contrato funcione antes de haver módulos, o EFI vivo DEVE trazer built-in
`CONFIG_SYSFB_SIMPLEFB`, `CONFIG_DRM_SIMPLEDRM`,
`CONFIG_DRM_FBDEV_EMULATION`, `CONFIG_DRM_CLIENT_DEFAULT_FBDEV` e
`CONFIG_FRAMEBUFFER_CONSOLE`. A variante automatizada do QEMU é outro
artefato: embute `/dev/vda` e `distropica.test=1` e não pode ser apresentada
como instalador humano.

O instalador copia esse mesmo EFI para `EFI/BOOT/BOOTX64.EFI` na ESP. A gestão
do sistema instalado deverá reter o EFI anterior em
`EFI/distropica/anterior.efi` e nunca remover o kernel em execução. Rotação
A/B, atualização do EFI quando `/boot/vmlinuz-*` muda, entrada NVRAM e rescue
continuam fora do núcleo implementado.

## 8. Camada inicial de instalação de disco

O PID 1 da mídia viva implementa um fluxo deliberadamente estreito:

1. encontra a própria mídia, configura DHCP se `MODE=online` e cria
   `/run/distropica-prepared` com modo `0700`;
2. antes de listar, pedir ou autorizar disco algum, chama
   `minipax install-media --only-binary --export-boot-efi ...`, materializa e
   verifica toda a closure em `/run`, configura a senha de root e mede o EFI,
   `profile.lock`, Minipax, Minitrue e `/sbin/init` preparados;
3. só depois de anunciar que nenhum disco foi alterado, exige um dispositivo
   de bloco inteiro digitado no console ou autorizado pela cmdline
   `distropica.install=`, recusa o disco que contém a mídia e verifica se raiz e
   ESP comportam os snapshots preparados;
4. cria MBR com ESP FAT32 de 64 MiB e raiz ext2 ocupando o restante, monta os
   alvos e copia a raiz já validada;
5. executa `minitrue verify` no disco e coteja novamente `profile.lock` e os
   caminhos executáveis críticos; instala na ESP o snapshot EFI de `/run` e
   confere seu hash;
6. sincroniza e publica **por último**, sem sobrescrever, o marcador
   `/var/lib/minipax/disk-install.complete`, que vincula o hash de
   `profile.lock`; só uma raiz com esse marcador exato é elegível ao boot;
7. sincroniza, desmonta, remove os snapshots de `/run` e reinicia. No boot
   seguinte, prefere a raiz completa e faz `switch_root` para `/sbin/init`;
   uma raiz parcial volta ao caminho de instalação, não é iniciada.

Essa ordem troca memória por segurança: closure e EFI ficam integralmente em
`/run` durante a decisão e a escrita, mas mídia inválida ou incompleta falha
antes de qualquer autorização destrutiva. Não se promete ainda operar caches
grandes nesse desenho; streaming com uma área de dados autenticada continua
gate de release.

Os runners QEMU e VirtualBox reservam atualmente discos vazios de 4096 MiB por
padrão, para comportar a closure de produção. Esse valor é independente de
`MEDIA_SIZE_MIB=512`, que dimensiona somente a saída IMG; a ISO segue o tamanho
do payload. A instalação continua obrigada a medir os snapshots e recusar um
destino pequeno antes do wipe. O MBR com ESP FAT32 de 64 MiB descrito acima
também não muda: 512 MiB não é o tamanho da ESP do target.

`bootstrap/live/build-efi --install-device /dev/...` embute também
`distropica.test=1`, suprime a interação e deixa root bloqueado. Essa opção é
para aceite automatizado e é destrutiva; não é o caminho de usuário. Sem
essa opção, o instalador DEVE pedir e confirmar a senha de root, concluir o
preflight sem alterar disco e então pedir que o operador digite o dispositivo
inteiro a apagar.

`bootstrap/live/accept-qemu` consome uma ISO construída dessa forma, cria sem
sobrescrever um disco raw e uma variável store OVMF, instala com rede ausente e
encerra no reboot. Depois inicia o mesmo disco sem a ISO e exige as mensagens
de `rcS` e do getty. Logs, hashes, versões e parâmetros ficam preservados em
`acceptance.meta`. A execução final-v10 passou sem NIC: instalou a ISO num
disco vazio e iniciou esse disco sem a ISO. Num probe negativo separado, um
`profile.lock` incoerente com `media.meta` foi recusado antes do wipe. Duas
composições locais da ISO foram byte a byte idênticas:

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

Esses identificadores registram uma execução de desenvolvimento; não são pinos
de release nem substitutos de um manifesto oficial externo assinado.
Uma segunda composição local byte a byte igual continuará sem provar
reprodução entre builders independentes.

O caminho humano foi exercitado separadamente por
`bootstrap/live/accept-virtualbox`. O runner recusou preventivamente as flags
automatizadas, confirmou prompts pelo framebuffer, injetou a senha pelo
teclado PS/2, esperou o preflight, ejetou a ISO antes de autorizar `/dev/sda` e
depois comprovou o reboot pelo VDI e o login `root` como uid 0. A instalação e
o segundo boot ocorreram com uma NIC VirtIO/NAT presente, mas com o cabo
desconectado. Num terceiro boot, o cabo foi conectado e o `rcS` da base obteve
DHCP IPv4, rota default e servidor DNS; o runner resolveu apenas `localhost`
pelo resolvedor da NAT e alcançou o gateway, sem depender da Internet.

Na **evidência histórica network-v1**, o cache da ISO era um superconjunto do
world inicial: `ripgrep` não constava em
`target.world`, e o runner comprovou que comando, registro e intenção estavam
ausentes. Depois da prova de rede, desligou novamente o cabo e executou
`minitrue --offline rectify ripgrep`. O objeto já presente no cache instalou
`ripgrep` 15.2.0, criou seu registro e o acrescentou ao world; um `minitrue
verify` posterior terminou sem divergências:

```text
EVIDENCIA_VIRTUALBOX_NETWORK_V1=local-custom
ACCEPTANCE_META=target/vbox-acceptance-network-v1/evidence/acceptance.meta
ACCEPTANCE_FORMAT=1
VBOX_VERSION=7.2.6_Ubuntur172322
VBOXMANAGE_BINARY_SHA256=3d019f23c6d755ed1f6a3bb05f4481fd56015719bf51e4299dca0267fbcc021a
FIRMWARE=efi64
GRAPHICS=vmsvga
STORAGE=IntelAhci
GUEST_DISK=/dev/sda
NIC_TYPE=virtio
INSTALL_NETWORK=nat-cable-disconnected
THIRD_BOOT_NETWORK=nat-cable-connected
DNS_PROBE=localhost-via-vbox-nat-host-resolver
SECURE_BOOT=off
CMDLINE=console=ttyS0,115200 console=tty0 panic=-1 rdinit=/init
ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
REPEATED_ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
BOOT_EFI_SHA256=71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88
DISK_SHA256=1dc7d872dae51a99ebf3063bd55d1e20234f58ddfa41af2212cad63ccdf41165
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
MINITRUE_VERIFY=yes
FINAL_RESULT=passed
```

O runner atual expressa um aceite diferente, ainda não executado sobre uma
mídia recomposta. Com o cabo desligado no segundo boot, ele deve encontrar
ripgrep 15.2.0, Vim 9.2.0837 e o meta `miniplenty-buildbase` instalados. `base`,
`linux`, `ripgrep`, `vim` e o meta são explícitos no `world`; entre os
componentes da toolchain, apenas o meta é top-level. Os registros de Vim,
ncurses 6.6, Make 4.4.1, linux-headers, glibc, mathlibs-glibc, zlib 1.3.1,
binutils-glibc 2.45 e gcc-pass2 15.3.0 devem declarar origem de canal. Ncurses
não pode ser top-level. Jq, tree e Zig devem começar somente no cache e, junto
das sementes `gcc`, `binutils`, `binutils-cross`, `libstdcxx`, `gmp`, `mpfr` e
`mpc`, não podem possuir registro no target inicial.

Ainda sem link, o runner deve validar Vim e seu alias `vi`, compilar e executar
C com headers Linux/glibc; compilar e executar C++17 com STL, strings, vetores,
`unique_ptr`, exceções e dependência em `libstdc++.so.6`; criar, indexar e
linkar um arquivo estático com `ar`/`ranlib`; e executar um Makefile que chama
GCC. Deve então instalar jq do binário upstream por
`minitrue --offline rectify jq` e compilar tree da fonte por
`minitrue --offline rectify tree`, mantendo Zig ausente. A ausência de tree no
canal e `ORIGIN=fonte` comprovam a compilação sem forçar suas dependências a
ignorar os artefatos binários. Depois de
`minitrue verify` limpo, um novo boot deve comprovar a persistência de Vim, jq e
tree. Só então liga a NAT para as provas separadas de DHCP, DNS e gateway. Até
essa execução sobre a nova mídia recomposta existir, os hashes e resultados
network-v1 acima continuam históricos e não sustentam o novo fluxo;
`MEDIA_SIZE_MIB=512` dimensionará a IMG, não a ISO usada no aceite.

O aceite VirtualBox histórico não substitui o final-v10 de QEMU: o primeiro prova a
experiência humana, o console gráfico com SATA `/dev/sda`, a configuração
automática no VirtIO/NAT e o consumo offline de um objeto extra; o segundo
preserva a automação em `/dev/vda` e o probe negativo que demonstra
fail-before-wipe. Ambos são execuções locais `custom` de desenvolvimento, não
testes em hardware real, prova de acesso à Internet, reprodução entre builders
independentes nem publicação oficial.

O MBR/ext2/64 MiB é uma escolha de bootstrap compatível com os applets do
BusyBox, não o desenho final GPT/ext4/ESP maior. Dual boot, seleção de
partições existentes, redimensionamento, NVMe/USB genéricos, LUKS, LVM, RAID,
filesystems alternativos e interface gráfica ficam fora deste marco.

## 9. Gates para a mídia oficial

O perfil `profiles/official` está deliberadamente com `STATUS=development` e
`INSTALL_READY=yes`. Não há, neste marco, ISO oficial publicada nem alegação
de reprodução oficial. Antes de mudar para `release`, são obrigatórios:

- repetir o aceite sobre o futuro artefato canônico pinado e publicado;
- ampliar e testar os drivers do kernel vivo em hardware UEFI real;
- ligar a construção do EFI ao `live.world`/lock e implementar atualização,
  retenção e rotação atômica do EFI instalado;
- runit, configuração final de contas e a política de rede além do DHCP IPv4
  simples validado em VirtIO/NAT;
- publicar canal binário oficial, chave pinada e bundle estático assinado;
- implementar `channel refresh` explícito, autenticado e com diff auditável;
- converter as mutações do Journal ainda baseadas em caminhos para operações
  fd-relative confinadas, fechando TOCTOU contra mutador concorrente;
- perfil canônico com os três pinos de release e manifesto externo assinado
  contendo o SHA-256 final esperado;
- streaming das árvores e, para imagens maiores, partição de dados separada;
- limite de entradas para objetos de canal e tratamento uniforme por `rescue`
  de todos os comandos auxiliares executados depois do wipe;
- limpeza fd-relative da saída de `--export-boot-efi`; até lá, chamadores
  privilegiados devem escolher um diretório-pai de confiança, como o `/run`
  `0700` usado pela mídia viva;
- toolchain de composição pinada, incluindo o `xorriso` e suas dependências;
- publicação consistente do conjunto imagem + sidecars, com recuperação ou
  limpeza explícita de conjuntos parciais;
- reprodução independente da `.img` e da `.iso`, incluindo sidecars;
- política e implementação de assinatura dos artefatos publicados.

Os testes atuais demonstram composição determinística em ambiente controlado,
validação estrutural de PE/COFF, geração GPT/FAT e ISO, publicação individual
sem sobrescrita, ingestão hostil de payload e instalação offline real do
perfil mínimo por canal. O EFI e o fluxo de disco estão implementados; o
aceite final-v10 em QEMU comprovou instalação automatizada, segundo boot sem
mídia até `rcS`/getty e recusa antes do wipe; o aceite VirtualBox comprovou a
variante humana, seus prompts gráficos, instalação SATA, reboot pelo VDI sem
ISO, login root, DHCP/DNS/gateway no VirtIO/NAT, instalação de `ripgrep` 15.2.0
com o link desligado e `verify` posterior limpo — tudo na revisão histórica
network-v1. O aceite atual de Vim/ncurses, do meta `miniplenty-buildbase`, da
toolchain final do canal, das sementes ausentes, da compilação offline de
C/C++/STL/archive/Make, do jq binário e do tree compilado ainda está pendente.
Isso não prova boot da IMG,
Internet, hardware real, reprodução independente ou publicação oficial.

## 10. Questões em aberto

- formato e implementação do stub de uma futura UKI real;
- retenção/rotação atômica dos EFIs corrente e anterior;
- BIOS legado: só será considerado diante de hardware que o justifique;
- LUKS: initramfs, prompt e recuperação precisam ser dimensionados;
- composição final de `base` e `live.world`, justificada na árvore Newspeak;
- formato da assinatura e rotação da chave de publicação das mídias;
- fronteira exata entre a interface interativa de disco e os comandos
  autônomos de rescue.
