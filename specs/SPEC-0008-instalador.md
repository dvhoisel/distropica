# SPEC-0008 — minipax, instalação e mídia

**Status:** implementação inicial v0.3 · 2026-07-21

**Depende de:** SPEC-0003 (minitrue `--root`), SPEC-0005 (estágios),
SPEC-0006 (init), SPEC-0009 (canais) e SPEC-0010 (reprodutibilidade).

O Ministério da Paz cuida de territórios novos. Seu contrato não começa na
ISO: começa num **perfil resolvido**, que pode ser materializado diretamente
num filesystem ou empacotado como mídia de instalação.

## 1. Um pipeline, destinos diferentes

Estes três caminhos DEVEM convergir para os mesmos insumos e a mesma
identidade:

1. a futura mídia mínima oficial inicia o ambiente vivo e instala o sistema;
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
- o **instalador de máquina**, ainda futuro, particiona disco, monta o alvo,
  configura contas/rede/fstab e chama o materializador.

Essa separação permite auditar e usar o pipeline numa distribuição hospedeira
sem conceder implicitamente permissão para alterar tabelas de partição.

## 2. Perfil e lock comuns

Um perfil v1 é um diretório com, no mínimo:

```text
perfil/
├── profile
├── live.world
├── target.world
└── overlay/       # opcional
```

O arquivo `profile` declara `PROFILE_FORMAT=1`, `NAME`, `ARCH`,
`SOURCE_DATE_EPOCH`, `STATUS=development|release` e, opcionalmente,
`MEDIA_SIZE_MIB` e `INSTALL_READY=yes|no` (default `yes`). O marco atual aceita
somente `x86_64`; um perfil de release exige `INSTALL_READY=yes`.

`STATUS=release` também exige três pinos SHA-256, em hexadecimal minúsculo:

- `OFFICIAL_CONTENT_SHA256`: conteúdo canônico resolvido do perfil;
- `OFFICIAL_BOOT_EFI_SHA256`: `BOOTX64.EFI` aceito para compor a mídia;
- `OFFICIAL_MINITRUE_SHA256`: executor aceito para a instalação direta.

A ausência de qualquer pino invalida um perfil de release. Um hash presente
não é autoridade por si só: o arquivo de perfil e, finalmente, o manifesto da
mídia ainda precisam de distribuição externa assinada.

- `live.world` descreve o ambiente que o futuro `BOOTX64.EFI` precisa tornar
  disponível na mídia viva;
- `target.world` descreve os pacotes materializados no sistema instalado;
- `overlay/` aplica a personalização final do filesystem;
- a árvore Newspeak vem de `--newspeak DIR` ou `DISTROPICA_NEWSPEAK`;
- `--cache DIR` acrescenta um snapshot fechado para operação offline.

Os worlds são normalizados de forma canônica. Árvores são recusadas quando
contêm tipos ou caminhos fora da política de cada snapshot. O
`SOURCE_DATE_EPOCH` fixa timestamps dos arquivos empacotados.

O lock textual inclui hashes SHA-256 dos dois worlds, overlay, Newspeak e
cache, além de nome, `PROFILE_CLASS`, arquitetura, epoch, `INSTALL_READY`, o
`PROFILE_CONTENT_SHA256` calculado e os três pinos oficiais. Ele pode ser
inspecionado sem construir ou instalar nada:

```sh
minipax lock --profile profiles/official
minipax lock --profile profiles/official --output ./profile.lock
```

Saídas nunca são sobrescritas. Um lock identifica os bytes resolvidos; ele
não é, sozinho, uma assinatura nem uma declaração de que esses bytes vieram
do projeto.

### 2.1 Classes de perfil

- `development`: `NAME=official`, `STATUS=development` e nenhum override que
  force personalização;
- `official-inputs`: perfil chamado `official`, marcado `release`, sem
  override de `target.world`, `live.world` ou overlay e cujo conteúdo
  resolvido coincide com `OFFICIAL_CONTENT_SHA256`;
- `custom`: qualquer outro nome ou o uso de `--world`, `--live-world` ou
  `--overlay`; divergência do pino de conteúdo também rebaixa um perfil de
  release para esta classe.

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
minipax install --profile DIR --target DIR [opções]
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
6. executa do mesmo `memfd` selado
   `minitrue --root DIR rectify <target.world>`;
7. executa do snapshot `minitrue verify`, aplica o overlay e verifica
   novamente;
8. grava `install.manifest` e promove o lock pendente para
   `/var/lib/minipax/profile.lock`.

O perfil de desenvolvimento oficial ainda declara `INSTALL_READY=no`: sem
canais/toolchain no target, `base` e `linux` não fecham a instalação vazia.
Assim, o comando oficial atual falha cedo e preserva o target; a cobertura de
instalação usa uma fixture materializável e não é um teste ponta a ponta do
perfil oficial.

O caminho original do executável não volta a ser aberto entre `rectify` e os
dois `verify`: substituí-lo durante a operação não troca o programa que está
rodando. O ambiente é reconstruído por allowlist, com PATH fixo de sistema,
locale UTC, proxies opcionais e `NEWSPEAK_PATH`/`SOURCE_DATE_EPOCH` definidos
pelo perfil. O manifesto registra `PROFILE_CLASS`, `INSTALL_CLASS`,
`MINITRUE_SHA256`, versão e hash do executável `minipax` e os modos
online/from-source. `INSTALL_CLASS=official-inputs` exige que o hash do
snapshot coincida com `OFFICIAL_MINITRUE_SHA256`.

Opções relevantes:

- `--minitrue ARQ` escolhe o binário; `MINITRUE` e depois `PATH` são os
  fallbacks;
- `--offline --cache DIR` exige cache não vazio e repassa a proibição de rede
  ao `minitrue`;
- `--from-source` repassa `--no-binary`, recusando futuros artefatos de canal;
- `--resume` somente retoma um target que já possua marcador pendente ou lock
  do `minipax`, e recusa um perfil divergente.

Exemplo a partir de outra distribuição Linux:

```sh
minipax install \
  --profile profiles/official \
  --newspeak newspeak \
  --minitrue ./minitrue \
  --target /mnt
```

`--target` **nunca particiona nem formata**. Neste marco também não configura
boot, fstab, contas ou rede. Para virar uma máquina inicializável, `/mnt`
precisa ser um filesystem preparado pelo usuário ou pela futura camada de
instalação de disco, e os gates de §9 precisam estar fechados.

## 4. Geração de mídia

O compositor implementado usa o mesmo perfil:

```sh
minipax media build \
  --profile DIR \
  --mode online|offline \
  --format img|iso \
  --boot-efi BOOTX64.EFI \
  --output ARQ
```

O payload contém:

- `EFI/BOOT/BOOTX64.EFI`, fornecido explicitamente;
- `profile.lock`, `live.world` e `target.world`;
- snapshots determinísticos de Newspeak e overlay;
- `media.meta`, que vincula modo, perfil, lock, arquitetura e hash do EFI;
- `cache.tar` apenas na variante offline.

O compositor verifica que `--boot-efi` é um arquivo PE/COFF que declara o
subsistema EFI Application. Ele **não demonstra que esse executável contém um
kernel, um initramfs funcional ou o `minipax`, nem testa seu boot**. O hash do
arquivo é registrado em `media.meta` e no manifesto; `MEDIA_CLASS` só chega a
`official-inputs` quando `PROFILE_CLASS` já possui essa classe e o hash
coincide com `OFFICIAL_BOOT_EFI_SHA256`.

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
| `online` | proibido | o ambiente vivo obterá os artefatos durante a instalação e o `minitrue` os verificará pelas receitas |
| `offline` | obrigatório | incorpora o snapshot indicado por `--cache`; a instalação deverá rodar com rede proibida |

O builder vincula o cache no lock, mas não prova por si só que ele fecha todo
o grafo de `target.world`. Essa prova pertence ao teste end-to-end de
instalação offline.

### 4.3 Limites de escala deste marco

Cada árvore de Newspeak, overlay ou cache é coletada na memória e limitada,
separadamente, a **128 MiB de conteúdo em arquivos regulares** e **50 mil
entradas**. Arquivos de perfil/world têm ainda o limite de 1 MiB. Esses são
limites explícitos de desenvolvimento, não o tamanho pretendido de uma mídia
offline final.

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

- usa `MINIPAX` e `MINITRUE` fornecidos, quando ambos estão definidos; ou
- compila os dois com Cargo.

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

O `BOOTX64.EFI` do marco inicial deverá incorporar o ambiente descrito por
`live.world`, localizar o payload da mídia, iniciar o `minipax` e localizar a
raiz instalada por `LABEL=distropica-root`. Essa integração ainda não está
implementada nem validada. `minipax media build` recebe o EFI pronto justamente
para não inventar sucesso na ausência desse componente.

A futura gestão do sistema instalado deverá reter o EFI anterior em
`EFI/distropica/anterior.efi` e nunca remover o kernel em execução. Rotação
A/B, entrada NVRAM e rescue continuam fora do núcleo implementado.

## 8. Camada futura de instalação de disco

Uma interface separada e explicitamente destrutiva deverá orquestrar:

1. exibição e confirmação do plano de particionamento;
2. GPT com ESP FAT32 e raiz ext4, ou seleção manual de partições existentes;
3. montagem da raiz em um target temporário;
4. chamada a `minipax install --target ...` com o perfil escolhido;
5. instalação do EFI, fstab por LABEL, hostname, contas, rede e serviços;
6. relatório final e teste de consistência.

O default de desenho permanece ESP de 512 MiB e o restante como ext4 com
label `distropica-root`. Dual boot assistido, redimensionamento, LUKS, LVM,
RAID, filesystems alternativos e interface gráfica ficam fora do v0.

## 9. Gates para a mídia oficial

O perfil `profiles/official` está deliberadamente com `STATUS=development`.
Não há, neste marco, ISO oficial pronta nem alegação de boot comprovado. Antes
de mudar para `release`, são obrigatórios:

- kernel EFI-stub com initramfs vivo autocontido e integração com o payload;
- runit, configuração de contas e caminho de rede fechados;
- canais binários assinados para que a instalação normal não compile a base;
- perfil canônico com os três pinos de release e manifesto externo assinado
  contendo o SHA-256 final esperado;
- cache offline completo, streaming das árvores e, para imagens grandes,
  partição de dados separada da ESP;
- teste offline com a rede fisicamente indisponível;
- bundle estático assinado de `minipax` + `minitrue` e toolchain de composição
  pinada, incluindo o `xorriso` e suas dependências;
- publicação consistente do conjunto imagem + sidecars, com recuperação ou
  limpeza explícita de conjuntos parciais;
- teste QEMU/OVMF: mídia instala disco virgem e o disco inicia até o getty,
  sem a mídia, com `minitrue verify` limpo;
- repetição em hardware UEFI real;
- reprodução independente da `.img` e da `.iso`, incluindo sidecars;
- política e implementação de assinatura dos artefatos publicados.

Os testes atuais demonstram composição determinística em ambiente controlado,
validação estrutural de PE/COFF, geração estrutural de GPT/FAT e ISO,
publicação individual sem sobrescrita e o fluxo de materialização com um
`minitrue` de teste. Eles não demonstram que a ISO seja inicializável ou
instalável e não substituem os testes de boot e instalação acima.

## 10. Questões em aberto

- formato e implementação do stub de uma futura UKI real;
- retenção/rotação atômica dos EFIs corrente e anterior;
- BIOS legado: só será considerado diante de hardware que o justifique;
- LUKS: initramfs, prompt e recuperação precisam ser dimensionados;
- composição final de `base` e `live.world`, justificada na árvore Newspeak;
- formato da assinatura e rotação da chave de publicação das mídias;
- fronteira exata entre a interface interativa de disco e os comandos
  autônomos de rescue.
