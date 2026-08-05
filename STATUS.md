# STATUS — o que está feito, testado e futuro

Fonte única da verdade sobre a maturidade. As `specs/` descrevem a **norma**;
este arquivo descreve o **estado**. Atualizado à mão em 2026-07-28 após
reconstruir a closure com o perfil de rede, provar o fechamento de
dependências, emitir e assinar o canal com ferramenta própria, compor a ISO e
concluir o aceite automatizado `rede-v2` no VirtualBox.

O que mudou de natureza nesta revisão: a auditoria de fechamento deixou de
**reprovar** — os 11 erros viraram 0, e agora medidos sobre a closure real, não
em simulação. Entraram onze receitas de rede (bash, nftables, WireGuard, nmap,
mtr, tcpdump e as bibliotecas), mais `pkgconf` e `findutils`, que o kernel e o
netfilter exigiam para construir. A raiz do alvo passou a ser **ext4** com
tabela **GPT escrita pelo Minipax**, ambas exercitadas contra disco pela
primeira vez. O kernel da mídia passou a ser compilado **dentro do rootfs**,
pelo compilador que a própria distro produziu. E o **IPv6 saiu do zero**: há
evidência, não configuração escrita.
Legenda: ✅ feito · 🟡 parcial · ⬜ design/futuro.

## Licenciamento e publicação

| Peça | Estado | Nota |
|---|---|---|
| Código e documentação próprios | ✅ | `GPL-3.0-or-later`; texto integral, escopo e regra de contribuição versionados |
| Licença na base e no ambiente vivo | ✅ E2E local | `base` instala a GPL e o aviso de escopo em `/usr/share/licenses/distropica/`, `build-efi` os incorpora no initramfs e a mídia atual foi recomposta e aceita |
| Inventário completo de terceiros | ⬜ gate de release | gerar por artefato, a partir dos insumos efetivamente distribuídos; os payloads compostos de Zig e `gcc-pass2` usam `NOASSERTION` até o SBOM conclusivo, sem perder licenças nem avisos upstream |
| Bundle de fontes correspondentes | ✅ `miniplenty-v2` custom | publicado ao lado da ISO: revisão `941383e`, 144 crates vendorizadas, fontes upstream, configs exatas de BusyBox/kernel, receitas registradas, sidecars, inventário TSV e hashes; continua sendo gate por artefato futuro |

Os hashes QEMU final-v10 e VirtualBox network-v1 abaixo são evidência histórica
anterior à mudança de licença do pacote `base` (revisão funcional `7148ebd`).
Não são pinos de uma mídia recomposta a partir da árvore licenciada atual.

## Reconstrução com contrato de flags — mídia `0.10-v2`

Árvore inteira reconstruída (131 pacotes) depois que `CFLAGS`/`CXXFLAGS`
entraram no contrato de build **e na identidade da receita**. Aceite `PASS`,
instalação offline e segundo boot sem mídia.

```text
CANAL=98 pacotes; fechamento: 2673 requisito(s), todos com provedor declarado
CACHE=600 MB                       (era 824 MB)
ISO=target/distropica-0.10-v2.iso  (683 MiB; era 907 MiB)
ISO_SHA256=b42a12445d8a6a0db16ffe937f90dbf341ff5d4f58f5e25228c23368fd0182ad
EFI_SHA256=a9289cb7b022a78f05bdeaffaf422eee2a03b7629af535c70501066759624f5e
DEPURACAO=3.3 MiB em 386.1 MiB de ELF (0.9%); era 266.0 MiB em 656.0 (40.5%)
```

**Símbolos de depuração: 266,0 MiB → 3,3 MiB.** A causa não era descuido de
receita: sem `CFLAGS` no ambiente o autoconf usa o SEU default, `-g -O2`, e
isso pegou 81 dos 86 pacotes com ELF. Declarar `-O2` consertou os autotools e
NÃO bastou — o `zig cc` emite depuração por padrão, e sete pacotes que embarcam
usam toolchain zig, a `glibc` entre eles com 28,7 MiB. Foi preciso `-g0`
explícito. Resíduo nomeado: `make` 1,50 MiB, `libmpfr` 0,70, `gcc-pass2` 0,67,
`glibc` 0,22.

As flags entram no fingerprint porque mudam o payload: se não entrassem, dois
payloads diferentes teriam a mesma identidade e o `REPROCORR` gravado deixaria
de ser reproduzível. O custo é assumido — invalidou 135 de 135 identidades.

**Armadilha de medição**, para quem for conferir: um binário LINKADO mostra
`.debug_*` mesmo compilado com `-g0`, herdadas do `crt1.o`/`crti.o`/`crtn.o` da
glibc, 9 a 11 seções cada, enquanto ELA não for reconstruída. O objeto
compilado no mesmo comando já sai com zero. Depois da glibc nova: zero nos crt.

O `bootstrap/verifica-0.10` mede as quatro promessas sobre o que EMBARCA, e não
sobre a árvore de build — que infla o número com toolchain que não vai na mídia.

### `regulatory.db`: instalada, e o boot ainda reclama

O `error -2` no boot **continua** e é esperado. O `cfg80211` é builtin e o
`regulatory_init_db` roda em `late_initcall`, quando só existe o initramfs; a
raiz ainda não está montada. Quem carrega de verdade é o `query_regdb_file`,
por `request_firmware_nowait`, SOB DEMANDA — quando um rádio aparece e um
domínio é consultado. Em QEMU não há rádio, então essa consulta nunca acontece
e o sucesso não é observável aqui.

O que ficou provado sem hardware: o `firmware_class` procura em
`/lib/firmware`, o `/lib` instalado é symlink para `usr/lib`, e
`/lib/firmware/regulatory.db` e `/usr/lib/firmware/regulatory.db` resolvem para
o MESMO inode — 6380 bytes, modo 0644. E o certificado que assina o `.p7s` é
byte a byte o `wens.hex` que este kernel embute. O arquivo certo, no lugar
certo, com a assinatura certa; falta só o rádio.

### Provisionais voltaram a aceitar correção

Seis provisionais foram refrescados nesta rodada e quatro cederam TUDO —
`binutils` entregou os 199 caminhos do baseline ao `binutils-glibc` e hoje é só
registro. Antes deste ciclo, toda correção de receita nos nove provisionais era
descartada em silêncio; o `chmod 4755` do busybox ficou seis versões inerte
assim.

## Evidência integrada atual — `grafica-v1`

A ISO com modo gráfico instala, reinicia sem mídia e **abre o Firefox em
português**. A prova não é o aceite: o `accept-qemu` lê o SERIAL, e sessão
gráfica não aparece no serial. A evidência é a captura de tela feita pelo
monitor do QEMU, com o `bootstrap/live/screenshot-qemu` escrito para isso — a
primeira mostra o painel do weston com os lançadores e o relógio; a segunda,
com o Firefox rodando como cliente do compositor, mostra a janela de
boas-vindas em pt-BR.

```text
CANAL=78 pacotes; fechamento: 2089 requisito(s), todos com provedor declarado
CACHE=664 MB (streaming; teria sido recusado pelo limite antigo de 384 MiB)
ISO=target/distropica-v2.iso       (744 MB)
ISO_SHA256=8666d3ee07a1bea5f592fa9bd0bdb1e32b55c2b8a838f0db43316ccf40e92972
TELA_1=target/tela-v8.png          (painel do weston, 1280x800)
TELA_2=target/prova-ff/tela.png    (Firefox 153.0.1 pt-BR aberto)
```

**Sete falhas foram encontradas no caminho, e NENHUMA delas falhava no build.**
Todas produziriam uma ISO que instala, boota e não serve:

| Sintoma | Causa |
|---|---|
| `undefined symbol: gdk_x11_display_get_xdisplay` | 21 símbolos do libxul exigem GTK3 com backend X11 |
| instalador recusa a mídia (416 MiB) | streaming faltava do lado da INSTALAÇÃO, não só da composição |
| tela preta, `no input devices` | o `mdev` cria o nó mas não popula a base do udev, que é quem a libinput consulta |
| tela preta, `failed to compile XKB keymap` | faltava o `xkeyboard-config` — dados de teclado, não código |
| `Starting with no config file` | comentário com `;` no weston.ini invalida o ARQUIVO INTEIRO |
| `libasound.so.2: cannot open` | `KIND=binary` não declarava DEPS; a ALSA ficou fora do fecho |
| `Cannot spawn a message bus` | faltava `machine-id`, que tem de ser gerado no 1º boot e não vir no payload |

O que a revisão traz, e o que custou:

- **Modo gráfico**: weston 14.0.2 com backend DRM e renderizador pixman, seatd
  0.9.3, Firefox 153.0.1 pt-BR (Mundo A, `/opt`), GTK3 com os backends Wayland
  **e X11**, `weston-terminal` como único emulador de terminal da árvore. A
  tty1 vira sessão gráfica quando há `/dev/dri/card*`; a tty2 é getty sempre.
- **A corrente X11, medida e não suposta**: o `libxul.so` do Firefox declara
  onze bibliotecas cliente do X e a `libasound` no `NEEDED`, com `-z now`, e
  referencia **vinte e um símbolos `gdk_x11_*`** que só existem num GTK3 com o
  backend X11 ligado. Descoberto executando o binário
  (`undefined symbol: gdk_x11_display_get_xdisplay`), não lendo documentação.
  Custo: dezessete receitas novas de bibliotecas cliente, `at-spi2-core`
  substituindo o `atk` avulso, `libxml2`, backend `xlib` no cairo e GLX no
  libepoxy. Nada disso é exercido em execução — a sessão é Wayland — mas o
  carregador dinâmico não sabe disso.
- **Streaming do cache**, sem o qual nada acima caberia: ver o item "Escala do
  Minipax" em Limitações.
- **`/etc/mdev.conf`**: o `mdev` criava os nós achatados em `/dev`, enquanto
  libdrm procura `/dev/dri/card0` e libinput procura `/dev/input/event0`. Sem
  as regras `=dri/` e `=input/`, o compositor sobe, não acha vídeo nem teclado
  e morre — sem nada falhar em voz alta.
- **A guarda que a auditoria impôs**: `channel emit` recusou o canal três vezes
  por DEPS incompletos, e as três estavam certas. A mais instrutiva: o libtool
  sobrelinka, e cada extensão do X carrega `libxcb`, `libXau` e `libXdmcp` no
  próprio `NEEDED` — o que eu tinha suposto que viesse só por transitividade.
  Os DEPS finais saíram de `readelf -d`, não da leitura da receita.
- **A CEGUEIRA da auditoria, que a mesma corrente expôs — e que foi
  CORRIGIDA.** `minitrue audit firefox` lia **zero arquivos**: a auditoria
  percorria apenas claims `f:`, e o payload do Mundo A é UMA claim de árvore
  `d:` sobre `/opt/<pacote>/<versão>`. Todo pacote binário era um ponto cego
  inteiro, e foi por essa fresta que a `alsa-lib` — construída, presente na
  árvore, exigida pelo `libxul.so` — não entrou na mídia. O `audit` agora
  expande as claims `d:` em arquivos e os lê com o mesmo parser: o Firefox
  passou de 0 para **30 arquivos e 321 requisitos**, e a árvore inteira de 1073
  para **1203 arquivos e 2845 requisitos**.

  Duas sutilezas que a correção teve de modelar, ambas descobertas por erro
  falso na primeira tentativa:
  - **o payload do Mundo A resolve contra si mesmo.** O `libxul.so` não tem
    RUNPATH e exige `libnspr4.so` e mais treze vizinhas de `/opt`; quem as acha
    é o lançador, que põe o próprio diretório no `LD_LIBRARY_PATH`. A busca
    inclui o diretório do arquivo **e a raiz da árvore** — a segunda porque
    plugins em subdiretório (`gmp-clearkey/0.1/libclearkey.so`) exigem
    bibliotecas que moram na raiz. O acréscimo é estreito: fora de uma claim
    `d:`, biblioteca de sistema ausente continua sendo erro;
  - **symlinks dentro da árvore são pulados**, senão o mesmo arquivo é contado
    duas vezes — ou, se apontassem para fora, o payload de outro pacote seria
    analisado como se fosse deste.

  Sobra um achado REAL, da Mozilla e não nosso: `libonnxruntime.so` declara
  `RUNPATH` literalmente igual a `$`, um `$ORIGIN` truncado no build deles.
  Fica como erro visível, porque RUNPATH relativo faz o carregador procurar a
  partir do diretório de trabalho do processo — imprevisível e, no limite,
  controlável por terceiros. Não é corrigível sem tocar no payload, e tocar no
  payload obrigaria a remover a marca Firefox.
- **A montagem do cache virou script** (`bootstrap/cache-from-channel`). Fazê-la
  à mão custou três iterações de ISO, cada uma descobrindo UM item faltando
  depois de compor 740 MB e bootar: a assinatura do Zig sob NOME DERIVADO
  (`sha256(hash+chave+URL)`, e não o hash do artefato), o achatamento do
  `pool/` por sha256 (o cache offline não tem `pool/` — isso é layout do
  repositório HTTP), e os tarballs-FONTE do `cache.world` (`make` e `tree` são
  `KIND=source`, e o filtro por `KIND=binary` os deixava de fora). O script
  confere cada sha256 contra o índice e aborta em vez de produzir um cache que
  só falha na máquina do usuário.

## Evidência integrada anterior — `rede-v3`

A closure foi reconstruída com o perfil de rede e emitida num canal local
assinado com **24 artefatos** (eram 11). A instalação direta
`--offline --only-binary` no hospedeiro e a instalação interativa por ISO
passaram; esta última percorreu três boots automatizados no VirtualBox 7.2.6.
A ISO foi ejetada antes do wipe, o segundo boot ocorreu offline, e o terceiro
comprovou persistência e a rede do NAT. Isso é evidência `local-custom`, não
release oficial, hardware real nem reprodução entre builders.

Três coisas foram exercitadas pela primeira vez: a tabela **GPT escrita pelo
Minipax** (`sda1`/`sda2`, no lugar do MBR que o fdisk do BusyBox produzia), a
raiz **ext4** montada com `ordered data mode` — o journal que motivou a troca —
e o **IPv6**.

```text
ISO=target/distropica-rede-v3.iso
ISO_SHA256=a709d6007aa22c6a494195c0c4e458cc48fe52318bfd426420c13d1a00602a38
BOOT_EFI_SHA256=c539482dda41abb05f82c86a5c3dffae734ff79890ce8b4a7b8eb696c276c072
PROFILE_CONTENT_SHA256=e3a8ab28d7e2ae52a329320b2ebd49d4277b460bf58d0f965dcd87863f93cdc5
CHANNEL_INDEX_SHA256=16825a68eb372d72169067186a977b5976caa0d795490442a636b1e1732d4aa2
ACCEPTANCE_META=target/vbox-rede-v3/evidence/acceptance.meta
ACCEPTANCE_META_SHA256=0b75af8a499f44ce6b4354d9a11d5cb7bdc5bfa539ccf163467c0b0d1cfdeb8c
DISK_SHA256=9da2b6141fc32cdb8dab1c08ad539d855a8dd7837c6fdcc0a41241cf95d21631
MEMORY_MIB=3072
FINAL_RESULT=passed
```

O `BOOTX64.EFI` desta revisão tem 16,1 MB, contra 19,4 MB da anterior: o
`mke2fs` e o `e2fsck` passaram a ser linkados com `-s`. O ganho bruto nos
binários foi de 7,4 MB (4,0→0,7 e 5,0→0,9), mas o initramfs é comprimido com
gzip dentro do kernel e símbolo de depuração comprime bem, então o efeito no
artefato final foi 3,3 MB. A `rede-v2` — mesma closure, EFI sem strip — também
passou; as duas execuções estão registradas porque a diferença entre elas é o
tamanho do EFI, e ele é o que faz o firmware demorar a carregar.

### IPv6 — a primeira medição

```text
IPV6_KERNEL_LOOPBACK=yes     exigido: o stack v6 do kernel responde em ::1
IPV6_LINK_LOCAL=yes          exigido: a interface tem endereço fe80::
IPV6_GLOBAL_ADDRESS=yes      observado: o NAT do VirtualBox entrega SLAAC
IPV6_NAMESERVER=no           observado: essa rede não anuncia RDNSS
```

Os dois primeiros são exigências do aceite porque não dependem de
infraestrutura externa. Os dois últimos são **observações**: dependem de haver
roteador v6 na rede do hipervisor, e transformá-los em exigência faria a
configuração do VirtualBox passar por atestado da distro. `IPV6_NAMESERVER=no`
é resultado legítimo — o `rdisc6` rodou e não havia RDNSS para ler. O que não
se admite é a linha faltar e a ausência passar por sucesso.

### RAM: 3 GiB agora são requisito, não detalhe do teste

Com 2048 MiB **esta mídia não instala**: o instalador é morto pelo OOM killer,
sem mensagem própria. A causa é o modelo de memória, não um vazamento — o
Minipax materializa as árvores inteiras em RAM, o `cache.tar` tem 311 MB, e a
raiz validada (821 MB) vive em `/run`, que é tmpfs, **antes** de qualquer
escrita em disco. Esse é o preço deliberado da garantia fail-before-wipe, e ele
escala com o world: dobrar o número de pacotes dobrou o pico.

Fica devendo, e é gate para hardware real: o `init` deveria conferir a memória
disponível no preflight e **recusar cedo com mensagem**, em vez de ser morto
pelo kernel. Morrer no OOM é o pior modo de falha possível — indistinguível de
travamento, e sem pista do motivo.

### Delta online — `miniplenty-v2`

A v2 acrescenta somente duas receitas opcionais online-only: yq 4.53.2, binário
estático oficial (`ORIGIN=vendor`), e GNU nano 9.1, compilado da fonte oficial
com a toolchain nativa (`ORIGIN=fonte`). Ambas foram instaladas numa cópia do
target e passaram em `minitrue verify`. Como não pertencem a `target.world` nem
a `cache.world`, seus payloads não foram incorporados à mídia. A ISO foi
recomposta em cerca de 10 segundos reutilizando EFI, canal e cache; o conteúdo
das duas receitas e os sidecars foram conferidos. O aceite completo da v2 no
VirtualBox ainda não foi repetido.

```text
ISO=target/distropica-miniplenty-v2.iso
ISO_SHA256=06be0ed021a3916c76b8e823d1e3a7846246eaccf38f00a49f7e5190c5e07a13
PROFILE_LOCK_SHA256=9528e4217ec6363256cda252d7992861bcc74e5a997d1903ddb151e55a4720ab
NEWSPEAK_SHA256=65017476e659fad53d50745abd3b0e7498f2a687ea40d6643798ede7ae4f9568
BOOT_EFI_SHA256=a800e2aca03dd62cd9e7db3bb894c24f7bdb1fdc19a26abf91566b3b824771b9
MEDIA_MANIFEST_SHA256=07910b519086908f6baee417c299077d9e857cc35a91de64d51dec659c735d34
SOURCE_REVISION=941383e129fedf969838ae29dce24d5c8ef89df7
SOURCE_BUNDLE=distropica-miniplenty-v2-corresponding-sources.tar.zst
SOURCE_BUNDLE_SHA256=9e9ea4e8baaf247353f64ebce5eff41851a1a0034a4f57d44fab835a68fd7651
```

### Primeira auditoria de fechamento (histórico) — a closure não fechava

Registro do primeiro veredito, mantido porque é o que dá sentido ao
fechamento provado logo abaixo. `minitrue audit` (SPEC-0013 §4) rodou sobre o
target `miniplenty-v2` já instalado. O parser foi cotejado arquivo a arquivo com o `readelf` do host nos
414 ELF do rootfs: **zero** `DT_NEEDED` omitido, zero inventado, zero
divergência de `PT_INTERP` e zero divergência de versão de símbolo. Sobre essa
base, o veredito é que a closure atual **não se fecha**, com 11 erros de duas
naturezas — ambos reais, nenhum falso positivo:

- **`/bin/bash` não existe na distro**, e a glibc entrega `ldd`, `tzselect`,
  `xtrace` e `sotruss` com `#!/bin/bash`. Esses quatro scripts estão quebrados
  no sistema publicado; ninguém percebeu porque ninguém os executou;
- **dependência acidental de shell**: `gcc-pass2` (3 scripts), `glibc`
  (`mtrace`), `ncurses` (`ncursesw6-config`) e `vim` (`vimtutor`,
  `macros/less.sh`) usam `/bin/sh`, que existe **só porque** o busybox está
  instalado — nenhum deles declara `busybox` em `DEPS`. É exatamente o que o
  §4.4 proíbe: depender por acaso da dependência de outro pacote.

Há ainda 5 notas de `DEPS` declarada sem requisito estático observado
(`gcc-pass2`→`linux-headers`/`binutils-glibc`,
`miniplenty-buildbase`→agregação): permitidas pelo §4.4, pendentes de
justificativa.

**As receitas foram corrigidas E construídas.** Duas decisões distintas,
porque os dois casos não são iguais:

- **A glibc deixou de entregar os cinco scripts.** `ldd`, `tzselect`, `xtrace`,
  `sotruss` e `mtrace` não são ABI, são utilitários de shell; fazer a
  biblioteca C depender de um shell seria a correção errada. O `ldd`, em
  especial, é o que esta distro recusa como ferramenta de confiança — ele é o
  loader executando o objeto sob suspeita (SPEC-0013 §4.1), e `minitrue audit`
  faz o mesmo trabalho sem executar nada.
- **`gcc-pass2`, `ncurses` e `vim` passaram a declarar `busybox`.** Ali os
  scripts são legítimos e o shell é uma dependência real: o certo é declará-la,
  não escondê-la.

Construir o perfil de rede acrescentou uma terceira decisão da mesma família:
o **openssl** deixou de entregar `CA.pl` e `tsget.pl`, que exigiam
`/usr/bin/perl`. Declarar perl arrastaria o interpretador inteiro para a
closure de RUNTIME de todo alvo com openssl — e o nmap e o tcpdump põem o
openssl lá. Pelo mesmo critério saíram o `e2scrub` do e2fsprogs (exige LVM, que
esta distro não tem) e o `dnssort` do ndisc6 (perl).

### Fechamento provado — 11 erros viraram 0, agora medidos

O veredito anterior foi obtido em **simulação** (cópia por hardlink com `DEPS`
editada à mão). Este foi medido sobre a closure real, reconstruída:

```text
AUDIT_ROOT=target/e2-strip-rebuild-v2-root
AUDIT_FORMAT=1
PACKAGES=24
FILES_INTERPRETED=527
FACTS=904
ERRORS=0
NOTES=5
CLOSURE_SHA256=ed50c261bdbc22b6f1615b01a48d62c0d4a0cf9324bfad82e4b3d3fbaa4f1485
"fechamento provado: todo requisito observado tem provedor declarado"
```

As cinco notas restantes são permitidas pelo §4.4 e legítimas: `base`→`ndisc6`
e `wireguard-tools`→`nftables`/`busybox` são arestas de RUNTIME, que análise
estática não enxerga por natureza — o `rcS` chama o `rdisc6`, o `wg-quick`
chama o `nft`. É exatamente o caso que o §4.1 manda declarar na receita e
cobrir por teste de integração.

O gate funcionou na prática: `channel emit` conferiu os 904 requisitos antes de
publicar e imprimiu *"fechamento conferido"*. Publicar deixou de ser possível
sem que o conjunto se feche.

### Perfil de rede — construído e embarcado

Onze receitas novas, todas construídas e no `target.world`: `bash` 5.3,
`nftables` 1.1.6, `wireguard-tools` 1.0.20260223, `nmap` 7.99, `mtr` 0.96 e
`tcpdump` 4.99.6 como desejos top-level; `libmnl`, `libnftnl`, `libpcap`,
`libcap` e o `openssl` entram por `DEPS`, que é onde a relação de fato existe.
Todos os SHA-256 conferidos contra o tarball real do upstream.

Duas receitas entraram por necessidade demonstrada, não por escolha:

- **`pkgconf` 3.0.4** — não havia pkg-config algum nesta árvore, e o
  `configure` da libnftnl e do nftables usa `PKG_CHECK_MODULES`, que é
  exigência dura. Sem ela os dois recusam construir.
- **`findutils` 4.11.0** — o gerador de initramfs do kernel monta a lista de
  arquivos com `find -printf`, que o BusyBox não implementa. Ver a limitação
  sobre construir o kernel dentro do rootfs, abaixo: **sem GNU find a distro
  não conseguia construir o próprio kernel vivo**.

**O kernel vivo passou a ter o perfil de rede.** A ESP do alvo recebe o
`BOOTX64.EFI` da mídia, então é esse kernel que roda depois do boot — e ele
desabilitava `NETFILTER` de propósito e não tinha `WIREGUARD`, `TUN` nem
`USER_NS`. Embarcar nftables e wireguard-tools contra ele seria distribuir
userspace sem com o que falar. Os onze símbolos foram conferidos no `.config`
do artefato construído, não só pedidos.

**`nmap` carrega o único patch de fonte da árvore, e ele é temporário por
construção.** O 7.99 não compila contra o OpenSSL 4.0 (`ASN1_STRING` opaco,
`const` nos retornos, `OPENSSL_atexit` removido). É o patch do Linux From
Scratch, cuja origem declarada é o PR #3331 do próprio nmap — fechado porque os
mantenedores implementaram o mesmo conserto em 2026-06-16. Já está no master do
upstream; sai daqui quando sair em release. O conteúdo entra no `FINGERPRINT`
pelo snapshot de `files/`, então é tão pinado quanto o tarball.

**`tshark` ainda não é alcançável; `tcpdump` entrou no lugar.** A leitura do
`CMakeLists.txt` do Wireshark desfaz a estimativa anterior de que faltava só
CMake: ele exige `cmake ≥ 3.22`, **`GLib ≥ 2.54` e `libgcrypt ≥ 1.8` como
obrigatórios**, não condicionados à GUI Qt. Como a GLib se constrói com Meson,
a corrente real é `ninja` → `meson` → `libffi` + `pcre2` → `glib` →
`libgpg-error` → `libgcrypt` → `cmake` → `wireshark`: nove receitas, das quais
cinco ou seis são as mesmas de que a pilha gráfica precisa. Até lá, `tcpdump`
4.99.6 dá captura hoje sobre a `libpcap` que já está escrita, sem nenhuma
ferramenta de build nova — e o fluxo continua sendo o que este perfil escolheu:
capturar na máquina, analisar o `.pcap` noutro lugar.

**IPv6 exercitado pela primeira vez.** O kernel sempre teve
`CONFIG_IPV6=y` e o busybox instalado tem `udhcpc6` e `ping6` compilados
(conferido rodando o binário — o `.config` em `source-inputs` é do busybox do
initramfs, onde `UDHCPC6` está desligado). O que faltava era userspace: o
`rcS` só chamava `udhcpc`. Agora ele tenta, em ordem e sem tornar nada fatal,
DHCPv6 (`udhcpc6` + `default6.script` novo, que **acrescenta** nameserver em
vez de reescrever o `resolv.conf` do v4) e, se ainda não houver nameserver v6,
lê o RDNSS do Router Advertisement com `rdisc6` — o kernel faz SLAAC sozinho
mas não expõe o RDNSS, e o busybox não sabe lê-lo. Daí a receita `ndisc6`
1.0.8, que **remove do STAGE** o daemon `rdnssd`: numa distro sem gerenciador
de serviço, uma execução única é a forma certa. Uma versão anterior deste
documento dizia que ela era "compilada **sem** o daemon", por `--disable-rdnssd`
— era falso, e a falsidade foi construída pela ferramenta: essa opção não
existe no `configure` do ndisc6, o autoconf apenas avisa "unrecognized options"
e segue, e o daemon vinha instalado. A mesma armadilha pegou o `nftables`
(`--disable-python`, `--disable-json`). Flag inexistente é aceita em silêncio,
e a receita passa a documentar uma decisão que nunca tomou; só o manifesto
denuncia. O kernel do alvo ganhou também
`IPV6_MULTIPLE_TABLES`, de que o `wg-quick` com `Table=auto` depende no lado
v6. O aceite `rede-v2` registrou os quatro fatos de IPv6 na seção de evidência
acima — dois exigidos, dois observados. O `rdisc6` executou de verdade no boot,
o que só é possível porque o `--sbindir=/usr/bin` foi corrigido: antes ele ia
para `/usr/sbin`, fora do PATH, e o `rcS` teria seguido em silêncio sem nunca
o encontrar. O caminho de RDNSS em si continua sem prova positiva — a rede do
hipervisor não anuncia DNS por RA, então o `rdisc6` rodou e não achou nada.

Uma ressalva que continua valendo, e uma que foi resolvida:

- **O kernel do alvo continua não sendo o kernel que boota.** A ESP do sistema
  instalado recebe o `BOOTX64.EFI` da mídia. A divergência de CONFIGURAÇÃO foi
  fechada — o kernel vivo agora tem o mesmo perfil de rede do alvo —, mas a
  divergência ESTRUTURAL permanece: uma atualização de `/boot/vmlinuz-*` pelo
  canal não alcança o EFI de boot. Retenção, rotação e atualização atômica da
  ESP seguem como gate.
- **Resolvida: a dependência acidental de shell.** A `glibc` não declara `bash`
  porque deixou de entregar os scripts que o exigiam; quem precisa de bash
  declara (`nftables` o faz, para o `config.status` que seu próprio `configure`
  gera). O fechamento provado acima é a medida disso.

### Hardware amd64 real — alvo declarado, parcialmente preparado

A mídia passou a ter como requisito bootar e instalar em máquina real, não só
em hipervisor. Levantamento do que isso exige, com o que já existe:

- **Mídia: já está certa.** O `xorriso` compõe com `-efi-boot-part
  --efi-boot-image`, `--gpt_disk_guid` e `--protective-msdos-label`
  (`minipax/src/media.rs:779`): a ESP aparece como partição GPT e um `dd` para
  pendrive deve ser bootável por firmware UEFI. Nada a fazer aqui.
- **Drivers: feito.** O kernel vivo cobria só máquina virtual — virtio, AHCI,
  teclado PS/2 — e falharia do pior jeito numa máquina real: sobe e não acha
  disco, ou sobe e não aceita tecla. Entraram builtin NVMe e VMD (sem o
  segundo, o NVMe fica invisível nos Intel que o escondem), a pilha USB
  (xHCI/EHCI, storage, HID — teclado de desktop e a própria mídia em
  pendrive), MMC/SDHCI, as NICs com fio comuns (Intel `e1000e`/`igb`/`igc`,
  Realtek `r8169`), `CPU_IDLE`/`INTEL_IDLE` (sem estados de baixa energia um
  laptop instala quente) e o gancho de `MICROCODE`. Os críticos entraram
  também na guarda que aborta o build se o `olddefconfig` os descartar.
- **Particionamento: GPT, pelo Minipax.** O instalador criava MBR porque o
  `fdisk` do BusyBox 1.35 não escreve GPT — e MBR trava acima de 2 TiB. O
  Minipax já escrevia GPT para compor a IMG; `minipax partition` reusa esse
  código, o que mantém o caminho que **apaga disco** dentro do Rust auditado.
  Duas diferenças em relação à IMG: os GUIDs vêm de `/dev/urandom` (dois discos
  instalados não podem compartilhar identidade de partição) e o setor lógico
  vem do chamador — presumir 512 num 4Kn escreveria a tabela no endereço
  errado. As cópias de reserva são gravadas antes do cabeçalho primário.
- **Raiz ext4.** Sem journal, desligamento sujo em hardware real vira
  verificação completa em vez de replay. O applet do busybox só faz ext2, e o
  initramfs não tem glibc — então a mídia leva um **mke2fs estático** próprio,
  compilado com o mesmo CC musl que já serve aos binários Rust e conferido
  pelo mesmo `require_static`, com seu `mke2fs.conf` ao lado. No sistema
  instalado, a receita `e2fsprogs` 1.47.4 entra em `target.world` e supersede
  os applets equivalentes do busybox. A margem exigida da raiz subiu de 64 para
  128 MiB por causa do journal.
- **Wi-Fi: deliberadamente fora.** `WIRELESS` continua desabilitado; exige blob
  de firmware, que é outra decisão.
- **Particionamento e ext4 agora EXERCITADOS** — mas em hipervisor. O aceite
  `rede-v2` mostrou `sda: sda1 sda2` e `EXT4-fs (sda2) … ordered data mode`
  num disco de verdade do VirtualBox. É a primeira vez que o GPT do Minipax e
  o `mke2fs` estático rodam fora de teste unitário.
- **RAM: 3 GiB.** Com 2 GiB a instalação morre no OOM killer. Ver a seção de
  evidência: é consequência do modelo de memória do instalador, não de um
  vazamento, e o preflight ainda não avisa.
- **Nada disso foi testado em hardware real.** Toda a evidência é QEMU e
  VirtualBox. Um aceite em máquina física é o próximo tipo de prova que falta,
  e nenhuma linha acima o substitui.

### `pack` v2 — a cegueira medida, e o que não mudou

O v1 não capturava xattr, e a consequência era maior do que "perde capability
na instalação": a **mesma árvore, com e sem `security.capability`, dava o
mesmo `reprocorr`**. A raiz de confiança não distinguia binário privilegiado
de binário comum. Medido com o minitrue anterior, ainda instalado no target,
contra o atual:

```text
árvore SEM xattr,  minitrue anterior : 7167ce1381e4bbb982eda0253a9ae6b8c1bec132ca071cc97a31d6d64ffca099
árvore SEM xattr,  minitrue com v2   : 7167ce1381e4bbb982eda0253a9ae6b8c1bec132ca071cc97a31d6d64ffca099  (idêntico)
árvore COM xattr,  minitrue anterior : 7167ce1381e4bbb982eda0253a9ae6b8c1bec132ca071cc97a31d6d64ffca099  (cego)
árvore COM xattr,  minitrue com v2   : c7de48cf4ae6e5285b1c29500806fd7f2a3967182bfe49f058081b3ef8600732
                                       tar declara DISTROPICA.pack=2
```

A primeira e a segunda linhas são a garantia de compatibilidade: nenhum
artefato existente muda de hash. A terceira é o bug. A quarta é o conserto.

## minitrue (a ferramenta)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| `rectify` mundo A (vendor → /opt) | ✅ | ✅ unit + E2E local offline + VBox atual | o aceite instalou jq 1.8.2 do binário upstream, offline, e confirmou `ORIGIN=vendor` e persistência após reboot |
| `rectify` mundo B (fonte → /usr) | ✅ | ✅ unit + E2/E2-clean + VBox atual | o aceite compilou tree 2.3.2 da fonte, offline, com `ORIGIN=fonte`; a prova histórica também compilou Make 4.4.1 |
| Perfis de toolchain (`none`/`seed`/`cross`/`native`) | ✅ | ✅ unit + E2E local offline | `seed`/`cross` em receita fonte implicam Zig no fingerprint e no plano de compilação local; a prova Make instalou Zig antes do build e o manteve fora do `world`. Canal/binário e `none`/`native` não o instalam |
| Receitas de montagem (sem SRC) | ✅ | ✅ | `build()` gera o pacote (config, esqueleto de `/etc`) — nada a baixar; usada por `base` 0.2, com snapshot autocontido em `files/` e fábrica `/etc` |
| Metapacotes (`KIND=meta`, mundo M) | ✅ | ✅ unit + instalação direta + VBox atual | agregam somente `DEPS`, não têm SRC, funções de build, payload nem artefato de canal; registro v2 usa `KIND=meta`, `WORLD=M`, `ORIGIN=meta` e manifesto vazio. `miniplenty-buildbase` é o primeiro consumidor |
| Runner mundo B em rootfs (bwrap, --unshare-net, --clearenv) | ✅ | ✅ | isola rede/ambiente do `build()`, mas o **rootfs fica gravável**; avaliação top-level da receita e mundo A ainda rodam no host |
| `retry` de ICE | ✅ | — | usado no E2 |
| `fingerprint` de build | ✅ | ✅ | **transitivo**; inclui `DEPS`, `BUILD_DEPS` e Zig implícito para fonte `seed`/`cross`. Snapshot de `recipe`+`files/`, e o mesmo `files/` autocontido é materializado no `WORK` (symlinks auxiliares são recusados) |
| Supersessão provisional (`PROVISIONAL` + `SUPERSEDES=`) | ✅ | ✅ | declarativa; no mundo B a cessão volta se a instalação falha. `SUPERSEDES` fica no registro e prova cadeias provisional→provisional; mundo A e restauração ao remover sucessor ainda faltam |
| `pack` determinístico (v2) | ✅ | ✅ | a parte mais madura. O v2 captura **xattr/capability** em registro PAX por entrada, e a claim `f:` passa a prendê-los — antes um `setcap` sumia no empacotamento e o `verify` não acusava. Versão declarada = mínima exigida do leitor, então árvore sem xattr hasheia idêntico ao v1 e nenhum `REPROCORR`/`ARTIFACT_HASH` migra. Faltam ACL, `trusted.*` e sparse |
| Manifesto v2 (conteúdo + tipo) | ✅ | ✅ | `f:` prende modo+conteúdo do regular, `l:` prende alvo, `d:` prende modo do diretório-raiz+árvore (payload A e vazios B); leitura v0/v1 mantida |
| `verify` (presença + integridade por claim) | ✅ | ✅ unit + instalação direta + VBox atual | inspeção confinada ao rootfs; confere conteúdo/tipo/alvo/árvore, denuncia journal pendente/formato futuro e exige que toda `DEPS` de registro v2 tenha registro factual válido. Não verifica `BUILD_DEPS` nem varre regulares órfãos em /usr |
| `cache verify` (disponibilidade sem instalação) | ✅ | ✅ unit + E2E local + VBox atual | força offline/sem TOFU, confere hashes e assinaturas dos nomes explicitamente passados e não cria registro, link ou entrada no `world`; conferiu jq, Make, tree e Zig na mídia atual. Ainda não resolve nem prova a closure completa da SPEC-0013 |
| `memoryhole` (+ preserva modificado) | ✅ | 🟡 | sem `--tudo`, sem `--orfaos`; sem rollback do payload |
| `explain` / `why` (proveniência) | ✅ | ✅ | ORIGIN/hash-arq; ABOUT/REPROCORR congelados no meta, com fallback literal legado sem executar receita histórica; corroboração e reprocorr. Não mostra ainda cadeia completa, aresta tipada, plan lock ou `build-residue` |
| `--sync` (convergir ao world) | ⬜ | — | stub; SPEC-0011 |
| Plano/plan lock e closures tipadas | ⬜ | — | `PLAN_LOCK_FORMAT=1`, `plan` e convergência por um resolvedor comum são norma-alvo da SPEC-0013 |
| Auditoria ELF/ABI + mapa de provedores (`audit`) | ✅ | ✅ unit + cotejo com `readelf` | `AUDIT_FORMAT=1`; lê `PT_INTERP`, `DT_NEEDED`, `DT_SONAME`, `RPATH`/`RUNPATH`, `verneed`/`verdef` e shebang **sem executar nada** — parser próprio pela tabela de programa, sem `ldd`. Mapa de provedores vem dos registros, resolve usr-merge componente a componente e árvore `d:` do mundo A. Serialização canônica + `CLOSURE_SHA256`. **É gate de `channel emit`**: publicar payload com requisito sem provedor declarado é recusado. `dlopen`/plugin/subprocesso continuam fora do alcance estático, e a composição de mídia ainda não é gateada |
| PATH/view de build fechado | ⬜ | — | o runner limpa o ambiente, mas ainda expõe `/usr/bin:/bin` do rootfs; ferramentas implícitas podem vazar para o build |
| `rollback` / `unperson` / `lint` | ⬜ | — | stub |
| Canal binário assinado | ✅ | ✅ unit + E2E offline | config HTTPS/chave minisign pinada, índice canônico v2 assinado com `RECIPE_FINGERPRINT`, cache endereçado por conteúdo, `.tar.zst` com limites e conferência do tar interno; seleção exige que a identidade autenticada coincida com a receita efetiva. `/etc/minitrue/channels/` existente é autoritativo e, vazio, desativa a seed |
| Resolução `--no-binary` / `--only-binary` | ✅ | ✅ unit + E2E offline histórico | binário de canal preserva mundo B; `--only-binary` resolve metapacotes locais sem artefato, mas exige artefato para cada dependência fonte e não expande `BUILD_DEPS` nem Zig implícito |
| Lock de canal | ✅ | ✅ unit + E2E offline | `CHANNEL_LOCK_FORMAT=2`; seleção, chave, índice, pacote, fingerprint autenticado, caminho, hash de transporte, `reprocorr` e trust; persistido por hash em `/var/lib/minitrue/channel-locks/` e cotejado semanticamente por `verify` |
| `channel emit` | ✅ | ✅ unit | `CHANNEL_EMIT_FORMAT=2`; reutiliza o tar autenticado do cache para registros vindos de canal e só reconstrói registros locais quando topologia, metadados e `ARTIFACT_HASH` podem ser provados; emite pool + índice sem assinatura. Release deve emitir no próprio build |
| `channel keygen` / `channel sign` | ✅ | ✅ unit + cotejo com o `minisign` 0.12 | Assinar deixou de depender do hospedeiro. O consumidor sempre exigiu minisign, mas o produtor chamava o binário `minisign` do host — dependência de host bem no ponto da **raiz de confiança do canal**, o oposto do que o resto da árvore faz. Formato `Ed`/`ED` implementado sobre a ed25519-dalek que as attestations já traziam; `sign` confere com `minisign-verify` o que acabou de escrever, isto é, o produtor é validado pelo consumidor antes de publicar. Chave sem senha só: scrypt exigiria dependência nova e é **recusado**, não ignorado. **Equivalência medida**: para a mesma chave e a mesma mensagem, a assinatura é byte-idêntica à do `minisign` 0.12, e o binário do host valida a nossa. Falta suporte a chave com senha |
| Gestão de canais (`add/remove/list/refresh`) | ⬜ | — | hoje a configuração é administrada por arquivos estritos; em especial, não há `channel refresh` auditável. A CLI administrativa da SPEC-0009 é gate de release |
| Lock global por rootfs (flock) | ✅ | ✅ | rectify/memoryhole; auto-libera na saída |
| Confinamento de caminhos destrutivos | 🟡 | ✅ unit | `openat2(RESOLVE_IN_ROOT)` em inspeção/remoção; Journal aceita usr-merge interno e recusa ancestral que resolve fora do rootfs, mas mutações do Journal ainda usam caminhos após o preflight. Converter tudo a operações fd-relative para fechar TOCTOU contra mutador concorrente é gate de release |
| Registro transacional do mundo B (meta = commit) | ✅ | ✅ | `manifest`/`recipe`/`meta` entram no journal; `TRANSACTION_ID` do meta, escrito por último, decide recovery |
| `RECORD_FORMAT=` | ✅ | ✅ | hoje 2; v0/v1 pode migrar in-place sob guardas ou reconstrói; provisional já cedido congela; formato futuro falha fechado |
| Journal + rollback do mundo B (STAGE→/) | ✅ | ✅ | formato 2 + `txid`; intenção antes da mutação; recovery **global** antes de nova operação; journal legado, >1 ativo ou rollback sobre claim posterior falha fechado e preserva backups. Sem promessa contra perda de energia: falta `fsync` |
| `SUPERSEDES=` explícito | ✅ | ✅ | declarado em 6 receitas do E2; colisão não-declarada = doublethink |
| Assinatura upstream por artefato (`SIG`) | ✅ | ✅ | minisign/signify; cache prende hash do artefato+chave+URL e é revalidado |
| Verificação OpenPGP / `SIGSUMS` | ⬜ | — | parser reconhece os campos, executor falha explicitamente; Marco 0.2, sem `gpg` externo |
| `reprocorr` (raiz de confiança) | ✅ | ✅ | build de fonte grava `ARTIFACT_HASH`=`pack(STAGE)`; receita que pina `REPROCORR` exige reprodução (crimestop). SPEC-0009 §8.1 |
| Attestation + corroboração (`attest`/`corroborate`) | ✅ | ✅ | `ATTEST_FORMAT=1`, ed25519-dalek; versão+fingerprint impedem replay e a emissão exige registro v2, txid, baseline, snapshots e claims íntegros. ≥2 builders pinados concordam. **Independência ainda simulada** (1 máquina) |

## minipax (perfil, instalação e mídia)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| CLI única (`install`, `media build`, `lock`) | ✅ | ✅ unit | binário Rust separado; `bootstrap/distropica-bootstrap` apenas o localiza/compila e delega |
| Perfil estrito + `profile.lock` | ✅ | ✅ unit | `PROFILE_LOCK_FORMAT=2`/`PROFILE_CONTENT_FORMAT=2`; normaliza os três worlds e prende `cache.world` em `CACHE_WORLD_SHA256`, além de Newspeak/overlay/cache, arch, epoch, `MEDIA_SIZE_MIB=512`, `INSTALL_READY` e pinos oficiais. `MEDIA_SIZE_MIB` dimensiona a IMG, não fixa a ISO |
| Instalação em rootfs (`--target`) | ✅ | ✅ unit + E2E dev atual | prepara FHS/usr-merge, congela Newspeak/cache e, offline, executa `cache verify` antes de `rectify` + `verify`; o target atual inteiro foi materializado de canal numa raiz vazia e passou nas provas de toolchain |
| Ingestão de mídia (`install-media`) | ✅ | ✅ unit | valida controles sem seguir symlinks, hashes de lock/EFI, coerência modo/cache e reconstitui o perfil byte a byte antes de tocar no target; `--export-boot-efi` cria sem sobrescrever o snapshot EFI validado e o remove se a instalação falhar |
| Executor e `install.manifest` | ✅ | 🟡 unit + E2E dev | copia Minitrue para `memfd` selado, mede o Minipax, persiste ambos em `/usr/bin`; manifesto prende hashes, classe e opções `OFFLINE`/`FROM_SOURCE`/`ONLY_BINARY`. O target mínimo exige executores estáticos para usá-los após o boot |
| Retomada e proteção do target | ✅ | ✅ unit | recusa `/`, target sujo e perfil divergente; `--resume` exige marca anterior do Minipax |
| IMG GPT+FAT32 | ✅ | ✅ unit local | GPT/FAT internos; GUIDs e serial FAT derivam do hash do payload completo. Duas composições da fixture dão o mesmo sha256; ainda não há prova entre builders nem de boot |
| ISO UEFI/El Torito | ✅ | ✅ unit local | fixa metadados; usa caminho absoluto do `xorriso`, hash antes/depois e ambiente fechado, registra versão+hash e pós-valida `CD001`. Reproduziu só localmente |
| Sidecars (`.sha256`, `.media.lock`, `.manifest`) | ✅ | ✅ unit | temporários publicados sem sobrescrever antes da imagem; não há transação multi-arquivo, logo corrida/falha pode deixar sidecars sem imagem |
| Classes de insumos de release | ✅ | 🟡 unit | `PROFILE_CLASS`, `MEDIA_CLASS` e `INSTALL_CLASS` podem ser `official-inputs` após os respectivos pinos; isso não declara reprodução oficial |
| Modos canônicos das árvores | ✅ | ✅ unit | dirs `0755`, `root/` do overlay `0700`, `shadow`/`gshadow` e backups `0600`, executáveis `0755`, demais regulares `0644`; não depende dos modos que o Git preserva |
| Limites das árvores | ✅ | ✅ unit | Newspeak e overlay: 128 MiB de conteúdo regular cada, **em memória**; cache: **streaming**, teto de 4 GiB−1 (limite do FAT32 para UM arquivo, não de RAM); 50.000 entradas por árvore. Desde 2026-07-30 a árvore de cache é coletada por REFERÊNCIA (`EntryKind::RegularAt`), o `cache.tar` é escrito direto num `Write` com o sha256 saindo do mesmo fluxo, e o payload vai do disco para a mídia com buffer fixo. O instalador faz o mesmo em duas passadas: uma valida a árvore inteira lendo só cabeçalhos, a outra extrai. `payload_hash` inalterado — as ISOs continuam bit a bit idênticas às da versão em memória, o que os testes de reprodutibilidade provam. No canal, `.tar.zst` selado e tar descompactado ainda coexistem |
| Modo offline/cache | ✅ | ✅ unit + E2E atual | `cache.world` exige jq, Make, tree e Zig. Make também é instalado por depender de `miniplenty-buildbase`; jq/tree começam ausentes para as provas e Zig fica somente no cache. Com o modo gráfico, a árvore passou a **647 MB** — o que só é possível porque o cache virou streaming |
| Modo online/bootstrap de canal | ✅ | ✅ unit | Minipax exige config + índice/assinatura pareados, rejeita objetos e semeia antes de `rectify`; Minitrue valida minisign no uso. Não há endpoint oficial para E2E |
| BOOT EFI vivo (kernel+initramfs+Minipax+Minitrue) | ✅ | ✅ E2E QEMU histórico + VirtualBox atual | fixa Linux 7.1.4, BusyBox e executores musl `static-pie`. `CONFIG_MODULES=y`, nenhum `.ko` na mídia e release `7.1.4-distropica-live`; o EFI atual inclui `simpledrm`+`fbcon` e VirtIO de rede built-in, sem fixar o disco |
| Instalação por ISO em QEMU/OVMF | ✅ | ✅ E2E final-v10 | aceite histórico e automatizado: antes de escolher disco, materializa closure em `/run` e exporta snapshot EFI validado; depois particiona, copia, verifica, instala EFI e publica o marcador completo por último. Segundo boot ocorreu sem ISO |
| Instalação por ISO no VirtualBox | ✅ | ✅ E2E local atual | `miniplenty-v1` provou EFI64/VMSVGA/SATA, ejeção antes do wipe, reboot sem ISO, Vim/ripgrep/toolchain por padrão, C/C++/arquivo/Make offline, jq binário, tree fonte, persistência, `verify` e VirtIO/NAT; Zig permaneceu só no cache |
| Boot da IMG em QEMU/OVMF | 🟡 | — | compositor IMG existe e reproduziu localmente; o aceite funcional final-v10 exercitou somente a ISO |
| Particionamento/escrita destrutiva em disco | ✅ | ✅ QEMU final-v10 + VirtualBox atual | PID 1 só recebe/autoriza o disco depois do preflight em `/run`: `/dev/vda` no aceite automatizado e `/dev/sda` no VirtualBox. O negativo final-v10 deixou um disco histórico de 256 MiB intacto; o aceite atual usou 4096 MiB. Cria MBR com ESP FAT32 de 64 MiB + raiz ext2; não é ainda um particionador geral |

O perfil `profiles/official` continua com `STATUS=development`, mas agora
declara `INSTALL_READY=yes`. Seu `target.world` contém `base`, `linux`,
`ripgrep`, `vim` e `miniplenty-buildbase`. A receita meta tem
`DEPS="base make gcc-pass2"`, registro `KIND=meta`/`WORLD=M` e nenhum payload;
o fecho final de GCC traz `linux-headers`, glibc, `mathlibs-glibc`, zlib e
`binutils-glibc`; Vim traz ncurses. Make, GCC/G++, assembler e linker ficam instalados desde o
primeiro boot, mas apenas `miniplenty-buildbase` é desejo top-level da
toolchain. Seu `cache.world` contém jq, Make, tree e Zig: essa declaração só
exige disponibilidade offline; Make é instalado por causa do metapacote,
jq/tree começam ausentes e Zig fica no cache/sob demanda. O lock v2 separa essas intenções com `TARGET_WORLD_SHA256` e
`CACHE_WORLD_SHA256`. O perfil fixa `MEDIA_SIZE_MIB=512` para dimensionar a
IMG; a ISO segue o tamanho do payload. Os runners atuais usam discos de
4096 MiB.

Como o cache de desenvolvimento é passado por `--cache`, o E2E recebe classe
`custom`; isso não o publica nem cria um canal oficial. Mesmo uma futura classe
`official-inputs` não será, por si,
reprodução oficial: isso dependerá do sha256 final pinado num manifesto
oficial externo assinado.

A closure atual foi reconstruída, exercitada, reemitida no canal local assinado
e integrada ao cache, lock, EFI e ISO aceitos no VirtualBox. O rebuild repetido
em ambiente independente ainda é necessário para o claim de reprodutibilidade.

O aceite final-v10 executou ISO → disco vazio → segundo boot sem ISO, com rede
ausente e TCG. Duas composições locais da ISO foram byte a byte idênticas. Uma
ISO cujo `profile.lock` não correspondia ao hash de `media.meta` foi recusada
ainda no preflight, e o disco de teste permaneceu igual a um arquivo zerado de
256 MiB. Esse probe negativo foi encerrado no shell de rescue pelo timeout; o
`RESULT=pass` abaixo pertence somente ao aceite positivo de duas fases:

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

Separadamente, o aceite **histórico** network-v1 iniciou a ISO numa VM
VirtualBox EFI64 com adaptador VirtIO/NAT e o cabo virtual desligado. Instalou em `/dev/sda`, ejetou
a ISO **antes** do wipe e concluiu a partir da closure pré-validada em RAM. O
segundo boot iniciou o mesmo VDI sem mídia óptica e ainda sem rede, chegando ao
login de `root`. No terceiro boot, com o cabo ligado, obteve DHCP IPv4, rota
padrão, `resolv.conf` com nameserver IPv4, resolução de `localhost` pelo host
resolver do NAT e resposta do gateway. O cabo foi então desligado: `ripgrep`,
ausente no sistema inicial, foi instalado explicitamente na versão 15.2.0 a
partir do objeto extra do cache, e `minitrue verify` passou. Esse probe de DNS é
local e não prova acesso à Internet. As duas composições locais dessa ISO foram
byte a byte idênticas. É um segundo hipervisor no mesmo host, não hardware real
nem builder independente:

```text
EVIDENCIA_VIRTUALBOX_NETWORK_V1=local-custom
ACCEPTANCE_META=target/vbox-acceptance-network-v1/evidence/acceptance.meta
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
ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
REPEATED_ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
BOOT_EFI_SHA256=71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88
OFFLINE_SERIAL_LOG_SHA256=d31045696f9996e269f25e1e97c8dfa69ea2821ca78804c850503bacac01ba3d
ONLINE_SERIAL_LOG_SHA256=f4691c6db2c4885bf93e58718d3cdfc57883ae1be185a0f4346e5aa92ac866b4
ISO_EJECTED_BEFORE_WIPE=yes
INSTALL_AND_SECOND_BOOT_OFFLINE=yes
SECOND_BOOT_WITHOUT_ISO=yes
ROOT_LOGIN=yes
THIRD_BOOT_WITH_NAT=yes
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
RUN_STATE=passed
FINAL_RESULT=passed
```

O runner atual executou a prova: ripgrep 15.2.0, Vim 9.2.0837,
`miniplenty-buildbase`, GNU Make 4.4.1, binutils 2.45 e GCC/G++ 15.3.0 presentes
desde o primeiro boot; metapacote registrado no mundo M sem payload; componentes
da toolchain vindos do canal e fora do world explícito; Zig ausente; e, ainda
sem link, compilação/execução C e C++, criação e link de arquivo estático,
construção por Makefile e `verify` limpo. Também instalou jq 1.8.2 do binário
upstream e tree 2.3.2 da fonte, ambos offline, e comprovou sua persistência após
o terceiro boot. Os hashes da execução atual estão no início deste documento.

Esses hashes identificam uma execução do workspace
de desenvolvimento; não serão pinos de release nem substituirão manifesto
externo assinado. Endpoint, chave e publicação oficiais continuam ausentes.

## Bootstrap (SPEC-0005)

| Estágio | Estado | Nota |
|---|---|---|
| E0 — chroot musl-estático | ✅ | |
| E1 — `./configure && make` | ✅ | |
| E2 — glibc + gcc nativo | ✅ | **Evidência histórica E2-clean:** um rootfs novo, com seed limpo, construiu 16 pacotes. O grafo atual com zlib e `install-strip` também foi reconstruído uma vez e passou C/C++/arquivo/Make; falta comparação em dois ambientes limpos |
| E3 — kernel + boot | 🟡 | O smoke anterior bootou Linux 7.1.4 do E2 com raiz 9p. Separadamente, o EFI-stub live atual passou em ISO→disco→boot sem mídia no VirtualBox, cobrindo `simpledrm`/`fbcon`, PS/2, AHCI, `/dev/sda`, VirtIO/NAT, toolchain e `verify`; faltam runit, `.config` de hardware geral e gestão completa de contas |
| — openssl 4.0.1 (base de confiança do kernel) | ✅ | mundo B, compilado pela toolchain nativa (libcrypto/libssl, `-DZLIB`); SHA conferido no download. Habilita geração/uso da chave de módulos; **attestation usa ed25519-dalek e independe de OpenSSL**. O materializador de `/etc` agora trata symlinks, com regressão coberta |
| — base 0.2 (config Fase B) | ✅ E2E local | receita de montagem `GPL-3.0-or-later` com `TOOLCHAIN=none`: além de `/etc/inittab`, `rcS`, `rcK`, `os-release`, `hostname` e a cópia da GPL, sobe interfaces e tenta DHCP IPv4 sem tornar a falha fatal. O fingerprint atual entrou no canal/cache/ISO aceitos; DHCP, rota e DNS local passaram. Não cria `/etc/shadow`, portanto sozinha não fecha login autenticado |
| E4 — userland vendor / GUI | ⬜ | |

## Reprodutibilidade (SPEC-0010)

| Item | Estado |
|---|---|
| Ambiente determinístico (epoch/LC/TZ/umask) | ✅ |
| `ar` determinístico | ✅ |
| m4, gmp, **gcc**, **glibc** byte-idênticos (2 builds) | ✅ histórico para as receitas e os artefatos então medidos; o `gcc-pass2` atual com `install-strip` foi reconstruído uma vez, não ×2 |
| Hash de artefato via `pack` = `reprocorr` | ✅ histórico (m4/gcc/glibc); payloads atuais de GCC/binutils emitidos e exercitados, ainda sem comparação ×2 |
| `REPROCORR` pinado + verificado no build | ✅ (`m4` pina; build de fonte grava `ARTIFACT_HASH` e exige reproduzir o pinado — crimestop se divergir) |
| Cotejo do artefato completo produzido pelo E2-clean | ⬜ (passo posterior à primeira execução a frio) |
| Identidade declarativa do sistema (`profile.lock`) | ✅ (`PROFILE_LOCK_FORMAT=2`/`PROFILE_CONTENT_FORMAT=2`; inclui `CACHE_WORLD_SHA256`, tamanho, prontidão, hash calculado e os três pinos oficiais) |
| Executor da instalação medido = executado | ✅ local (`memfd` selado, ambiente fechado e hash no `install.manifest`) |
| Rootfs instalado byte-a-byte idêntico | ⬜ (`INSTALLED_AT`, uid/gid e demais metadados ainda impedem o claim) |
| IMG byte-idêntica em duas composições | ✅ local (fixture, mesmo binário/toolchain; GPT/FAT normalizados) |
| ISO byte-idêntica em duas composições | ✅ local para fixture, ISO final-v10 e ISO network-v1 do VirtualBox (mesmos insumos, binário e `xorriso`, cujo executável é medido) |
| IMG/ISO byte-idênticas entre builders independentes | ⬜ |
| Reprodução reconhecida contra manifesto oficial externo assinado | ⬜ (sidecars locais não são autoridade) |
| R4 — reprodução funcional da mídia de desenvolvimento | ✅ local para o perfil atual no VirtualBox: instalação, reboots, toolchain, jq binário, tree fonte, persistência, `verify` e rede NAT. Não prova Internet, hardware real, builders independentes nem release oficial |

## Limitações conhecidas (do parecer externo)

- **E2-clean histórico (uma vez):** um rootfs novo reproduziu a frio o fluxo
  com seed limpo e grafo corrigido. Achou e consertou 2 bugs que o rootfs sujo
  mascarava (SUPERSEDES seed→busybox; libstdc++ lib64×lib usr-merge). As
  receitas atuais com `install-strip` já tiveram um rebuild funcional; faltam
  dois ambientes limpos para a nova prova "reproduzível ×2" e mover scripts,
  hashes e logs hoje transitórios para um diretório versionado `proofs/e2/`.
- **Mídia instalável validada em QEMU/OVMF e VirtualBox/EFI:** o aceite
  automatizado final-v10 cobriu a ordem
  atual. O PID 1 primeiro materializa e verifica toda a closure em
  `/run/distropica-prepared`, configura a conta e recebe de
  `install-media --export-boot-efi` um snapshot EFI medido. Somente depois pede
  ou aceita o disco, confere capacidade, particiona, copia, roda
  `minitrue verify`, grava o EFI e publica por último
  `disk-install.complete`. O teste negativo confirmou a recusa de um
  `profile.lock` incoerente com `media.meta` antes de qualquer wipe. Isso ainda
  não prova boot da IMG, hardware real, reprodução entre builders ou release
  oficial. O aceite network-v1 separado repetiu o caminho positivo no
  VirtualBox 7.2.6: console, teclado PS/2, AHCI `/dev/sda`, ejeção da ISO antes
  do wipe, instalação e segundo boot com o cabo virtual desligado e login de
  root. No terceiro boot, VirtIO/NAT exerceu o DHCP IPv4 não fatal de `base`
  0.2, rota padrão, nameserver IPv4, resolução local e gateway. Depois de
  desligar novamente o cabo, instalou `ripgrep` 15.2.0 do cache e passou em
  `minitrue verify`. A execução atual `miniplenty-v1` substituiu esse passo pela
  presença inicial de ripgrep, Vim, metapacote M, Make e toolchain GCC final,
  seguida por provas C/C++/arquivo/Makefile, jq binário e tree fonte offline;
  Zig permaneceu apenas no cache. Isso não foi um probe da Internet.
- **Gates do perfil oficial:** o canal e `--only-binary` estão implementados,
  e o perfil marca `INSTALL_READY=yes`, mas o cache usado no E2E é de
  desenvolvimento com `TRUST=builder`. O superset network-v1 — a closure do
  target antigo mais o objeto pinado de `ripgrep` — foi testado historicamente.
  Agora `target.world` inclui ripgrep, Vim e `miniplenty-buildbase`; Make pertence
  tanto à closure instalada quanto à disponibilidade de `cache.world`, jq/tree
  ficam disponíveis para as provas e Zig pertence somente ao cache/sob demanda.
  A mídia integrada foi construída e aceita; GCC/binutils foram reemitidos com
  `install-strip`. Ainda não há
  endpoint, chave de release, índice ou artefatos oficiais publicados. A
  separação nominal de `base` 0.2 para `base-config`, runit e a política uid/gid
  continuam abertos; o agregador de produção agora é a verdadeira meta-receita
  `miniplenty-buildbase`. `profiles/official` permanece
  `STATUS=development`, portanto nenhuma saída recebe a classe de insumos
  oficiais. `STATUS=release` já exige três pinos separados:
  `OFFICIAL_CONTENT_SHA256`, `OFFICIAL_BOOT_EFI_SHA256` e
  `OFFICIAL_MINITRUE_SHA256`. A coincidência gera apenas `official-inputs`; o
  claim de reprodução depende de comparar o sha256 final com um manifesto
  oficial externo assinado, cuja publicação ainda não existe.
- **Cobertura do kernel vivo:** o `.config` cobre UEFI x86_64, virtio,
  CD/SCSI, AHCI/PIIX, teclado PS/2, ISO9660, ext2/ext4, FAT e o framebuffer EFI
  pelo caminho `simpledrm`/`fbcon`. Isso fechou o console, a entrada e o disco
  SATA do VirtualBox usado no aceite, além do alvo QEMU. O network-v1 também
  fechou o caminho local do adaptador VirtIO, DHCP IPv4, rota, DNS e gateway
  NAT nessa VM; não permite afirmar acesso à Internet nem suporte genérico a
  controladores NVMe, USB, outras placas de rede, GPUs ou armazenamento
  encontrados em hardware real. O kernel mantém
  `CONFIG_MODULES=y`, mas o initramfs não leva módulos; tudo que a instalação
  precisa deve estar built-in. `LOCALVERSION=-distropica-live` produz o
  release `7.1.4-distropica-live`, isolando a busca automática de
  `/lib/modules/7.1.4` que pertence ao kernel do target.
- **Kernel EFI embutido:** o mesmo `BOOTX64.EFI` da mídia é copiado para a
  ESP do sistema instalado. Como kernel e initramfs estão incorporados, uma
  atualização de `/boot/vmlinuz-*` pelo canal não atualiza automaticamente o
  EFI de boot; retenção/rotação e atualização atômica do EFI são gates.
- **Publicação da mídia não é transação de conjunto:** os três sidecars são
  preparados e publicados sem substituição antes da imagem. Isso evita imagem
  publicada pelo Minipax sem sidecars, mas corrida ou falha pode deixar parte
  ou todos os sidecars sem imagem; não existe rollback multi-arquivo.
- **Escala do Minipax:** o cache **deixou de ser limite de memória** em
  2026-07-30. Newspeak e overlay seguem em memória, a 128 MiB de conteúdo
  regular cada, e isso está certo: são árvores pequenas por natureza. O cache
  passou a streaming em toda a cadeia — `collect` guarda referência em vez de
  conteúdo, `pack_into` escreve o tar direto no destino somando o sha256 no
  caminho, a composição da mídia copia do disco para a ISO com buffer fixo, e o
  instalador valida numa passada de cabeçalhos antes de extrair noutra. O teto
  que restou, 4 GiB−1, é o do FAT32 para um arquivo, e não de RAM. O que
  destravou: o cache do perfil gráfico mede **647 MB**, contra os 267 MB do
  perfil de rede, e teria sido recusado. O `payload_hash` não mudou, o que os
  testes de reprodutibilidade de ISO e IMG comprovam. O instalador vivo
  continua montando a raiz pré-validada em `/run`, trocando memória por
  garantia fail-before-wipe — e ela funcionou: a primeira tentativa da mídia
  gráfica foi recusada pelo limite antigo do instalador **antes de tocar no
  disco**, caindo no shell de resgate.
- **Travamento intermitente do OVMF antes do kernel, NÃO caracterizado.** Em
  parte das execuções o firmware fica preso no splash do TianoCore, com o QEMU
  a 100% de CPU, 113 bytes de serial e zero escrita em disco — por 18 minutos
  numa observação. Repetir o mesmo comando com a mesma ISO arranca em 10 s.
  O que a medição diz, e o que ela NÃO diz: a estrutura da mídia está
  descartada como causa — GPT, El Torito e a ESP de 64 MiB em LBA 128 são
  idênticos entre a ISO que trava e a que não trava, e a mesma ISO faz as duas
  coisas. A hipótese inicial de que era o TAMANHO (777 → 780 MB) não sobreviveu
  ao teste: a v9, a maior, arrancou 6 de 6 vezes seguidas com o hospedeiro
  ocioso, em 2, 4 e 8 GiB de RAM; as falhas foram todas com carga alta, mas a
  v7 arrancou 2 de 2 sob a MESMA carga, então nem isso explica. Fica registrado
  como fenômeno observado sem causa estabelecida — e é gate: uma mídia que
  boota em duas de três tentativas não é instalável para um usuário, por mais
  que o aceite passe na tentativa seguinte.

  O que foi descartado por medição, para quem retomar não refazer:
  - **Não é a mídia corrompida.** A ESP extraída da ISO é FAT32 válido (129.046
    clusters de dados, 1 setor por cluster, assinatura 0xAA55), e o
    `EFI/BOOT/BOOTX64.EFI` dentro dela tem sha256 IDÊNTICO ao arquivo de origem
    — andei a árvore de diretórios FAT à mão para confirmar. O bloco que o GPT
    aponta em LBA 128 e o `/boot/esp.img` extraído pelo ISO9660 têm o mesmo
    sha256, então o `--efi-boot-image` do xorriso fez o que promete.
  - **Não é configuração do QEMU.** Bissecção com `-smp 2`, `-cpu qemu64`,
    `-boot order=d,strict=on`, `-machine pc` e `-machine q35`: TODAS as
    combinações produzem sucesso e falha em execuções repetidas da mesma ISO.
  - **Não é RAM do convidado.** 2, 4 e 8 GiB, duas execuções cada: seis
    sucessos.
  - **Correlaciona com o tamanho, mas fracamente.** A ISO de 777 MB arrancou
    10 de 10; a de 780 MB, cerca de dois terços das vezes. Amostra pequena.

  A mensagem do firmware, quando falha, é `BdsDxe: failed to load Boot0002
  "UEFI QEMU DVD-ROM" ...: Not Found` seguida de `No bootable option or device
  was found` — o OVMF ENXERGA o dispositivo e não constrói a opção de boot da
  ESP do El Torito. Suspeita a investigar, não verificada: a ESP tem 64 MiB
  para um payload de 17 MB (o `create_plain_esp` usa
  `max(payload + 16 MiB, 64 MiB)`), e o firmware lê esse bloco inteiro por IDE
  emulado, em PIO. Encolher a ESP para o mínimo do FAT32 (~34 MiB) cortaria
  essa leitura pela metade e tiraria 30 MB da ISO. Vale tentar antes de culpar
  o OVMF.
- **Escala do canal:** o consumidor sela transporte e tar e limita cada um a
  16 GiB, mas ainda não limita a quantidade de entradas do tar. Um objeto
  assinado enorme pode esgotar memória no preflight — sem alcançar o wipe, mas
  tornando a instalação indisponível. Streaming e limite de entradas são gates.
- **Resgate depois do wipe:** falhas verificadas de cópia, hash, sync e
  desmontagem entram no shell de rescue e o marcador final continua fail-closed.
  Alguns comandos auxiliares pós-wipe ainda dependem apenas de `set -e`; se um
  deles falhar, PID 1 pode encerrar em vez de abrir o rescue. Uniformizar esse
  tratamento é gate de robustez do instalador.
- **Destino de `--export-boot-efi`:** a mídia viva usa um pai `0700` sob
  `/run`, mas a CLI genérica remove a exportação por pathname se a instalação
  falha. Chamadores privilegiados devem usar diretório de confiança até a
  limpeza ser convertida para operação fd-relative com identidade presa.
- **Bootstrap ainda é de desenvolvimento:** a casca versionada compila
  `minipax` e `minitrue` com Cargo (ou aceita binários indicados pelo ambiente)
  e delega. Por padrão usa `x86_64-unknown-linux-musl`, exige compilador C
  compatível + `readelf` e recusa executável com segmento `INTERP`: os binários
  produzidos são musl `static-pie`, não ligados ao host. Caminhos explícitos em
  `MINIPAX`/`MINITRUE` continuam insumos do usuário. Um bundle imutável e
  assinado para download direto em outra distribuição ainda não foi publicado.
- **Transacional (mundo B):** payload, registro e cessões de manifesto passam
  pelo journal por pacote. Cada intenção precede a mutação; o `TRANSACTION_ID`
  do `meta` é a marca final. Sob o lock, um sweep recupera o único journal antes
  de qualquer nova operação; estados antigos com mais de um journal, ou rollback
  que atingiria ownership commitado depois, falham fechado e preservam backups.
  `verify` continua somente diagnóstico. O mundo A não possui transação de
  conjunto. **Não há `fsync`**, portanto não se promete recuperação após perda
  de energia. Também falta restaurar o payload provisional ao remover sucessor.
  Além disso, o Journal ainda faz parte das mutações por caminhos após validar
  ancestrais. O `flock` impede apenas concorrentes cooperativos; um mutador
  hostil com acesso ao mesmo rootfs pode explorar uma janela TOCTOU. Operações
  integralmente fd-relative e confinadas são gate de release.
- **Registro v2:** o fast path exige `meta`, `manifest`/`manifest@` e
  `recipe`/`recipe@` coerentes com o snapshot corrente; prende conteúdo de
  regulares, alvo de links e modo+árvore de diretórios. `manifest@` é baseline
  de provisional e a exceção legado exige dono sucessor para cada claim
  removida (inclusive por sucessor provisional que registre `SUPERSEDES`).
  A claim `f:` passa a prender **xattr/capability** quando o arquivo os tem
  (`pack` v2); sem xattr o hash é idêntico ao de antes, então nenhum registro
  migra. Ainda não registra ACLs, `trusted.*`, uid/gid ou timestamps.
- **Fidelidade de aplicação:** o mundo B sela o tar normalizado num `memfd`,
  indexa-o e copia regulares diretamente por offset; hash e instalação veem os
  mesmos bytes. Isso é Linux-only e custa RAM/swap proporcional ao artefato.
  `pack` preserva nomes não-UTF-8 e hardlinks, mas `rectify` os recusa até o
  Journal instalá-los sem mudar a topologia atestada. A aplicação reproduz
  tipo, bytes, modo e agora xattr/capability, não uid/gid/mtime/ACLs; o
  fallback `EXDEV` também não preserva hardlinks nem xattr e recusa
  diretórios/especiais entre mounts. Aplicar `security.capability` exige
  `CAP_SETFCAP`: sem ele a instalação **falha fechado e reverte**, em vez de
  materializar um sistema que diverge do artefato atestado.
- **Diretórios compartilhados:** claims `d:` bloqueiam sobreposição
  pai×descendente entre pacotes. Remoção mundo B usa apenas `rmdir` e preserva
  diretório que ganhou filhos; mudança de modo de diretório vazio preexistente
  é recusada, não silenciosamente aceita.
- **Sandbox parcial:** no mundo B de outro rootfs, bwrap isola rede e ambiente,
  mas monta o rootfs gravável. A avaliação top-level da receita e o mundo A
  ainda executam no host. Ideal: parse declarativo ou sandbox de avaliação,
  rootfs read-only e binds graváveis apenas para WORK/STAGE.
- **Escala de memória:** `Command::output` acumula stdout/stderr de build e
  `install_pkg`; artefatos grandes também ficam integralmente no `memfd` selado.
  Logs/artefatos devem migrar para streaming antes de tratar imagens grandes.
- **Attestation local:** a emissão prova coerência do registro e do payload que
  ainda está instalado, mas `ARTIFACT_HASH`/`FINGERPRINT` sem pino externo ainda
  são campos locais. Provar contra adulteração privilegiada posterior exige
  retenção do artefato selado, índice/canal assinado ou attestation no build.
- **Confiança de canal vs P6:** o índice v2 assinado carrega o
  `recipe_fingerprint`, e a seleção exige que ele coincida com a receita
  efetiva; o lock v2 e o `CHANNEL_PATH` do registro preservam essa identidade,
  que `verify` coteja semanticamente. Sem `REPROCORR`, porém, o hash continua
  autenticando o publicador, não uma reprodução independente. Também não há
  monotonicidade externa para impedir que um servidor reapresente um índice
  antigo ainda corretamente assinado.
- **Atualização administrativa de canal:** consumo, lock v2 e emissão existem,
  mas `channel add/remove/list/refresh` não. Sem um `refresh` explícito que
  valide assinatura, produza diff auditável e só então avance o snapshot, a
  operação rolling do canal oficial não está fechada; é gate de release.
- **Nomes canônicos:** hoje `gcc` = scaffolding, `gcc-pass2` = o GCC real;
  renomeação final ainda pendente mesmo após o E2-clean.
- **Agregador e configuração-base agora são distintos:**
  `miniplenty-buildbase` implementa o agregador normativo `KIND=meta`/`WORLD=M`;
  `base` 0.2 continua sendo a receita com payload de configuração de boot. Uma
  eventual renomeação para `base-config` ainda precisará preservar ownership de
  rootfs já registrados.
- **Kernel ainda não é reproduzível entre builders:** a receita gera uma nova
  chave de assinatura de módulos em cada build. A política de release precisa
  separar o artefato reprodutível da assinatura/chave operacional.
- **O `ld` nativo exige `-rpath-link` explícito, e falhar disso responde
  errado em vez de falhar.** O linker desta árvore não resolve sozinho a
  dependência TRANSITIVA de uma biblioteca compartilhada em `/usr/lib`. Isso
  já era conhecido em `elfutils`, `perl` e `gcc-pass2`; o perfil de rede
  mostrou que o modo de falha tem três graus, e só o primeiro é seguro:
  1. **erro de link direto** — `nftables` (a `libnftables.so` precisa da
     `libnftnl.so`) e `e2fsprogs` (a `libblkid.so` precisa da libuuid do
     próprio pacote). Barulhento, fácil de diagnosticar.
  2. **erro de compilação longe da causa** — no `tcpdump`, o `configure`
     ACHOU a libcrypto por pkg-config, mas o teste de LINK de
     `EVP_CIPHER_CTX_new` falhou pelo `libz` transitivo; o autoconf registrou
     `no`, o pacote compilou o próprio shim legado dessas funções, e o erro
     apareceu como redefinição contra o `evp.h`, a setenta linhas da causa.
  3. **binário mutilado, sem erro nenhum** — no `mtr`, a `libncursesw.so.6`
     precisa da `libtinfo.so.6`; o teste de link falhou, o `configure`
     concluiu que não havia curses e construiu o mtr **sem a interface de
     tela**, que é a razão de ele existir. O build passou, o pacote instalou,
     e o binário só sabia `--report`. Nenhum teste de build pegaria isso.
  Quem denunciou o terceiro caso foi uma **nota** da auditoria de fechamento —
  "DEPS declara ncurses, mas nenhum requisito estático observado o exige" —,
  não um erro. É o argumento mais forte a favor de o `audit` reportar também o
  que está declarado a mais, e não só o que falta.
- **O kernel vivo passou a ser construído DENTRO do rootfs, e isso revelou que
  a distro não sabia construí-lo.** O `build-efi` ganhou `--rootfs`: as
  invocações do `make` do kernel rodam sob bwrap com o rootfs montado como
  `/`, então o kernel da mídia é compilado pelo gcc que a própria distro
  construiu, não pelo do hospedeiro. Fazer isso expôs um defeito que o host
  vinha mascarando: o gerador de initramfs do kernel monta a lista de
  arquivos com `find -printf "%p %m %U %G"`, e o `find` do BusyBox não
  implementa `-printf` — responde `unrecognized` e devolve lista **vazia**. O
  kernel embutia um initramfs de 512 bytes (só os dois nós de dispositivo) e
  a máquina bootava até `check access for rdinit=/init failed: -2`. Daí a
  receita `findutils` 4.11.0, que supersede o applet do BusyBox. A lição não
  é sobre o kernel: é que **"a distro é autossuficiente" só se verifica
  tirando o hospedeiro do caminho**, porque enquanto ele estiver lá as
  lacunas são preenchidas por acidente e não aparecem. O `date` do BusyBox
  também falha no mesmo script, mas ali é inócuo — a chamada tem `|| :` e o
  `build-efi` já normaliza todos os mtimes para o epoch.
- **Modo de arquivo em `files/` entra no fingerprint, e o Minipax normaliza a
  árvore — então os dois têm de concordar.** O `own_fingerprint` de uma
  receita empacota `files/` com os modos; o Minipax, ao materializar a árvore
  Newspeak para a mídia, normaliza tudo para os modos canônicos (diretórios
  `0755`, executáveis `0755`, demais regulares `0644`). Se o arquivo no repo
  tiver outro modo — um `udhcpc6.script` criado `0664`, um diretório `files/`
  em `0775` —, o fingerprint que o minitrue grava no registro difere do que o
  Minipax calcula ao instalar, e o canal é recusado com `crimestop
  (identidade)` na hora da instalação: a três passos da causa, sem nada que
  aponte para o modo de um arquivo. Só `base` e `nmap` têm `files/`, e ambas
  foram normalizadas. **Não há guarda**: nada impede criar um arquivo novo em
  `files/` com modo não-canônico e só descobrir na mídia. O conserto
  estrutural é o minitrue calcular o fingerprint sobre a MESMA visão
  normalizada que o Minipax usa, em vez de sobre os modos que o disco por
  acaso tem.
- **Flag inexistente de `configure` é aceita em silêncio.** O autoconf apenas
  avisa `unrecognized options` e segue. Duas receitas afirmaram por semanas
  desligar coisas que nunca estiveram desligadas: `ndisc6` com
  `--disable-rdnssd` (entregando o daemon) e `nftables` com `--disable-python`
  e `--disable-json`. O aviso se perde no meio do log; o que denuncia é o
  manifesto. Conferir `./configure --help` ao escrever receita nova é a
  disciplina que falta, e não há guarda automática para isso.
- **Alcance da auditoria de fechamento:** `audit` prova o que é estaticamente
  observável — `PT_INTERP`, `DT_NEEDED`, versões de símbolo e shebang. Não
  alcança `dlopen`, plugin, helper chamado por subprocesso, dado, serviço nem
  protocolo; para esses, o §4.1 exige aresta explícita de receita e teste de
  integração. Desde 2026-07-28 ela **é gate de `channel emit`** — publicar
  passou a exigir fechamento provado —, mas a composição de mídia ainda não é
  gateada. Só confere o payload do
  mundo B e as árvores do mundo A já instaladas — não audita `BUILD_DEPS` nem o
  ambiente do runner, que continuam abertos (SPEC-0013 §5).
- **ABOUTs desatualizados:** alguns descrevem dívidas já resolvidas. O valor é
  congelado no `meta` para `explain`; corrigir exige atualizar a receita e
  reinstalar o pacote.

## Ferramentas de CI (estado local)

`cargo test`/Clippy/fmt no `minitrue` e no `minipax` · `sh -n` em
receitas e nos scripts de bootstrap/canal/live. O teste ISO usa `xorriso`
quando disponível. ShellCheck e `cargo-audit` não instalados.
