# Distrópica

> Uma distribuição Linux distópica. Não instala pacotes: **retifica registros**.

**[Site oficial](https://distropica.com.br/)** ·
**[Baixar a ISO de desenvolvimento (378 MiB)](https://distropica.com.br/releases/distropica-rede-v3.iso)** ·
**[SHA-256](https://distropica.com.br/releases/distropica-rede-v3.iso.sha256)** ·
**[Manifesto](https://distropica.com.br/releases/distropica-rede-v3.iso.manifest)** ·
**[Fontes correspondentes](https://distropica.com.br/releases/distropica-rede-v3-corresponding-sources.tar.zst)** ·
**[SHA das fontes](https://distropica.com.br/releases/distropica-rede-v3-corresponding-sources.tar.zst.sha256)** ·
**[Inventário das fontes](https://distropica.com.br/releases/distropica-rede-v3-sources.tsv)**

> **Atenção:** `rede-v3` é uma imagem de desenvolvimento para VM UEFI **64 bits**.
> O instalador apaga integralmente o dispositivo escolhido. Use um disco virtual
> descartável e confira o SHA-256 antes do boot.
>
> Requisitos da VM: firmware **EFI de 64 bits** (no VirtualBox, `--firmware efi64`;
> o EFI de 32 bits não carrega o `BOOTX64.EFI` e reporta "no bootable medium"),
> **3 GiB de RAM** — com menos, o instalador é morto pelo OOM killer ao validar a
> closure em memória — e disco de pelo menos 4 GiB.

A Distrópica parte de uma observação desconfortável sobre o mundo atual: os
projetos novos (Zig, Go, Rust, os aplicativos das corporações) distribuem
binários oficiais prontos, enquanto o mundo antigo (GNU, glibc, o núcleo do
que chamamos de "sistema") exige compilação a partir dos manuscritos. A
Distrópica abraça essa distopia em vez de escondê-la: **usa primeiro o binário
do mantenedor original; depois, o binário assinado da própria distribuição; e
só compila localmente quando ninguém publica um binário elegível**.

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

Cada ISO, EFI, cache ou canal binário publicado deve vir acompanhado de acesso
equivalente ao seu bundle de fontes correspondentes: revisão da Distrópica,
crates Rust vendorizadas, fontes upstream exatas, configurações, patches,
scripts, licenças e inventário. A imagem custom `rede-v3` atende essa
regra por meio do [bundle associado](https://distropica.com.br/releases/distropica-rede-v3-corresponding-sources.tar.zst),
preso à revisão `941383e` e ao SHA-256 da ISO. O repositório público é a fonte
do desenvolvimento, mas não substitui sozinho esse conjunto por artefato.
Gerar uma imagem para uso privado não exige publicá-la; redistribuí-la
transfere ao redistribuidor as obrigações das licenças presentes.

## Premissas

Acima de todas, uma lente (**P0**): a Distrópica é **pragmática acima de
ideológica** — cada premissa existe por um fim prático, não por dogma, e a
única ideologia inegociável é a coerência da própria casa.

1. **Nenhum gerenciador de pacotes existente.** A ferramenta própria
   (`minitrue`) é deliberadamente pequena: sem solver, sem protocolo de
   repositório, sem banco de dados opaco. O estado é o filesystem.
2. **Binário do mantenedor original primeiro.** Se o projeto publica binário
   oficial para Linux, é ele que entra — verificado por hash.
3. **Binário da Distrópica em seguida.** Quando o upstream só publica fontes,
   a Distrópica compila uma vez e entrega o resultado pelo canal assinado; o
   computador do usuário não precisa reconstruir a base.
4. **Fonte só quando ninguém publica um binário elegível.** A compilação local
   é o último recurso e usa a fonte oficial pinada pela receita.
5. **Sem systemd.** PID1 mínimo e inspecionável. Devolver a simplicidade ao
   usuário: todo mecanismo do sistema deve ser explicável em uma página.
6. **FHS 3.0.** Nada de hierarquias exóticas: vendors em `/opt`, mundo
   compilado em `/usr`, estado em `/var`.
7. **A rede nunca decide o que é verdade.** Todo artefato é conferido contra
   o hash pinado na receita. Divergência é *crimestop*.
8. **Edge — sempre o estável mais recente.** A árvore pina a versão estável
   mais nova do upstream (a começar pelo kernel); *edge* é o estável na sua
   borda, não *bleeding edge*. Rolling: não há versão-do-sistema nem release
   congelado.
9. **Opinativa — uma escolha canônica por função.** Onde há vários softwares
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
| [SPEC-0013](specs/SPEC-0013-dependencias.md) | Grafo tipado, fechamento ABI, plan lock, convergência e dependências da pilha gráfica |

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
  com o grafo então vigente. O grafo atual, incluindo `zlib` explícito e os
  payloads `install-strip` de GCC/binutils, também foi reconstruído uma vez e
  passou nas provas C, C++, `ar` e Make; ainda falta repeti-lo em dois ambientes
  limpos para uma nova prova forte (SPEC-0005 §4).
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
  `ripgrep`, `vim`, `miniplenty-buildbase`, o conjunto de rede, o Wi-Fi e
  `desktop` como target padrão. Esse último é um metapacote sem
  payload: suas dependências diretas são `base`, `make` e `gcc-pass2`, cuja
  closure final instala `linux-headers`, glibc, `mathlibs-glibc`, `zlib`,
  `binutils-glibc` e o GCC nativo; Vim traz `ncurses`. Assim, Make, `gcc`, `g++`, `as`, `ld`, `ar`
  e `ranlib` já fazem parte do sistema mínimo, vindos do canal em uma instalação
  `--only-binary`; Zig permanece apenas no cache e é materializado sob demanda
  quando uma compilação fonte `seed`/`cross` realmente ocorre. Antes de
  retificar o target, o Minipax confere os artefatos declarados em `cache.world`
  com `minitrue --offline cache verify`. `install-media` valida o payload antes
  de materializá-lo. O perfil fixa `MEDIA_SIZE_MIB=1024` para dimensionar a
  saída IMG e registrar esse parâmetro no lock; a ISO cresce conforme o payload
  e não fica limitada nem preenchida até 1024 MiB por esse campo. Desde
  2026-07-30 a árvore de cache é **transmitida em fluxo**, e não materializada
  em memória: `collect` a coleta por referência, `pack_into` escreve o
  `cache.tar` direto no destino somando o sha256 no caminho, e o instalador a
  valida numa passada de cabeçalhos antes de extrair noutra. O teto que restou
  é o do FAT32 para um arquivo (4 GiB−1), e não o da RAM. Foi isso que permitiu
  o cache saltar de 267 MB para 647 MB sem mudar o `payload_hash` — as ISOs
  continuam bit a bit reprodutíveis.
- **Modo gráfico — Wayland, weston e Firefox.** A tty1 vira sessão gráfica
  quando o pacote `desktop` está instalado e existe `/dev/dri/card*`; senão,
  vira um getty, e a tty2 é sempre um getty de emergência. O compositor é o
  **weston** com backend DRM e renderizador **pixman** — que compõe direto no
  buffer do KMS, sem EGL e sem GBM, porque numa árvore com Mesa softpipe o GL
  não aceleraria nada e só acrescentaria uma superfície de falha. O navegador é
  o binário oficial pt-BR da Mozilla, do Mundo A, em `/opt`.

  **O preço do Firefox está escrito porque é grande.** Medindo o `libxul.so`
  com `readelf -d`, ele declara `libX11`, `libxcb`, `libXext`, `libXrandr`,
  `libXcomposite`, `libXdamage`, `libXfixes`, `libXrender`, `libXcursor`,
  `libXi` e `libasound` no `NEEDED` — ligação dura, com `-z now`, resolvida
  pelo carregador antes da primeira linha de código. Pior: ele referencia
  **vinte e um símbolos `gdk_x11_*`**, que só existem num GTK3 compilado com o
  backend X11. Uma árvore Wayland-only simplesmente não carrega esse binário, e
  isso não se descobre lendo documentação — se descobriu executando e lendo
  `undefined symbol: gdk_x11_display_get_xdisplay`.

  Daí a corrente: dezessete receitas novas de bibliotecas **cliente** do X11
  (não há servidor X nesta árvore, nem XWayland), o `at-spi2-core` — que o
  backend X11 do GTK3 exige como dependência dura e que substituiu o `atk`
  avulso —, o `libxml2` de que ele depende, o backend `xlib` no cairo e o GLX
  no libepoxy. Em execução, **nada disso é exercido**: com `WAYLAND_DISPLAY`
  no ambiente e `DISPLAY` ausente, o GDK escolhe Wayland e o caminho X11 fica
  morto. Elas existem para o `ld.so`, não para o usuário. A alternativa seria
  uma biblioteca de tocos falsos que quebraria no dia em que alguém a
  chamasse, ou compilar o Firefox da fonte — o que exige Rust, clang,
  cbindgen, nodejs e NASM.
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
  limpo. Essa é evidência histórica da revisão network-v1. A mídia atual
  `miniplenty-v1` também passou no runner automatizado do VirtualBox: ripgrep,
  Vim e `miniplenty-buildbase` já estavam no sistema; C, C++, biblioteca
  estática e Makefile funcionaram offline; jq foi instalado do binário upstream
  e tree foi compilado da fonte; ambos persistiram após reboot e Zig permaneceu
  somente no cache. O terceiro boot confirmou DHCP, rota e DNS local. O kernel mantém
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
  `gcc-pass2` e `binutils-glibc`, com `install-strip`, foram reconstruídas e
  exercitadas uma vez; ainda precisam de rebuild repetido e nova comparação.

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
`mathlibs-glibc`, zlib e `binutils-glibc`. Como `base` e o metapacote são desejos
explícitos do perfil, ambos entram em `/etc/minitrue/world`; as dependências da
toolchain ficam instaladas sem se tornarem desejos top-level.

O `cache.world` do perfil declara jq, GNU Make, tree e Zig como disponibilidades
obrigatórias da mídia offline. Na instalação, o Minipax chama
`minitrue --offline cache verify` antes de `rectify`: hashes e a assinatura do
Zig são conferidos sem download, registro ou instalação. Isso
mantém distintas a disponibilidade no cache, autenticada por
`CACHE_WORLD_SHA256`, e a intenção do `target.world`. Make acaba instalado por
ser dependência de `miniplenty-buildbase`, não por constar em `cache.world`;
jq e tree começam ausentes para as provas pós-instalação, e Zig continua apenas
disponível para futuras compilações fonte.

### Pacotes opcionais baixados diretamente do upstream

A árvore também oferece duas provas **online-only**, deliberadamente ausentes de
`target.world` e `cache.world`. A ISO leva apenas suas receitas; portanto o
download acontece no computador instalado, diretamente do upstream, quando a
pessoa solicita:

```sh
# Binário Linux x86_64 estático publicado pelo projeto yq.
minitrue rectify yq
yq --version

# Tarball de fontes publicado pelo GNU nano; build com GCC/Make nativos.
minitrue rectify nano
nano --version

minitrue verify
```

`yq` 4.53.2 fica no Mundo A com `ORIGIN=vendor`; GNU nano 9.1 fica no Mundo B
com `ORIGIN=fonte` e depende da ncurses já instalada pelo Vim. As duas receitas
foram exercitadas numa cópia do target: os hashes conferiram, as versões
executaram e `verify` terminou limpo. Sem rede, ambas falham fechado em vez de
consumir o cache da mídia.

A composição `target/distropica-rede-v3.iso` incorpora essas receitas e
reutiliza exatamente o EFI, o canal e o cache da mídia aceita anteriormente. A
recomposição levou cerca de 10 segundos e produziu SHA-256
`06be0ed021a3916c76b8e823d1e3a7846246eaccf38f00a49f7e5190c5e07a13`.
Essa v2 teve conteúdo e sidecars verificados, mas ainda não repetiu o aceite
completo no VirtualBox; o resultado `FINAL_RESULT=passed` abaixo pertence à v1.

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
  --iso target/distropica-miniplenty-v1.iso \
  --run-dir target/acceptance-virtualbox
```

Esse cenário passou de ponta a ponta em 2026-07-22 no VirtualBox
`7.2.6_Ubuntur172322`. A instalação e o segundo boot ocorreram sem rede; a ISO
foi ejetada antes do wipe. No sistema instalado, Vim 9.2.0837 e ripgrep 15.2.0
já estavam presentes, a toolchain nativa compilou as quatro provas offline, jq
1.8.2 foi instalado como binário upstream e tree 2.3.2 foi compilado da fonte.
O terceiro boot confirmou a persistência e `minitrue verify`, além de DHCP,
rota, DNS local e gateway do NAT:

```text
EVIDENCIA_VIRTUALBOX_MINIPLENTY_V1=local-custom
ACCEPTANCE_META=target/vbox-miniplenty-v6/evidence/acceptance.meta
ACCEPTANCE_META_SHA256=2a88b7853a410c6de0ccbc4462de74ef7a307028cbd7a3356c47d7e02eed1561
VBOX_VERSION=7.2.6_Ubuntur172322
FIRMWARE=efi64
GRAPHICS=vmsvga
STORAGE=IntelAhci
GUEST_DISK=/dev/sda
ISO_SHA256=bd71b63aada991578f0b6d3d87f7d67c88d4715e19566690ef6925991eafabc7
BOOT_EFI_SHA256=a800e2aca03dd62cd9e7db3bb894c24f7bdb1fdc19a26abf91566b3b824771b9
PROFILE_LOCK_SHA256=c84d6424646c78204ee822ff0a7617f941419130ea3c05cc60f4b320dc952f67
CHANNEL_INDEX_SHA256=9451dfa340802ac9109eaed017d9ca5d08ca220ce1fd65ac72bac28ff27c9396
RUN_STATE=passed
ISO_EJECTED_BEFORE_WIPE=yes
INSTALL_AND_SECOND_BOOT_OFFLINE=yes
SECOND_BOOT_WITHOUT_ISO=yes
ROOT_LOGIN=yes
RIPGREP_VERSION=15.2.0
VIM_VERSION=9.2.0837
GCC_VERSION=15.3.0
MAKE_VERSION=4.4.1
NATIVE_C_COMPILE_RUN_OFFLINE=yes
NATIVE_CXX_COMPILE_RUN_OFFLINE=yes
NATIVE_ARCHIVE_LINK_OFFLINE=yes
NATIVE_MAKE_BUILD_OFFLINE=yes
JQ_BINARY_INSTALL_OFFLINE=yes
JQ_VERSION=1.8.2
TREE_SOURCE_BUILD_OFFLINE=yes
TREE_VERSION=2.3.2
VIM_JQ_TREE_PERSISTED_AFTER_REBOOT=yes
ZIG_AFTER_TREE_ABSENT=yes
DHCP_IPV4=yes
DEFAULT_ROUTE=yes
DNS_LOCALHOST=yes
NAT_GATEWAY_PING=yes
MINITRUE_VERIFY_AFTER_REBOOT=yes
FINAL_RESULT=passed
```

Essa é uma prova funcional local, não uma reprodução independente nem um pino
de release. A prova de rede limita-se ao
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
`base`, `linux`, `ripgrep`, `vim` e `miniplenty-buildbase`; o metapacote `KIND=meta`
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

Um canal local assinado de desenvolvimento já contém os 11 artefatos da closure
atual (`base`, toolchain, kernel, Vim/ncurses e zlib). Ele alimentou a instalação
direta e a ISO aceita no VirtualBox; não é endpoint nem canal oficial publicado.
Os payloads `install-strip` funcionaram no rebuild e no guest, mas ainda faltam
dois builders independentes para a afirmação de reprodutibilidade. A ISO não
tem tamanho fixado por `MEDIA_SIZE_MIB`.

O outro caminho também foi exercitado com os executores musl estáticos: a
instalação direta `--offline --only-binary` materializou o target atual inteiro
a partir do mesmo canal, terminou com `minitrue verify` e compilou C/C++/Make.
Vim começou instalado, enquanto jq e tree foram retificados depois, ainda
offline, respectivamente do binário upstream e da fonte. O lock teve SHA-256
`c84d6424646c78204ee822ff0a7617f941419130ea3c05cc60f4b320dc952f67`;
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
