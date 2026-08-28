# Distrópica

> Uma distribuição Linux distópica. Não instala pacotes: **retifica registros**.

**[Site oficial](https://distropica.com.br/)** ·
**[Baixar a ISO 0.14 (1355 MB)](https://distropica.com.br/releases/distropica-0.14-x86_64.iso)** ·
**[SHA-256](https://distropica.com.br/releases/distropica-0.14-x86_64.iso.sha256)** ·
**[Manifesto](https://distropica.com.br/releases/distropica-0.14-x86_64.iso.manifest)** ·
**[Fontes correspondentes](https://distropica.com.br/releases/distropica-0.14-corresponding-sources.tar.zst)** ·
**[SHA das fontes](https://distropica.com.br/releases/distropica-0.14-corresponding-sources.tar.zst.sha256)** ·
**[Inventário das fontes](https://distropica.com.br/releases/distropica-0.14-sources.tsv)** ·
**[Índice de licenças](https://distropica.com.br/releases/distropica-0.14-licencas.tsv)**

> **Atenção:** a `0.14` é uma **pré-release de desenvolvimento** para VM UEFI
> **64 bits**, e a própria mídia declara isso de si: `PROFILE_CLASS=custom`.
> O instalador apaga integralmente o dispositivo escolhido. Use um disco virtual
> descartável e confira o SHA-256 antes do boot
> (`26fdd6d1183f8f5ddcc3b0b22d71626c68e9d607e2e67d510074572569723f0e`).
>
> Ela pede a **senha de root antes do caminho do disco**: toda a interação
> acontece antes de qualquer escrita, e a partir do disco escolhido a
> instalação corre sozinha.
>
> Requisitos da VM: firmware **EFI de 64 bits** (no VirtualBox, `--firmware efi64`;
> o EFI de 32 bits não carrega o `BOOTX64.EFI` e reporta "no bootable medium").
>
> O tamanho mínimo da raiz **não é constante**: o instalador o calcula a partir
> do cache da própria mídia e recusa disco menor dizendo de quanto precisa. A
> conta é `cache × 5 + 512 MiB` — cinco e não quatro porque, durante a
> instalação, o cache **vive no disco alvo ao mesmo tempo** que a árvore cresce,
> e o pico é a soma dos dois, não o maior deles; o fator quatro em si saiu de
> medição (um cache de 664 MiB produziu uma árvore de 2096 MiB, razão 3,16) e o
> resto é margem. O `cache.tar` da `0.14` tem 1264 MiB, o que dá cerca de
> **6,7 GiB** de raiz mínima.

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

## Apoio

A Distrópica conta com o apoio do **[Prov](https://prov.net.br)**.

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
scripts, licenças e inventário. A imagem custom `0.14` atende essa
regra por meio do [bundle associado](https://distropica.com.br/releases/distropica-0.14-corresponding-sources.tar.zst),
preso à revisão `3a84811` e ao SHA-256 da ISO, e acompanha um
[índice de licenças](https://distropica.com.br/releases/distropica-0.14-licencas.tsv)
com os 5575 textos extraídos dos artefatos e das fontes correspondentes.
Todos os 199 pacotes do inventário declaram licença — não há nenhum
`LICENSE=NOASSERTION`. Três são **receitas de montagem da própria
Distrópica** (`base`, `desktop`, `miniluv`): não têm SRC, geram arquivos
legíveis, e a licença delas é a do repositório — `GPL-3.0-or-later`, em
[LICENSE](LICENSE). Para os demais, a evidência vem do artefato ou da fonte
correspondente, e o índice diz, pacote a pacote, de qual dos dois: o
`ca-certificates` é o caso extremo — a concessão MPL mora no cabeçalho do
`certdata.txt` da Mozilla, e não em arquivo de licença nenhum.
O repositório público é a fonte
do desenvolvimento, mas não substitui sozinho esse conjunto por artefato.
Gerar uma imagem para uso privado não exige publicá-la; redistribuí-la
transfere ao redistribuidor as obrigações das licenças presentes.

O gate automatizado usa `bootstrap/source-bundle --artifact ARQ
--minitrue-bin MINITRUE_PRODUTOR ... --strict`
e depois `bootstrap/sbom --bundle DIR --strict`. Para ISO/IMG, a interface
legada `--media ARQ --live-kernel-config CONFIG --live-util-linux-tar TAR`
também preserva os campos `MEDIA*`; o EFI usa `--artifact BOOTX64.EFI` com os
mesmos dois insumos vivos. O tar de util-linux é cotejado com os pinos do
`build-efi` e entra no inventário como `insumo-live`. Para canal, `ARQ` é o
`index` diretamente na saída de `channel emit --release`: o `emit.meta` v3
irmão prova a raiz local e prende esses bytes por `INDEX_SHA256`; as linhas do
próprio índice — nunca o cache reduzido da mídia — decidem o inventário e
prendem os objetos de `pool/`. O índice ainda DEVE ser assinado antes da
publicação. `MINITRUE_PRODUTOR` é exatamente o executável que calculou os
fingerprints e produziu os registros; em perfil `release`, seu SHA-256 precisa
coincidir com `OFFICIAL_MINITRUE_SHA256`.
Sem `--strict`, ambos os scripts conservam o modo diagnóstico de desenvolvimento
e podem terminar com pendências explícitas.

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

A `0.14` está **publicada** em <https://distropica.com.br/> (2026-08-24): ISO
instalável, canal binário assinado com 192 pacotes e bundle de fontes
correspondentes aprovado no gate estrito. O sistema instalado sobe em modo
gráfico — compositor **labwc**, navegador **Epiphany** com **vídeo livre**
(WebM/VP9/Opus), terminal **foot**, barra de tarefas **yambar**, lançador
**fuzzel** — e instala software do canal pela rede: o **GIMP 3.2** entra assim,
com `minitrue rectify gimp`.

Duas correções da `0.14` valem menção porque a `0.13` falhava nelas, e as duas
saíram de máquina real, não de suposição. O instalador passou a **registrar a
entrada de arranque na NVRAM do firmware** (`minipax efi-boot`, escrevendo
`Boot####`/`BootOrder` direto no efivarfs): antes, o carregador ficava só no
caminho de reserva `\EFI\BOOT\BOOTX64.EFI`, que a norma obriga o firmware a
procurar em mídia removível mas não em disco fixo — o resultado era instalar
bem e cair na ROM de PXE no reboot. E a renderização inteira saiu do
caminho OpenGL, em três camadas. A casca desenha por **Cairo** (o próprio GTK
já recusa GL sobre rasterizador de software — a detecção dele é por nome e não
reconhecia "softpipe"); a página é pintada pelo **Skia em CPU**
(`WEBKIT_SKIA_ENABLE_CPU_RENDERING=1`), porque o WebProcess perguntava só
"existe contexto GL?" e o softpipe respondia que sim; e a **composição
acelerada foi desligada** (`WEBKIT_DISABLE_COMPOSITING_MODE=1`), sem o que um
elemento `<video>` — que não é pintado, e sim composto — continuava subindo
cada quadro pelo caminho acelerado. As três foram provadas em A/B fotografado:
rolagem deixava a viewport em branco por segundos, e o vídeo saiu de **1,1
para 22 quadros por segundo** num VP9 de 150 s, com o decodificador entregando
~3000 quadros e zero descartes nos dois casos — o gargalo nunca foi decodificar,
foi apresentar.

A base de tipos MIME também passou a ser compilada no primeiro boot. Ela nunca
foi: a receita do `shared-mime-info` prometia o drop-in e ele não existia, de
modo que `g_content_type_guess` ficava sem base — abrir um `.html` do disco
mostrava o código-fonte, e o diálogo de abrir do GTK não classificava nada.

O vídeo por Media Source — o caminho do YouTube — completou-se em seguida: o
`vp9parse` entrou no `gst-plugins-bad` (o MSE exige parser registrado para
`video/x-vp9`, como exigia o `opusparse` para o áudio), e um crash que
derrubava o navegador ao abrir páginas de vídeo foi eliminado. A causa era o
próprio `WEBKIT_DISABLE_COMPOSITING_MODE=1` da rodada anterior: ele faz o
`AcceleratedBackingStore::create()` devolver nullptr, e conteúdo que força
composição — o player do YouTube força — leva o UI a chamar método em objeto
inexistente. A variável saiu; quem desliga a composição é a política do
próprio navegador (`hardware-acceleration-policy='never'`), e a guarda do
build confere o **valor efetivo** da chave com `gsettings`, não o texto —
porque o schema é relocável e um override com path é aceito em silêncio e
ignorado.

A barreira técnica que justificava o projeto — compilar o "mundo antigo" a
partir de nada além de binários upstream — foi **demonstrada**:

- **Bootstrap (Estágio 2) — executado pelo `rectify`.** A partir de um mundo
  musl semeado apenas pelo binário oficial do Zig (`zig cc`), o `minitrue
  rectify gcc-pass2` construiu os 16 pacotes até um **gcc nativo** (C e C++)
  hospedado na **glibc**, sem toolchain de outra distro. Essa execução
  **E2-clean** é evidência histórica: ocorreu uma vez, a frio, num rootfs novo
  com o grafo então vigente. Uma segunda execução histórica, já com `zlib`
  explícito e os payloads `install-strip` de GCC/binutils, também reconstruiu o
  grafo que existia naquele momento e passou nas provas C, C++, `ar` e Make;
  isso não é prova da closure hoje versionada nem substitui duas reconstruções
  limpas para uma nova prova forte (SPEC-0005 §4).
- **`minitrue` — implementado** (Rust): mundo A (`/opt`), mundo B (`/usr`) e
  mundo M para metapacotes declarativos (`KIND=meta`, `WORLD=M`, sem payload),
  hash + assinatura (minisign), registros em texto com **fingerprint de build**
  e **manifesto v3** (conteúdo + tipo, alvo de symlink, árvore mundo A e
  diretório compartilhado estrutural `D:`),
  empacotamento determinístico (`pack`), imagem de STAGE selada, attestations
  Ed25519 sem replay histórico, toolchain por estágio, journal transacional com
  recuperação global no mundo B, runner de build em rootfs via bwrap e
  **`explain`/`why`** (a proveniência como comando). O canal binário está
  implementado no **formato de índice 4**, assinado por minisign, com o
  fingerprint da receita dentro da identidade autenticada, chave pinada,
  artefatos `.tar.zst` endereçados por conteúdo, `RELEASE_ROOT` e o PLAN_LOCK do
  produtor no cabeçalho, lock imutável da seleção e resolução
  `--no-binary`/`--only-binary` sem puxar dependências de build quando um
  artefato de canal é escolhido. O registro fecha em `RECORD_FORMAT=4`, com
  `APPLIED_PLAN_RECEIPT` *content-addressed* do mundo completo e ponteiro
  atômico `applied-plans/current`. `verify` coteja semanticamente a
  proveniência gravada com esse lock, inclusive caminho e fingerprint.
  A prova de um pacote instalado é a da sua ORIGEM, e não uma só: `record-vendor`
  para o Mundo A, `record-source` para o que se compilou aqui, `record-channel`
  para o que veio pronto — este último preso ao `CHANNEL_SHA256` e ao
  `ARTIFACT_HASH` do registro, sem exigir da máquina instalada o tarball
  upstream que ela nunca baixou.
  Há uma suíte local automatizada; a matriz de cobertura vive no `STATUS.md`.
- **`minipax` — núcleo implementado** (Rust): resolve um perfil comum, sela
  seus insumos num `profile.lock`, materializa o sistema em um `--target` e
  compõe mídias determinísticas nos formatos GPT/FAT32 (`.img`) e ISO9660
  UEFI (`.iso`). Instalação direta e geração de mídia usam o mesmo
  `target.world`, `live.world`, `cache.world`, overlay, árvore Newspeak e cache
  fechado. O lock v3 autentica `cache.world` separadamente: ele declara
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
- **Wi-Fi gerenciável, e a cadeia inteira precisa existir.** O daemon é o
  **iwd** e a interface gráfica é o **iwgtk**, no painel. Nenhum dos dois basta
  sozinho: o iwgtk fala com o iwd por **D-Bus de sistema**, que precisa estar de
  pé; o iwd testa algoritmos de criptografia pelo **AF_ALG** ao subir e sai se
  faltar `CRYPTO_DES`; ele procura o socket em `/var/run`, que só existe se
  houver o link de compatibilidade para `/run`; o iwgtk é uma `GtkApplication` e
  registra a si mesma no **barramento de sessão**, que não é o de sistema; e a
  conta que roda a sessão precisa estar no grupo **netdev**, senão a política do
  próprio iwd nega o acesso. Cada um desses elos, faltando, produz o mesmo
  sintoma — clicar no ícone e nada acontecer — e nenhum deles falha em voz alta.
  Estão todos verificados em execução, com foto.

- **A sessão gráfica não roda como root.** Ela roda como a conta comum
  `distropica`, criada no primeiro boot junto dos grupos `seat` (falar com o
  seatd), `audio` (abrir `/dev/snd`) e `netdev` (comandar o iwd). O `/etc/rc.d/session`
  larga o privilégio com `su -l` antes de chamar o compositor. Isso é a diferença
  entre um navegador comprometido poder ler o `/home` e poder reescrever o `/usr`.
  O `su -` do usuário **de volta** para root funciona, e isto foi medido em
  execução e não deduzido: no sistema instalado, `login: root` → `su -
  distropica` → `su -` devolve root, com o binário em `-rwsr-xr-x` e um applet
  fora do `/etc/busybox.conf` ainda rodando como uid 1000.

  Esta linha já afirmou o contrário, e vale registrar por que a afirmação
  errada era plausível. O `minitrue rectify` avisa, a cada ciclo, que a
  correção da receita do busybox **não foi aplicada** — e o aviso é verdadeiro,
  mas sobre o *rootfs de build*, onde o busybox é provisional e já cedeu `ar`,
  `awk` e `strings` aos sucessores; um provisional que cedeu não pode ser
  reconstruído sem retomar o que cedeu. No **alvo** não há registro anterior
  nenhum: o busybox é instalado do zero pela receita, e o `chmod 4755` roda
  como qualquer outra linha dela. Tomei o aviso do build por um fato sobre o
  produto, e escrevi isso aqui sem executar `su -` uma vez sequer.

- **O botão de energia desliga a máquina.** Um `acpid` escuta o evento e chama
  `poweroff`, o init roda o `rcK` e o filesystem fecha coerente. Sem isso a única
  saída era segurar o botão e cortar a energia com o disco montado — e o journal
  do ext4 guardava tamanho de arquivo sem os dados, corrompendo o `/etc/passwd`
  no boot seguinte de um jeito que o busybox tolera e a glibc não.

- **Modo gráfico — Wayland, labwc, Epiphany e foot.** A tty1 vira sessão
  gráfica quando o pacote `desktop` está instalado e existe `/dev/dri/card*`;
  senão, vira um getty, e a tty2 é sempre um getty de emergência. A sessão
  **não roda como root** desde a 0.12: o despachante da tty1 é o init, e a
  queda de privilégio para a conta comum é dele.

  O compositor é o **labwc** sobre **wlroots**, e o renderizador continua sendo
  por software: o wlroots é construído com `-Drenderers=[]` e compõe direto no
  buffer *dumb* do KMS, sem EGL e sem GBM, porque numa árvore com Mesa softpipe
  o GL não aceleraria nada e ainda dependeria de o gbm achar driver. O labwc
  reimplementa o modelo do Openbox: tema `themerc` compatível com Openbox 3.6,
  configuração em `rc.xml`, menu raiz em `menu.xml`, e cada atalho declarado um
  a um em vez de um modificador global único. O lema do projeto é *no bling* —
  e é essa recusa que o torna adequado aqui. O labwc em si não traz painel nem
  relógio; quem os repõe é a **família do foot**, toda em C sem toolkit sobre
  fcft e pixman: o **yambar** é a barra de tarefas — janelas abertas
  (minimizadas inclusive, que sem ela desapareceriam da tela sem caminho de
  volta; clicar ativa, via **wlrctl**), estado da rede (clicar abre o applet)
  e relógio —, o **fuzzel** é o lançador (`W-d`, três letras, Enter), o
  **fnott** dá dono às notificações e o **wbg** desenha a logo da distro na
  camada de fundo. Os lançadores continuam também no menu do botão direito.
  XWayland fica desligado, coerente com o wlroots; nenhuma janela X roda
  sobre este compositor.

  O navegador é o **Epiphany** (GNOME Web) sobre **WebKitGTK**, e a troca pelo
  Firefox foi de um pacote por um: medido, tirar o Firefox da closure removia
  exatamente ele mesmo, porque tudo o que ele puxava é compartilhado com a
  pilha gráfica. O que muda de verdade é a natureza do que fica — C e C++
  auditáveis por `NEEDED`, em vez de um binário upstream opaco. **Vídeo, só o
  livre**: o WebKit é construído com GStreamer e a pilha entra até o
  `gst-plugins-good` — WebM, VP9, Opus e Vorbis tocam, com Media Source
  ligado, que é o que o streaming adaptativo exige. O `bad` e o `ugly` ficam
  de fora, e com eles H.264 e AAC: uma página que só ofereça MP4/H.264
  continua muda, e isso é posição declarada, não surpresa. O terminal é o
  **foot**, cliente Wayland nativo em C, sem
  toolkit — desenha direto em superfície pixman com os glifos que o fcft
  rasteriza, e sua closure inteira são três receitas pequenas.

  **O X11 não saiu da closure, e vale dizer por quê**, porque é fácil prometer
  o contrário. A árvore ainda traz `libx11`, `libxcb`, `libxext` e `libxrender`
  — não por causa do navegador nem do compositor, mas porque o **cairo** desta
  árvore é construído com os backends X, e labwc depende de cairo e pangocairo.
  Em execução nada disso é exercido: elas existem para o `ld.so`, não para o
  usuário. Quem tirará o X11 daqui é a troca do gtk3/GIMP, não a do navegador.
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
  limpo. Essa é evidência histórica da revisão network-v1. A mídia posterior
  `miniplenty-v1` também passou no runner automatizado do VirtualBox: ripgrep,
  Vim e `miniplenty-buildbase` já estavam no sistema; C, C++, biblioteca
  estática e Makefile funcionaram offline; jq foi instalado do binário upstream
  e tree foi compilado da fonte; ambos persistiram após reboot e Zig permaneceu
  somente no cache. O terceiro boot confirmou DHCP, rota e DNS local. O kernel
  vivo fixa `CONFIG_MODULES=n`, e a mídia não distribui módulos: os drivers
  indispensáveis são built-in. O release `7.1.8-distropica-live` permanece
  distinto do kernel `7.1.8` do target. Isso ainda não é uma ISO oficial
  publicada nem prova suporte a hardware UEFI genérico.
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

Ainda não fechados: reemissão dos payloads do canal oficial para a árvore
atual, publicação de um bundle estático assinado, reprodução independente da
mídia, cobertura de hardware UEFI real,
runit, `--sync` e o rollback
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
`PROFILE_LOCK_FORMAT=3` e `PROFILE_CONTENT_FORMAT=3`; `CACHE_WORLD_SHA256`
prende a lista normalizada e `CHANNEL_BOOTSTRAP_SHA256` prende separadamente o
endpoint do canal, a origem da árvore, a chave e a seed assinada que
permanecerão no alvo.

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

# 3. Reserva um namespace privado para a publicação consistente. O compositor
# recusa parent pertencente a outro UID ou gravável por grupo/outros.
install -d -m 0700 target/media-output

# 4. Compõe uma ISO instalável com o mesmo perfil e cache (requer xorriso).
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode offline --cache "$CACHE" \
  --format iso --boot-efi target/BOOTX64.EFI \
  --output target/media-output/distropica.iso

# A variante para pendrive usa o mesmo payload em GPT/FAT32.
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode offline --cache "$CACHE" \
  --format img --boot-efi target/BOOTX64.EFI \
  --output target/media-output/distropica.img
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
install -d -m 0700 target/media-test-output
./bootstrap/distropica-bootstrap media build \
  --profile profiles/official --mode offline --cache "$CACHE" \
  --format iso --boot-efi target/BOOTX64-test.EFI \
  --output target/media-test-output/distropica-test.iso
bootstrap/live/accept-qemu \
  --iso target/media-test-output/distropica-test.iso \
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
release nem substituirá um manifesto oficial assinado. Endpoint, chave e índice
do canal estão publicados, e desde 2026-08-22 a **mídia também**: a `0.14` está
no ar com ISO, bundle de fontes correspondentes aprovado no gate estrito
(`bootstrap/sbom --strict`, todos os pacotes com texto de licença),
inventário e índice de licenças. O que ainda não existe é o *manifesto oficial
assinado* no sentido da SPEC — a raiz produtora continua `STATUS=development`,
e é isso que separa "publicada" de "release estável".

O perfil `profiles/official` declara `INSTALL_READY=yes`, mas continua com
`STATUS=development`. A prontidão significa que o world mínimo pode ser
materializado num alvo vazio quando o cache/canal correto é fornecido; não
significa release ou mídia oficial. O target atual inclui
`base`, `linux`, `e2fsprogs`, `ripgrep`, `vim` e `miniplenty-buildbase`; o metapacote `KIND=meta`
fica no mundo M sem payload e agrega Make e a toolchain GCC final. Em
`--only-binary`, o metapacote é resolvido localmente, mas seus pacotes fonte
precisam existir como artefatos autenticados do canal: a instalação não deve
recompilar GCC no computador do usuário. O cache de desenvolvimento usado nos
testes não é versionado como release. Cada build fonte local passa a reter
atomicamente o tar selado sob o próprio `ARTIFACT_HASH`. `minitrue channel emit
--release --output DIR <pacotes...>` exige e revalida esses objetos, gera pool,
índice v4 e `emit.meta` v4 com `INDEX_SHA256`, `PRODUCER_PLAN_LOCK_SHA256` e
`RELEASE_ROOT=yes`; o índice ainda precisa ser assinado. Sem `--release`, o comando prefere o retido, mas aceita o tar
autenticado de outro canal ou a reconstrução provada das claims e marca
`RELEASE_ROOT=no`. Esse fallback é desenvolvimento/recuperação, nunca raiz de
publicação.

Um canal local assinado de desenvolvimento já contém os 11 artefatos da closure
então testada (`base`, toolchain, kernel, Vim/ncurses e zlib). Ele alimentou a
instalação direta e a ISO aceita no VirtualBox; é evidência histórica distinta
do endpoint oficial agora publicado.
Os payloads `install-strip` funcionaram no rebuild e no guest, mas ainda faltam
dois builders independentes para a afirmação de reprodutibilidade. A ISO não
tem tamanho fixado por `MEDIA_SIZE_MIB`.

O outro caminho também foi exercitado com os executores musl estáticos: a
instalação direta `--offline --only-binary` materializou o target inteiro então
versionado a partir do mesmo canal, terminou com `minitrue verify` e compilou
C/C++/Make.
Vim começou instalado, enquanto jq e tree foram retificados depois, ainda
offline, respectivamente do binário upstream e da fonte. O lock teve SHA-256
`c84d6424646c78204ee822ff0a7617f941419130ea3c05cc60f4b320dc952f67`;
isso é evidência local do fluxo, não um pino oficial.

`bootstrap/channel-from-rootfs` existe somente para migrar registros históricos
v1 e sempre produz `TRUST=builder`. Os exemplos fornecem `$CACHE` explicitamente,
mas seus bytes entram em `CACHE_SHA256`: com o perfil ainda em
`STATUS=development`, a classe permanece `development`; num perfil de release,
somente o cache que reproduzir o pino de conteúdo pode chegar a
`official-inputs`.

O modo `online` incorpora somente o bootstrap de canal fechado pelo lock:
`channel-config/<nome>` e o par assinado
`channels/<nome>/{index,index.minisig}`, mais `newspeak-origem` com a URL-base
e a mesma chave oficial usadas por `rectify newspeak`. Os artefatos não entram nessa mídia;
são obtidos da URL HTTPS pinada durante a instalação. O consumidor, a
validação minisign e o lock de canal já existem. O perfil oficial versiona o
bootstrap real de `https://distropica.com.br/canal/oficial/`, inclusive a chave
pública pinada e uma seed assinada. `--cache DIR` é somente o cache fechado da
mídia offline e não substitui essa autoridade; `cache.tar` e
`channel-bootstrap.tar` têm hashes independentes no lock. O Minipax confere o
layout, prende os bytes e instala o bootstrap no alvo depois de consumir o
cache. Online, o Minitrue busca o índice corrente e valida criptograficamente
`index.minisig` contra a chave pinada antes da seleção; offline, usa a seed
assinada sem consultar a rede. Uma invocação explícita de `rectify` pode
persistir o snapshot operacional autenticado que usou na própria seleção e no
lock; não há atualização em background. Cada linha v2 obrigatoriamente
autentica
`NAME VERSION ARCH RECIPE_FINGERPRINT PATH SHA256 [REPROCORR]`; a seleção só é
aceita quando o fingerprint assinado coincide com a receita efetiva. A
existência de `/etc/minitrue/channels/` é uma decisão administrativa: se o
diretório estiver vazio, nenhum canal é carregado e a seed do cache não é
reativada. O modo `offline` exige o cache completo e leva seus objetos na mídia;
a instalação direta equivalente usa `--offline --cache DIR`.

O endpoint, a chave e o índice do canal estão publicados. Para a árvore
Newspeak, o perfil já pina a origem e a mesma chave, mas, na auditoria desta
revisão, `newspeak.tar` e `newspeak.tar.minisig` ainda retornavam 404 nesse
endpoint; portanto não há E2E oficial de `rectify newspeak`.

Fora de uma instalação, `minitrue channel refresh [canal]...` faz a atualização
administrativa: baixa e autentica todos os índices selecionados, imprime
`CHANNEL_REFRESH_FORMAT=1` com hashes e linhas removidas/acrescentadas, força a
saída antes da primeira mutação e só então troca cada par índice/assinatura
atomicamente. É a via de avançar snapshots sem instalar; o comando não resolve
receitas nem instala pacotes.
`--world`, `--live-world` e `--overlay` explícitos criam uma variante
personalizada. Um `--cache` fornecido entra integralmente em `CACHE_SHA256` e
só conserva `official-inputs` quando seus bytes reproduzem o pino de conteúdo
do perfil de release; qualquer diferença vira `custom`. Saídas de
mídia recebem os sidecars `.sha256`, `.media.lock` e `.manifest`; cada nome é
publicado sem sobrescrita. O diretório pai precisa pertencer ao UID efetivo e
não ser gravável por grupo/outros. Um journal durável recupera quedas e desfaz
prefixos incoerentes; os sidecars são promovidos primeiro e a imagem aparece
por último como marcador de commit. Repetir a mesma requisição reconhece um
conjunto completo e canônico como sucesso idempotente, sem aceitar mistura de
gerações.

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
proveniência. Neste marco, as árvores Newspeak e overlay são limitadas, cada
uma, a 128 MiB de conteúdo regular em memória. O cache é transmitido em fluxo,
admite até 50 mil entradas e fica limitado a 4 GiB−1 por arquivo pelo FAT32,
não pela RAM: sua coleta guarda referências, a composição escreve `cache.tar`
diretamente no destino e a instalação o valida numa passada de cabeçalhos antes
de extrair noutra. Conteúdo e tar do cache não coexistem integralmente em
memória.
Os modos não dependem dos bits preservados pelo Git:
diretórios são normalizados para `0755` (com `root/` do overlay em `0700`),
`shadow`/`gshadow` e seus backups para `0600`, regulares executáveis para `0755`
e os demais para `0644`. Durante o consumo de canal, o snapshot `.tar.zst` e o
tar descompactado selado coexistem; o pico de RAM pode aproximar a soma dos
dois. Na instalação viva soma-se ainda a raiz preparada em `/run`, deliberada
para garantir validação completa antes do disco. Uma partição de dados própria
para caches maiores continua sendo gate de release.

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
assinado e a reemissão do canal para as receitas atuais ainda são gates de
release. Na variante
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
