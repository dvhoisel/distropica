# Licenciamento da Distrópica

Copyright (C) 2026 Daniel Hoisel.

## Código e documentação próprios

Salvo indicação expressa em contrário, o código, os scripts de build e
instalação, a lógica autoral das receitas, os perfis, as especificações e a
documentação produzidos para a Distrópica são licenciados sob a
**GNU General Public License, versão 3 ou qualquer versão posterior**
(`GPL-3.0-or-later`). O texto integral da versão 3 está em [LICENSE](LICENSE).
O aviso curto que acompanha os artefatos está em [NOTICE](NOTICE).

Essa concessão “ou posterior” é a que governa o conteúdo próprio mesmo que
uma ferramenta de detecção identifique o arquivo `LICENSE` apenas como GPLv3.
Versões antigas que tenham sido efetivamente disponibilizadas sob outra
licença conservam as permissões já concedidas para aquelas cópias.

## Receitas e componentes de terceiros

O campo `LICENSE=` de uma receita Newspeak descreve a licença do **payload do
pacote**, não a licença autoral do arquivo `recipe`. A implementação original
da receita pertence ao código da Distrópica e segue a regra acima; o software
que ela baixa, compila ou instala mantém a licença indicada pelo upstream.

Em particular, esta licença não relicencia Linux, BusyBox, glibc, GCC, Zig,
ripgrep, dependências Cargo nem qualquer outro componente de terceiros. Uma
ISO ou um canal da Distrópica reúne componentes sob licenças distintas, cada
um com seus próprios avisos e condições. O inventário definitivo e as
combinações efetivamente distribuídas precisam ser verificados a partir dos
insumos exatos de cada publicação.

O pacote `base`, por conter payload escrito para a própria Distrópica, passa a
declarar `GPL-3.0-or-later` nesta revisão. Cópias anteriores disponibilizadas
como `MIT-0` não perdem retroativamente essa permissão.

### Codecs de mídia: a fronteira é deliberada

Desde a 0.14 a árvore reproduz vídeo, e reproduz **só o formato livre**. O
WebKit é construído com GStreamer e a pilha vai até o `gst-plugins-good`:
WebM (matroska), VP8/VP9 (`libvpx`, BSD com concessão de patente explícita do
Google), Opus (BSD, RFC 6716, com promessa irrevogável de patente) e Vorbis
(BSD). O `gst-plugins-base` e o `gst-plugins-good` são LGPL-2.1-or-later.

Do `gst-plugins-bad` entra **um único elemento**, o `opusparse`
(LGPL-2.1-or-later), e ele existe por uma exigência do WebKit: o Media Source
Extensions recusa um fluxo `audio/x-opus` sem um parser de áudio registrado, e
sem ele o áudio de página nenhuma toca. O pacote é construído com
`--auto-features=disabled` e o payload instalado é literalmente um arquivo —
`libgstopusparse.so` —, conferido por guarda na própria receita. Opus é BSD,
RFC 6716, com promessa irrevogável de patente: nenhum formato onerado entra de
carona.

O `gst-plugins-ugly` **não entra**, e o resto do `gst-plugins-bad` também não.
Com eles ficam de fora H.264, HEVC, AAC e MP3 — formatos cuja distribuição em
binário envolve licenciamento de patente que esta distro não contratou. A
consequência prática é dita em voz alta em vez de descoberta pelo usuário: uma
página que ofereça apenas MP4/H.264 não toca. Não é limitação técnica; é a
mesma fronteira que mantém o `linux-firmware` como exceção declarada e nada
além dela.

## Binários e fontes correspondentes

Publicar o repositório de fontes não equivale, sozinho, a publicar uma release
binária. Para cada ISO, EFI, cache ou canal distribuído pelo projeto, a
Distrópica deverá oferecer, com acesso equivalente, um conjunto de fontes
correspondentes àquele artefato. Esse conjunto deve incluir, conforme o caso:

- a revisão exata da Distrópica, os dois `Cargo.lock` e as crates vendorizadas
  (geradas no momento do empacotamento por
  `cargo vendor --manifest-path minitrue/Cargo.toml -s minipax/Cargo.toml vendor`;
  não são versionadas no repositório, porque são cópia verbatim do que o
  `Cargo.lock` já pina e somam 182 MB);
- fontes upstream exatas, configurações, patches e scripts de build/instalação;
- fontes e configuração do kernel e do BusyBox presentes na mídia;
- textos de licença, avisos de copyright e um inventário legível por máquina;
- hashes que associem inequivocamente o bundle-fonte ao artefato binário.

Uma receita com URL e hash é rastreabilidade, mas não substitui a retenção
durável exigida de quem redistribui o binário. A imagem custom de
desenvolvimento `rede-v3` é acompanhada por um
[bundle de fontes correspondentes](https://distropica.com.br/releases/distropica-rede-v3-corresponding-sources.tar.zst),
seu [hash](https://distropica.com.br/releases/distropica-rede-v3-corresponding-sources.tar.zst.sha256)
e um [inventário legível por máquina](https://distropica.com.br/releases/distropica-rede-v3-sources.tsv).
Isso não promove a imagem a release oficial: o SBOM arquivo a arquivo e o
inventário conclusivo de licenças continuam sendo gates dessa futura
publicação.

Em particular, o tar binário oficial do Zig agrega sysroots, libc++, libunwind
e outras fontes auxiliares sob várias licenças. A receita atual declara uma
expressão composta para esse conjunto, em vez de atribuir incorretamente MIT ao
bundle inteiro. Os textos upstream continuam dentro do tar/payload, e o SBOM
arquivo a arquivo do artefato continua sendo gate de publicação.

O mesmo critério conservador vale para `gcc-pass2`: seu payload final combina o
compilador, bibliotecas cobertas pela GCC Runtime Library Exception, manuais
GFDL e componentes auxiliares sob outras licenças. Sua receita atual também
declara uma expressão composta explícita; isso não altera nenhuma licença
upstream nem reduz as obrigações de fornecer fontes, exceções e avisos
correspondentes. Nesta revisão, todas as receitas da árvore que geram payload
têm uma declaração específica de licença, sem que isso dispense o inventário
conclusivo do artefato gerado; metapacotes sem payload não descrevem software de
terceiro.

## Textos e bundle preparatório

O bundle de fontes e o SBOM não substituem a presença dos avisos junto dos
binários. O gate estrito `bootstrap/sbom --bundle DIR --strict` parte do
`INVENTARIO` exato daquele artefato — não de um catálogo global — e produz
`licenses.tar`, `licenses.tar.sha256`, `PACOTES`, `INDICE` e
`MANIFEST.sha256`. `PACOTES` e `INDICE` precisam concordar sem pacote ou texto
ausente/extra; o manifesto prende cada regular por caminho e SHA-256.

Esse fechamento ainda é interno ao bundle. Até `PLAN_LOCK_FORMAT=1` expor
nome, versão, fingerprint e hash do conjunto material realmente distribuído,
o Minipax não transporta nem instala esse tar e o profile permanece no formato
3. Autoconsistência e hash não substituem o vínculo ao plano autenticado. Os
textos próprios — GPL, NOTICE e este documento — já ficam no caminho estável
`/usr/share/licenses/distropica/` por meio do pacote `base` e do ambiente vivo.

O formato falha fechado para link, hardlink, arquivo especial, caminho ou modo
não canônico, divergência entre inventários e conteúdo, arquivo individual
acima de 32 MiB, conjunto acima de 128 MiB ou mais de 20.000 entradas. Esses
tetos acomodam o inventário medido sem converter um arquivo de controle em
canal de armazenamento ilimitado; ultrapassá-los exige revisão explícita do
formato, não um bypass no compositor.

## Firmware: a exceção declarada

O pacote `linux-firmware-wifi` é o **único payload da Distrópica do qual não
existe fonte correspondente**, e essa exceção é declarada aqui em vez de
diluída. São blobs binários de Intel, Qualcomm Atheros e Realtek, redistribuíveis
sob as licenças dos fabricantes, para os quais nenhum código-fonte foi publicado
por ninguém — nem pelo fabricante, nem pelo kernel.org, nem por nós. Não há
bundle de fontes correspondentes a oferecer porque não há fonte.

A exceção é aceita por uma razão prática e verificável: sem firmware, o driver
carrega, o rádio não inicializa e a placa deixa de existir para o sistema. A
alternativa a estes blobs não é um Wi-Fi livre — é Wi-Fi nenhum na maioria das
máquinas reais.

Os limites que a acompanham:

- é **subconjunto deliberado**, só as famílias comuns em laptop amd64, e não o
  `linux-firmware` completo;
- o `WHENCE` do upstream — o índice que declara proveniência e licença de cada
  arquivo — é instalado junto, em `/usr/share/licenses/linux-firmware-wifi/`,
  e é ele que torna a redistribuição defensável;
- a receita declara a licença como `linux-firmware (ver WHENCE)` e não a
  atribui a nenhuma licença livre, pelo mesmo critério conservador aplicado ao
  Zig e ao `gcc-pass2`;
- **não entra na mídia live**: o instalador não leva firmware, e portanto
  instalar por Wi-Fi não é suportado.

Quem quiser uma Distrópica sem blob nenhum remove este pacote do perfil; nada
mais na árvore depende dele, e o restante do sistema continua íntegro.

## Firefox: binário de terceiro com marca registrada

O pacote `firefox` é o **binário oficial da Mozilla**, do Mundo A, instalado em
`/opt` sem qualquer modificação. Não é compilado aqui, e a razão é medida: o
build a partir da fonte exige Rust, clang, cbindgen, nodejs e NASM, uma árvore
maior que tudo o que esta distro construiu somado.

Isso o coloca numa categoria diferente do firmware e diferente do resto da
árvore, e a diferença precisa estar escrita:

- o **código-fonte existe e é público** — o Firefox é MPL-2.0 e a Mozilla
  publica a árvore inteira. Não há aqui a lacuna irreparável do firmware; há
  uma escolha de não compilar, que pode ser revertida no dia em que a corrente
  de build couber;
- o payload **agrega** NSS, NSPR, libvpx, dav1d, ffvpx e mais de uma dezena de
  componentes sob licenças próprias. Rotular o conjunto apenas como MPL-2.0
  seria falso; a receita atual declara uma expressão composta, incluindo a
  evidência `LicenseRef-firefox-about-license`, pelo mesmo critério conservador
  aplicado ao Zig e ao `gcc-pass2`;
- a **marca "Firefox" não é software livre**. A política de distribuição da
  Mozilla permite redistribuir o binário oficial *sem modificação*; qualquer
  alteração no payload obrigaria a remover a marca. É por isso que o
  `install_pkg` da receita apenas extrai e não toca em nada — a ausência de
  modificação não é descuido, é condição de licença;
- para uma release oficial, o bundle de fontes correspondentes deve incluir o
  ponteiro para a revisão exata publicada pela Mozilla, do mesmo modo que
  inclui os tarballs upstream dos pacotes compilados.

Quem quiser uma Distrópica sem binário de terceiro remove `firefox` do
`DEPS` do pacote `desktop`; o modo gráfico continua subindo, com o weston e o
`weston-terminal`, e sem navegador.

## Uso privado e redistribuição

Quem apenas constrói ou modifica a Distrópica para uso privado não é obrigado
por esta política a publicar sua cópia. Quem redistribui binários deve cumprir
as licenças aplicáveis componente a componente.

## Marca

A GPL rege copyright do código, não concede por si só direito de apresentar
uma variante como publicação oficial da Distrópica. Isso não restringe o
direito de copiar, modificar ou redistribuir o código nos termos da GPL; apenas
evita atribuição ou endosso falsos.
