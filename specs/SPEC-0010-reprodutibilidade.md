# SPEC-0010 — Builds, sistemas e mídias reprodutíveis

**Status:** implementação parcial v0.6 · 2026-07-23
**Depende de:** SPEC-0003 (minitrue), SPEC-0004 (newspeak), SPEC-0008
(minipax), SPEC-0009 (canais) e SPEC-0013 (closure e plan lock).

## 1. Princípio: reprodutibilidade é a raiz da confiança

A SPEC-0001 §4 listava a reprodutibilidade bit-a-bit como *aspiração*. A
SPEC-0009 a promove a *mecanismo de segurança*: se o build de uma receita é
reprodutível, o hash do artefato é uma função só da receita (versionada e
assinada) — então **qualquer canal binário, oficial ou samizdat, vira mero
CDN** (SPEC-0009 §6). A confiança deixa de ser "confie em quem buildou" e
passa a "confie na receita, e verifique o hash por reprodução". É o que faz
o mundo B distribuível com segurança e o usuário não recompilar a base.

Definição operacional: **mesma receita + mesmo toolchain-semente → árvore
`STAGE` byte-a-byte idêntica**, em qualquer máquina, a qualquer tempo.

Essa definição é o primeiro degrau, não uma licença para chamar qualquer
saída posterior de reprodutível. O projeto distingue os níveis abaixo:

| Nível | Identidade comparada | Situação atual |
|-------|----------------------|----------------|
| **R1 — pacote** | tar normalizado do `STAGE` (`reprocorr`) | provado historicamente para os artefatos então medidos de m4, gmp, gcc e glibc; o `gcc-pass2` atual com `install-strip` e o novo `binutils-glibc` ainda precisam de rebuild ×2 |
| **R2 — sistema declarado** | `profile.lock`: `target.world`, `live.world`, `cache.world`, Newspeak, overlay, cache, arquitetura, epoch, orçamento da IMG e prontidão de instalação | implementado no `minipax`; torna intenção e disponibilidade offline auditáveis sem confundi-las |
| **R2b — rootfs byte-a-byte** | árvore instalada inteira, já materializada | **não provado**; registros contêm tempo de instalação e uid/gid ainda não fazem parte do contrato |
| **R3 — mídia** | bytes finais de `.img` ou `.iso` para o mesmo conjunto completo de insumos | provado localmente com fixtures e, na revisão histórica da ISO humana aceita no VirtualBox, por duas composições idênticas no mesmo ambiente; a mídia do perfil atual e a reprodução entre builders ainda não foram feitas (§8) |
| **R4 — reprodução funcional** | mídia dá boot e instala um sistema equivalente em outra máquina | provado localmente pelas revisões históricas final-v10 em QEMU/OVMF e network-v1 em VirtualBox. O fluxo atual com Vim/ncurses, `miniplenty-buildbase`, toolchain final de canal, jq binário e tree compilado offline ainda está pendente; hardware real e reprodução oficial também não foram provados |

Portanto, R3 não implica R4: uma imagem pode ser byte-reprodutível e ainda
conter apenas um PE/COFF sintaticamente válido usado como fixture de teste.

## 2. As fontes de não-determinismo e os consertos

| Fonte | Sintoma | Conserto |
|-------|---------|----------|
| Timestamps de build (`__DATE__`, mtimes) | binário/arquivo muda a cada build | `SOURCE_DATE_EPOCH` fixo |
| Locale / colação | ordenação de símbolos, mensagens | `LC_ALL=C LANG=C LANGUAGE=` |
| Fuso horário | datas embutidas | `TZ=UTC` |
| Permissões herdadas | modos de arquivo variam | `umask 022` |
| Caminho de build | `__FILE__`/debug embutem o path | caminho **canônico** no chroot |
| Archives `.a` | o `ar` embute mtimes/uid/gid dos `.o` | binutils `--enable-deterministic-archives` (ar zera metadados) |

Os quatro primeiros + o caminho canônico são **ambiente**; o minitrue os
impõe. O `ar` determinístico é **toolchain**; está na receita do binutils.

## 3. O contrato (o que o minitrue garante)

Ao rodar `build()` de um pacote mundo B, o `minitrue` (SPEC-0003 §3) injeta
um ambiente determinístico:

- `SOURCE_DATE_EPOCH` — da receita (campo `EPOCH`) ou o default fixo do
  projeto (`1704067200`, 2024-01-01 UTC). Fixo ⇒ reprodutível; a receita
  pode pinar a data de release do upstream.
- `LC_ALL=C`, `LANG=C`, `LANGUAGE=`, `TZ=UTC`.
- `umask 022` antes do `build()`.
- caminho de build **canônico**: `/tmp/minitrue-build-<nome>` dentro do
  chroot. Como todo build de release roda no chroot, o path é idêntico
  entre builders — nenhum `-ffile-prefix-map` necessário no caminho feliz.

A receita NÃO precisa fazer nada para o caso comum; herda o ambiente. Se
introduzir não-determinismo próprio (ex.: gravar a data corrente, ordenar
por readdir), DEVE corrigi-lo — e o campo `EPOCH` está disponível.

## 4. Empacotamento determinístico do artefato

O `STAGE` idêntico só vira **hash** idêntico se o empacotamento também for
determinístico. **Decidido (2026-07-20): o próprio minitrue emite um tar
normalizado em Rust** — `minitrue pack <dir>` (crate `tar`, sem depender do
GNU tar na base). O minitrue é o empacotador canônico da corroboração (§5):
quem confere a reprodutibilidade tara com o mesmo código, então o formato só
precisa ser **determinístico**, não idêntico byte-a-byte ao do GNU tar.

Equivale a este `tar`, e normaliza o mesmo que ele normalizaria:

```
tar --format=gnu --sort=name --mtime=@$SOURCE_DATE_EPOCH \
    --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - .
```

O que o `pack` normaliza (tudo que é volátil):

- **ordem** por nome armazenado, byte-a-byte (diretórios com `/` ao final,
  então o pai sempre precede o conteúdo) — independe da ordem de `readdir`;
- **mtime** = `SOURCE_DATE_EPOCH` em toda entrada (não o mtime do disco);
- **uid/gid** = 0, **uname/gname** vazios (não o dono que buildou);
- **modo** mascarado em `07777`; nada de atime/ctime/device.

Caminhos > 100 chars (o gcc tem vários) viram entradas GNU LongName, que o
`pack` também emite deterministicamente. `channel emit` (SPEC-0009 §4) usa
`pack` e compressão zstd determinística em Rust para o artefato do canal.

O formato é **versionado** (`v1`), gravado num cabeçalho PAX global no início
do tar (`DISTROPICA.pack=1`) — muda quando a normalização mudar, e um leitor
pode recusar versão que não entenda. O `pack` transmite arquivo→tar→hasher
(sem carregar arquivo nem tar inteiro em RAM), preserva nomes não-UTF-8 e
hardlinks, e **recusa** arquivos especiais (FIFO/dispositivo/socket).
O **v2** acrescenta **xattrs** — e com eles as *file capabilities*. A versão
declarada é a **mínima exigida do leitor**, não a do escritor: árvore sem
xattr continua sendo empacotada e hasheada como v1, byte a byte, de modo que
nenhum `REPROCORR` pinado nem `ARTIFACT_HASH` já gravado migra. Os valores vão
em hexadecimal num registro PAX por entrada (`DISTROPICA.xattr.<nome>`), em
ordem canônica de nome, restritos aos namespaces `security.` e `user.`.

Isso corrige uma cegueira do v1 que não era só de fidelidade: como o
empacotamento ignorava `security.capability`, **duas árvores idênticas exceto
por uma capability produziam o mesmo `reprocorr`**. A raiz de confiança não
distinguia um binário privilegiado de um sem privilégio, e a attestation
atestava os dois com o mesmo hash.

Limitação que **permanece** no v2: **não** captura ACLs (`system.posix_acl_*`),
`trusted.*` nem sparse — como dois builds da mesma receita dão a mesma árvore,
isso não quebra o determinismo, mas quebra a fidelidade e está registrado.

**O que o `reprocorr` cobre — o tar, não o `.tar.zst`.** O `reprocorr`
(SPEC-0009 §3/§6) é o sha256 do **tar normalizado** (a saída de `pack`),
nunca do `.tar.zst`: o zstd não é garantidamente byte-reprodutível entre
versões e níveis, então acoplar a confiança à saída comprimida seria frágil.
O `.tar.zst` é só **transporte** — o índice do canal pina o sha256 *dele*
para integridade do download; a corroboração descomprime e confere o tar
interno contra o `reprocorr`. A **raiz de confiança única** do `reprocorr` é
a **receita assinada** (SPEC-0009 §6): a cópia no índice é declaração do
publicador, e se divergir da receita, vale a receita.

## 5. Verificação — o modo `corroborado`

A reprodutibilidade é *afirmável* mas precisa ser *checável*. No protótipo
atual não existe um modo separado `--check-repro`: todo `rectify` de mundo B
empacota o STAGE num `memfd` selado, grava o sha256 do tar normalizado em
`ARTIFACT_HASH` e, quando a receita declara `REPROCORR`, compara imediatamente
os dois. Divergência aborta com crimestop antes de aplicar o payload. Um comando
dedicado poderá apenas expor essa mesma operação sem instalar; o consumidor e
o emissor de canais já reutilizam a mesma identidade de tar normalizado.

- O cotejo compara **o sha256 do tar normalizado** com o `reprocorr` pinado na
  **receita** (autoridade; o índice traz só uma cópia). Igual ⇒ a
  reprodutibilidade se sustenta ⇒ o binário daquele canal pode ser confiado sem
  confiar no publicador.
- É esse hash reproduzido que o `TRUST=corroborado` (SPEC-0009 §6) exige
  bater; e é ele que o mantenedor pina como `reprocorr` ao publicar.

## 6. Evidência histórica (verificada em 2026-07-19/20)

Com o ambiente determinístico + `ar` determinístico, dois builds
independentes do mesmo pacote deram **`STAGE` byte-a-byte idêntico**:

- **m4 1.4.21** — idêntico já com o ambiente (sem `.a`).
- **gmp 6.3.0** — a princípio os `.a` (`libgmp.a`, `libgmpxx.a`) diferiam
  (mesmo tamanho, hash distinto: mtimes dos `.o` no `ar`); com binutils
  `--enable-deterministic-archives`, **idêntico** — inclusive os `.so`.

O ambiente está embutido no `install_source` do minitrue; o `ar`
determinístico, na receita do binutils.

**Hash de artefato — o laço fechado (2026-07-20).** Os dois `DESTDIR`
independentes do m4 (byte-a-byte idênticos como árvore) empacotam, via
`minitrue pack` (formato v1), para o **mesmo sha256**
(`de4710b70e7acc1267cf106b285f80e4a384ce6923fb4ed2b3bf4181bb29946e`),
hoje pinado em `newspeak/m4/recipe` e conferido no registro E2-clean. O hash
`3502e68…` citado em notas anteriores vinha de uma iteração pré-canônica do
empacotador e não é mais o pino do formato v1. É a
cadeia inteira demonstrada: **build reprodutível → empacotamento
determinístico → hash de artefato idêntico**. Esse sha256 é exatamente o
`reprocorr` que o mantenedor pina na receita e cuja cópia o índice v2 assinado
pode declarar (SPEC-0009 §3/§6); `TRUST=corroborado` exige que bata (§5). O
empacotador foi validado à parte
numa árvore com caminho > 100 chars (GNU LongName), symlink e modos
distintos: dois `pack` do mesmo diretório dão bytes idênticos, e o GNU tar
lista o resultado sem erro (formato válido).

**gcc reproduz — a toolchain inteira (2026-07-20).** Dois builds
independentes do gcc da passada 1 (`c,c++`), cada um instalado num `DESTDIR`
próprio, deram **todos os arquivos com o mesmo sha256** (comparação arquivo
a arquivo do install: `cc1`, `cc1plus`, `g++`, `libgcc`, todos os headers de
plugin — 185 arquivos, 564 MB). E os dois `DESTDIR` empacotam, via `minitrue
pack`, para um **hash de artefato idêntico**:

```
e340111069e0f1cd29e0659d7cda6d0b28222534938299f80f52af342e5b02f1   (gcc-d1 == gcc-d2, formato v1)
```

É a confirmação, em escala, da tese do codegen determinístico: o gcc da
passada 1 é *flaky* (ICE aleatório), mas a instabilidade é **só crash** — o
`.o` que sai é sempre o mesmo, e por isso o pacote de saída, com todos os
seus geradores (`gen*`, `insn-*.c` etc.), reproduz. Um compilador não
confiável para *rodar* produziu um artefato confiável para *verificar*.

**glibc reproduz — o outro grande (2026-07-20).** Mesmo teste, mesmo
resultado: dois builds independentes da glibc 2.42 (compilada pelo gcc
passada-1) deram install idêntico arquivo a arquivo, e os dois `DESTDIR`
empacotam para um hash de artefato idêntico:

```
9a1648d2a4eebc8a345b67b886af414e3d8492b457cb3459d228218f711ac05a   (glibc-d1 == glibc-d2, formato v1)
```

Importa porque a glibc tem `configure`s que rodam durante o `make` e podiam
cravar algo volátil (data, host, ordem) — não cravaram, sob o ambiente
determinístico. Isso demonstrou, para aquelas receitas e aqueles artefatos, que
gcc e glibc podiam sustentar um canal `corroborado` (§5). Os hashes continuam
como evidência histórica; não certificam automaticamente a closure atual.

As receitas atuais de `binutils-glibc` e `gcc-pass2` passaram a solicitar
`make install-strip`, motivadas pelo footprint do payload anterior sem strip.
Os novos payloads ainda não foram reconstruídos nem reemitidos: é necessário
medir a redução real, executar probes de compiladores, headers, bibliotecas e
ferramentas e repetir o build para demonstrar identidade byte a byte. Portanto,
R1 e a corroboração desses novos artefatos continuam pendentes; também não se
afirma ainda que exatamente ou somente símbolos DWARF serão retirados. Símbolos
de depuração poderão formar pacotes `-dbg` separados.

**Codegen determinístico (o achado que destrava gcc/glibc).** O gcc da
passada 1 é *flaky* (ICE segfault aleatório, corrupção de memória do
binário feito por clang). A pergunta perigosa era: a instabilidade afeta
só *crashes* ou também o *código gerado*? Teste (2026-07-19): o **mesmo
`.c` compilado 4× pelo gcc-passada-1 deu 1 hash único** (`.o` idênticos);
o zig cc idem em 3×. Conclusão: **a flakiness é só crash, não corrompe a
saída** — quando compila, produz idêntico. Logo o loop de retry (SPEC-0005)
não afeta o resultado: retenta-se até não estourar, e o `.o` produzido é o
mesmo de um build limpo. Isso é a base para gcc/glibc reproduzirem apesar
do compilador flaky.

**Caminho de build embutido — pouco, e coberto.** Teste: dois builds do
mesmo `.c` com `-g` em caminhos absolutos **diferentes** deram `.o`
idênticos **sem** `-ffile-prefix-map` — o `zig cc` (clang) não crava o
path absoluto no debug info por padrão. Mesmo assim, os shims do minitrue
passam `-ffile-prefix-map=$WORK=.` como defesa-em-profundidade (cobre
`__FILE__` e `comp_dir` onde ocorram), tornando a reprodutibilidade
independente do caminho — não só do caminho canônico do chroot.

## 7. Identidade declarativa do sistema

O `minipax` não usa o nome de um perfil como prova de identidade. Ele resolve
o perfil, normaliza `target.world`, `live.world` e o `cache.world` opcional,
empacota deterministicamente overlay, árvore Newspeak, cache e bootstrap de
canal, e grava um `profile.lock` textual com `PROFILE_LOCK_FORMAT=3`. A
identidade calculada usa `PROFILE_CONTENT_FORMAT=3`.
O lock também registra `INSTALL_READY`; `STATUS=release` exige valor `yes`.
O lock contém os hashes desses insumos — inclusive `CACHE_WORLD_SHA256` e
`CHANNEL_BOOTSTRAP_SHA256` —, o hash de conteúdo calculado, os três pinos
oficiais, além de nome, classe, arquitetura,
`SOURCE_DATE_EPOCH` e `MEDIA_SIZE_MIB`; o sha256 do próprio lock é a identidade
curta dos insumos do perfil. Ele não representa a resolução tipada das
dependências. O futuro `PLAN_LOCK_FORMAT=1` da SPEC-0013 cumprirá esse papel e
terá seu hash referenciado pelo `profile.lock`. Um perfil com `STATUS=release`
precisa pinar os três campos
`OFFICIAL_CONTENT_SHA256`, `OFFICIAL_BOOT_EFI_SHA256` e
`OFFICIAL_MINITRUE_SHA256`. Só a coincidência exata do conteúdo calculado com
o primeiro pode produzir `PROFILE_CLASS=official-inputs`; qualquer world,
Newspeak, overlay ou cache divergente é classificado como `custom`, assim
como o uso explícito de `--world`, `--live-world` ou `--overlay`. `--cache`
não é por si só personalização: seus bytes entram em `CACHE_SHA256` e no hash
de conteúdo, de modo que só o cache byte-idêntico ao pino do perfil de release
pode conservar `official-inputs`; qualquer diferença continua rebaixando.
Essa classe
atesta os insumos declarados, não uma reprodução oficial. O perfil versionado
atual segue em `development`, declara `INSTALL_READY=yes` e pode materializar
o target mínimo com um cache binário assinado de desenvolvimento. Ele não pode
emitir a classe `official-inputs`: não há pinos nem canal de release publicado.
`minipax lock --profile <dir>` expõe exatamente esse documento para auditoria
ou o grava, sem sobrescrever, quando recebe `--output`.

O target atual declara `base`, `linux`, `ripgrep`, `vim` e
`miniplenty-buildbase`. O último é um conjunto `KIND=meta`, sem payload: sua
identidade explícita no `world` (`WORLD=M`, `ORIGIN=meta`) agrega `base`, Make e
`gcc-pass2`; Make e `gcc-pass2` permanecem dependências, enquanto `base` também
é listado diretamente. Vim é outra intenção explícita e ncurses é sua
dependência transitiva. Na política
`--only-binary`, Vim, ncurses, Make, linux-headers, glibc, mathlibs-glibc, zlib,
binutils-glibc e gcc-pass2 são materializados pelo canal. Jq, Make, tree e Zig
integram `cache.world`; essa disponibilidade entra em R2 pelo lock, mas não cria
registro ou intenção no target binário. A fonte de Make fica congelada para
rebuild e oferta offline, embora seu binário seja instalado por depender do
meta; Zig permanece semente sob demanda. Jq e tree começam ausentes: um pedido
offline instala o primeiro do binário upstream e compila o segundo da fonte
oficial com a toolchain nativa.

A closure de execução de `gcc-pass2` é deliberadamente
`linux-headers + glibc + mathlibs-glibc + zlib + binutils-glibc`. `gcc` passada 1,
`binutils-cross` e `libstdcxx` intermediário são somente dependências de build;
o GCC final supersede o último e instala a libstdc++ definitiva. Essa fronteira
faz a identidade declarada do sistema apto a compilar incluir headers e
binutils nativos, mas excluir as sementes `gcc`, `binutils`, `binutils-cross`,
`libstdcxx`, `gmp`, `mpfr`, `mpc` e Zig no caminho atendido pelo canal. O
`minitrue verify` confere a presença factual das `DEPS` de execução de cada
registro tipado v2/v3, além da integridade de seus próprios arquivos.

Uma instalação direta usa exatamente esse snapshot. O Minipax copia a árvore
Newspeak e o cache fechados e congela também os executores: abre o Minitrue
resolvido, copia seus bytes para um `memfd`, sela escrita e mudança de tamanho,
calcula o hash desse snapshot e executa o mesmo descritor por `/proc/self/fd`;
mede também o próprio Minipax. Depois das verificações, persiste os dois
snapshots medidos em `/usr/bin`.
Cada invocação parte de ambiente limpo e recebe apenas o conjunto explícito de
variáveis determinísticas, caminho e, quando presentes, proxies. Assim, trocar
o arquivo original entre o hash e a execução não troca o programa executado.

No modo offline, o Minipax chama primeiro
`minitrue --root <alvo> --offline cache verify <cache.world>`; isso confere os
artefatos e assinaturas já presentes sem rede, instalação ou mudança do
`world`. Em seguida chama `rectify <target.world>`, exige `verify` antes e
depois do overlay administrativo e só então promove
`profile.lock.pending` a `profile.lock`. O `install.manifest` prende o hash e a
classe do perfil, `INSTALL_CLASS`, arquitetura, hash do overlay, hash do
Minitrue efetivamente executado, versão e hash do executável Minipax e as
opções `OFFLINE`, `FROM_SOURCE` e `ONLY_BINARY`; `--resume` exige o mesmo lock
e o mesmo manifesto. A instalação
só recebe `INSTALL_CLASS=official-inputs` quando o perfil já tem essa classe e
o executor reproduz `OFFICIAL_MINITRUE_SHA256`; caso contrário, é rebaixada
para `custom` (ou permanece `development` para o perfil de desenvolvimento sem
override explícito).

O coletor limita Newspeak e overlay a 128 MiB de arquivos regulares cada e
mantém essas duas árvores pequenas em memória. O cache usa referências aos
arquivos: seu tar normalizado é escrito diretamente no destino e lido pelo
instalador em duas passadas de streaming (validação de cabeçalhos e extração),
sem carregar conteúdo ou tar integral na RAM. Cada árvore admite 50.000
entradas. O teto do cache e de `cache.tar` é 4 GiB−1, não como orçamento de
memória, mas porque o arquivo vive hoje numa FAT32, cujo tamanho máximo de
arquivo é menor que 4 GiB.

Os modos dessas árvores também fazem parte da representação canônica: dirs
`0755`, `root/` do overlay `0700`, `shadow`/`gshadow` e backups `0600`,
executáveis `0755`, demais regulares `0644` e symlinks `0777`; regulares de
cache são sempre `0644`. Assim o lock e a mídia não dependem da capacidade do
Git de preservar apenas o bit executável.

Isso fecha **R2 (sistema declarado)**: duas execuções podem demonstrar que
partiram da mesma intenção e dos mesmos insumos. Ainda não fecha R2b. Entre os
bytes voláteis ou incompletamente modelados estão `INSTALLED_AT` dos registros,
uid/gid, mtimes da árvore aplicada, xattrs/ACLs/capabilities e qualquer saída
não determinística de receita sem `REPROCORR`. A comparação byte-a-byte do
rootfs completo só poderá ser reivindicada depois que esses campos forem
normalizados ou explicitamente separados como estado de máquina.

## 8. Normalização do envelope de mídia

`minipax media build` recebe o perfil resolvido, o modo `online|offline`, o
formato `img|iso` e um `BOOTX64.EFI` externo. O hash do EFI, a representação
canônica do perfil, o lock, os três worlds (incluindo `cache.world`, ainda que
vazio), o snapshot Newspeak, o overlay e o bootstrap de configuração +
índice/assinatura do canal entram no payload. No modo offline entra ainda o
cache completo; no modo online, `cache.tar` é recusado. Os dois snapshots têm
hashes separados no lock, para que o override usado na instalação offline não
substitua a autoridade que deve restar no alvo.
O builder valida cabeçalhos DOS/PE, máquina AMD64, optional header PE32+,
subsystem de aplicação EFI, número de seções e limites das tabelas. Isso prova
apenas a forma e a arquitetura declarada do executável: **não** prova que ele
inicia nem que contém o ambiente vivo.

O perfil atual fixa `MEDIA_SIZE_MIB=1024`. Esse valor dimensiona somente a saída
IMG e participa do lock; a ISO cresce conforme o payload e não é limitada nem
preenchida até esse tamanho. O campo também não dimensiona o disco em que o
sistema será instalado. Os runners atuais criam destinos de 4096 MiB por padrão
e ainda precisam executar a nova mídia. Os discos e hashes de 256 MiB citados
nas evidências históricas abaixo continuam exatamente os fatos daqueles
ensaios.

O repositório agora fornece `bootstrap/live/build-efi`, que constrói um
EFI-stub com Linux 7.1.8, initramfs, BusyBox e executores estáticos. Isso cria
um insumo vivo conhecido, mas a validade de qualquer arquivo arbitrário ainda
não decorre do parser PE. No consumo, `minipax install-media` reconstrói o
perfil e exige reproduzir `profile.lock` byte a byte antes de tocar no target.
Com `--export-boot-efi`, cria sem sobrescrever um snapshot do EFI já validado e
o remove se a instalação falhar. O PID 1 usa essa opção ao materializar toda a
closure em `/run` antes de escolher um disco; só depois copia e verifica o root,
instala o snapshot EFI e publica por último o marcador completo.
O construtor do EFI ainda não recebe o lock nem prova automaticamente que seu
conteúdo corresponde a `live.world`. O build fixa
`LOCALVERSION=-distropica-live` e `CONFIG_MODULES=n`: como não empacota nenhum
`.ko`, todos os drivers de mídia, disco, rede, vídeo, entrada e áudio são
built-in e guardados como `=y` depois do `olddefconfig`. Além de eliminar uma
superfície de carga que o artefato não usa, o release distinto continua
separando a identidade do kernel vivo da árvore `/lib/modules/7.1.8` do target.

Nos dois kernels, `KBUILD_BUILD_TIMESTAMP` precisa ser não só estável, mas
parseável pelo `date` do próprio builder. `usr/gen_initramfs.sh` reconverte esse
texto para alimentar `gen_init_cpio`; se a conversão falha, o script upstream
silencia a falha e o gerador usa `time(NULL)` nos diretórios e nós do CPIO. O
builder Distrópica usa BusyBox, que não aceita a forma longa do GNU date. Por
isso target e live usam `YYYY-MM-DD HH:MM:SS` sob `TZ=UTC` e exigem que a
reconversão resulte exatamente em `SOURCE_DATE_EPOCH` antes de compilar.

O kernel instalado segue outro contrato: `CONFIG_MODULE_SIG_FORCE=y`, SHA-512
e chaveiro confiável embutido, porém `CONFIG_MODULE_SIG_ALL=n`. A compilação
produz os módulos **sem** assinatura automática e não recebe segredo. A receita
pina um certificado X.509 público e um manifesto que associa, para cada `.ko`,
o sha256 do corpo unsigned ao sha256 de um CMS detached público. Antes de
anexar qualquer assinatura com `scripts/sign-file -s`, o build exige cobertura
exata (nenhum módulo/assinatura ausente ou extra), confere os dois hashes e
valida o CMS contra os bytes e o certificado pinado com `-nointern`. Depois,
extrai novamente corpo, CMS e descritor do `.ko` final e os coteja. A chave RSA
de autoria do bundle nasce em diretório `0700` fora de worktree/rootfs, não é
impressa e é removida antes de o bundle público ser materializado; regenerar o
bundle é operação offline explícita, não passo do build reproduzível.

O construtor produz duas classes operacionais que NÃO DEVEM ser confundidas.
Sem `--install-device`, a variante humana omite `distropica.test=1`, usa a
cmdline `console=ttyS0,115200 console=tty0 panic=-1 rdinit=/init` e traz
simpledrm/fbcon built-in para prompts no framebuffer. Com
`--install-device /dev/vda`, a variante de aceite QEMU embute também
`distropica.test=1`, automatiza o alvo destrutivo e deixa root bloqueado. Os
hashes de uma variante não corroboram nem identificam a outra.

Os três pinos de release fecham fronteiras diferentes. O conteúdo exato produz
`PROFILE_CLASS=official-inputs`; a mídia só preserva
`MEDIA_CLASS=official-inputs` quando também reproduz
`OFFICIAL_BOOT_EFI_SHA256`; e a instalação só preserva
`INSTALL_CLASS=official-inputs` quando executa o snapshot que reproduz
`OFFICIAL_MINITRUE_SHA256`. Uma divergência é permitida para desenvolvimento ou
customização, mas rebaixa a classe correspondente.

`official-inputs` é deliberadamente uma autoatribuição estreita: afirma que os
bytes locais coincidem com os pinos do perfil, nunca que a saída final é a mídia
oficial nem que foi reproduzida independentemente. A expressão **reprodução
oficial** fica reservada ao cotejo do sha256 final da imagem com um manifesto
oficial externo, publicado e assinado por uma raiz de release. O `.sha256` e o
`.manifest` gerados ao lado de uma construção local são evidência, não essa
autoridade externa.

### 8.1 Imagem de disco (`.img`)

O compositor interno, versionado como `minipax-fatfs-gpt-v1`, normaliza:

- tamanho de setor de 512 bytes, MBR protetor, GPT primária e de backup;
- início da ESP no LBA 2048 e tabela com 128 entradas de 128 bytes;
- tamanho total vindo de `MEDIA_SIZE_MIB`, com regiões não usadas zeradas;
- GUID do disco, GUID da partição e serial FAT derivados deterministicamente
  de `MEDIA_INPUT_SHA256`, o hash com domínio e framing do payload completo,
  com domínios distintos para cada identificador;
- ESP FAT32, label `DISTROPICA`, ordem canônica dos payloads e timestamps FAT
  derivados de `SOURCE_DATE_EPOCH`;
- CRCs GPT recalculados sobre as tabelas normalizadas.

Não há `losetup`, mount nem dependência de `mkfs`: GPT e FAT são compostos em
Rust. `MEDIA_INPUT_SHA256` enquadra, em ordem canônica, caminho, tamanho e bytes
de cada arquivo do payload. O `profile.lock` dentro dele prende
`MEDIA_SIZE_MIB` e os pinos; `media.meta` prende modo, hash efetivo do BOOT EFI
e versão do Minipax. Formato e compositor ficam no manifesto externo da mídia.
Todos esses campos são necessários para explicar os bytes finais, embora só o
payload completo alimente os GUIDs e o serial FAT.

### 8.2 ISO (`.iso`)

A ISO contém a mesma árvore de payload e uma ESP FAT determinística para a
entrada UEFI El Torito. O `minipax` fixa uid/gid, modos, volume, datas de todos
os arquivos, `SOURCE_DATE_EPOCH`, GUID GPT e parâmetros ISO9660/El Torito. A
composição final é delegada ao `xorriso`. O Minipax resolve seu caminho via
`PATH`, canonicaliza um arquivo real absoluto, calcula seu sha256 e usa esse
mesmo caminho absoluto para consultar a versão e compor a ISO, em ambiente
fechado. Ao terminar, recalcula o hash do executável e recusa se ele mudou;
também reabre a saída e exige o descritor ISO9660 `CD001`. Versão e hash do
`xorriso` ficam em `TOOL` no manifesto e fazem parte da evidência necessária
para reprodução byte-a-byte. Trocar de binário ou versão ainda não é prometido
como neutro.

### 8.3 Publicação e sidecars

A mídia e os três sidecars nascem integralmente num staging privado, no mesmo
filesystem do destino. O diretório pai da saída precisa ser real, pertencer ao
UID efetivo e não permitir escrita por grupo/outros; o Minipax ancora nele o
lock, o staging, as validações e as promoções por descritor. Cada nome é criado
atomicamente **sem substituição**. Os sidecars duráveis aparecem primeiro e a
imagem por último, como marcador externo de commit. Para `<saída>`, o
`minipax` cria:

- `<saída>.sha256` — hash dos bytes finais;
- `<saída>.media.lock` — cópia exata do `profile.lock`;
- `<saída>.manifest` — formato, modo, arquitetura, classe, hashes da mídia,
  do payload completo, do lock e do BOOT EFI, e compositor usado.

O lock e metadados essenciais também vão dentro da mídia. Como não existe uma
primitiva atômica multi-arquivo, um journal durável no staging prende a
requisição, os insumos, os hashes, os inodes e a fase da promoção. Depois de
queda ou erro, uma repetição com a mesma requisição recupera ou desfaz o prefixo
sem misturar gerações; um conjunto final completo, canônico e da mesma
requisição é sucesso idempotente. Symlinks, troca de paths, bytes incoerentes,
hardlinks estranhos e requisição diferente são recusados. A assinatura e
publicação do manifesto oficial externo, contra o qual se compara o hash final
para reconhecer uma reprodução, continuam pertencendo ao pipeline futuro de
release.

### 8.4 Escala do modo offline

O cache offline entra no mesmo payload, admite 50.000 entradas e usa streaming
de ponta a ponta (§7). A closure gráfica medida já ultrapassou o antigo teto em
memória e continuou compondo sem cópia integral do cache na RAM. O limite que
resta é 4 GiB−1 para o único `cache.tar` armazenado na FAT32. Se uma closure
futura o ultrapassar, será necessária uma partição de dados autenticada ou
outro layout; formato, integridade e montagem desse caminho ainda precisam ser
especificados.

Há ainda dois multiplicadores explícitos de pico: no consumo do canal, o
`.tar.zst` selado e o tar descompactado coexistem em `memfd` (**zst + tar**); no
instalador vivo, a closure materializada em `/run` permanece até terminar a
cópia e a verificação do disco. Essa escolha é deliberada para garantir
fail-before-wipe. Essa ocupação de `/run` é separada do streaming de
`cache.tar` já implementado e ainda precisa ser dimensionada para cada mídia.

## 9. Evidência atual e gates de mídia

Os testes do `minipax` executam duas composições locais da mesma fixture, em
saídas separadas, e exigem o mesmo sha256 usando o mesmo binário, dependências
e versão do compositor. Para IMG, também conferem a assinatura GPT; para ISO,
quando `xorriso` está disponível, conferem byte-identidade e o descritor
ISO9660 `CD001`. Há ainda testes do lock, normalização de world, confinamento
de overlay, recusa de target sujo e ingestão hostil de mídia. O canal assinado
e `--only-binary` materializaram o perfil mínimo anterior num E2E offline real;
isso não aceita o perfil atual com Vim, jq e tree. Ainda não houve cotejo R3
entre builders independentes. O runner
`bootstrap/live/accept-qemu` registra hashes, parâmetros e logs das duas fases
(instalação e segundo boot sem ISO). A execução final-v10 passou depois da
validação da closure e do EFI em `/run` antes da escolha do disco. Uma segunda
composição da ISO foi byte a byte idêntica; num probe negativo separado, um
`profile.lock` incoerente com `media.meta` falhou no preflight e deixou o disco
de teste zerado:

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

O aceite interativo histórico network-v1, em VirtualBox
7.2.6/EFI64/VMSVGA/SATA, usou um EFI
sem `--install-device`. Ele confirmou os dois prompts de senha e o prompt de
disco no framebuffer, ejetou a ISO depois do preflight e antes de autorizar o
wipe de `/dev/sda`, acompanhou o reboot pelo VDI sem ISO e autenticou `root`
como uid 0. Instalação e segundo boot ocorreram com o cabo da NIC VirtIO NAT
desligado. No terceiro boot, o runner ligou o cabo e comprovou DHCP IPv4, rota,
DNS local e gateway; depois desligou o cabo novamente e instalou o ripgrep
15.2.0, ausente do world inicial, com `minitrue --offline rectify`. O
`minitrue verify` posterior permaneceu limpo. A ISO foi composta duas vezes
com bytes idênticos no mesmo ambiente:

```text
EVIDENCIA_VIRTUALBOX_INTERATIVO_V1=local-custom
ACCEPTANCE_META=target/vbox-acceptance-network-v1/evidence/acceptance.meta
VBOX_VERSION=7.2.6_Ubuntur172322
GUEST_DISK=/dev/sda
NIC_TYPE=virtio
INSTALL_NETWORK=nat-cable-disconnected
THIRD_BOOT_NETWORK=nat-cable-connected
CMDLINE=console=ttyS0,115200 console=tty0 panic=-1 rdinit=/init
ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
REPEATED_ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
BOOT_EFI_SHA256=71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88
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
RUN_STATE=passed
FINAL_RESULT=passed
```

Essas são evidências locais de desenvolvimento, não pinos oficiais nem um
manifesto externo assinado. A igualdade das duas composições da ISO humana
fortalece R3 somente dentro do mesmo ambiente; não substitui a comparação
entre builders independentes. Do mesmo modo, o VirtualBox fecha o caminho
humano, enquanto o QEMU automatizado continua sendo a evidência específica do
negativo fail-before-wipe.

O runner atual deve provar uma identidade funcional diferente. No segundo boot
sem cabo, ripgrep 15.2.0, Vim 9.2.0837 e o registro sem payload de
`miniplenty-buildbase` devem existir; apenas o meta representa a toolchain no
`world`. Vim e o meta são top-level; ncurses 6.6, Make 4.4.1, linux-headers,
glibc, mathlibs-glibc, zlib 1.3.1, binutils-glibc 2.45 e GCC/G++ 15.3.0 devem ter origem de
canal sem se tornarem intenções top-level. Jq, Make, tree e Zig constam em
`cache.world`; jq, tree e Zig devem começar sem registro, e também precisam
estar ausentes as sementes `gcc`, `binutils`, `binutils-cross`, `libstdcxx`,
`gmp`, `mpfr` e `mpc`.

Sem conectar a rede, o runner deve validar uma edição com Vim, compilar e
executar C com headers Linux e glibc, C++17 com STL/exceções e
`libstdc++.so.6`, uma biblioteca estática com `ar`/`ranlib` e um Makefile que
invoque GCC. Depois deve instalar jq do binário upstream com
`minitrue --offline rectify jq` e compilar tree da fonte com
`minitrue --offline rectify tree`, mantendo Zig ausente e exigindo
`minitrue verify` limpo. Um novo boot deve demonstrar a persistência de Vim, jq
e tree; a NAT só é ligada depois para DHCP, DNS e gateway. Como a nova mídia
ainda não foi recomposta nem executada com os discos padrão de 4096 MiB, a
evidência network-v1 não pode ser reutilizada como prova de R4 para o perfil
atual. `MEDIA_SIZE_MIB=1024` dimensiona a variante IMG, não a ISO desse aceite.

Essas provas exercitam localmente R2 e o compositor de R3, não fecham um
release. Permanecem gates:

- repetir o aceite fail-before-wipe sobre o futuro artefato canônico pinado e
  publicado;
- ligar a construção do EFI ao `live.world`/lock e fixar os três pinos de
  release (`CONTENT`, `BOOT_EFI` e `MINITRUE`);
- reemitir o canal oficial já publicado contra a árvore corrente e seu
  metapacote normativo `miniplenty-buildbase`; `base` permanece receita de
  montagem com payload;
- converter o Journal path-based restante para operações fd-relative
  confinadas contra TOCTOU de mutador concorrente;
- definir como a atualização de `/boot/vmlinuz-*` atualiza e retém o EFI com
  kernel/initramfs embutidos;
- manter o cache em streaming e definir uma partição de dados autenticada caso
  o modo offline ultrapasse o teto de arquivo da FAT32;
- definir uid/gid e os metadados hoje ausentes antes de afirmar R2b;
- pinar a versão do `xorriso` no ambiente oficial de reprodução;
- repetir IMG e ISO em builders independentes, publicar um manifesto oficial
  externo assinado e comparar nele os hashes finais.

## 10. Questões em aberto

- ~~**gcc/glibc reprodutíveis**~~ — **resolvido (2026-07-20):** apesar dos
  geradores do gcc e dos `configure`s-durante-o-`make` da glibc, os dois
  reproduzem — install idêntico arquivo a arquivo e hash de artefato
  idêntico em ambos (§6). Os dois maiores do Estágio 2 estão provados.
- ~~Builds fora do chroot (caminho não canônico)~~ — **resolvido**: os
  shims passam `-ffile-prefix-map=$WORK=.`, e o `zig cc` já não crava o
  path por padrão (§6). A reprodutibilidade não depende mais do caminho.
- ~~**Empacotamento em Rust vs GNU tar** para o `channel emit` (§4)~~ —
  **resolvido**: Rust (`minitrue pack`), tar normalizado, sem depender do
  GNU tar na base (§4, §6). A compressão zstd e a emissão de pool + índice
  estão encadeadas; assinatura e publicação continuam externas.
- **Reprodutibilidade do próprio `minitrue`** (o binário Rust estático):
  desejável (o buscador que verifica tudo deveria ser verificável); Cargo +
  `SOURCE_DATE_EPOCH` chega perto — medir.
- Datas `EPOCH` por receita: convencionar (data de release do upstream) ou
  deixar no default fixo? Tende ao default, com override quando fizer
  diferença.
