# SPEC-0010 — Builds, sistemas e mídias reprodutíveis

**Status:** rascunho v0.1 · 2026-07-19
**Depende de:** SPEC-0003 (minitrue), SPEC-0004 (newspeak), SPEC-0008
(minipax), SPEC-0009 (canais).

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
| **R1 — pacote** | tar normalizado do `STAGE` (`reprocorr`) | provado para m4, gmp, gcc e glibc |
| **R2 — sistema declarado** | `profile.lock`: worlds, Newspeak, overlay, cache, arquitetura, epoch, tamanho de mídia e prontidão de instalação | implementado no `minipax`; torna os insumos auditáveis e repetíveis |
| **R2b — rootfs byte-a-byte** | árvore instalada inteira, já materializada | **não provado**; registros contêm tempo de instalação e uid/gid ainda não fazem parte do contrato |
| **R3 — mídia** | bytes finais de `.img` ou `.iso` para o mesmo conjunto completo de insumos | provado localmente com fixtures e o mesmo binário/toolchain; reprodução entre builders ainda não foi feita (§8) |
| **R4 — reprodução funcional** | mídia dá boot e instala um sistema equivalente em outra máquina | **não provado**; requer BOOT EFI vivo e aceite QEMU/OVMF |

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
`pack` também emite deterministicamente. `rectify --emit` (SPEC-0009 §4)
usará `pack` + compressão (zstd, a integrar) para o artefato do canal.

O formato é **versionado** (`v1`), gravado num cabeçalho PAX global no início
do tar (`DISTROPICA.pack=1`) — muda quando a normalização mudar, e um leitor
pode recusar versão que não entenda. O `pack` transmite arquivo→tar→hasher
(sem carregar arquivo nem tar inteiro em RAM), preserva nomes não-UTF-8 e
hardlinks, e **recusa** arquivos especiais (FIFO/dispositivo/socket).
Limitação conhecida do v1: **não** captura xattrs, ACLs, capabilities nem
sparse — como dois builds da mesma receita dão a mesma árvore, isso não
quebra o determinismo, mas quebra a fidelidade e está registrado.

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
dedicado poderá apenas expor essa mesma operação sem instalar quando os canais
chegarem.

- O cotejo compara **o sha256 do tar normalizado** com o `reprocorr` pinado na
  **receita** (autoridade; o índice traz só uma cópia). Igual ⇒ a
  reprodutibilidade se sustenta ⇒ o binário daquele canal pode ser confiado sem
  confiar no publicador.
- É esse hash reproduzido que o `TRUST=corroborado` (SPEC-0009 §6) exige
  bater; e é ele que o mantenedor pina como `reprocorr` ao publicar.

## 6. Estado atual (verificado 2026-07-19)

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
`reprocorr` que o mantenedor pina no índice do canal (SPEC-0009 §6) e que o
`TRUST=corroborado` exige bater (§5). O empacotador foi validado à parte
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
determinístico. Com gcc **e** glibc reprodutíveis, os dois pacotes que
justificavam todo o Estágio 2 estão prontos para virar binário de canal
`corroborado` (§5) — a base distribuível sem "confie em quem buildou".

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
o perfil, normaliza `target.world` e `live.world`, empacota deterministicamente
overlay, árvore Newspeak e cache, e grava um `profile.lock` textual, formato 1.
O lock também registra `INSTALL_READY`; `STATUS=release` exige valor `yes`.
O lock contém os hashes desses insumos, o hash de conteúdo calculado, os três
pinos oficiais, além de nome, classe, arquitetura,
`SOURCE_DATE_EPOCH` e `MEDIA_SIZE_MIB`; o sha256 do próprio lock é a identidade
curta do plano. Um perfil com `STATUS=release` precisa pinar os três campos
`OFFICIAL_CONTENT_SHA256`, `OFFICIAL_BOOT_EFI_SHA256` e
`OFFICIAL_MINITRUE_SHA256`. Só a coincidência exata do conteúdo calculado com
o primeiro pode produzir `PROFILE_CLASS=official-inputs`; qualquer world,
Newspeak, overlay ou cache divergente é classificado como `custom`. Essa classe
atesta os insumos declarados, não uma reprodução oficial. O perfil versionado
atual segue em `development`, declara `INSTALL_READY=no` e não pode emitir a
classe `official-inputs` nem iniciar a materialização do target oficial.
`minipax lock --profile <dir>` expõe exatamente esse documento para auditoria
ou o grava, sem sobrescrever, quando recebe `--output`.

Uma instalação direta usa exatamente esse snapshot. O Minipax copia a árvore
Newspeak e o cache fechados e congela também o executor: abre o Minitrue
resolvido, copia seus bytes para um `memfd`, sela escrita e mudança de tamanho,
calcula o hash desse snapshot e executa o mesmo descritor por `/proc/self/fd`.
Cada invocação parte de ambiente limpo e recebe apenas o conjunto explícito de
variáveis determinísticas, caminho e, quando presentes, proxies. Assim, trocar
o arquivo original entre o hash e a execução não troca o programa executado.

O Minipax chama `minitrue --root <alvo> rectify <target.world>`, exige `verify`
antes e depois do overlay administrativo e só então promove
`profile.lock.pending` a `profile.lock`. O `install.manifest` prende o hash e a
classe do perfil, `INSTALL_CLASS`, arquitetura, hash do overlay, hash do
Minitrue efetivamente executado, versão e hash do executável Minipax e as opções `OFFLINE` e
`FROM_SOURCE`; `--resume` exige o mesmo lock e o mesmo manifesto. A instalação
só recebe `INSTALL_CLASS=official-inputs` quando o perfil já tem essa classe e
o executor reproduz `OFFICIAL_MINITRUE_SHA256`; caso contrário, é rebaixada
para `custom` (ou permanece `development` para o perfil de desenvolvimento).

O coletor atual limita **cada** árvore Newspeak, overlay ou cache a 128 MiB de
arquivos regulares e 50.000 entradas. Ele mantém conteúdo e tar normalizado em
memória; esses são limites explícitos do protótipo, não capacidade de release.
Streaming é necessário antes de aceitar árvores reais maiores.

Isso fecha **R2 (sistema declarado)**: duas execuções podem demonstrar que
partiram da mesma intenção e dos mesmos insumos. Ainda não fecha R2b. Entre os
bytes voláteis ou incompletamente modelados estão `INSTALLED_AT` dos registros,
uid/gid, mtimes da árvore aplicada, xattrs/ACLs/capabilities e qualquer saída
não determinística de receita sem `REPROCORR`. A comparação byte-a-byte do
rootfs completo só poderá ser reivindicada depois que esses campos forem
normalizados ou explicitamente separados como estado de máquina.

## 8. Normalização do envelope de mídia

`minipax media build` recebe o perfil resolvido, o modo `online|offline`, o
formato `img|iso` e um `BOOTX64.EFI` externo. O hash do EFI, o lock, os worlds,
o snapshot Newspeak, o overlay e, no modo offline, o cache entram no payload.
O builder valida cabeçalhos DOS/PE, máquina AMD64, optional header PE32+,
subsystem de aplicação EFI, número de seções e limites das tabelas. Isso prova
apenas a forma e a arquitetura declarada do executável: **não** prova que ele
inicia nem que contém o ambiente vivo.

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

A mídia nasce em arquivo temporário irmão e é concluída pelo compositor. Os
três sidecars também são preparados integralmente em temporários; em seguida,
são publicados um a um e, somente depois deles, a imagem recebe o nome final.
Cada publicação é uma criação atômica **sem substituição**. Uma saída
preexistente — inclusive criada numa corrida após o preflight — faz a operação
falhar; arquivo ou symlink jamais é substituído. Para `<saída>`, o `minipax`
cria:

- `<saída>.sha256` — hash dos bytes finais;
- `<saída>.media.lock` — cópia exata do `profile.lock`;
- `<saída>.manifest` — formato, modo, arquitetura, classe, hashes da mídia,
  do payload completo, do lock e do BOOT EFI, e compositor usado.

O lock e metadados essenciais também vão dentro da mídia. A ordem impede que o
Minipax publique a imagem antes de seus sidecars, mas os quatro nomes externos
**não** formam uma transação única. Falha ou corrida durante a sequência pode
deixar um prefixo dos sidecars — ou todos eles — sem a imagem; não há rollback
multi-arquivo automático. A assinatura e publicação do manifesto oficial
externo, contra o qual se compara o hash final para reconhecer uma reprodução,
continuam pertencendo ao pipeline futuro de release.

### 8.4 Escala do modo offline

O cache offline entra hoje no mesmo payload e está sujeito, como árvore, aos
limites de desenvolvimento de 128 MiB e 50.000 entradas (§7). Um cache de
release real tende a superar tanto essa estratégia em memória quanto o desenho
de uma única ESP/FAT contendo tudo. O caminho esperado exige coleta e escrita
em streaming e provavelmente uma partição de dados offline separada; formato,
integridade e montagem dessa partição ainda precisam ser especificados.

## 9. Evidência atual e gates de mídia

Os testes do `minipax` executam duas composições locais da mesma fixture, em
saídas separadas, e exigem o mesmo sha256 usando o mesmo binário, dependências
e versão do compositor. Para IMG, também conferem a assinatura GPT; para ISO,
quando `xorriso` está disponível, conferem byte-identidade e o descritor
ISO9660 `CD001`. Há ainda testes do lock, normalização de world, confinamento
de overlay, recusa de target sujo e orquestração do mesmo `target.world` por um
`minitrue` falso. Ainda não houve cotejo R3 entre builders independentes.

Essas provas exercitam localmente R2 e o compositor de R3, não fecham um
release. Permanecem gates:

- construir um BOOT EFI vivo com kernel+initramfs+minipax+minitrue e fixar os
  três pinos de release (`CONTENT`, `BOOT_EFI` e `MINITRUE`);
- bootar IMG e ISO em QEMU/OVMF e instalar num disco vazio;
- remover a mídia e provar boot do sistema instalado com `minitrue verify`;
- implementar canais e a meta-receita normativa `base`, para que o caminho
  comum não recompile o Estágio 2;
- substituir os snapshots de árvores em memória por streaming e definir a
  partição de dados do modo offline;
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
- ~~**Empacotamento em Rust vs GNU tar** para o `--emit` (§4)~~ —
  **resolvido**: Rust (`minitrue pack`), tar normalizado, sem depender do
  GNU tar na base (§4, §6). Falta só encadear a compressão (zstd) e o
  `rectify --emit` que grava o artefato no layout do canal.
- **Reprodutibilidade do próprio `minitrue`** (o binário Rust estático):
  desejável (o buscador que verifica tudo deveria ser verificável); Cargo +
  `SOURCE_DATE_EPOCH` chega perto — medir.
- Datas `EPOCH` por receita: convencionar (data de release do upstream) ou
  deixar no default fixo? Tende ao default, com override quando fizer
  diferença.
