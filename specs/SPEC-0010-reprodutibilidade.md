# SPEC-0010 — Builds reprodutíveis

**Status:** rascunho v0.1 · 2026-07-19
**Depende de:** SPEC-0003 (minitrue), SPEC-0004 (newspeak), SPEC-0009 (canais).

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

A reprodutibilidade é *afirmável* mas precisa ser *checável*:

- `minitrue rectify --check-repro <pacote>` — builda localmente, empacota
  (o tar normalizado do `pack`), e compara **o sha256 desse tar** com o
  `reprocorr` pinado na **receita** (autoridade; o índice traz só uma
  cópia). Igual ⇒ a reprodutibilidade se sustenta ⇒ o binário daquele canal
  é confiável sem confiar no publicador.
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
(`3502e68fc3eb5fecc2cc39e5e45164640bc5a02c13216ad51867e74c212e3e8f`). É a
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

## 7. Questões em aberto

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
