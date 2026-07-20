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
determinístico. `minitrue rectify --emit` (SPEC-0009 §4) DEVE tarar o
`STAGE` com ordem e metadados normalizados:

```
tar --format=gnu --sort=name --mtime=@$SOURCE_DATE_EPOCH \
    --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - . | zstd -19
```

(No v0, o busybox tar não tem `--sort`; o `--emit` usa o GNU tar da base,
ou o próprio minitrue emite um tar normalizado em Rust — a decidir.)

## 5. Verificação — o modo `corroborado`

A reprodutibilidade é *afirmável* mas precisa ser *checável*:

- `minitrue rectify --check-repro <pacote>` — builda localmente, empacota,
  e compara o hash com o `reprocorr` pinado (na receita ou no índice do
  canal). Igual ⇒ a reprodutibilidade se sustenta ⇒ o binário daquele canal
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

- **gcc/glibc reprodutíveis:** os pacotes maiores ainda não foram testados
  para reprodutibilidade; gcc tem geradores e a glibc tem
  `configure`-embutidos que podem exigir ajuste. Testar é o próximo passo.
- ~~Builds fora do chroot (caminho não canônico)~~ — **resolvido**: os
  shims passam `-ffile-prefix-map=$WORK=.`, e o `zig cc` já não crava o
  path por padrão (§6). A reprodutibilidade não depende mais do caminho.
- **Empacotamento em Rust vs GNU tar** para o `--emit` (§4): decidir.
- **Reprodutibilidade do próprio `minitrue`** (o binário Rust estático):
  desejável (o buscador que verifica tudo deveria ser verificável); Cargo +
  `SOURCE_DATE_EPOCH` chega perto — medir.
- Datas `EPOCH` por receita: convencionar (data de release do upstream) ou
  deixar no default fixo? Tende ao default, com override quando fizer
  diferença.
