# SPEC-0011 — Modelo de release: rolling edge

**Status:** rascunho v0.1 · 2026-07-20
**Palavras-chave normativas:** DEVE / NÃO DEVE / DEVERIA / PODE (RFC 2119).
**Depende de:** SPEC-0001 (premissas, P1/P2/P7), SPEC-0003 (minitrue, `--sync`,
registro), SPEC-0008 (kernel, boot A/B), SPEC-0009 (canais), SPEC-0010
(reprodutibilidade).

## 1. Princípio: rolling é o mecanismo, edge é a política

A Distrópica não tem *releases* — não há "Distrópica 12", nem
stable/testing/unstable, nem congelamento periódico. Há uma linha única,
continuamente retificada. Dois eixos, ortogonais:

- **Rolling** (este spec) — o **mecanismo**: o sistema se move sempre para a
  frente, sem saltos de versão-do-sistema. A árvore newspeak num commit É o
  conjunto consistente (P1); avançar = adotar um commit mais novo da árvore e
  convergir o sistema a ele.
- **Edge** (SPEC-0001 P7) — a **política de versão**: cada receita pina o
  **estável mais recente** do upstream. A árvore é continuamente reapontada
  para esse estável-mais-novo.

Juntos: a árvore rola para a frente (rolling) sempre para o estável-mais-novo
(edge), e `rectify --sync` retifica o sistema instalado à árvore.

Isto **não é um modelo novo a construir** — é o que o design já pressupõe. A
SPEC-0001 nunca mencionou "versão do sistema"; a ausência era proposital. Este
spec nomeia e completa o que falta operar.

## 2. Por que rolling é o único modelo coerente (tema)

Rolling release é 1984 tornado política de manutenção: *"o passado era
continuamente reescrito para bater com o presente."* O Ministério da Verdade
(`minitrue`) retifica os registros perpetuamente; não há edição arquivada, só
o agora. `rectify --sync` contra uma árvore que se move **é** a retificação
contínua.

O modelo oposto — *point release*: versões congeladas, arquivadas, com
changelog do que mudou — preservaria o passado, e seria anti-temático. Não há
como uma distro chamada Distrópica manter um "release estável de dois anos
atrás": seria um passado que se recusa a ser reescrito. A Distrópica não
preserva versões; retifica para o presente.

## 3. O motor — o que faz o sistema rolar

### 3.1 A árvore newspeak como pacote gerido

O linchpin (resolve a questão aberta de SPEC-0003 §11). A árvore de receitas é
ela mesma atualizável:

- `minitrue rectify newspeak` (nome especial) busca o **tarball da árvore** do
  repositório oficial via HTTPS.
- O tarball DEVE vir **assinado** (minisign, chave do projeto pinada — P6);
  assinatura inválida ⇒ *crimestop*, sem contorno.
- A troca é **atômica**: a árvore inteira é substituída de uma vez, nunca
  receita a receita. Árvore parcial = conjunto inconsistente (viola P1) — a
  origem clássica do *partial upgrade* quebrado.
- Não exige git instalado (é um tarball, não um clone) — coerente com a base
  mínima e com P1 (sem protocolo de repositório próprio).

### 3.2 `rectify --sync` — a convergência

Chegada a árvore nova, `--sync` converge o sistema à árvore (= ao `world`
resolvido contra a árvore corrente, SPEC-0003 §2):

- para cada pacote do `world` e suas dependências, se a versão/identidade da
  árvore difere da registrada, retifica (reinstala/rebuilda, ou baixa do
  canal);
- aponta órfãos (instalados que não constam mais); NUNCA remove sozinho
  (SPEC-0003 §2);
- é o "upgrade do sistema" do rolling — mas expresso como **reconciliação**,
  não como um comando de update à parte. O sistema não "atualiza"; **converge
  ao presente**.

## 4. Detecção de mudança e o fingerprint de build

Rolar exige saber o que mudou entre a árvore antiga e a nova. Hoje o registro
compara `VERSION` (SPEC-0003 §6): versão diferente ⇒ retifica. Cobre o caso
comum do edge (quase todo roll é um bump de versão).

O que faltava: a receita que muda **sem** bumpar versão (novo conserto, novo
toolchain, nova dependência) não disparava rebuild. É o **fingerprint de
build** — uma identidade que resume a receita.

**Implementado (v1, 2026-07-20).** O registro guarda `FINGERPRINT=` (sha256 do
arquivo `recipe` inteiro — que carrega VERSION, SRC, TOOLCHAIN, DEPS,
BUILD_DEPS e o corpo de `build()` — mais o `files/`, via o `pack`
determinístico da SPEC-0010). A idempotência do `rectify` compara **versão E
fingerprint**: receita corrigida com a mesma versão ⇒ fingerprint diferente ⇒
re-builda. Consertado o "GCC 15.3.0 mudou várias vezes sem bump" que o modelo
só-`VERSION` ignorava.

**Transitivo (2026-07-20).** O fingerprint de build é o `own_fingerprint` da
receita (arquivo + `files/`) **combinado com os fingerprints das suas
`DEPS`+`BUILD_DEPS`**, recursivamente (memoizado, robusto a ciclo). Então uma
mudança no `binutils` propaga para o `gcc`, e um roll que altera só um build-dep
**re-builda os dependentes**. Consertado o limite não-transitivo. (Mudar o
algoritmo invalida os fingerprints antigos ⇒ um `rectify` seguinte re-builda a
árvore uma vez — comportamento correto de uma troca de esquema.)

É a **mesma peça** que o Estágio 2 pediu para rodar pelo `rectify` (SPEC-0005
§4) — uma dívida, dois usos. O `--sync` (§3.2), quando implementado, usa este
fingerprint para decidir o que retificar.

## 5. A segurança do rolling (newer = menos testado)

Rolling quebra mais que point-release; a rede de proteção não é opcional.

### 5.1 Rollback do mundo inteiro

- **Mundo A** já retém versões lado a lado em `/opt` (corrente+1), mas o comando
  `rollback` que faria o flip de symlink ainda é stub (SPEC-0003 §5).
- **Mundo B** possui journal por pacote para reverter uma instalação que falha
  antes do commit; isso **não** é rollback de release. Um `--sync` de
  glibc/gcc já commitado ainda não volta como conjunto. O rolling DEVE ter
  **rollback de mundo B**: um snapshot do estado retificável antes de cada
  `--sync`. O
  mecanismo (manifesto+backup por caminho, ou retenção do artefato de canal, ou
  snapshot de filesystem) é questão aberta (§8).

### 5.2 Coerência do mundo inteiro

O maior perigo do rolling é o *partial upgrade*. A Distrópica o evita por
construção: a árvore num commit é consistente, e `--sync` atualiza contra a
árvore **inteira**, nunca um pacote de um commit e o resto de outro. Regra: o
usuário NÃO DEVE misturar pacotes de commits diferentes da árvore (ex.:
`NEWSPEAK_PATH` apontando para árvores de épocas distintas ao mesmo tempo).
`rectify <pacote>` avulso usa a árvore corrente, que já é consistente.

### 5.3 O canal acompanha o roll

Para o mundo B (glibc, gcc, …), edge sem canal significaria recompilar a base a
cada bump. O canal (SPEC-0009) DEVE republicar quando a árvore bumpa: nova
receita → novo `reprocorr` (SPEC-0010) → novo artefato no índice. A
reprodutibilidade é o que torna isto seguro — o binário do roll é verificável
por reprodução, não por confiança no publicador. Sem canal, o edge é caro; com
ele, o usuário rola sem compilar.

## 6. O kernel edge — o componente mais arriscado, e sua rede

P7 começa pelo kernel: a Distrópica acompanha o **stable mais recente** do
kernel.org (não um LTS antigo). É o maior risco do edge — kernel novo =
hardware novo suportado, mas menos rodagem.

A rede já existe (SPEC-0008 §4): a ESP mantém o UKI corrente e o **anterior**
(`EFI/distropica/anterior.efi`), e `rectify` do pacote `linux` rotaciona os
dois. Kernel edge que não bota → escolher a entrada anterior no firmware, sem
menu nem timeout. É o rollback-de-mundo-B (§5.1) na forma mais crítica, e a
razão de o boot A/B ter sido desenhado antes deste spec: **edge no kernel só é
aceitável porque o boot anterior sempre sobrevive.**

"Stable mais recente" é o *mainline stable* (a série nova), não
necessariamente o *longterm*. Quem precise de estabilidade extrema PODE pinar
uma série longterm na sua árvore (ressalva pragmática de P7), mas o default do
projeto é o stable novo.

## 7. Estado atual e o que falta

| Peça | Estado |
|------|--------|
| Design rolling (tree-at-commit, sem release) | pronto — é o que P1 pressupõe |
| Política edge (P7) | especificada (SPEC-0001 P7 + este spec) |
| Boot A/B do kernel (rollback do mais arriscado) | especificado (SPEC-0008 §4) |
| `rectify newspeak` (árvore-como-pacote) | **não implementado** (§3.1) |
| `rectify --sync` | speced, *stubbed* (SPEC-0003) |
| Fingerprint de build | **implementado, transitivo** (§4) |
| Rollback de mundo B | **lacuna** (§5.1) |
| Canal republicando no roll | speced (SPEC-0009), não implementado |

Com o fingerprint feito, restam três peças: **árvore-como-pacote** (o motor)
e **rollback de mundo B** (a rede) — exclusivamente-rolling — e o **canal**
republicando (compartilhada com reprodutibilidade). O fingerprint v1 →
transitivo é refinamento, não bloqueio.

## 8. Questões em aberto

- **Mecanismo do rollback de mundo B**: snapshot por manifesto+backup,
  retenção do artefato de canal, ou filesystem com snapshot (mas ext4-only no
  v0, SPEC-0008)? A decidir.
- **Cadência do roll**: a árvore é republicada contínua (a cada bump) ou em
  lotes coerentes (um *sync point* testado)? Contínuo é mais edge; lotes
  reduzem a chance de pegar um bump quebrado antes da correção. Tende a lotes
  coerentes, com os bumps críticos (kernel, glibc) mais cuidadosos.
- **Diff da árvore antes do `--sync`**: mostrar o que muda de versão antes de
  aplicar — desejável, e o registro-texto já permite computá-lo.
- **News / intervenção manual** (à la Arch): bumps que exigem ação do admin.
  Um campo na árvore? A decidir.
- **Edge × reprodutibilidade da base**: cada bump de glibc/gcc refaz as provas
  (SPEC-0010) e o `reprocorr` do canal. Convém um *gate*: não republicar a base
  sem a prova refeita.
