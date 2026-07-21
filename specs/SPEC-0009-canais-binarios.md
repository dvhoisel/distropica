# SPEC-0009 — Canais binários (oficial e samizdat)

**Status:** rascunho v0.1 · 2026-07-19
**Depende de:** SPEC-0001 (premissas, P2/P6), SPEC-0003 (minitrue),
SPEC-0004 (newspeak), SPEC-0008 (minipax).

## 1. Princípio: a premissa aplicada a si mesma

A premissa fundadora (SPEC-0001 P2/P3) é "usa binário do mantenedor se
existir; compila da fonte só o que não houver binário". Levada ao limite,
ela resolve sozinha a pergunta "o usuário final compila a glibc?": **não** —
porque assim que a Distrópica compila a glibc **uma vez** (o bootstrap do
Estágio 2, SPEC-0005), passa a existir um binário, e o usuário baixa esse,
como baixaria o do Firefox.

O mundo B (glibc, gcc, coreutils — sem binário upstream) é compilado **uma
vez, pelo mantenedor**, e publicado como binário. Um **canal** é o meio
dessa publicação. Do ponto de vista do `minitrue`, um binário de canal é
buscado pelo mesmo caminho de *fetch* de um binário de vendor: baixa,
verifica, extrai, registra — sem rodar `build()`. O *layout* de instalação,
porém, é o do mundo do pacote: o binário de canal de um pacote `KIND=source`
instala como **mundo B** (árvore em `/usr`, `WORLD=B`), não em `/opt` — ver
§4. A compilação local de fonte vira o **último recurso** — só para o que nem o upstream nem nenhum canal confiável
publica, e que o usuário especificamente pede.

Consequência: o processo doloroso do bootstrap é do mantenedor, único. O
usuário final quase nunca compila.

## 2. Anatomia de um canal

Um canal é uma tripla:

| Parte | O que é |
|-------|---------|
| **URL base** | HTTPS de onde vêm o índice e os artefatos |
| **Chave** | chave pública pinada (minisign) que assina o índice |
| **Prioridade** | ordem de consulta relativa aos outros canais |

Dois tipos:

- **Canal oficial** — publicado pela Distrópica, chave do projeto,
  pré-configurado, prioridade máxima por padrão. É a saída do Ministério
  da Verdade: os binários "oficialmente retificados".
- **Canal samizdat** — não oficial, porém confiável: um terceiro que
  publica binários da Distrópica. O usuário o adiciona **explicitamente**,
  pinando a chave dele — e é esse ato explícito que é a decisão de
  confiança. (O nome ecoa o livro clandestino de Goldstein em 1984,
  circulado de mão em mão fora do canal oficial.)

Nada de repositório "central comunitário" implícito (SPEC-0001 P1): não há
canal ativo que o usuário não tenha configurado, exceto o oficial.

## 3. O índice do canal (assinado)

Cada canal expõe um **índice** — texto puro, um artefato por linha,
assinado com a chave do canal (minisign). Formato de cada linha:

```
<nome> <versão> <arch> <caminho-relativo> <sha256> [reprocorr]
```

Ex.: `glibc 2.42 x86_64 pool/glibc-2.42-x86_64.tar.zst <sha256>`.

- O índice inteiro é coberto por uma assinatura destacada
  (`index.minisig`); `minitrue` recusa índice cujo `minisig` não bate com
  a chave pinada do canal — *crimestop* de índice.
- O índice diz **onde** está o artefato e **qual** o hash esperado. A rede
  entrega bytes; a chave+hash decidem a verdade (P6).
- O `<sha256>` (obrigatório) cobre o **`.tar.zst` servido** — integridade do
  download.
- `reprocorr` (opcional): o hash reprodutível — **sha256 do tar normalizado
  interno** (a saída de `minitrue pack`, SPEC-0010 §4), **não** do `.tar.zst`
  (o zstd não é byte-reprodutível entre versões). É a *cópia declarada pelo
  publicador*; a **autoridade única** é o `reprocorr` pinado na **receita**
  (§6) — se divergirem, vale o da receita. Usado na corroboração (§6).

## 4. O artefato binário

Um artefato de canal é o **staging (`STAGE`/DESTDIR) do build de fonte
empacotado** — exatamente a árvore que a receita mundo B (SPEC-0004)
instalaria. Instalar = extrair em `/` (respeitando a política de `/etc`,
SPEC-0002 §6) e registrar o manifesto — **layout mundo B** (`WORLD=B`,
árvore em `/usr`, nada em `/opt`), idêntico ao que a receita produziria
compilando. O que se herda do mundo A é só o **fetch** de um tarball passivo
(baixa/verifica/extrai, sem `build()`), **não** o layout: um binário de
canal de pacote `KIND=source` não vira mundo A. Muda só a origem —
pré-buildado em vez de compilado localmente.

- Nome: `<nome>-<versão>-<arch>.tar.zst`.
- **Produção (mantenedor):** `minitrue rectify --emit <pacote>` roda o
  `build()`, empacota o `STAGE` (tar normalizado → `.tar.zst`) e imprime
  **dois** hashes: o `<sha256>` do `.tar.zst` (integridade, vai no índice) e
  o `reprocorr` = sha256 do tar normalizado interno (reprodutibilidade, vai
  na **receita** e, como cópia, no índice). O mantenedor publica o tarball e
  acrescenta a linha ao índice, reassinando-o.
- O artefato NÃO carrega scripts de pós-instalação (SPEC-0001 §2): é
  árvore passiva, como qualquer tarball.

## 5. Resolução: binário de canal vs. fonte

Para `minitrue rectify X` (versão V vem SEMPRE da receita newspeak — o
canal **não** escolhe versão; a árvore versionada é a fonte de verdade):

1. X já instalado em V e `verify` limpo ⇒ no-op.
2. Percorre os canais em ordem de prioridade. O primeiro que ofereça
   `X V <arch>` no índice (assinatura do índice conferida) e cujo artefato
   passe na política de confiança (§6) **vence**: baixa, confere sha256,
   extrai, registra (com a proveniência, §7).
3. Nenhum canal aceitável ⇒ **fallback**: `build()` da fonte, localmente
   (mundo B, SPEC-0004). É o último recurso.

`--offline` restringe ao cache; `--no-binary` força o build de fonte
(para quem quer compilar); `--only-binary` proíbe o fallback (falha se
nenhum canal tiver — útil em máquina sem toolchain).

## 6. Confiança — e por que canal não oficial pode ser seguro

A cadeia de confiança de instalar um binário depende de **haver ou não um
hash reprodutível pinado na receita** (que é versionada e assinada):

- **Com `reprocorr` na receita (build reprodutível):** após conferir o
  `<sha256>` do `.tar.zst` contra o índice assinado (integridade do
  download), o minitrue **descomprime** e confere o sha256 do **tar
  normalizado interno** contra o `reprocorr` **pinado na receita** — a raiz
  de confiança única (versionada, assinada), não o índice nem o publicador.
  Bateu ⇒ o canal é **só um espelho (CDN)**. Um canal samizdat é tão seguro
  quanto o oficial: só consegue te entregar exatamente o artefato
  reprodutível canônico, ou é recusado. A rede segue sem decidir a verdade
  (P6 preservado ao pé da letra). **Esta é a forma forte**, e o motivo de a
  reprodutibilidade (aspiração em SPEC-0001 §4) virar mecanismo de segurança
  aqui.
- **Sem hash reprodutível (build não determinístico):** é preciso confiar
  em **quem** buildou. Política por canal:
  - `oficial`: confia no projeto (chave oficial).
  - `corroborado`: aceita o binário samizdat só se o hash **coincidir com
    o do canal oficial** (ou com o de ≥N canais independentes) — "confie na
    receita, verifique nos pares".
  - `builder`: confiança pura no publicador samizdat (a mais fraca; exige
    opt-in explícito e é registrada como tal).

Regras invariantes, valham quais canais valerem:

1. Versão vem da receita; canal não substitui versão.
2. Todo artefato é conferido por sha256 (vindo do índice **assinado**).
   Divergência ⇒ *crimestop*, sem flag de força.
3. Rotação de chave de canal é evento auditável (troca do pino na config,
   com justificativa).
4. Chave de canal NUNCA é buscada na rede em tempo de instalação
   (SPEC-0001 P6): é pinada na config, versionável.

## 7. Configuração e comandos

Canais vivem em `/etc/minitrue/channels/<nome>` (texto, do administrador —
SPEC-0002 §6), uma tripla por arquivo:

```
URL=https://bin.distropica.org/x86_64
KEY=RW...            # chave minisign do canal
PRIORITY=100
TRUST=oficial        # oficial | corroborado | builder
```

O canal oficial vem pré-instalado (`00-oficial`). Comandos do `minitrue`:

```
minitrue channel add <nome> <url> <key> [--trust corroborado] [--prio N]
minitrue channel remove <nome>          # samizdat; o oficial pede --forcar
minitrue channel list                   # nome, url, trust, prioridade
minitrue channel refresh [<nome>]       # rebaixa e verifica os índices
```

`channel add` é o ato explícito de confiança em um samizdat. O default de
`--trust` para samizdat é `corroborado` (o mais seguro que não seja o
oficial); `builder` exige a flag consciente.

## 8. Registro e proveniência

O registro de um pacote (SPEC-0003 §6) ganha, no `meta`:

- `ORIGIN=oficial|canal:<nome>|fonte` — de onde veio o binário (ou se foi
  compilado localmente);
- `CHANNEL_SHA256=` — o hash servido pelo índice (para auditoria);
- `TRUST=` — a política sob a qual foi aceito.

`archives` mostra a proveniência; `verify` pode reconferir o hash contra o
índice corrente. Assim o sistema é auditável: "quais binários vieram de
samizdat, e sob que confiança?".

### 8.1 Attestations e corroboração — o Miniluv com lei escrita (implementado)

A federação de §6 (`corroborado`) tem forma concreta. Duas camadas:

**Raiz — `reprocorr` (build reprodutível).** A receita pina `REPROCORR=`
(sha256 do `pack(STAGE)`, SPEC-0010 §4). No build de fonte, o `minitrue`
computa o `pack(STAGE)`, grava `ARTIFACT_HASH=` no registro, e — se a receita
pina — EXIGE que batam: divergir é **crimestop (reprodução)**, não aviso. É a
autoridade única (§6): a rede vira espelho. (1ª receita a pinar: `m4`.)

**Federação — attestations assinadas.** Uma attestation é texto assinado
(ed25519): ordem canônica `ATTEST_FORMAT, PACKAGE, VERSION, RECIPE_FINGERPRINT,
ARTIFACT_HASH, BUILDER, BUILDER_KEY`, seguido de `BUILT_AT` (informativo) e
`SIG=` (hex, sobre o corpo canônico). Diz: *"o builder K obteve, da receita R
(fingerprint F), o artefato H."*

Comandos:

```
minitrue attest keygen <nome> <arquivo-da-chave>   # gera par ed25519 (secreta 0600)
minitrue attest <pacote> <builder> <arquivo>       # emite a attestation assinada (stdout)
minitrue corroborate <pacote>                      # veredito de corroboração
```

Confiança e regra:

- Builders CONFIÁVEIS têm a pubkey PINADA em `/etc/minitrue/builders/<nome>`
  (o ato explícito de confiança, §7). Attestation de builder não-pinado, ou com
  assinatura que não bate, é **ignorada** (não é de quem diz ser — *crimestop*).
- Attestations chegam em `var/lib/minitrue/attestations/<pacote>/`. Agrupadas
  por `ARTIFACT_HASH` e contando builders confiáveis DISTINTOS:
  - **≥2 concordam com o hash local** ⇒ **corroborado** (ortodoxo);
  - **um confiável atesta hash diferente** ⇒ **DIVERGÊNCIA** — desvio (§9),
    crimestop mesmo que outros concordem (uma testemunha herege basta pro alarme);
  - **<2** ⇒ não corroborado.

`explain` mostra a linha de corroboração e se o build reproduziu o REPROCORR
pinado. **Honestidade (SPEC-0001 §4):** independência de builder de verdade pede
máquinas independentes (o vão "reproduzível ×2"); numa só máquina o mecanismo é
o mesmo, mas a independência é simulada — a garantia forte vem de builders REAIS
e separados publicando attestations convergentes.

## 9. Ameaças (o que um canal malicioso pode e não pode)

- **Não pode** empurrar outra versão (a versão vem da receita).
- **Não pode** passar hash divergente do índice assinado sem quebrar a
  assinatura (chave pinada) — nem burlar o sha256 do artefato.
- **Não pode**, num pacote reprodutível, entregar nada além do artefato
  canônico (senão o hash não bate com o `reprocorr` da receita).
- **Pode**, num pacote NÃO reprodutível sob `TRUST=builder`, entregar um
  binário adulterado assinado por ele — é a confiança inerente a qualquer
  canal binário, e por isso `builder` é opt-in gritante e a
  reprodutibilidade é o caminho recomendado.

## 10. Relação com a premissa e o mundo A

O binário-Distrópica é "binário do mantenedor" para o mundo B: uma vez que
existe, P2 manda preferi-lo à fonte. Não fere P1 (não é gerenciador de
pacotes externo; é o próprio `minitrue` consumindo um tarball assinado) nem
P6 (tudo pinado). A meta-receita `base` do instalador (SPEC-0008 §7) DEVE
resolver-se por binários de canal — é o que garante que o usuário **não
compila a base** ao instalar.

Ordem de preferência de um artefato, do mais ao menos preferido:
1. binário oficial do **upstream** (mundo A: firefox, zig…);
2. binário do **canal oficial** da Distrópica (mundo B pré-buildado);
3. binário de **canal samizdat** (conforme política de confiança);
4. **compilação de fonte** local (último recurso).

## 11. Não-objetivos e questões em aberto

- Protocolo de repositório sofisticado (deltas, resolução de versões
  múltiplas): fora — o índice é uma lista assinada, e a árvore newspeak num
  commit é o conjunto consistente (SPEC-0001 P1).
- **Reprodutibilidade de fato** do build da base: hoje aspiração
  (SPEC-0001 §4); vira requisito prático para o modo `corroborado` valer.
  Definir o conjunto de flags/ambiente determinístico é trabalho próprio.
- Mirrors do canal oficial (mesma chave, URLs alternativas): trivial de
  acomodar (vários arquivos de canal com a mesma `KEY`); formalizar.
- Assinatura do índice: minisign no v0; OpenPGP quando a verificação PGP
  chegar (SPEC-0004 §5).
- Federação/descoberta de samizdats confiáveis (uma "lista de listas"
  assinada pelo projeto): tentador, mas reintroduz confiança central —
  decidir se vale.
- `minitrue channel` e `--emit`: implementação depois do Marco 0.2
  (hoje o minitrue faz mundo A e mundo B; canais são a camada seguinte).
