# SPEC-0012 — Os Quatro Ministérios

**Status:** rascunho v0.2 · 2026-07-21
**Palavras-chave normativas:** DEVE / NÃO DEVE / DEVERIA / PODE (interpretação análoga à RFC 2119).

## 1. Propósito

*1984* tem quatro ministérios: **Verdade** (Minitrue, propaganda e reescrita
do passado), **Paz** (Minipax, a guerra perpétua), **Fartura** (Miniplenty,
produção e racionamento) e **Amor** (Miniluv, lei, punição, a Sala 101). A
Distrópica usa esse quarteto como **mapa de responsabilidades** das suas
ferramentas — não por estética, mas porque um nome que *diz o que a coisa faz*
é documentação que não desatualiza.

Fiel ao **P0** (SPEC-0001, pragmatismo acima de ideologia): o tema serve à
memorização e à coesão; onde ele brigar com a clareza, a clareza vence.

## 2. O mapa

| Ministério | Em *1984* | Na Distrópica | Onde |
|---|---|---|---|
| **Minitrue** (Verdade) | reescreve o passado | a ferramenta do usuário: `rectify`, `memoryhole`/unperson, `explain`/`why`; hoje também hospeda comandos de mantenedor | SPEC-0003 — **existe** (binário) |
| **Miniplenty** (Fartura) | produção, racionamento | lado mantenedor: build, `pack`, `attest`, `--emit`, índices, publicação, reprodução | SPEC-0009/0010 — **parcial** (`pack`/`attest` implementados dentro do minitrue; binário próprio futuro) |
| **Minipax** (Paz) | a guerra perpétua | canal e instalador: distribui e assenta a base | SPEC-0008/0009 — **desenhado** |
| **Miniluv** (Amor) | lei, punição, Sala 101 | **enforcement**: verificar, rejeitar o não-conforme, punir o desvio | §4 — **latente, onipresente** |

## 3. Fronteiras (Minitrue / Miniplenty / Minipax)

- **Minitrue** DEVE caber numa página: buscar, verificar, registrar, apagar,
  explicar, consumir canal. É o que o usuário roda. Nada que só o mantenedor
  precise entra aqui.
- **Miniplenty** é o Ministério da Fartura: **produz**. Build controlado,
  `pack` determinístico, emissão de attestations, `--emit`, índices assinados,
  reprodução cruzada. `pack` e `attest` já são território implementado de
  Miniplenty, mas continuam subcomandos do binário `minitrue`; isso evita uma
  separação executável antes de a interface de produção/publicação estabilizar.
  A separação em binário próprio permanece futura e NÃO muda a identidade dos
  formatos já emitidos.
- **Minipax** carrega o que Miniplenty produziu até a máquina do usuário:
  canal (SPEC-0009) e instalador (SPEC-0008).

## 4. Miniluv — o Ministério do Amor

Miniluv **NÃO é um quarto binário**. No livro, o Ministério do Amor não tem
um "produto": é o terror onipresente que faz as ficções dos outros três
colarem. Aqui é igual — o **enforcement** permeia todas as ferramentas em vez
de morar num comando:

- **`crimestop`** — a recusa de um artefato cuja assinatura não confere
  ("*crimestop (assinatura): X não é de quem diz ser*"). SPEC-0009.
- **`room101`** — o log de interrogatório do build que falha ("*o
  interrogatório completo está em…*"): a Sala 101 do mundo B.
- **`verify`** — integridade tipada (conteúdo, alvo de link e árvore no
  manifesto v2); pega adulteração. SPEC-0003.
- **doublethink** — a colisão de donos (dois pacotes reivindicando o mesmo
  caminho) é heresia e é barrada. SPEC-0003 §7.
- **`MODULE_SIG_FORCE`** no kernel — o mesmo gesto, um andar abaixo: o kernel
  recusa o `.ko` não-assinado ("*Loading of unsigned module is rejected*") e o
  adulterado (`EKEYREJECTED`), confiando só na chave do Ministério da Verdade
  embutida no chaveiro builtin (ver newspeak/linux, newspeak/openssl).

Onde Miniluv **cristaliza** em doutrina própria é na política de
**attestations** (SPEC-0009 §8.1), cujo mecanismo local já existe. Miniplenty
emite; Minitrue/Miniluv verifica e aplica a lei. O corpo Ed25519 canônico assina
`{ATTEST_FORMAT, PACKAGE, VERSION, RECIPE_FINGERPRINT, ARTIFACT_HASH, BUILDER,
BUILDER_KEY}`. A corroboração só considera a identidade exata
`VERSION`+`RECIPE_FINGERPRINT`: uma attestation histórica não pode ser
reapresentada como divergência da versão atual. ≥2 builders confiáveis e
distintos convergindo no hash ⇒ **corroborado** (absolvido); um confiável
divergindo nessa mesma identidade ⇒ desvio.

A implementação usa `ed25519-dalek` e independe do OpenSSL instalado na distro.
Ainda são futuros o transporte, a descoberta/publicação federada e a
independência operacional entre builders reais; hoje as attestations são
produzidas e coletadas localmente.

## 5. Referências

SPEC-0003 (minitrue), SPEC-0008 (instalador/Minipax), SPEC-0009 (canais/
Miniluv+Miniplenty), SPEC-0010 (reprodutibilidade), SPEC-0011 (rolling).
