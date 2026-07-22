# SPEC-0009 — Canais binários (oficial e samizdat)

**Status:** implementação inicial v0.5 · 2026-07-22
**Depende de:** SPEC-0001 (premissas, P2/P6), SPEC-0003 (minitrue),
SPEC-0004 (newspeak), SPEC-0008 (minipax).

**Estado de implementação:** consumo de canais, `--only-binary`, cache offline,
bootstrap online, lock de seleção e `channel emit` já existem. O índice v2
canônico é assinado com minisign e autentica o fingerprint da receita; a chave
é pinada localmente e cada artefato tem hash de transporte e `reprocorr`. Lock
e emissão usam formato 2, e `verify` coteja semanticamente a proveniência
registrada com o lock content-addressed. A CLI administrativa
`channel add/remove/list/refresh`, a publicação de um canal oficial e a
distribuição/rotação de sua chave ainda não existem. Em particular,
`channel refresh` autenticado, com diff auditável antes de avançar o snapshot,
é gate de release. O cache exercitado no E2E é de desenvolvimento,
`TRUST=builder`.

## 1. Princípio: a premissa aplicada a si mesma

A premissa fundadora (SPEC-0001 P2/P3) é "usa binário do mantenedor se
existir; compila da fonte só o que não houver binário". Levada ao limite,
ela resolve sozinha a pergunta "o usuário final compila a glibc?": **não** —
no caminho normal. Assim que builders produzem e publicam um artefato aceito
para a glibc (bootstrap do Estágio 2, SPEC-0005), o usuário pode baixar esse
artefato como baixaria o do Firefox.

O mundo B (glibc, gcc, coreutils — sem binário upstream) é compilado por um
ou mais **builders**, quantas vezes forem necessárias, e seus resultados podem
ser comparados e atestados. Não existe uma compilação singular do mantenedor
que se torne verdade por autoridade. Um **canal** é o meio de publicar os
artefatos aceitos. Do ponto de vista do `minitrue`, um binário de canal é
buscado pelo mesmo caminho de *fetch* de um binário de vendor: baixa,
verifica, extrai, registra — sem rodar `build()`. O *layout* de instalação,
porém, é o do mundo do pacote: o binário de canal de um pacote `KIND=source`
instala como **mundo B** (árvore em `/usr`, `WORLD=B`), não em `/opt` — ver
§4. A compilação local de fonte vira o **último recurso** — só para o que
nem o upstream nem nenhum canal confiável publica, ou para quem pede
explicitamente uma reprodução.

Consequência: o usuário normal quase nunca compila; o reprodutor
deliberadamente pode repetir o bootstrap inteiro. Receita, pinos,
`REPROCORR`, assinaturas e corroboração — não a identidade de uma máquina de
build única — sustentam a confiança.

## 2. Anatomia de um canal

Um canal é uma tripla:

| Parte | O que é |
|-------|---------|
| **URL base** | HTTPS de onde vêm o índice e os artefatos |
| **Chave** | chave pública pinada (minisign) que assina o índice |
| **Prioridade** | ordem de consulta relativa aos outros canais |

Dois tipos:

- **Canal oficial** — será publicado pela Distrópica com chave do projeto e
  pré-configurado no release, com prioridade máxima por padrão. É a saída do
  Ministério da Verdade: os binários "oficialmente retificados".
- **Canal samizdat** — não oficial, porém confiável: um terceiro que
  publica binários da Distrópica. O usuário o adiciona **explicitamente**,
  pinando a chave dele — e é esse ato explícito que é a decisão de
  confiança. (O nome ecoa o livro clandestino de Goldstein em 1984,
  circulado de mão em mão fora do canal oficial.)

Nada de repositório "central comunitário" implícito (SPEC-0001 P1): não há
canal ativo que o usuário não tenha configurado, exceto o oficial.

No estado de desenvolvimento atual, nem mesmo o oficial vem configurado: não
há endpoint, chave de release ou artefatos públicos. Um cache fechado pode
semear configuração, índice e objetos para a instalação offline.

## 3. O índice do canal (assinado)

Cada canal expõe um **índice v2** — texto puro, um artefato por linha,
assinado com a chave do canal (minisign). O formato obrigatório de cada linha
é:

```
NAME VERSION ARCH RECIPE_FINGERPRINT PATH SHA256 [REPROCORR]
```

Ex.: `glibc 2.42 x86_64 <fingerprint> pool/glibc-2.42-x86_64.tar.zst <sha256>`.
São exatamente seis campos, ou sete quando `REPROCORR` está presente. O
formato anterior sem `RECIPE_FINGERPRINT` é recusado; não há fallback
posicional.

- O índice inteiro é coberto por uma assinatura destacada
  (`index.minisig`); `minitrue` recusa índice cujo `minisig` não bate com
  a chave pinada do canal — *crimestop* de índice.
- `RECIPE_FINGERPRINT` (obrigatório) faz a identidade da receita parte dos
  bytes assinados. A seleção exige que ele coincida com o fingerprint da
  receita efetiva local; divergência é *crimestop (identidade)*.
- `PATH` diz **onde** está o artefato e `SHA256`, **qual** hash é esperado. A
  rede entrega bytes; a chave+hash decidem a verdade (P6).
- `SHA256` (obrigatório) cobre o **`.tar.zst` servido** — integridade do
  download.
- `REPROCORR` (opcional): o hash reprodutível — **sha256 do tar normalizado
  interno** (a saída de `minitrue pack`, SPEC-0010 §4), **não** do `.tar.zst`
  (o zstd não é byte-reprodutível entre versões). É a *cópia declarada pelo
  publicador*; a **autoridade única** é o `reprocorr` pinado na **receita**
  (§6) — se divergirem, vale o da receita. Usado na corroboração (§6).

### 3.1 Snapshots imutáveis e lock de canal

Um índice assinado que muda com o tempo serve para **descoberta**, mas não
fecha uma instalação reproduzível: dois builders poderiam consultar o mesmo
URL em dias diferentes e selecionar conjuntos diferentes. Por isso cada
operação de instalação que seleciona binários resolve os canais uma vez num
**snapshot imutável**, identificado pelo SHA-256 dos bytes canônicos do índice
depois de sua assinatura ser validada, e persiste um **lock de canal**. A mídia
congela configuração, índice/assinatura e, no modo offline, objetos pelo
`profile.lock`; o lock de canal nasce quando o Minitrue resolve a instalação.

O formato implementado é texto canônico (`CHANNEL_LOCK_FORMAT=2`) e fecha:

- arquitetura;
- para cada canal usado: nome, URL, SHA-256 da chave pinada, SHA-256 do índice
  validado e política de confiança;
- para cada pacote selecionado: nome, versão, fingerprint autenticado pelo
  índice e já cotejado com a receita efetiva, canal, caminho, SHA-256 dos bytes
  servidos, `reprocorr` e política de confiança.

O lock v1 continha um campo de fingerprint preenchido apenas pela receita
local, não pelo índice assinado. Ele é recusado: não pode ser promovido
implicitamente à semântica autenticada do formato 2.

O arquivo fica em
`/var/lib/minitrue/channel-locks/<sha256-do-corpo>.lock`; o hash do nome também
é gravado no registro de cada pacote selecionado. O vínculo direto com o lock
de perfil e a assinatura/publicação desse lock junto à release continuam
evoluções necessárias.

Regras:

1. depois de criado o lock, nenhuma atualização de índice muda a operação em
   curso; todos os downloads precisam corresponder ao snapshot;
2. artefato ausente no snapshot falha fechado — não se substitui
   silenciosamente por uma versão mais nova;
3. uma futura atualização administrativa do lock será explícita e deverá
   produzir diff auditável;
4. uma release deverá publicar seu lock junto da mídia e incluí-lo na
   proveniência. A reprodução do perfil oficial deverá reutilizar essa
   seleção, não resolver novamente o "mais recente";
5. um perfil customizado produz seu próprio lock e hashes. Mesmo que use os
   mesmos canais, ele não pode reivindicar a identidade da release oficial.

O lock não transforma URL em raiz de confiança: a assinatura do índice ainda
é verificada contra a chave pinada, e os bytes ainda precisam bater com os
hashes. Ele apenas torna a escolha temporal explícita e repetível. O `minipax`
leva configuração, índice assinado e objetos no cache da mídia offline; na
online, leva somente configuração + índice/assinatura pareados e proíbe os
objetos. O `minitrue` cria o lock ao resolver a instalação. Embutir um lock de
release já pré-resolvido ainda não foi implementado.

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
- **Produção (builder/publicador):** depois de um build fonte registrado em
  formato v2, `minitrue --root ROOT channel emit --output DIR <pacote>...`
  comprime para `.tar.zst` e escreve `pool/`, o índice v2 e `emit.meta` com
  `CHANNEL_EMIT_FORMAT=2`. Para um registro instalado de canal, reutiliza o tar
  original autenticado no cache content-addressed, revalidando o hash de
  transporte, o `ARTIFACT_HASH` interno e a topologia instalável. Sem esse
  objeto — ou para um build local — o fallback reconstrói a árvore a partir das
  claims e do epoch registrados; só emite se conseguir provar topologia e
  metadados e reproduzir exatamente `ARTIFACT_HASH`. Qualquer ambiguidade falha
  fechado. A saída declara `INDEX_SIGNED=no`: o publicador precisa conferir a
  attestation, assinar externamente `index` como `index.minisig` e só então
  publicar. O pipeline de release DEVE emitir no mesmo build que produz o
  artefato e conservar o objeto autenticado; reconstrução posterior é fallback
  local/de recuperação, não raiz de publicação de release.
  `bootstrap/channel-from-rootfs` é um migrador separado e explícito para
  registros históricos v1; ele produz apenas canal de desenvolvimento
  `TRUST=builder`.
- O artefato NÃO carrega scripts de pós-instalação (SPEC-0001 §2): é
  árvore passiva, como qualquer tarball.
- No consumo atual, o `.tar.zst` conferido é copiado para um snapshot selado e
  permanece vivo enquanto o tar interno é descompactado para outro `memfd`
  selado. Isso fecha hash→uso, mas faz o pico de RAM aproximar a soma de
  **zst + tar**. Transporte e tar são limitados a 16 GiB cada, mas a quantidade
  de entradas ainda não tem teto próprio. Streaming autenticado e um limite de
  entradas são gates de release para artefatos grandes ou patológicos.

## 5. Resolução: binário de canal vs. fonte

Para `minitrue rectify X` (versão V vem SEMPRE da receita newspeak — o
canal **não** escolhe versão; a árvore versionada é a fonte de verdade):

1. X já instalado em V e `verify` limpo ⇒ no-op.
2. Percorre os canais em ordem de prioridade. O primeiro que ofereça
   `X V <arch>` no índice, cuja assinatura foi conferida e cujo
   `RECIPE_FINGERPRINT` autenticado coincide com a receita efetiva, e cujo
   artefato passe na política de confiança (§6) **vence**: baixa, confere
   sha256, extrai e registra (com a proveniência, §8).
3. Nenhum canal aceitável ⇒ **fallback**: `build()` da fonte, localmente
   (mundo B, SPEC-0004). É o último recurso.

`--offline` restringe ao cache; `--no-binary` força o build de fonte
(para quem quer compilar); `--only-binary` proíbe o fallback (falha se
nenhum canal tiver — útil em máquina sem toolchain). Quando o canal vence, o
plano não expande `BUILD_DEPS` nem dependências de toolchain implícitas: uma
receita fonte `seed`/`cross` conserva Zig no fingerprint autenticado, mas não o
instala se não houver compilação local.

### 5.1 Usuário normal, reprodutor e gerador de mídia

O modo normal e o modo de reprodução partem do **mesmo world e das mesmas
receitas**, mas não produzem necessariamente o mesmo lock de canal. O modo
interno `SourceOnly` (`--from-source`/`--no-binary`) não seleciona artefatos de
canal e, portanto, não deve fingir uma seleção binária nem reutilizar como sua
identidade o lock v2 produzido pelo caminho normal:

- **normal:** instala os artefatos binários fechados por um
  `CHANNEL_LOCK_FORMAT=2`. O instalador
  de release usa semântica `--only-binary` para a base: a falta de um binário
  é erro claro, não o início acidental de horas de compilação;
- **reprodutor (`SourceOnly`, exposto por `--from-source`/`--no-binary`):**
  recompila a partir das
  fontes e receitas pinadas, mede o tar normalizado e compara com
  `REPROCORR` e attestations. Pode então instalar a árvore ou entregá-la ao
  construtor de ISO/IMG;
- **perfil customizado:** pode escolher outro world/overlay e usar binários,
  fontes ou uma combinação declarada. Seu lock, manifesto e hash são novos;
  reprodutível não significa oficial.

Assim, "gerada no computador do usuário" significa sempre que a composição,
o filesystem e a mídia são montados localmente. Só o modo de reprodução
promete também recompilar o mundo B localmente. Uma ISO oficial reproduzida
por hash requer a seleção canônica aplicável ao modo escolhido, o perfil oficial
sem overrides e todos os parâmetros determinísticos do empacotamento
(SPEC-0005/0008/0010); não se atribui um lock de canal a uma execução que não
consumiu canal.

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
  - `corroborado`: a política final aceitará o binário samizdat só se o hash
    **coincidir com o do canal oficial** ou com o de ≥N canais independentes.
    A implementação inicial é mais restritiva: só considera esse canal quando
    a própria receita já pina `REPROCORR`; sem esse pino, ignora a entrada. A
    federação multi-canal ainda não existe.
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
SPEC-0002 §6), uma configuração por arquivo:

```
URL=https://bin.distropica.org/x86_64/
KEY=RW...            # chave minisign do canal
PRIORITY=100
TRUST=oficial        # oficial | corroborado | builder
```

A própria existência de `/etc/minitrue/channels/` é uma decisão
administrativa e vence por inteiro; as duas fontes não são mescladas. Se esse
diretório existir vazio, significa **nenhum canal** e desativa explicitamente
a seed. Somente quando ele estiver ausente um cache offline poderá semear os
mesmos arquivos em `/var/cache/minitrue/channel-config/`. Índice e assinatura
verificados ficam em `/var/cache/minitrue/channels/<nome>/`.

O comando de produção implementado é:

```
minitrue --root ROOT channel emit --output DIR <pacote>...
```

Sua saída declara `CHANNEL_EMIT_FORMAT=2` e contém linhas no formato v2 de
§3. Em release, esse comando integra o job de build; o fallback que reconstrói
um STAGE já instalado serve a desenvolvimento e recuperação.

A gestão `channel add/remove/list/refresh` descrita no desenho ainda não foi
implementada; adicionar ou rotacionar um canal hoje é editar explicitamente o
arquivo e distribuir sua chave por um meio confiável. Também não há um
`00-oficial` publicado neste marco. Antes de release, `channel refresh` precisa
validar a assinatura com a chave já pinada, mostrar um diff auditável da
seleção e só então publicar atomicamente o novo snapshot; rede não pode avançar
o estado silenciosamente.

## 8. Registro e proveniência

O registro de um pacote (SPEC-0003 §6) ganha, no `meta`:

- `ORIGIN=canal:<nome>|fonte` no mundo B — de onde veio o artefato (ou se foi
  compilado localmente); mundo A continua usando `ORIGIN=vendor`;
- `CHANNEL_PATH=` — o caminho autenticado do artefato no índice;
- `CHANNEL_SHA256=` — o hash servido pelo índice (para auditoria);
- `CHANNEL_INDEX_SHA256=` — o índice validado que decidiu a seleção;
- `CHANNEL_LOCK_SHA256=` — o lock imutável que contém a seleção;
- `TRUST=` — a política sob a qual foi aceito.

`archives` mostra a origem; `verify` abre o lock content-addressed, exige
`CHANNEL_LOCK_FORMAT=2`, confere o hash do próprio lock e coteja semanticamente
nome, versão, fingerprint, canal, caminho, trust, hash do artefato, hash do
índice e `reprocorr` com o `meta` e a receita. Ele não confia apenas em campos
homônimos nem consulta um índice de rede que possa ter avançado. Assim o
sistema é auditável: "quais binários vieram de samizdat, e sob que confiança?".

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
- **Não pode** reapresentar para a mesma versão um artefato de outra revisão
  da receita: o fingerprint faz parte do índice assinado e é cotejado antes da
  seleção.
- **Não pode** passar hash divergente do índice assinado sem quebrar a
  assinatura (chave pinada) — nem burlar o sha256 do artefato.
- **Não pode**, num pacote reprodutível, entregar nada além do artefato
  canônico (senão o hash não bate com o `reprocorr` da receita).
- **Pode**, num pacote NÃO reprodutível sob `TRUST=builder`, entregar um
  binário adulterado assinado por ele — é a confiança inerente a qualquer
  canal binário, e por isso `builder` é opt-in gritante e a
  reprodutibilidade é o caminho recomendado.

## 10. Relação com a premissa e o mundo A

Um artefato aceito de canal é o "binário disponível" para o mundo B: uma vez
que existe para o snapshot escolhido, P2 manda preferi-lo à fonte no modo
normal. Não fere P1 (não é gerenciador de pacotes externo; é o próprio
`minitrue` consumindo um tarball assinado) nem
P6 (tudo pinado). O metapacote `miniplenty-buildbase` (SPEC-0008 §4.2) é
resolvido localmente: por ser `KIND=meta`, não tem payload nem artefato de
canal. Sob `--only-binary`, porém, cada dependência `KIND=source` de sua closure
de runtime DEVE ser satisfeita por um artefato aceitável do canal. É isso que
impede compilar localmente `base`, Make ou a toolchain durante a instalação;
`base` continua sendo uma receita de montagem com payload de configuração, não
um meta.

Ordem de preferência de um artefato, do mais ao menos preferido:
1. binário oficial do **upstream** (mundo A: firefox, zig…);
2. binário do **canal oficial** da Distrópica (mundo B pré-buildado);
3. binário de **canal samizdat** (conforme política de confiança);
4. **compilação de fonte** local (último recurso).

## 11. Não-objetivos e questões em aberto

- Protocolo de repositório sofisticado (deltas, resolução de versões
  múltiplas): fora — o índice é uma lista assinada, e a árvore newspeak num
  commit é o conjunto consistente (SPEC-0001 P1).
- **Reprodutibilidade completa da base:** m4, gmp, gcc e glibc reproduziram
  entre dois builds nas receitas e artefatos históricos então medidos. A
  receita atual de `gcc-pass2` com `install-strip`, a closure inteira e o kernel
  ainda não possuem a nova prova independente necessária para um canal oficial
  corroborado.
- Mirrors do canal oficial (mesma chave, URLs alternativas): trivial de
  acomodar (vários arquivos de canal com a mesma `KEY`); formalizar.
- Assinatura do índice: minisign no v0; OpenPGP quando a verificação PGP
  chegar (SPEC-0004 §5).
- Federação/descoberta de samizdats confiáveis (uma "lista de listas"
  assinada pelo projeto): tentador, mas reintroduz confiança central —
  decidir se vale.
- CLI administrativa de canais, vínculo do lock de canal ao lock de perfil,
  anti-replay/monotonicidade do índice e publicação do canal oficial.
