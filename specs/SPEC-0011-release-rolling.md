# SPEC-0011 — Modelo de release: rolling edge

**Status:** rascunho v0.4 · 2026-07-23
**Palavras-chave normativas:** DEVE / NÃO DEVE / DEVERIA / PODE (RFC 2119).
**Depende de:** SPEC-0001 (premissas, P1/P2/P7), SPEC-0003 (minitrue, `--sync`,
registro), SPEC-0008 (kernel, boot A/B), SPEC-0009 (canais), SPEC-0010
(reprodutibilidade).
**Complementado por:** SPEC-0013 (plano congelado, closure tipada e coleta de
órfãos).

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

O protocolo concreto usa a seed pinada
`/var/cache/minitrue/newspeak-origem`, com `URL=` para um diretório HTTPS e
`KEY=` para a chave pública minisign. Sob essa URL vivem `newspeak.tar` e
`newspeak.tar.minisig`. O perfil oficial semeia
`URL=https://distropica.com.br/newspeak/` e a mesma chave pública oficial já
pinada para o canal; a URL não é descoberta nem substituída pela rede. A cadeia
do produtor reutiliza as ferramentas próprias que já empacotam e assinam sem
depender do host:

```sh
minitrue pack newspeak newspeak.tar
gestor-de-segredos ... | \
  minitrue channel sign --passphrase-fd 0 <chave-secreta> newspeak.tar \
    <chave-pública-esperada>
```

O segundo comando cria `newspeak.tar.minisig` e verifica imediatamente a
assinatura com o mesmo consumidor usado no alvo. A passphrase não atravessa
argumento, ambiente ou arquivo da árvore publicável: chega pelo pipe já aberto,
é limitada e seu buffer no signer é apagado ao sair. Chaves sem senha continuam
aceitas sem `--passphrase-fd`. Ao materializar, o cliente
normaliza os modos pela mesma política do Minipax (diretórios e executáveis
`0755`, demais regulares `0644`), para o fingerprint da árvore atualizada ser
o mesmo da árvore congelada na mídia mesmo quando o checkout do produtor veio
de um `umask` diferente.

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

A resolução que antecede essa convergência deve ser o plano único e tipado da
SPEC-0013 §7: o preview e a aplicação compartilham algoritmo e plan lock;
build-deps inativas não entram na closure runtime; órfãos são apenas apontados.

## 4. Detecção de mudança e o fingerprint de build

Rolar exige saber o que mudou entre a árvore antiga e a nova. Hoje o registro
compara `VERSION` (SPEC-0003 §6): versão diferente ⇒ retifica. Cobre o caso
comum do edge (quase todo roll é um bump de versão).

O que faltava: a receita que muda **sem** bumpar versão (novo conserto, novo
toolchain, nova dependência) não disparava rebuild. É o **fingerprint de
build** — uma identidade que resume a receita.

**Implementado (v1, 2026-07-20).** O registro guarda `FINGERPRINT=` (sha256 do
arquivo `recipe` inteiro — que carrega VERSION, SRC, LICENSE, TOOLCHAIN, DEPS,
BUILD_DEPS e o corpo de `build()` — mais o `files/`, via o `pack`
determinístico da SPEC-0010). A idempotência do `rectify` compara **versão E
fingerprint**: receita corrigida com a mesma versão ⇒ fingerprint diferente ⇒
re-builda. Consertado o "GCC 15.3.0 mudou várias vezes sem bump" que o modelo
só-`VERSION` ignorava.

**Transitivo (2026-07-22).** O fingerprint de build é o `own_fingerprint` da
receita (arquivo + `files/`) **combinado com os fingerprints das suas
`DEPS`+`BUILD_DEPS` e das dependências de toolchain implícitas**, recursivamente
(memoizado, robusto a ciclo). Em receitas fonte `TOOLCHAIN=seed|cross`, a
identidade de Zig entra mesmo sem `BUILD_DEPS=zig`. Então uma mudança no
`binutils` propaga para o `gcc`, e mudar a semente propaga a todos os pacotes
afetados. O plano só instala Zig quando escolhe compilação local; um artefato de
canal conserva a mesma identidade sem expandir dependências de build.
Consertado o limite não-transitivo. (Mudar o algoritmo invalida os fingerprints
antigos ⇒ um `rectify` seguinte re-builda a árvore uma vez — comportamento
correto de uma troca de esquema.)

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
| `rectify newspeak` (árvore-como-pacote) | **implementado e coberto por testes unitários** (§3.1); falta E2E contra a publicação oficial |
| `rectify --sync` | speced, *stubbed* (SPEC-0003) |
| Fingerprint de build | **implementado, transitivo** (§4) |
| Rollback de mundo B | **lacuna** (§5.1) |
| Canal binário: consumo, lock v2 e emissão | **implementação inicial pronta** (SPEC-0009) |
| `channel refresh` autenticado + diff auditável | **implementado e coberto por teste unitário** |
| Republicação automática a cada roll | especificada, não implementada |

Com o fingerprint transitivo, o protocolo binário inicial e a
**árvore-como-pacote** feitos, restam **rollback de mundo B** (a rede) —
exclusivamente rolling — e a automação que recompõe, assina e publica árvore e
canal a cada roll. O consumidor online já busca e valida o índice corrente pela
chave pinada, de modo que pacotes posteriores à mídia ficam alcançáveis;
`channel refresh` permite apresentar o diff e avançar sem instalar; o consumo
durante `rectify` continua sendo uma mutação explícita distinta: autentica e
pode persistir o snapshot operacional preso na própria seleção/lock. Não há
avanço em background.
Endpoint, chave, índice e pool oficiais já estão publicados,
mas ainda precisam ser reemitidos em cada roll pela automação descrita acima.

## 7.1 Exigência de publicação: conferir a versão de TODO software empacotado

**Antes de publicar qualquer mídia, a árvore inteira é conferida contra o
upstream de cada componente.** Não é recomendação nem etapa opcional do
checklist: uma mídia cuja árvore não foi conferida não está pronta para
publicar, do mesmo jeito que uma sem bundle de fontes correspondente não está.

### Por que isto virou exigência escrita

A P7 (SPEC-0001) já mandava pinar o estável mais recente. Ela foi violada em
silêncio: a **0.12 foi publicada com o kernel 7.1.4 enquanto o kernel.org já
publicava o 7.1.8**, e nada na árvore acusou — nem receita, nem aceite, nem o
`channel emit`. A premissa existia, a mídia saiu contra ela, e a violação só
apareceu porque um humano perguntou.

Uma premissa sem verificação é uma intenção. O que separa as duas é isto:

- a receita pina a versão, e nada nela sabe que existe uma versão mais nova;
- os aceites provam que a mídia INSTALA, e nunca que ela está ATUAL;
- o `channel emit` audita o FECHAMENTO das dependências, não a idade delas.

Nenhum dos três guardas existentes olha para fora da árvore. Este olha.

### O que a conferência precisa produzir

Para cada receita da `newspeak/`, uma linha com: a versão pinada, a versão
estável mais nova do upstream, e o veredito. Três desfechos, e os três precisam
aparecer:

- **atual** — pinado é igual ao estável mais novo;
- **atrasado** — há estável mais novo; exige subir, ou registrar a ressalva
  pragmática da P7 (regressão comprovada) no arquivo irmão
  `newspeak/<pacote>/versao-pinada`, com motivo e data;
- **não conferido** — o upstream não publica um índice legível. Esta é a
  categoria perigosa: ela precisa ser **listada por nome**, e não somada num
  total. Um relatório que diz "112 de 120 conferidos" e cala sobre os oito faz
  parecer conferido o que não foi.

### A ressalva pragmática continua valendo

A P7 permite pinar versão anterior quando o estável-mais-novo regride —
precedente do gawk 5.3.2. O que a exigência acrescenta é que essa decisão passa
a ser **explícita e datada ao lado da receita**, em `versao-pinada`, e não a
consequência de ninguém ter olhado. O arquivo separado evita mudar o fingerprint
e recompilar payloads só por atualizar uma justificativa de governança.
"Atrasado sem motivo registrado" e "pinado por regressão" deixam de ser
indistinguíveis.

## 8. Conjunto publicável e fontes correspondentes

O repositório da Distrópica é `GPL-3.0-or-later` para seu conteúdo próprio,
mas uma mídia é um agregado de componentes sob licenças distintas. Publicar
uma ISO, EFI, cache ou canal NÃO consiste apenas em publicar o binário e o
commit que o descreve. Cada artefato oficial DEVE oferecer acesso equivalente
a um bundle de fontes correspondente e associado pelo hash do artefato.

O bundle DEVE conter a revisão exata da Distrópica, `Cargo.lock` e crates
vendorizadas dos executores estáticos, fontes upstream exatas, configurações,
patches, scripts de compilação/instalação, textos de licença e inventário
legível por máquina. Para Linux e BusyBox, inclui expressamente a fonte e a
configuração usadas. URLs e hashes das receitas são rastreabilidade, não uma
garantia durável de disponibilidade por parte do redistribuidor.

A mídia viva e o sistema instalado DEVEM carregar a GPL da Distrópica em
`/usr/share/licenses/distropica/GPL-3.0-or-later.txt` e a concessão
`GPL-3.0-or-later` em `NOTICE`. Licenças e avisos de terceiros também DEVEM ser
materializados antes de uma release oficial. A publicação do
repositório-fonte, sem artefato binário oficial, não promove o perfil
`development` a release.

O `LICENSE=` congelado no registro é uma entrada declarativa para esse
inventário, não substitui o inventário por artefato, os textos e avisos
upstream nem a análise das combinações efetivamente distribuídas.
`NOASSERTION` conserva explicitamente essa pendência e não libera o artefato
para publicação oficial.

O gate executável de publicação é `bootstrap/source-bundle --artifact ARQ
--output DIR --cache CACHE --minitrue-root ROOT --minitrue-bin
MINITRUE_PRODUTOR --strict`, seguido de
`bootstrap/sbom --bundle DIR --strict`. O primeiro recalcula o SHA-256 antes e
depois de promover cada objeto content-addressed e recusa fonte ausente,
divergente ou `LICENSE=NOASSERTION`; o segundo recusa qualquer pacote que
permaneça `SEM EVIDÊNCIA`. Para ISO/IMG, `--media ARQ --live-kernel-config CONFIG
--live-util-linux-tar TAR` é a forma legada compatível; o modo estrito recusa a
falta da configuração do kernel vivo ou da fonte exata do util-linux que o
`build-efi` compila em `cfdisk`/`sfdisk`. O bundle do EFI usa a forma genérica
`--artifact BOOTX64.EFI` com esses mesmos dois argumentos. O script lê
`UTIL_LINUX_VERSION`, `UTIL_LINUX_URL` e `UTIL_LINUX_SHA256` diretamente dos
pinos do `bootstrap/live/build-efi`, confere o tar e o registra como
`insumo-live`; não existe receita Newspeak artificial para encobrir esse insumo.
Para um canal, `ARQ` é `index` diretamente na saída de `channel emit
--release`: o `emit.meta` v4 irmão com `RELEASE_ROOT=yes` prende a raiz local,
o `PLAN_LOCK` produtor e os bytes por `PRODUCER_PLAN_LOCK_SHA256` e
`INDEX_SHA256`. O inventário deriva
das linhas desse próprio índice, nunca do cache reduzido da mídia; seu hash
vincula o bundle ao conjunto exato, e cada linha vincula por SHA-256 o
respectivo objeto de `pool/`. A assinatura do índice continua
obrigatória antes da publicação. O modo sem `--strict` pode produzir
diagnóstico incompleto durante o desenvolvimento, mas NÃO satisfaz o gate desta
seção. `MINITRUE_PRODUTOR` é o executável exato que calculou os fingerprints e
produziu os registros; o bundle registra seu SHA-256 e, quando o perfil está em
`STATUS=release`, o modo estrito exige que ele coincida com
`OFFICIAL_MINITRUE_SHA256`.

`bootstrap/sbom --strict` transforma a evidência desse bundle em um payload
determinístico preparatório: cria `licenses.tar` e `licenses.tar.sha256` ao lado do
diretório `licencas/`. Dentro do tar, `PACOTES` é a projeção canônica e sem
duplicatas das quatro primeiras colunas do `INVENTARIO` daquele bundle;
`INDICE` precisa cobrir exatamente esses pacotes e exatamente cada arquivo de
evidência por hash; `MANIFEST.sha256` cobre todo regular restante. Essa
projeção impede ampliação para um catálogo global ou `BUILD_DEPS`, mas ainda é
uma afirmação do próprio bundle: sozinha não prova que suas identidades
correspondem ao plano realmente distribuído.

O tar é emitido em ordem de bytes, com formato GNU, uid/gid/mtime zero, modos
`0755` para diretórios e `0644` para regulares. O consumidor recusa caminho
não UTF-8 ou não canônico, link/hardlink/tipo especial, entrada ausente ou
extra, manifesto divergente, arquivo acima de 32 MiB, tar/conteúdo acima de
128 MiB ou mais de 20.000 entradas. O parser interno abre o arquivo e cada
componente de seu caminho por descritor com `NOFOLLOW`, revalida
inode/metadados depois da leitura e possui um instalador fd-relative
experimental. GPL, NOTICE e este documento do próprio projeto já viajam no
pacote `base` e no ambiente vivo sob `/usr/share/licenses/distropica/`.

`PLAN_LOCK_FORMAT=1` já expõe, para cada identidade material, nome, versão,
kind/mundo, fingerprint transitivo, hash do payload, `LICENSE`, `MATERIAL_ID` e
`PROVENANCE_SHA256`, distinguindo runtime/cache-only/identity-only. O núcleo
também possui parser/import tipado de `LIVE_COMPONENTS`,
`LIVE_RUNNER_PROOF` e `LIVE_LOCK` para `PURPOSE=media` strict, ancorado por
hashes esperados externos. A integração produtiva no profile/Minipax e a API
de consumo de um plan lock externo verificado ainda não existem; tampouco está
fechada a aplicação de um plano de mídia sobre target vazio sem nova resolução
online. Assim, a comparação de `PACOTES`, `LICENSES_SHA256` e o bump do
`profile.lock` permanecem bloqueados: autoconsistência continua sendo evidência
preparatória, não gate de release.

O comando de gate do EFI é, concretamente:

```sh
bootstrap/source-bundle --artifact "$EFI" --output "$EFI_SOURCES" \
  --cache "$CACHE" --minitrue-root "$ROOT" --minitrue-bin "$MINITRUE_BIN" \
  --live-kernel-config "$EFI_WORK/linux-source/.config" \
  --live-util-linux-tar "$UTIL_LINUX_TAR" --strict
bootstrap/sbom --bundle "$EFI_SOURCES" --strict
```

Para o canal, a origem binária do gate é `minitrue --root ROOT channel emit
--release --output DIR <pacotes...>`. Esse modo exige os tars selados retidos
atomicamente durante os próprios builds locais e grava `RELEASE_ROOT=yes` em
`emit.meta`, junto de `INDEX_SHA256`; a emissão comum com reconstrução grava
`RELEASE_ROOT=no` e não é publicável como release.

## 9. Questões em aberto

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
