# SPEC-0003 — minitrue, a ferramenta

**Status:** rascunho v0.9 · 2026-07-22
**Depende de:** SPEC-0001 (política), SPEC-0002 (layout), SPEC-0004 (receitas).

## 1. Identidade

`minitrue` é um binário único, **estático** (Rust, alvo
`x86_64-unknown-linux-musl`), sem daemon, sem estado fora de
`/var/lib/minitrue`, `/var/cache/minitrue` e dos caminhos que instala. Roda
em qualquer Linux x86_64 — inclusive no rootfs nu do Estágio 0, onde não há
libc instalada.

O núcleo voltado ao usuário faz quatro coisas: **busca, verifica, registra,
apaga**. O binário ainda abriga operações de mantenedor (`pack` e `attest`)
enquanto a fronteira Miniplenty não ganha um executável próprio (SPEC-0012).
O que ele não é: solver, protocolo sofisticado de repositório, banco de dados
opaco ou init. A orquestração pertence ao minitrue; build e extração são
delegados a `sh` e `tar` (busybox).

## 2. Interface de linha de comando

```
minitrue rectify   <pacote>…      instala/atualiza; acrescenta ao world (§2)
minitrue rectify   --sync         converge o sistema ao world inteiro (§2)
minitrue channel emit --output DIR <pkg>…
                                  mantenedor: emite pool + índice de canal
                                  não assinado (SPEC-0009 §4)
minitrue cache verify <pacote>…   confere artefatos e assinaturas já presentes,
                                  sem rede, instalação ou alteração do world
minitrue rollback  <pacote> [<v>] mundo A: volta o current à versão retida (§5)
minitrue unperson  <pacote>…      mundo A: some dos registros, fica em /opt (§5)
minitrue memoryhole <pacote>…     remove do sistema e do world; --orfaos:
                                  remove os órfãos apontados pelo --sync
minitrue archives  [padrão]       lista registros; marca não-pessoas e órfãos
minitrue verify    [<pacote>…]    confere registros contra o filesystem e
                                  varre /usr por links órfãos (§5)
minitrue newspeak  <pacote>       imprime a receita efetiva e sua origem
minitrue explain   <caminho>      de quem é o arquivo e toda a sua proveniência (§6)
minitrue why       <pacote>       por que este pacote está no sistema (§6)
minitrue lint      [<árvore>]     valida a árvore newspeak (SPEC-0004 §6)
minitrue channel   <sub>          add|remove|list|refresh de canais (norma futura;
                                  a configuração atual é por arquivos, SPEC-0009 §7)
minitrue pack      <dir> [saída]  tar normalizado determinístico + sha256 (SPEC-0010 §4)
minitrue attest keygen <nome> <chave> gera chave ed25519 de builder (SPEC-0009 §8.1)
minitrue attest <pkg> <builder> <chave> emite attestation assinada
minitrue corroborate <pkg>        confere attestations contra a identidade instalada
```

Esta é a interface normativa. No protótipo atual estão implementados
`rectify <pkg>`, `memoryhole`, `archives`, `verify`, `newspeak`, `explain`,
`why`, `pack`, `attest`, `corroborate`, `cache verify`, o consumo de canais
assinados e `channel emit`; `--sync`, rollback, `unperson`, `lint`, a CLI de gestão
`channel add|remove|list|refresh` e as variantes de remoção/varredura acima
continuam no Marco 0.2 (ver `STATUS.md`).

Opções globais:

| Opção | Efeito |
|-------|--------|
| `--root <dir>` | opera sobre outro rootfs (Estágio 0 popula o chroot assim); env `MINITRUE_ROOT` |
| `--jobs N` | paralelismo passado aos builds (`$JOBS`); default: nproc |
| `--offline` | proíbe rede; só aceita artefato já presente no cache |
| `--no-binary` / `--only-binary` | força build de fonte / exige artefato aceitável de canal e proíbe fallback de fonte (SPEC-0009 §5); ambas implementadas e mutuamente exclusivas |
| `NEWSPEAK_PATH` (env ou `conf`) | árvores de receitas separadas por `:`, em ordem de precedência — a primeira ocorrência do pacote vence (herança `KISS_PATH`); default `/var/lib/minitrue/newspeak` |
| `--tofu` | permite receita sem `SHA256`: baixa, calcula, imprime a linha `SHA256=…` pronta para colar, instala com aviso gritante. Se a receita pina `SIGKEY`, a assinatura continua obrigatória mesmo em TOFU — é o que torna a repinagem de versão segura. NÃO DEVE existir em builds de release da ferramenta destinados a usuários finais. É a única exceção a P6, e reconciliada lá: o TOFU **cria** o pino (aid de autoria), não o dispensa — SPEC-0001 P6 |

### Canais binários — contrato implementado

O consumidor atual lê configurações estritas sob `/etc/minitrue/channels/` ou,
quando esse diretório administrativo não existe, a semente em
`/var/cache/minitrue/channel-config/`. A existência do diretório
administrativo é autoritativa: vazio, ele desativa todos os canais sem
reativar silenciosamente a semente. Cada configuração prende URL HTTPS, chave
minisign, prioridade e confiança.

O índice canônico **v2** assinado autentica, por linha,
`NAME VERSION ARCH RECIPE_FINGERPRINT PATH SHA256 [REPROCORR]`. A seleção só
aceita versão, arquitetura e fingerprint iguais à receita efetiva, verifica a
assinatura também em cache-hit/offline, baixa o `.tar.zst` pelo hash de
transporte e valida limites, topologia e hash do tar interno antes de qualquer
aplicação. A escolha fica congelada num `CHANNEL_LOCK_FORMAT=2`, endereçado por
hash sob `/var/lib/minitrue/channel-locks/`; o registro conserva caminho,
hashes e confiança, e `verify` coteja esses campos semanticamente com o lock.

`channel emit` produz artefatos, índice v2 e `emit.meta` com
`CHANNEL_EMIT_FORMAT=2`, mas **não assina nem publica**. Para registros vindos
de canal, reutiliza o tar autenticado do cache; para registros locais, só
reconstrói quando consegue provar topologia, metadados e `ARTIFACT_HASH`, e
falha fechado na ambiguidade. Um release DEVE emitir junto do build, assinar o
índice externamente e conservar o artefato autenticado. O projeto ainda não
publicou URL, chave, índice nem pool de um canal oficial. Metapacotes não têm
payload nem `ARTIFACT_HASH` e, portanto, são recusados por `channel emit`: o
canal publica os pacotes fonte pré-buildados que eles agregam, nunca o nó
declarativo.

### Disponibilidade verificável do cache

`cache verify <pacote>…` carrega as receitas efetivas e exige que todos os
artefatos pinados já existam em `/var/cache/minitrue` com SHA-256 correto. Se a
receita declara `SIG`, a assinatura destacada também precisa estar presente e
ser válida contra `SIGKEY`. A operação impõe internamente o contexto offline e
desativa TOFU: nunca baixa, instala, cria registro, links ou entrada no
`world`. Pacote ou receita ausente e falha criptográfica continuam seguindo os
códigos de erro normais (§9).

O Minipax usa esse comando para cumprir o `cache.world` de um perfil offline
(SPEC-0008): `cache.world` é promessa de **disponibilidade autenticada**, não
uma segunda lista de pacotes a instalar.

### O arquivo `world` (`/etc/minitrue/world`)

A intenção do administrador, um pacote por linha (`#` comenta): o conjunto
dos pacotes **explicitamente desejados** — só top-level, nunca
dependências. Herança direta do `/etc/apk/world` do Alpine.

- `rectify <pacote>` acrescenta ao world; `memoryhole <pacote>` retira.
- `rectify --sync` converge o sistema à intenção: instala o que falta
  (world + dependências) e **aponta** órfãos — instalados sem constar no
  world nem ser dependência de quem consta. Órfão NUNCA é removido
  automaticamente; `memoryhole --orfaos` remove sob ordem explícita.
- `unperson` não altera o world: a intenção permanece, o corpo está lá.
- Reinstalar uma máquina = `minipax install --profile <perfil> --newspeak
  <árvore> --world <arquivo> --target <raiz>` (SPEC-0008).
- A dualidade que organiza a ferramenta: **o registro é o fato; o world é
  a intenção.** `verify` confere fatos; `--sync` reconcilia a intenção.
- Dependências de runtime, de build e de toolchain instaladas para satisfazer
  outro pacote não entram no `world`. Assim, Zig materializado automaticamente
  para compilar uma receita `seed`/`cross` permanece fora da intenção, a menos
  que tenha sido pedido explicitamente.
- Um `KIND=meta` pedido explicitamente, como `miniplenty-buildbase`, entra no
  `world`; sua retificação não acrescenta os componentes ao `world` (eles só
  aparecem ali se também forem pedidos separadamente). Remover o meta retira
  essa intenção sem apagar implicitamente os componentes.

## 3. Fluxo de `rectify`

1. **Carregar receita** (SPEC-0004): congela um snapshot do arquivo `recipe` e
   de `files/`, avalia o top-level por `sh` e lê os campos de volta. O mesmo
   snapshot de `recipe` é executado/registrado e o mesmo `files/` é
   materializado no `WORK`; edição concorrente da árvore não troca insumos no
   meio da operação. Receita inválida ⇒ erro 2. A avaliação top-level ainda
   ocorre no host (§8).
2. **Pré-condições**: `REQUIRES_GLIBC=1` e ausência de
   `/usr/lib/ld-linux-x86-64.so.2` ⇒ erro 5 com mensagem indicando o
   Estágio 2 (SPEC-0005).
3. **Dependências**: resolução por busca em profundidade com detecção de ciclo;
   instala o que falta, na ordem. Sem comparação de versões — a árvore
   newspeak em um commit é o conjunto consistente. Um `KIND=meta` **sempre
   expande suas `DEPS`**, inclusive quando o próprio registro já está íntegro;
   ele não consulta canal, não é barrado por `--only-binary` e não acrescenta
   dependências de build. A política binária continua valendo normalmente para
   cada dependência agregada. Para uma receita mundo B, a seleção de canal
   ocorre antes de expandir dependências de build: se um artefato é escolhido,
   apenas as `DEPS` de runtime entram no plano. Quando o pacote é realmente
   compilado (`--no-binary` ou fallback de fonte), o plano expande
   `BUILD_DEPS` e também a dependência de toolchain implícita em `zig` para
   `TOOLCHAIN=seed|cross`. Receitas `TOOLCHAIN=none|native`, `KIND=binary` e
   `KIND=meta` não ganham essa aresta. Declaração explícita duplicada de Zig é
   deduplicada.
4. **Fetch**: para cada URL de `SRC`, baixar para
   `/var/cache/minitrue/<sha256>` (nome do arquivo no cache = hash
   esperado). Se já existe com hash válido, rede não é tocada.
   Idempotência atual: pacote já na versão e no fingerprint da receita, com
   meta/snapshots coerentes e todas as provas tipadas do manifesto íntegras ⇒
   no-op ("os registros já estão corretos"). Em provisionals,
   `manifest@<versão>` é o baseline e o manifesto ativo pode ser um subconjunto
   após cessões comprovadas (§6). O fast path faz essa conferência local;
   `verify` continua sendo a varredura explícita do sistema.
5. **Verificação**: (a) SHA-256 do artefato ≠ pinado ⇒ apagar o download,
   erro 3, mensagem *crimestop* com esperado/obtido. Sem flag de contorno.
   (b) Se a receita pina assinatura por artefato (`SIG`, SPEC-0004 §5), ela é
   conferida como minisign/signify contra a chave versionada na árvore, com
   verificador embutido — nunca chamando gpg externo. O cache da assinatura é
   ligado ao hash do artefato, chave e URL e é revalidado em cache-hit; sob
   `--offline`, precisa estar presente. Falha ⇒ erro 7. `SIGSUMS` e OpenPGP são
   norma do Marco 0.2 e hoje falham explicitamente como não implementados.
6. **Instalação**:
   - **Mundo A** (`KIND=binary`): executa `install_pkg()` da receita com
     `PREFIX=/opt/<nome>/<versão>.tmp`; sucesso ⇒ rename atômico para
     `/opt/<nome>/<versão>`, flip do symlink `current`, criação dos links
     de comando (`LINKS`) em `/usr/bin`.
   - **Mundo B** (`KIND=source`): antes de compilar consulta os canais binários
     (SPEC-0009) por um artefato da identidade exata da receita. Havendo um
     aceitável, instala-o **como mundo B pré-buildado** — tarball passivo já
     autenticado, layout em `/usr`, `/etc`→factory, manifesto plano e
     `WORLD=B`, **não** em `/opt` — e não executa `build()`. `--only-binary`
     torna a ausência desse artefato um erro; `--no-binary` pula a consulta.
     Sem seleção de canal, o fluxo executa `build()` com `STAGE=` (DESTDIR) em
     diretório temporário; sucesso ⇒ checagem de colisão (§7) ⇒ cópia
     para `/`; se já havia versão anterior, caminhos órfãos do manifesto
     antigo são removidos após a cópia (upgrade = instalar novo + varrer
     sobras). Conteúdo de `etc/` no staging **não vai para `/etc`**: é
     desviado para `/usr/share/factory/etc/` e materializado pela política
     do administrador (SPEC-0002 §6) — copia se ausente; se existir
     modificado, grava `<arquivo>.new` ao lado e avisa; o hash do default
     pristine entra no registro (§6). Depois do build, o STAGE é empacotado
     diretamente num `memfd` selado; `ARTIFACT_HASH` e aplicação consomem essa
     mesma imagem imutável por offsets, sem uma extração gravável intermediária.
     Uma receita pode carregar simultaneamente defaults em `etc/` e dados
     estáticos em `usr/share/`: a convergência estrutural causada pelo desvio
     para a fábrica é aceita apenas nos diretórios não vazios `usr/` e
     `usr/share/`. Não se estende a `usr/share/factory`, a aliases usr-merge nem
     a diretórios vazios reivindicáveis. STAGE vazio, hardlinks, nomes não-UTF-8
     e tipos especiais são recusados.
   - **Mundo M** (`KIND=meta`): não faz fetch, não seleciona canal, não executa
     função e não aplica payload. Depois de retificar todas as `DEPS`, grava
     somente o registro declarativo v2 com manifesto vazio canônico (§6).
7. **Registro**: grava `/var/lib/minitrue/records/<nome>/{meta,manifest,recipe}` (§6);
   nomes pedidos explicitamente na linha de comando entram no `world` (§2).
8. **Falha de build**: log integral movido para
   `/var/log/room101/<nome>-<versão>.log`; staging descartado; nada é
   tocado no sistema real. Mensagem cita o caminho do log.

## 4. Fluxo de `memoryhole`

1. Recuperar primeiro eventual journal órfão do pacote e ler o manifesto em
   modo estrito; formato futuro, arquivo ausente, corpo de zero bytes ou tag
   desconhecida fazem a remoção falhar fechado. Há duas exceções tipadas para
   um manifesto canônico sem claims (`"\n"`): a combinação `KIND=meta`,
   `WORLD=M`, `ORIGIN=meta`; e um registro `PROVISIONAL=1` que já cedeu todas
   as claims, mantendo `manifest@VERSION` como baseline versionado. Remover na
   ordem inversa: links de comando, claims sob
   `/opt/<nome>` (mundo A) ou cada caminho listado (mundo B). Diretório vazio
   de mundo B sai somente por `rmdir`; pais não reivindicados não são podados.
2. Preservados por padrão: `/etc/opt/<nome>`, `/var/opt/<nome>` e qualquer
   caminho cuja prova de conteúdo/tipo/alvo diferir do manifesto (§6) —
   modificado pelo usuário ⇒ fica, com aviso. É a prova tipada do registro v2
   que torna essa promessa **enforçável** (sem ela, não há como saber o que o
   usuário mexeu). `--tudo` remove também esses.
3. Registro apagado por último. No mundo M, isso e a retirada do `world` são
   toda a remoção: suas `DEPS` ficam instaladas e podem passar a órfãs, mas não
   são apagadas sem ordem. Saída: `"<nome> nunca existiu."`
4. Pacote requerido por outro registro (`DEPS` reversa) ⇒ recusa com a
   lista de dependentes; isso impede remover um componente enquanto um meta o
   sustenta. `--force-orfaos` não existe no v0.

## 5. Rollback, unperson e órfãos (herança GoboLinux, mundo A)

Com versões lado a lado em `/opt`, ativar e desativar são operações de
symlink — o flip do `Current` do GoboLinux, aqui confinado ao mundo A:

- **`rollback <pacote> [<versão>]`** — flipa `/opt/<nome>/current` para a
  versão anterior retida (ou a indicada), refaz os links de comando
  conforme a receita **daquela** versão e atualiza o registro. Não toca na
  rede. Versão não retida ⇒ erro com a lista do que há.
- **`unperson <pacote>`** — remove os links de `/usr` e marca o registro
  como inativo, **mantendo** `/opt/<nome>` intacto. O pacote vira
  não-pessoa: existe fisicamente, mas nenhum registro visível aponta para
  ele. `rectify` reativa (sem rede, se a versão retida é a da receita);
  com a árvore já avançada, a reativação segue a receita corrente
  (baixando se preciso) e avisa a divergência. `archives` lista
  não-pessoas com a marca `unperson`.
- **Varredura de órfãos** — `verify` também confere a direção inversa dos
  manifestos: links em `/usr` apontando para dentro de `/opt` sem dono em
  manifesto algum (sobras de mexida manual) são listados como *wrongthink*,
  com sugestão de remoção. Nada é apagado sem ordem.
- Ambos os comandos recusam pacotes dos mundos B e M com explicação: no
  primeiro, os arquivos em `/usr` **são** a instalação; no segundo, não há
  payload nem versão retida para flipar.

**Política de retenção** (resolve a questão aberta da SPEC-0002):
`rectify` retém a versão anterior ao atualizar (corrente + 1); mais velhas
são removidas no upgrade. `memoryhole` remove tudo. Ajustável via
`KEEP_VERSIONS` em `/etc/minitrue/conf`.

## 6. O registro (`/var/lib/minitrue/records/<nome>/`)

Três papéis, persistidos em cinco folhas (`meta`, `manifest`,
`manifest@<versão>`, `recipe`, `recipe@<versão>`):

- `meta` — `RECORD_FORMAT=`, `NAME=`, `VERSION=`, `KIND=`, `WORLD=A|B|M`,
  `ORIGIN=`, `SHA256=` (por artefato), `DEPS=`, `SUPERSEDES=`, `FINGERPRINT=`,
  `ABOUT=`, `LICENSE=` (somente mundos A/B), `REPROCORR=`,
  `ARTIFACT_HASH=` (mundo B),
  `MANIFEST_BASELINE_SHA256=`, `INSTALLED_AT=` (ISO-8601) e
  `TRANSACTION_ID=` (mundo B). `ABOUT`, `LICENSE` e o pino `REPROCORR` são
  congelados no momento da instalação: inspeção posterior não precisa executar
  a receita histórica. O **`RECORD_FORMAT`** versiona o
  esquema do registro (hoje `2`), para migração e leitura consciente. O
  **`ORIGIN`** é de onde veio o artefato ou a declaração — `vendor` (mundo
  A), `fonte` (mundo B compilado localmente), `canal:<nome>` quando os canais
  (SPEC-0009 §8) o instalam, caso em que `TRUST=`, `CHANNEL_PATH=`,
  `CHANNEL_SHA256=`, `CHANNEL_INDEX_SHA256=` e `CHANNEL_LOCK_SHA256=` também
  entram, ou `meta` (mundo M local, sem campos de canal).
  O **`FINGERPRINT`** é a identidade de build (SPEC-0011 §4): sha256 do
  arquivo `recipe` inteiro + do `files/` (via o `pack` determinístico),
  **combinado transitivamente com o fingerprint das `DEPS`+`BUILD_DEPS` e da
  dependência de toolchain implícita** (`zig` em receitas fonte `seed`/`cross`). A
  idempotência do `rectify` compara **versão E fingerprint** — uma receita
  corrigida com a mesma versão muda o fingerprint e re-builda (conserta o
  "GCC 15.3.0 mudou várias vezes sem bump"), e uma mudança num build-dep ou na
  receita Zig propaga para os dependentes afetados (transitivo). A identidade
  inclui essa aresta mesmo quando um canal atende a instalação; o plano de
  instalação, porém, só materializa Zig quando haverá compilação local.
  O fast path exige ainda registro v2 íntegro: `recipe` e `recipe@<versão>`
  precisam coincidir byte a byte com o snapshot corrente e todas as provas do
  manifesto precisam conferir no filesystem. Em pacote comum,
  `manifest@<versão>` coincide com `manifest`; em provisional, a cópia
  versionada é o baseline imutável e o ativo pode conter apenas um subconjunto
  de linhas byte-idênticas após cessões.

  `LICENSE` é uma extensão aditiva de `RECORD_FORMAT=2`: registros A/B novos
  sempre o gravam e registros M sempre o omitem. Num v2 anterior sem o campo,
  a leitura aceita apenas uma atribuição única, literal, não vazia e inequívoca
  no snapshot `recipe`, aberto sem seguir symlink e sem executar shell.
  Expansão, substituição de comando, duplicidade ou forma ambígua não servem de
  fallback. A ausência não cria um novo formato; sem o fallback seguro, a
  licença fica indisponível e o fast path do registro A/B não é íntegro.
- `manifest` — uma entrada por linha, ordenada, no formato
  **`<prova>␠␠<caminho absoluto>`** (registro **v2**). A prova é
  `f:<sha256>` para **modo + conteúdo** de um regular, `l:<sha256>` para os bytes crus
  do alvo de um symlink e `d:<sha256>` para **modo do diretório-raiz + tar
  canônico da árvore**. O prefixo prende o tipo; portanto retargetar um link,
  trocar o tipo, mudar o modo de um diretório reclamado ou adulterar qualquer
  arquivo sob `/opt/<nome>/<versão>` invalida a claim. Isto sustenta o veredito
  intacto × modificado do `memoryhole`, o `verify` e o fast path.
  Xattrs/ACLs/caps, uid/gid e timestamps ainda não entram.

  Leitura permanece compatível com v1 (`<sha256>`/`-`) e v0 (somente caminho).
  Quando versão, fingerprint e snapshot já coincidem, o `rectify` pode migrar
  v0/v1 **in-place**, decorando claims legadas com o estado presente; uma claim
  v0 sem hash é promovida confiando nesse estado, pois o formato antigo não
  tinha prova melhor. Se esses guardas falham, há reconstrução. Um provisional
  legado que já cedeu claims não é achatado nem reconstruído: fica congelado
  somente quando cada linha ativa é idêntica ao baseline e cada linha removida
  possui hoje sucessor não-provisional, ou sucessor provisional cujo registro
  declara `SUPERSEDES=<cedente>`. Formato maior/desconhecido falha fechado,
  nunca é regravado como v2.
- `recipe` — snapshot fiel da receita avaliada e usada. O diretório `files/`
  também é congelado para o fingerprint e o mesmo snapshot é materializado no
  `WORK` do build, evitando mudança de insumo entre parse e execução.

No mundo M, `SHA256=` e `SUPERSEDES=` ficam vazios; não existem
`ARTIFACT_HASH`, `TRANSACTION_ID`, `PROVISIONAL`, `REPROCORR`, `LICENSE` nem
campos de canal. `manifest` e `manifest@<versão>` contêm exatamente um byte newline
(`"\n"`): é a representação canônica do conjunto vazio e seu hash alimenta
`MANIFEST_BASELINE_SHA256`. `verify` exige a tripla `KIND=meta`/`WORLD=M`/
`ORIGIN=meta`, os campos vazios/ausentes corretos, `DEPS` canônico não vazio,
fingerprint canônico, snapshots de receita coerentes e ambos os manifestos
iguais a essa forma vazia; qualquer marcador parcial ou claim de payload é
*wrongthink*.

Para **todo** registro v2, `verify` também percorre `DEPS`: cada nome precisa
ser canônico e apontar para um diretório de registro factual cujo `meta`
confirme o mesmo `NAME`. Isso prova o fechamento de runtime, inclusive o
conjunto sustentado por um meta. `BUILD_DEPS` e a aresta de toolchain não são
exigidos no sistema instalado, pois um artefato de canal deliberadamente não
os materializa.

`manifest` e `recipe` ganham cópia da versão ativa nos três mundos
(`manifest@<versão>`, `recipe@<versão>`). A receita versionada coincide com a
corrente; o manifesto versionado coincide em pacotes comuns e vira baseline
em provisionals, cujo ativo só perde linhas por cessão declarada. No mundo A
essas cópias também sustentam a retenção:
`meta` registra a versão ativa e o estado (`UNPERSON=1` quando desativado). É o
que permitirá `rollback` e `unperson`/reativação relinkarem sem rede (§5).

Mundo B: o manifesto registra o default pristine em
`/usr/share/factory/etc`; a cópia viva em `/etc` é estado do administrador e
fica fora dele. O `verify` atual confere a fábrica, não diagnostica divergência
da cópia viva.

**Transação e recuperação do mundo B.** A instalação por pacote cobre a cópia
de `STAGE` para `/`, as remoções do upgrade, as cessões de manifestos
provisórios e os arquivos do próprio registro. Cada intenção (`novo` ou
`backup`) é registrada no journal **antes** da mutação. O `meta`, escrito por
último, leva o `TRANSACTION_ID` da operação e é a marca de commit.

Sob o lock, recovery faz um **sweep global antes de qualquer nova mutação**:
journal cujo `txid` aparece no `meta` já commitou e só precisa ser retirado;
sem esse vínculo, as entradas são revertidas em ordem inversa. O invariante
novo admite no máximo um journal ativo; estado legado com mais de um, ou
rollback tardio que sobreporia claim commitada por outro pacote, falha fechado
e preserva journal/backups. Journals novos levam marcador de formato `2`;
órfão anterior a esse marcador não é interpretado automaticamente, pois uma
versão antiga permitia que o payload substituísse o próprio log. `verify` não
muta e apenas denuncia journals
pendentes. Isto cobre falha e término abrupto do processo depois que as
escritas chegaram ao kernel. **Não há `fsync` dos arquivos e diretórios da
transação**, portanto o v0 não promete recuperação coerente após perda de
energia. No mundo A, as trocas continuam atômicas arquivo-a-arquivo, sem uma
transação equivalente para o conjunto inteiro; em particular, a cessão feita
por sucessor mundo A ainda não tem rollback de conjunto.

Se backup e destino estão em mounts diferentes, o fallback copia primeiro
para um temporário no filesystem do destino e só publica o nome final por
`rename` após conteúdo, flush e permissões completos. A origem é removida por
último: uma cópia parcial nunca pode ser interpretada pelo recovery como
backup válido. Esse fallback preserva bytes, natureza arquivo/link e modo, mas
ainda não preserva uid/gid, timestamps, xattrs/ACLs/capabilities nem relações
de hardlink; diretório/especial entre mounts é recusado.

Toda mutação do Journal valida também ancestrais: symlink relativo do
usr-merge é aceito se resolver dentro do rootfs; symlink que resolve para fora,
dangling ou ancestral não-diretório falha antes da mutação. Inspeção e remoção
destrutiva usam resolução fd-relative confinada no kernel
(`openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`).

**Limite de concorrência hostil:** as mutações do Journal ainda voltam a operar
por caminhos depois desse preflight. A trava `flock` abaixo coordena instâncias
cooperativas do Minitrue, mas não impede outro processo privilegiado de trocar
um ancestral na janela validação→uso. Portanto, o contrato atual exige controle
administrativo exclusivo do rootfs durante a mutação e não promete defesa
contra esse TOCTOU. Migrar criação, rename, backup, chmod e rollback por inteiro
para descritores fd-relative confinados é gate de release.

O STAGE não pode ocupar o plano de controle (`/var/lib/minitrue`,
`/var/cache/minitrue`, `/etc/minitrue`) nem workspaces `minitrue-{build,work}-*`;
aliases canônicos e o destino vivo de `etc/*` são verificados antes de abrir o
journal. Limpezas temporárias de mundo A/B também consultam ownership antes de
remover qualquer árvore. As raízes de estado/cache/configuração precisam ser
diretórios reais (não symlinks), inclusive antes de ler ou atualizar `world`.

**Exclusão mútua.** Comandos que mutam (`rectify`, `memoryhole`) tomam uma
**trava exclusiva por rootfs** (`flock` em `var/lib/minitrue/lock`), advisory
e auto-liberada na saída do processo — dois `minitrue` não corrompem o mesmo
sistema ao mesmo tempo; o segundo recusa com erro claro.

### 6.1 Explicabilidade — `explain` e `why`

Se o registro **é** a verdade (o filesystem como banco, SPEC-0001), então a
verdade tem de ser **perguntável**. Dois comandos leem os registros e
respondem, sem estado extra:

- **`explain <caminho>`** — de quem é um arquivo e toda a sua proveniência:
  o pacote e a versão que o reivindicam (varrendo os manifestos), o mundo
  (A/B; mundo M não reivindica caminhos), a **origem** (`ORIGIN`:
  vendor/fonte/canal; `meta` aparece na inspeção do pacote), a **confiança** (`TRUST`,
  quando de canal), o **`reprocorr`** da receita (se pina hash reprodutível —
  a base da corroboração, SPEC-0010 §5) e os **corroboradores** (quando o canal
  os registra), se é **provisório**, o `FINGERPRINT`, o **hash do próprio
  arquivo regular** (manifesto v1/v2), quando foi instalado, a receita e o seu
  `ABOUT`, a licença declarada do payload (`LICENSE`), o
  alvo se for link, e a nota de fábrica se for um default de `/etc`. Um caminho
  sem dono é
  apontado como *wrongthink* (existe sem registro). Aceita caminho absoluto ou
  nome de comando (resolvido em `/usr/bin`); um `/etc/X` resolve pelo seu
  default de fábrica (`/usr/share/factory/etc/X`). Onde um provisório e o seu
  sucessor ainda coexistem no manifesto, vence o **não-provisório**.
  `ABOUT`, `LICENSE` e `REPROCORR` vêm do `meta` congelado. Para registros v2
  legados que não os possuam, o fallback aceita apenas uma atribuição shell
  única e comprovadamente literal na cópia de `recipe`; expansão, substituição
  de comando, duplicidade ou forma ambígua é omitida, nunca executada.
- **`why <pacote>`** — por que ele está no sistema: se é **desejado
  explicitamente** (consta no `world`, §2), quais pacotes o **requerem**
  (dependência reversa, lendo `DEPS` dos registros), e se é **órfão** (nem
  explícito nem dependência — candidato a `memoryhole --orfaos`); mais a
  origem e o estado provisório. O mesmo mecanismo explica um meta como desejo
  explícito e seus componentes como dependências dele.

É a característica distintiva: não "tenho um gerenciador pequeno", e sim
"todo arquivo do sistema explica a si mesmo". Habilitada pelo registro —
especialmente pelo `FINGERPRINT` (SPEC-0011 §4) e pelas provas tipadas do
manifesto v2.

### 6.2 Attestations e identidade de reprodução

A attestation v1 é Ed25519 e assina, em ordem canônica,
`ATTEST_FORMAT=1`, `PACKAGE`, `VERSION`, `RECIPE_FINGERPRINT`,
`ARTIFACT_HASH`, `BUILDER` e `BUILDER_KEY` (SPEC-0009 §8.1). A corroboração só
compara attestations da **mesma versão e do mesmo fingerprint** do registro
local; uma attestation válida de identidade anterior é histórica e não vira
divergência. Dois builders pinados e distintos concordando com o hash local
corroboram; um builder pinado divergindo nessa mesma identidade dispara
*crimestop*.

A implementação usa `ed25519-dalek` dentro do minitrue e **não depende de
OpenSSL**. O OpenSSL da base é necessário hoje para a assinatura dos módulos do
kernel, não para este protocolo.

Antes de emitir, a implementação exige registro mundo B v2 commitado, baseline
hashado, `recipe`/`recipe@` idênticos e claims tipadas conferindo no rootfs; um
`REPROCORR` pinado também precisa coincidir com `ARTIFACT_HASH`. Limite de
confiança: sem pino externo, `ARTIFACT_HASH` e `FINGERPRINT` continuam vindo do
registro local. Defender contra adulteração privilegiada posterior requer
reter a imagem selada, usar índice/canal assinado ou emitir no instante do
build. Mundo M não é atestável nem emitível: sua identidade é a receita e o
fingerprint transitivo, não um artefato.

## 7. Colisões (*doublethink*)

Antes de copiar staging para `/`, cada caminho é conferido contra os
manifestos existentes. Caminho já reivindicado por outro pacote ⇒ erro 4:

```
doublethink detectado: /usr/bin/rg já pertence a ripgrep 15.2.0
```

Sem `--force`. A resolução é humana: ajustar a receita (renomear link,
retirar arquivo) e commitar na árvore newspeak.

**Exceção declarativa — `SUPERSEDES`.** Uma colisão com um pacote
`PROVISIONAL` só **não** é doublethink quando a receita que instala **declara**
esse pacote em `SUPERSEDES` (SPEC-0004 §2). Aí a cópia **cede** o caminho: o
provisional o perde do seu manifesto, o sucessor o assume. Colisão com um
provisional **não declarado** volta a ser doublethink — fim do "qualquer
pacote toma o caminho de qualquer provisional". É o que torna a cadeia de
substituição do E2 (seed → cross → glibc/nativo, SPEC-0005 §4) explícita e
auditável, e não um efeito colateral do flag `PROVISIONAL`.

Quando o sucessor é mundo B, se sua instalação falha a mudança no manifesto
cedente participa do journal e é revertida com o restante da operação. Mundo A
ainda não possui transação de conjunto equivalente. **Dívida registrada:**
remover depois um sucessor já instalado ainda não restaura o payload do
cedente; isso exige retenção/rollback de supersessão além do journal de falha.

Claims `d:` também participam da exclusão de ownership: instalar um caminho
igual ou descendente de diretório reclamado por outro pacote é *doublethink*.
No upgrade do próprio dono, um diretório retirado só é removido se sua prova
`d:` ainda confere; se ganhou conteúdo/metadados, permanece no filesystem e
apenas deixa de ser reclamado.

## 8. Execução de receitas e confinamento

- O arquivo `recipe` e `files/` são congelados antes da operação. A avaliação
  top-level da receita ainda roda via `sh -e` **no host**, fora de bwrap; por
  isso a árvore de receitas continua sendo código confiável, não dados
  adversariais. O mesmo snapshot da receita é usado no build/registro e o
  snapshot de `files/` é materializado em `WORK`.
- `files/recipe` é nome reservado (qualquer tipo, inclusive symlink/hardlink)
  e o snapshot executável é criado com exclusão (`create_new`), sem seguir link
  no nome final. `VERSION`, dependências e `LINKS` também são componentes
  canônicos: não podem introduzir `/`, `..` ou controles em caminhos internos.
- Funções de receita recebem o ambiente mínimo controlado (a SPEC-0004 define
  `DL`, `WORK`, `PREFIX`/`STAGE`, `JOBS`, `CC`…). `install_pkg()` do mundo A
  também ainda roda no host, sem sandbox.
- Regra normativa: receita NÃO DEVE acessar rede (todo insumo entra por
  `SRC`) nem escrever fora de `WORK`/`PREFIX`/`STAGE`. Para builds de um
  rootfs (`--root` != `/`), o `build()` de mundo B roda dentro dele via
  `bwrap` com `--clearenv` e `--unshare-net` — SPEC-0005. O rootfs, porém, é
  montado **gravável**, então ainda é possível escrever fora de `STAGE`. O
  build no próprio sistema (`--root /`) roda direto, sem netns nem usuário
  dedicado. Alvo: rootfs read-only com binds graváveis só para WORK/STAGE e
  confinamento também da avaliação e do mundo A.
- O `pack` representa nomes não-UTF-8 e hardlinks, mas o aplicador de mundo B
  ainda opera com caminhos UTF-8 e não possui `linkat` transacional. Por isso
  `rectify` **recusa** ambos no `STAGE`, em vez de instalar uma topologia
  diferente daquela coberta por `ARTIFACT_HASH`.
- O tar normalizado fica inteiro num `memfd` selado enquanto é indexado e
  aplicado. Isso fecha a corrida hash→cópia, mas é Linux-only e consome RAM/swap
  proporcional ao artefato; stdout/stderr de `build()`/`install_pkg()` também
  são acumulados em memória na implementação atual.
- Maintainer scripts de `.deb`/`.rpm`: nunca executados (SPEC-0001 §2).

## 9. Saídas e códigos de erro

| Código | Significado |
|--------|-------------|
| 0 | sucesso |
| 1 | erro geral |
| 2 | receita inválida/ausente |
| 3 | hash divergente (*crimestop*) |
| 4 | colisão de arquivos (*doublethink*) |
| 5 | pré-condição ausente (ex.: glibc antes do Estágio 2) |
| 6 | falha de rede |
| 7 | assinatura obrigatória ausente no modo offline ou falha criptográfica (*crimestop*, variante assinatura) |
| 8 | divergência de reprodução/corroboração na mesma identidade (*crimestop*) |

Falha de transporte ao buscar assinatura continua sendo 6; entrada/receita
malformada é 2. Attestation coletada que seja malformada, não confiável,
histórica ou criptograficamente inválida é ignorada pela corroboração; o código
7 é usado quando a operação explicitamente exige uma assinatura válida.

Tom das mensagens: diagnóstico primeiro, tema depois (SPEC-0001 §3).
Sucesso de `rectify` termina em `doubleplusgood.`; `verify` limpo:
`thinkpol: nenhum wrongthink.`

## 10. Implementação v0 (Rust)

- Crates centrais: `ureq` (HTTP, rustls), `sha2`, `hex`, `anyhow`, `tar`, `fs2`
  e `ed25519-dalek`. Verificação de assinaturas embutida no binário:
  `minisign-verify` para minisign/signify e Ed25519 para attestations. OpenPGP
  destacado continua futuro (candidata: rPGP) — **sem gpg em runtime**. Nada de
  async. Ensaio verificado no spike (SPEC-0005 §8):
  ureq com raízes embutidas buscou HTTPS num rootfs sem `/etc/ssl`, e
  `minisign-verify` validou o tarball real do Zig; binário `static-pie` de
  2,4 MB. Build do minitrue para musl com crates que embutem C (ring)
  exige `CC` wrapper traduzindo o triple LLVM para o do zig.
- Raízes CA **embutidas** (webpki-roots): o fetch funciona num rootfs sem
  `/etc/ssl`. (As CAs também são um artefato upstream — Mozilla — pinado
  em build da ferramenta; a piada é séria.)
- Extração/execução delegadas a `sh`/`tar` do ambiente (busybox no
  chroot; qualquer POSIX no host).
- Tamanho alvo do binário: < 5 MB. Sem dependência de libc do sistema.
- O bootstrap da ferramenta em si: construída no host com cargo/rustup
  (toolchain binária oficial — coerente com P2); releases do projeto
  DEVERIAM publicar o binário estático para hosts sem Rust.

## 11. Questões em aberto

- ~~hash por arquivo instalado fica para v0.2~~ — **implementado e ampliado**
  (registro **v2**, §6): o `write_record` grava prova tipada de regular,
  symlink ou diretório. O `verify` confere conteúdo × tipo × alvo/árvore e o
  `memoryhole` do mundo B **preserva o caminho modificado**. Leitura continua
  retrocompatível com o hash v1 e com a linha apenas de caminho do v0.
- A própria árvore newspeak como pacote gerido (`minitrue rectify newspeak`
  puxando tarball do repositório oficial da Distrópica): elegante e
  resolve atualização sem git instalado; especificar o pacote especial —
  com a infra de assinaturas do v0.2, o tarball da árvore DEVERIA vir
  assinado (minisign) com a chave do projeto. **É o motor do modelo rolling
  edge (SPEC-0011 §3.1) — a peça que faz a árvore, logo o sistema, avançar
  para o estável-mais-novo (P7).**
- Downloads paralelos e retomada (range requests): v0.2.
