# SPEC-0013 — Fechamento de dependências e compatibilidade ABI

**Status:** rascunho v0.1 · 2026-07-23
**Palavras-chave normativas:** DEVE / NÃO DEVE / DEVERIA / PODE (RFC 2119).
**Depende de:** SPEC-0001 (P1/P2/P3/P8), SPEC-0002 (mundos A/B), SPEC-0003
(`minitrue`, `world`, registros), SPEC-0004 (Newspeak), SPEC-0008 (perfis e
mídia), SPEC-0009 (canais), SPEC-0010 (reprodutibilidade) e SPEC-0011
(`--sync` e rolling).

**Estado de implementação:** o Minitrue já distingue `DEPS`, `BUILD_DEPS`,
dependência implícita de toolchain e metapacotes; congela a árvore antes da
primeira mutação; calcula fingerprint transitivo; ordena o grafo por DFS;
recusa ciclos; escolhe canal antes de expandir dependências de build; registra
`DEPS`; verifica sua presença factual; explica dependências reversas; e impede
remover pacote ainda requerido. O **fechamento por inspeção estática (§4)**
entrou em 2026-07-24 como `minitrue audit`, com `AUDIT_FORMAT=1`: parser ELF
próprio, mapa de provedores vindo dos registros, confronto declaração ×
observação e `CLOSURE_SHA256` canônico. Desde 2026-07-28 ele **impede**:
`channel emit` recusa publicar pacote cujo payload exija provedor não
declarado. O PATH/view de build, `PLAN_LOCK_FORMAT=1`, `plan`, o preview
`plan --sync`, `cache verify --closure`, `RECORD_FORMAT=4` e o receipt global
estão implementados. Continuam não implementados o gate produtivo da
composição de mídia/profile, a aplicação `rectify --sync`, rollback e a coleta
explícita de órfãos.

## 1. Princípio: a árvore é o lock global

A Distrópica NÃO resolve dependências com um solver de versões ao estilo APT,
DNF ou Pacman. O snapshot integral da árvore Newspeak é a unidade de
consistência:

- cada nome canônico aponta para uma única receita e uma única versão;
- `DEPS` nomeia receitas desse mesmo snapshot, não expressões como
  `libfoo >= 1.2`;
- a árvore é promovida e substituída atomicamente; *partial upgrade* é
  inválido;
- versão, receita, auxiliares, dependências e toolchain participam da
  identidade transitiva;
- um artefato de canal só serve à identidade exata do snapshot corrente.

Essa escolha troca a flexibilidade de combinar versões arbitrárias por um
conjunto pequeno, opinativo e auditável, coerente com P1 e P8. A curadoria da
árvore faz o trabalho que outras distribuições delegam ao solver.

O mundo de sistema (`/usr`) DEVERIA ter um único provedor canônico para cada
ABI compartilhada. Quando um binário do mantenedor exige versão privada ou
incompatível de uma biblioteca, ele PODE carregá-la dentro de
`/opt/<pacote>/<versão>` e resolvê-la por `$ORIGIN`; NÃO PODE trocar
silenciosamente a biblioteca canônica de `/usr`. Se nenhuma das duas opções
for segura, o binário é inelegível para aquele snapshot.

## 2. Grafo tipado

As arestas têm semânticas diferentes e NÃO DEVEM ser achatadas numa única
lista:

| Aresta | Origem | Quando materializa | Persiste no registro | Entra no `world` |
|---|---|---|---|---|
| runtime | `DEPS` | sempre que o pacote estiver presente | sim; bloqueia remoção | não, salvo pedido explícito |
| build | `BUILD_DEPS` | somente quando houver build local | como proveniência; não bloqueia runtime | não |
| toolchain | derivada de `TOOLCHAIN` | somente quando houver build local | como proveniência | não |
| agregação | `DEPS` de `KIND=meta` | sempre; o meta não tem payload | sim | só o meta pedido explicitamente |
| ambiente do runner | contrato versionado de build | somente quando houver build local | como proveniência | não |

`TOOLCHAIN=seed|cross` implica hoje uma aresta de build para `zig`.
`TOOLCHAIN=none|native`, `KIND=binary` e `KIND=meta` não ganham essa aresta.
O ambiente mínimo do runner ainda é uma dependência implícita incompleta: a
implementação futura DEVE representá-lo por identidade versionada — por
exemplo, um metapacote de ferramentas de build — em vez de pressupor todos os
comandos que por acaso existam em `/bin` e `/usr/bin`.

Uma aresta runtime direta também é a autorização explícita para depositar
payload sob uma claim de diretório compartilhado `D:` do provedor
(`SHARED_DIRS`, SPEC-0003 §§6–7). A transitividade serve para presença/ordem,
mas NÃO amplia essa autoridade de namespace: quem grava sob `D:` precisa
nomear o dono diretamente em `DEPS`.

O resolvedor precisa manter cinco conjuntos relacionados, mas distintos:

- **closure de identidade:** todas as arestas que influenciam fingerprints,
  inclusive build/toolchain inativas por ter vencido um binário de canal;
- **closure runtime desejada:** roots do `world` + `DEPS` alcançáveis;
- **closure de execução do build:** runtime + `BUILD_DEPS` + toolchain + runner
  apenas nos nós que serão compilados localmente;
- **closure de cache:** objetos necessários para executar a política escolhida
  sem rede;
- **closure factual:** registros e claims que realmente existem no sistema.

Confundir identidade com instalação faria o canal puxar compiladores
desnecessários; confundir cache com intenção faria disponibilidade virar
instalação; confundir fato com desejo impediria detectar órfãos.

### 2.1 Resolução e ordem

Para cada operação, o Minitrue DEVE:

1. congelar receitas e `files/` de toda a closure de identidade;
2. validar nomes e detectar ciclos antes da primeira instalação;
3. calcular fingerprints transitivos sobre `DEPS`, `BUILD_DEPS` e toolchain;
4. escolher a origem de cada receita fonte;
5. expandir `DEPS` em qualquer origem;
6. expandir `BUILD_DEPS`, toolchain e runner somente nos nós que serão
   compilados localmente;
7. deduplicar nós e produzir ordem topológica, dependências primeiro;
8. concluir o preflight de índices, hashes, espaço e conflitos antes de mutar
   o sistema, na medida em que esses dados estejam disponíveis.

Um ciclo é erro fechado. Ciclos reais de upstream DEVEM ser resolvidos por
separação de payloads, estágio de bootstrap ou, quando forem inseparáveis, por
um único pacote composto. A Distrópica NÃO relaxa a detecção de ciclo para
simular ordenação válida.

### 2.2 Intenção, fato e órfãos

`/etc/minitrue/world` contém apenas desejos top-level. O registro contém o
fato instalado e as arestas resolvidas. Portanto:

- instalar dependência não a transforma em desejo;
- remover um meta retira a intenção, não apaga automaticamente sua closure;
- uma dependência de runtime não PODE ser removida enquanto houver dependente;
- pacote inalcançável do `world` é órfão, não lixo automaticamente autorizado;
- remoção de órfãos exige comando explícito.

Build-deps que deixem de ser necessários podem virar órfãos. Isso é preferível
a apagar automaticamente algo que o administrador ainda queira inspecionar.

## 3. Ordem de origem e expansão da closure

A preferência normal é:

1. binário oficial do mantenedor, `KIND=binary`, mundo A;
2. binário do canal oficial da Distrópica para uma receita `KIND=source`,
   mundo B pré-buildado;
3. binário de canal samizdat aceito pela política de confiança;
4. compilação local da fonte oficial.

Essa lista escolhe **origem do payload**, não versão. A versão continua vindo
da árvore Newspeak.

### 3.1 Binário do mantenedor

Um payload estático não deve ser declarado “sem dependências” apenas por não
ter `DT_NEEDED`: ele ainda pode executar comandos, carregar plugins ou exigir
arquivos e protocolos. Dependências semânticas continuam em `DEPS`.

Num payload dinâmico, bibliotecas privadas sob seu próprio `/opt` fazem parte
do mesmo artefato. Bibliotecas fornecidas pelo sistema, interpretador ELF,
serviços, comandos e dados externos DEVEM ser satisfeitos pela closure
declarada. `REQUIRES_GLIBC=1` é apenas a barreira grosseira do bootstrap; não
substitui conferir a versão real da ABI.

### 3.2 Binário da Distrópica

Um artefato de canal de mundo B é o `STAGE` de uma receita fonte já construído.
Ao escolhê-lo:

- apenas `DEPS` de runtime materializam no alvo;
- `BUILD_DEPS` e toolchain continuam presos à identidade e à proveniência,
  mas não são instalados;
- nome, versão, arquitetura, fingerprint da receita, closure e política de
  confiança DEVEM coincidir;
- o canal NÃO PODE adicionar dependência que a receita efetiva desconheça.

### 3.3 Fallback de fonte

Sem artefato aceitável, o modo normal expande runtime + build + toolchain e
executa `build()`. `--only-binary` falha antes disso; `--no-binary` força esse
caminho. Só os nomes pedidos explicitamente entram no `world`.

Exemplo: numa futura oferta de Nano pelo canal, o alvo recebe `nano`, `glibc`
e `ncurses`, mas não Make, GCC nem binutils. Sem o artefato, essas ferramentas
de build são materializadas, Nano é compilado e as ferramentas permanecem
fora do `world`.

## 4. Fechamento de runtime verificável por máquina

Receitas são declarações humanas necessárias, mas insuficientes. Antes de um
artefato entrar em canal oficial ou mídia, Miniplenty DEVE confrontar a
declaração com o payload real sem executar código dele.

### 4.1 Inspeção segura

O auditor NÃO DEVE usar `ldd` nem iniciar executáveis não confiáveis. Ele DEVE
interpretar estaticamente, conforme o tipo do arquivo:

- ELF: classe, arquitetura, endianness, `PT_INTERP`, `DT_NEEDED`, `DT_SONAME`,
  `DT_RPATH`/`DT_RUNPATH`, versões GNU requeridas e fornecidas;
- scripts: shebang e interpretador;
- symlinks: alvo normalizado dentro do payload ou caminho pertencente a um
  provedor declarado;
- plugins, helpers executados em runtime, dados, serviços e protocolos: aresta
  explícita de receita e teste de integração, pois não são inferíveis de forma
  completa por análise estática.

`linux-vdso`, o carregador do kernel e outros pseudo-provedores reconhecidos
DEVEM ter regras fechadas e versionadas; não podem virar uma allowlist genérica.

### 4.2 Mapa de provedores

Para a closure selecionada, Miniplenty DEVE construir um mapa de:

- caminho absoluto → pacote e claim de manifesto;
- `SONAME` → arquivo, pacote e ABI fornecida;
- interpretador/shebang → pacote provedor;
- biblioteca privada `$ORIGIN` → artefato que a contém.

Cada requisito observado precisa resolver para exatamente um provedor válido.
Ausência, ambiguidade, arquitetura errada, fuga por RPATH ou provedor fora da
closure são erros de publicação. Duplicidade privada dentro de `/opt` PODE ser
aceita quando sua resolução permanece confinada ao próprio pacote.

### 4.3 Compatibilidade, não apenas nome

Encontrar `libc.so.6` ou `libstdc++.so.6` não prova compatibilidade. O auditor
DEVE comparar versões de símbolos requeridas e fornecidas, incluindo
`GLIBC_*`, `GLIBCXX_*` e `CXXABI_*`. Para ABIs sem versionamento de símbolos,
a receita ou política do pacote DEVE fornecer teste/claim específico; a
presença do SONAME é necessária, mas pode não ser suficiente.

### 4.4 Declaração × observação

- requisito ELF ou shebang externo observado sem provedor no próprio artefato
  ou numa `DEPS` direta: erro; depender acidentalmente da dependência de outro
  pacote é proibido;
- `DEPS` declarado sem requisito estático observado: permitido, pois pode ser
  dependência semântica, mas o linter DEVERIA pedir justificativa ou teste;
- biblioteca privada observada dentro do próprio artefato: registrada no
  inventário, sem criar pacote fictício;
- dependência opcional descoberta em runtime: não é instalada por heurística;
  vira escolha explícita da receita, variante futura ou funcionalidade
  deliberadamente desabilitada.

O resultado DEVE ser serializado de forma canônica e receber um hash de
closure. Os dados normativos mínimos são os descritos nos §§4.1–4.3.

### 4.5 `AUDIT_FORMAT=1` — a serialização canônica

O formato físico, definido junto da implementação, é texto em linhas de sete
campos separados por TAB, uma por requisito observado:

```text
<pacote> <arquivo> <espécie> <requisito> <pacote provedor> <arquivo provedor> <versões>
```

- **espécie** é `needed` (`DT_NEEDED`), `interp` (`PT_INTERP`), `shebang` ou
  `estatico` — este último para o objeto que nada exige, porque "não depende de
  nada" também é um fato do fechamento;
- **versões** lista as versões de símbolo exigidas daquele provedor, separadas
  por vírgula e **ordenadas**, ou `-`; a ordenação é obrigatória porque a
  serialização não pode depender da ordem em que o linker gravou o `verneed`;
- requisito sem provedor usa `?` nos dois campos de provedor: o erro entra no
  hash, não é omitido dele;
- as linhas são ordenadas byte a byte e o conjunto é deduplicado.

`CLOSURE_SHA256` é o sha256 desse corpo — só do corpo, sem cabeçalho nem
rodapé, para que o hash descreva o grafo observado e não a moldura do
relatório. Duas auditorias do mesmo payload DEVEM dar o mesmo
`CLOSURE_SHA256`; qualquer mudança no que os artefatos exigem muda o hash. É
essa identidade, não o texto do relatório, que um gate de publicação deve
consumir.

## 5. Fechamento do ambiente de build

Hoje o runner limpa o ambiente e controla a rede, mas ainda expõe o
`/usr/bin:/bin` inteiro do rootfs. Assim, uma receita pode chamar `tar`, `sed`,
`grep`, `make` ou outro utilitário não declarado e funcionar apenas porque um
build anterior o deixou instalado. Isso é uma lacuna de correção e de
reprodutibilidade.

A migração terá duas fases:

1. **Auditoria:** declarar as ferramentas usadas por cada receita, definir um
   ambiente-base de runner versionado e fazer o linter apontar executáveis sem
   provedor na closure.
2. **Enforcement:** construir uma view/PATH contendo somente shell e funções
   injetadas pelo contrato, executáveis das dependências de build resolvidas e
   shims da toolchain escolhida. O restante do rootfs não deve ser encontrável
   por acidente.

O build DEVE falhar se usar ferramenta ausente da view. A view, seu ambiente
base, sysroot, toolchain e fingerprints das dependências DEVEM participar da
identidade de build. Monitorar `execve` pode auxiliar o lint, mas não substitui
o confinamento: um trace que não percorreu determinado ramo não prova ausência
de dependência.

## 6. Lock tipado do plano e registros

A resolução bem-sucedida produz um lock content-addressed do plano.
`PLAN_LOCK_FORMAT=1` contém:

- hash da árvore Newspeak, arquitetura, política binária e roots pedidos;
- para cada nó: nome, versão, kind, ação (`keep`, `meta`, `vendor`, `channel`
  ou `source`), origem e fingerprint da receita;
- arestas de runtime com nome e fingerprint esperado do provedor;
- arestas de build, toolchain e runner, mesmo quando não materializadas no
  alvo;
- `PURPOSE` (`rectify`, `sync`, `cache-closure`, `media` ou `channel-emit`),
  `BINARY_POLICY`, `ABI_POLICY`, `TREE_SHA256` e
  `BUILD_CONTRACT_SHA256`;
- papel explícito de root (`install`/`availability`) e material
  (`runtime`/`cache-only`/`identity-only`);
- `LICENSE`, `MATERIAL_ID` e `PROVENANCE_SHA256` em cada nó, derivados dos
  bytes tipados e de todos os `ARTIFACT` C-sort;
- identidade do artefato e referência ao `CHANNEL_LOCK_FORMAT=4` escolhido,
  quando houver;
- requisitos e provedores ABI observados, além de `ABI_STATIC`, `ABI_NONE` e
  `ABI_PENDING` disjuntos; o digest ABI é recomputável desses records;
- hash canônico da closure resolvida.

O lock deve viver por hash sob `/var/lib/minitrue/plan-locks/`. Arestas de
build/toolchain que influenciam a identidade mas não serão materializadas
aparecem como `identity-only`. Arestas de `DEPS` cujo consumidor é meta são
`aggregation`, sem serem achatadas em runtime.

`RECORD_FORMAT=3` é exclusivamente intermediário da operação que escreveu o
payload. O fechamento factual promove somente esses records para
`RECORD_FORMAT=4`, com `INSTALL_PLAN_LOCK_SHA256` e
`INSTALL_PLAN_SLICE_SHA256` imutáveis, payload e ABI factuais. Um v3 histórico
é legível para migração/sync, mas precisa ser reaplicado; não vira v4 por mera
reobservação. O commit global é
`APPLIED_PLAN_RECEIPT_FORMAT=1`: receipt content-addressed do world completo,
hash factual de exatamente cada diretório de record e ponteiro atômico
`applied-plans/current`. Ausência, record extra ou fact hash divergente falha
fechado.

Antes do primeiro payload/record, o mutador varre por descritores os namespaces
de locks, slices, records, receipts/current e seus alvos. Há limite de 64 MiB
por objeto, 100.000 entradas e 255 bytes por nome; nomes e records são
canônicos/C-sort, objetos preexistentes precisam corresponder ao hash do nome,
e symlink, tipo especial ou colisão estrangeira são recusados. Cada publicação
reabre o alvo e confere inode/metadata. Temporários reconhecíveis anteriores ao
commit são rollback seguro; o retry recalcula o receipt e só o rename de
`current`, seguido do fsync do pai, torna o novo estado autoridade global.

Esse formato NÃO substitui os locks existentes:

- `CHANNEL_LOCK_FORMAT=4` congela seleção, índice v4, `RELEASE_ROOT`, plano
  produtor e confiança de canais;
- `PROFILE_LOCK_FORMAT=3` congela os insumos de um perfil do Minipax, inclusive
  o bootstrap de canal separado do cache offline;
- `PLAN_LOCK_FORMAT=1` congela a resolução tipada desses insumos.

Uma futura composição oficial deve fazer o `profile.lock` referenciar o hash
do plan lock resolvido, em vez de fingir que o próprio lock de perfil já é a
resolução.

`verify` deixou de conferir apenas que “algum registro chamado glibc
existe”: ele confere que o provedor presente tem a identidade esperada e ainda
satisfaz a ABI registrada. `BUILD_DEPS` não se tornam requisitos de runtime,
mas permanecem explicáveis e reproduzíveis.

## 7. Planejamento, convergência e coleta

Todos os comandos abaixo DEVEM usar o mesmo resolvedor; não pode haver um
algoritmo simplificado para exibir e outro para instalar.

### 7.1 Plano somente-leitura

`minitrue plan <pacote>…` e `minitrue plan --sync` mostram,
antes de mutar:

- origem escolhida de cada nó;
- closure runtime e, onde houver build local, closure de build/toolchain;
- downloads/cache hits;
- instalações, rebuilds, substituições e conflitos;
- órfãos que resultarão, sem removê-los;
- motivo de cada aresta.

### 7.2 `rectify --sync`

`--sync` deve carregar o `world`, resolver a closure contra um único snapshot,
validar o plano inteiro e então convergir versão, fingerprint e origem. O
`world` só muda por pedido explícito. Falha depois de instalar dependências
pode deixar pacotes válidos fora do `world`; eles serão relatados como órfãos,
não apagados às cegas. Rollback atômico do mundo inteiro continua pertencendo
à SPEC-0011.

### 7.3 `why` e órfãos

O `why` já existente DEVE evoluir para mostrar aresta tipada, cadeia completa
até um root do `world`, origem e lock. Build-deps deixados por uma compilação e
fora da closure runtime devem aparecer como `build-residue`, uma espécie
explicável de órfão candidato. `memoryhole` continua recusando remover um
provedor de runtime alcançável. O futuro `memoryhole --orfaos` DEVE:

1. recalcular alcançabilidade a partir do `world` atual;
2. apresentar candidatos e seus motivos;
3. exigir ordem explícita;
4. reutilizar as proteções de ownership e preservação de modificados;
5. nunca tratar build-dep como runtime apenas porque participou do build.

### 7.4 Cache

`cache verify --closure <pacote>…` e `cache verify --closure --world ARQUIVO`
resolvem o mesmo plano sob `--offline` e provam, sem instalar, que todos
os objetos, índices, assinaturas e fontes necessários à política escolhida
estão presentes. Sob `--only-binary`, isso inclui todos os artefatos de canal
da closure runtime; sob build local, inclui fontes e closures de
build/toolchain ativadas. `cache.world` permanece uma lista de disponibilidades
intencionais, não uma segunda lista de instalação.

## 8. Canal, perfil e mídia

Um canal oficial só pode publicar artefato depois de:

1. validar a closure declarada e observada;
2. prender receita, dependências, ABI e hash do artefato;
3. produzir índice assinado e inventário;
4. exercitar a closure num rootfs limpo;
5. conservar as fontes correspondentes (SPEC-0011 §8).

Minipax NÃO resolve dependências por conta própria. Ele entrega perfil,
snapshot, cache e política ao Minitrue, recebe o lock resolvido e o incorpora
ao `profile.lock`/manifesto da mídia. Para uma mídia offline, a composição DEVE
falhar antes de gerar IMG/ISO se qualquer objeto da closure alvo estiver
ausente.

A publicação de um canal oficial assinado é pré-condição para oferecer um
catálogo amplo sem obrigar o usuário a compilar. O canal de desenvolvimento
embutido na mídia atual é evidência funcional, não satisfaz essa publicação.

## 9. Aplicação à pilha gráfica

Wayland é protocolo e bibliotecas, não um desktop isolado. Um perfil gráfico
mínimo precisará de um metapacote opinativo — nome provisório
`miniplenty-graphical` — cuja closure inclua exatamente uma escolha canônica
para cada função necessária, por exemplo:

- protocolos e bibliotecas Wayland;
- compositor;
- Mesa, DRM e driver/input;
- gestão de assento;
- teclado/XKB;
- terminal, fontes e configuração de sessão.

A lista concreta será decidida no Estágio 4; este spec não escolhe ainda os
projetos. Os componentes de mundo B DEVEM ser construídos uma vez, auditados e
servidos pelo canal. Instalar o meta materializa somente sua closure de
runtime; compiladores e geradores usados para produzi-la não chegam ao alvo por
serem `BUILD_DEPS`. A instalação oficial dessa pilha deve usar
`--only-binary`; uma ausência no canal falha em vez de recompilar o desktop no
computador do usuário.

Aplicativos gráficos do mantenedor continuam no mundo A, sob `/opt`, podendo
trazer bibliotecas privadas. Suas dependências na ABI gráfica comum do sistema
precisam passar pelo mesmo auditor. AppImage, Flatpak e mecanismos semelhantes
não são solução implícita de dependências da Distrópica.

## 10. Sequência de implementação

1. Auditar receitas existentes e versionar o contrato mínimo do runner.
2. Implementar scanner ELF/shebang, mapa de provedores e gate de closure no
   `pack`/`channel emit`.
3. Fechar o PATH/view de build e adicionar lint de ferramentas não declaradas.
4. Implementar lock tipado, `verify` exato e `cache verify --closure`.
5. Implementar `plan`, `rectify --sync` e coleta explícita de órfãos.
6. Reemitir o canal oficial assinado com closure e fontes correspondentes à
   árvore corrente.
7. Só então promover uma pilha gráfica como metapacote suportado.

O scanner e o fechamento do ambiente de build vêm antes de um solver mais
sofisticado: o problema imediato não é escolher entre vinte versões, e sim
provar que o único conjunto escolhido declara e contém tudo de que depende.

## 11. Estado resumido

| Peça | Estado em 2026-08-11 |
|---|---|
| `DEPS`/`BUILD_DEPS`/toolchain/meta | implementado |
| DFS, deduplicação e detecção de ciclo | implementado |
| fingerprint transitivo | implementado |
| seleção de canal antes de build-deps | implementado |
| `world`, `why` básico e proteção de dependência reversa | implementado |
| scanner ELF/ABI e mapa de provedores | implementado (`audit`, `AUDIT_FORMAT=1`) |
| gate de closure em `channel emit` | implementado — recusa publicação, com teste de regressão |
| gate de closure na composição de mídia | não implementado |
| ambiente/PATH fechado por closure | implementado |
| plan lock tipado e `verify` de identidade exata da dependência | implementado (`PLAN_LOCK_FORMAT=1`, record v4 + receipt) |
| `cache verify --closure` | implementado, read-only/offline |
| `plan` e preview `plan --sync` | implementados, read-only sob lock compartilhado |
| aplicação `rectify --sync`, rollback e coleta de órfãos | não implementados |
| canal oficial público | publicado; payloads da árvore corrente ainda precisam ser reemitidos |
| metapacote gráfico suportado | futuro |

## 12. Não-objetivos e questões em aberto

- Solver SAT de constraints e múltiplas versões de sistema: não-objetivo
  enquanto uma árvore canônica for suficiente.
- `recommends`, `suggests` e instalação oportunista: não; recursos opcionais
  devem ser escolhas explícitas e auditáveis.
- Pacotes virtuais/alternativas: adiar até existir um caso que não possa ser
  resolvido pela escolha canônica de P8. Um futuro `PROVIDES` não deve reabrir
  ambiguidade silenciosa.
- Inferência perfeita de `dlopen`, plugins, subprocessos e protocolos é
  impossível estaticamente; definir combinação de declaração, lint e testes.
- Integrar o import tipado `LIVE_LOCK`/`LIVE_COMPONENTS` do purpose `media` ao
  profile e à composição produtiva. A API/parser existe, mas não é ainda gate
  do Minipax nem autoriza publicação.
- Definir política de ABI para bibliotecas sem símbolos versionados.
- Decidir se o plano somente-leitura será comando `plan` ou flag de `rectify`;
  a exigência é compartilhar exatamente o resolvedor, não a grafia final.
