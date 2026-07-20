# SPEC-0003 — minitrue, a ferramenta

**Status:** rascunho v0.5 · 2026-07-19
**Depende de:** SPEC-0001 (política), SPEC-0002 (layout), SPEC-0004 (receitas).

## 1. Identidade

`minitrue` é um binário único, **estático** (Rust, alvo
`x86_64-unknown-linux-musl`), sem daemon, sem estado fora de
`/var/lib/minitrue`, `/var/cache/minitrue` e dos caminhos que instala. Roda
em qualquer Linux x86_64 — inclusive no rootfs nu do Estágio 0, onde não há
libc instalada.

Ele faz exatamente quatro coisas: **busca, verifica, registra, apaga**.
O que ele não é: solver, formato de repositório, banco de dados, init,
build system. Builds e extração são delegados a `sh` e `tar` (busybox).

## 2. Interface de linha de comando

```
minitrue rectify   <pacote>…      instala/atualiza; acrescenta ao world (§2)
minitrue rectify   --sync         converge o sistema ao world inteiro (§2)
minitrue rectify   --emit <pkg>   mantenedor: empacota o STAGE como artefato
                                  de canal, imprime os hashes (SPEC-0009 §4)
minitrue rollback  <pacote> [<v>] mundo A: volta o current à versão retida (§5)
minitrue unperson  <pacote>…      mundo A: some dos registros, fica em /opt (§5)
minitrue memoryhole <pacote>…     remove do sistema e do world; --orfaos:
                                  remove os órfãos apontados pelo --sync
minitrue archives  [padrão]       lista registros; marca não-pessoas e órfãos
minitrue verify    [<pacote>…]    confere registros contra o filesystem e
                                  varre /usr por links órfãos (§5)
minitrue newspeak  <pacote>       imprime a receita efetiva e sua origem
minitrue lint      [<árvore>]     valida a árvore newspeak (SPEC-0004 §6)
minitrue channel   <sub>          add|remove|list|refresh de canais (SPEC-0009 §7)
minitrue pack      <dir> [saída]  tar normalizado determinístico + sha256 (SPEC-0010 §4)
```

Opções globais:

| Opção | Efeito |
|-------|--------|
| `--root <dir>` | opera sobre outro rootfs (Estágio 0 popula o chroot assim); env `MINITRUE_ROOT` |
| `--jobs N` | paralelismo passado aos builds (`$JOBS`); default: nproc |
| `--offline` | proíbe rede; só aceita artefato já presente no cache |
| `--no-binary` / `--only-binary` | `rectify`: força build de fonte / proíbe o fallback de fonte (SPEC-0009 §5) |
| `NEWSPEAK_PATH` (env ou `conf`) | árvores de receitas separadas por `:`, em ordem de precedência — a primeira ocorrência do pacote vence (herança `KISS_PATH`); default `/var/lib/minitrue/newspeak` |
| `--tofu` | permite receita sem `SHA256`: baixa, calcula, imprime a linha `SHA256=…` pronta para colar, instala com aviso gritante. Se a receita pina `SIGKEY`, a assinatura continua obrigatória mesmo em TOFU — é o que torna a repinagem de versão segura. NÃO DEVE existir em builds de release da ferramenta destinados a usuários finais. É a única exceção a P6, e reconciliada lá: o TOFU **cria** o pino (aid de autoria), não o dispensa — SPEC-0001 P6 |

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
- Reinstalar uma máquina = `minipax --world <arquivo>` (SPEC-0008).
- A dualidade que organiza a ferramenta: **o registro é o fato; o world é
  a intenção.** `verify` confere fatos; `--sync` reconcilia a intenção.

## 3. Fluxo de `rectify`

1. **Carregar receita** (SPEC-0004): avaliada por `sh`, campos lidos de
   volta. Receita inválida ⇒ erro 2.
2. **Pré-condições**: `REQUIRES_GLIBC=1` e ausência de
   `/usr/lib/ld-linux-x86-64.so.2` ⇒ erro 5 com mensagem indicando o
   Estágio 2 (SPEC-0005).
3. **Dependências** (`DEPS`): resolução por busca em profundidade com
   detecção de ciclo; instala o que falta, na ordem. Sem comparação de
   versões — a árvore newspeak em um commit é o conjunto consistente.
4. **Fetch**: para cada URL de `SRC`, baixar para
   `/var/cache/minitrue/<sha256>` (nome do arquivo no cache = hash
   esperado). Se já existe com hash válido, rede não é tocada.
   Idempotência: pacote já na versão da receita e `verify` limpo ⇒ no-op
   ("os registros já estão corretos").
5. **Verificação**: (a) SHA-256 do artefato ≠ pinado ⇒ apagar o download,
   erro 3, mensagem *crimestop* com esperado/obtido. Sem flag de contorno.
   (b) Se a receita pina assinatura (`SIG`/`SIGSUMS`, SPEC-0004 §5), ela é
   conferida contra a chave versionada na árvore, com verificador embutido
   no próprio minitrue — nunca chamando gpg externo. Falha ou ausência do
   arquivo de assinatura ⇒ erro 7. Assinaturas são reconferidas mesmo em
   cache-hit; sob `--offline`, a assinatura precisa estar no cache.
6. **Instalação**:
   - **Mundo A** (`KIND=binary`): executa `install_pkg()` da receita com
     `PREFIX=/opt/<nome>/<versão>.tmp`; sucesso ⇒ rename atômico para
     `/opt/<nome>/<versão>`, flip do symlink `current`, criação dos links
     de comando (`LINKS`) em `/usr/bin`.
   - **Mundo B** (`KIND=source`): antes de compilar, consulta os canais
     binários (SPEC-0009) por um binário pré-buildado da versão da receita;
     havendo um aceitável, o instala **como mundo B pré-buildado** — mesmo
     *fetch* de um tarball passivo (baixa/verifica/extrai), mas layout mundo
     B (árvore em `/usr`, `/etc`→factory, manifesto plano, `WORLD=B`), **não**
     em `/opt` — e o `build()` não roda (SPEC-0009 §4). Só na falta é que
     executa `build()` com
     `STAGE=` (DESTDIR)
     em diretório temporário; sucesso ⇒ checagem de colisão (§7) ⇒ cópia
     para `/`; se já havia versão anterior, caminhos órfãos do manifesto
     antigo são removidos após a cópia (upgrade = instalar novo + varrer
     sobras). Conteúdo de `etc/` no staging **não vai para `/etc`**: é
     desviado para `/usr/share/factory/etc/` e materializado pela política
     do administrador (SPEC-0002 §6) — copia se ausente; se existir
     modificado, grava `<arquivo>.new` ao lado e avisa; o hash do default
     pristine entra no registro (§6).
7. **Registro**: grava `/var/lib/minitrue/records/<nome>/{meta,manifest,recipe}` (§6);
   nomes pedidos explicitamente na linha de comando entram no `world` (§2).
8. **Falha de build**: log integral movido para
   `/var/log/room101/<nome>-<versão>.log`; staging descartado; nada é
   tocado no sistema real. Mensagem cita o caminho do log.

## 4. Fluxo de `memoryhole`

1. Ler manifesto; remover na ordem inversa: links de comando, árvore
   `/opt/<nome>` (mundo A) ou cada caminho listado (mundo B); diretórios
   que ficarem vazios são removidos.
2. Preservados por padrão: `/etc/opt/<nome>`, `/var/opt/<nome>` e qualquer
   arquivo cujo sha256 diferir do registrado no manifesto (§6) — modificado
   pelo usuário ⇒ fica, com aviso. É o hash por arquivo do registro v1 que
   torna essa promessa **enforçável** (sem ele, não há como saber o que o
   usuário mexeu). `--tudo` remove também esses.
3. Registro apagado por último. Saída: `"<nome> nunca existiu."`
4. Pacote requerido por outro registro (`DEPS` reversa) ⇒ recusa com a
   lista de dependentes; `--force-orfaos` não existe no v0.

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
- Ambos os comandos recusam pacotes do mundo B com explicação: lá os
  arquivos em `/usr` **são** a instalação; não existe o que flipar.

**Política de retenção** (resolve a questão aberta da SPEC-0002):
`rectify` retém a versão anterior ao atualizar (corrente + 1); mais velhas
são removidas no upgrade. `memoryhole` remove tudo. Ajustável via
`KEEP_VERSIONS` em `/etc/minitrue/conf`.

## 6. O registro (`/var/lib/minitrue/records/<nome>/`)

Três arquivos-texto:

- `meta` — `VERSION=`, `KIND=`, `WORLD=A|B`, `SHA256=` (por artefato),
  `FINGERPRINT=`, `INSTALLED_AT=` (ISO-8601), `RECIPE_COMMIT=` (se conhecido).
  O **`FINGERPRINT`** é a identidade de build (SPEC-0011 §4): sha256 do
  arquivo `recipe` inteiro + do `files/` (via o `pack` determinístico). A
  idempotência do `rectify` compara **versão E fingerprint** — uma receita
  corrigida com a mesma versão muda o fingerprint e re-builda (conserta o
  "GCC 15.3.0 mudou várias vezes sem bump"). Limite do v1: não é transitivo
  (mudança num build-dep não muda o fingerprint do dependente).
- `manifest` — uma entrada por linha, ordenada, no formato `sha256sum`:
  **`<sha256>␠␠<caminho absoluto>`** (registro **v1**) — o hash do conteúdo
  instalado. Symlinks e diretórios levam `-` no lugar do hash (o alvo do
  link é conferido à parte). Para mundo A: a raiz `/opt/<nome>/<versão>` e
  cada link criado em `/usr`. O hash por arquivo é o que sustenta o veredito
  intacto × modificado do `memoryhole` (§4) e dá ao `verify` integridade por
  arquivo — não só para `/etc`.
- `recipe` — cópia fiel da receita usada (torna `memoryhole` e `verify`
  independentes de mudanças posteriores na árvore newspeak).

Mundo A com retenção: `manifest` e `recipe` ganham cópia por versão retida
(`manifest@<versão>`, `recipe@<versão>`); `meta` registra a versão ativa e
o estado (`UNPERSON=1` quando desativado). É o que permite `rollback` e
`unperson`/reativação relinkarem sem rede (§5).

Mundo B: os hashes dos defaults de `/etc` materializados também ficam no
registro — é a base do veredito intacto × modificado-pelo-admin que o
`verify` emite (§3, passo 6).

## 7. Colisões (*doublethink*)

Antes de copiar staging para `/`, cada caminho é conferido contra os
manifestos existentes. Caminho já reivindicado por outro pacote ⇒ erro 4:

```
doublethink detectado: /usr/bin/rg já pertence a ripgrep 15.2.0
```

Sem `--force`. A resolução é humana: ajustar a receita (renomear link,
retirar arquivo) e commitar na árvore newspeak.

## 8. Execução de receitas e confinamento

- Receitas rodam via `sh -e`, com ambiente mínimo controlado (§ SPEC-0004
  define as variáveis do contrato: `DL`, `WORK`, `PREFIX`/`STAGE`, `JOBS`,
  `CC`…).
- Regra normativa: receita NÃO DEVE acessar rede (todo insumo entra por
  `SRC`) nem escrever fora de `WORK`/`PREFIX`/`STAGE`. Para builds de um
  rootfs (`--root` != `/`), isso já é **sandbox**, não só contrato: o
  executor os roda dentro do rootfs via `bwrap` com `--clearenv` (ambiente
  hermético) e `--unshare-net` (sem rede) — SPEC-0005. **Dívida restante:** o
  build no próprio sistema (`--root /`) ainda roda direto (sem netns nem
  usuário dedicado), e o mundo A (`install_pkg`) ainda não é sandboxado.
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
| 7 | assinatura upstream inválida ou ausente (*crimestop*, variante assinatura) |

Tom das mensagens: diagnóstico primeiro, tema depois (SPEC-0001 §3).
Sucesso de `rectify` termina em `doubleplusgood.`; `verify` limpo:
`thinkpol: nenhum wrongthink.`

## 10. Implementação v0 (Rust)

- Crates: `ureq` (HTTP, rustls), `sha2`, `hex`, `anyhow`. Verificação de
  assinaturas embutida no binário: `minisign-verify` para minisign/signify
  e OpenPGP destacado via crate puro-Rust (candidata: rPGP) — **sem gpg em
  runtime**. Nada de async. Ensaio verificado no spike (SPEC-0005 §8):
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

- ~~hash por arquivo instalado fica para v0.2~~ — **decidido: entra já**
  (registro v1, §6): o manifesto guarda `<sha256>␠␠<caminho>`. É o que torna
  enforçável a promessa do `memoryhole` de preservar arquivo modificado (§4)
  e dá dentes ao `verify` (integridade por arquivo, não só presença). O
  `install_source` do minitrue hoje grava só o caminho — **implementação
  pendente** (hashear cada arquivo copiado ao montar o manifesto).
- A própria árvore newspeak como pacote gerido (`minitrue rectify newspeak`
  puxando tarball do repositório oficial da Distrópica): elegante e
  resolve atualização sem git instalado; especificar o pacote especial —
  com a infra de assinaturas do v0.2, o tarball da árvore DEVERIA vir
  assinado (minisign) com a chave do projeto. **É o motor do modelo rolling
  edge (SPEC-0011 §3.1) — a peça que faz a árvore, logo o sistema, avançar
  para o estável-mais-novo (P7).**
- Downloads paralelos e retomada (range requests): v0.2.
