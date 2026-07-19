# SPEC-0002 — Hierarquia de arquivos (FHS 3.0)

**Status:** rascunho v0.4 · 2026-07-19
**Referência:** Filesystem Hierarchy Standard 3.0 (2015).

## 1. Princípio: dois mundos, um padrão

A premissa "binário upstream primeiro" (SPEC-0001 P2) divide os pacotes em
dois mundos, e o FHS já tem lugar canônico para ambos:

| Mundo | O que é | Onde vive | Base no FHS |
|-------|---------|-----------|-------------|
| **A — vendor** | binário oficial do mantenedor, usado como veio | `/opt/<nome>/` | §3.13 (add-on application software) |
| **B — fonte** | compilado pela Distrópica por falta de binário | `/usr` (caminhos canônicos) | §4 |

Não há hierarquia inventada: nenhum `/store`, nenhum `/apps`, nenhum
symlink-farm exótico na raiz.

## 2. Mundo A — `/opt/<nome>`

- Cada pacote vendor DEVE ocupar exclusivamente `/opt/<nome>/`.
- Dentro da árvore do pacote, o minitrue mantém versões lado a lado e um
  apontador:

```
/opt/zig/0.16.0/…
/opt/zig/current -> 0.16.0
```

  (O FHS exige apenas que o pacote confine seus arquivos estáticos à sua
  árvore em `/opt/<nome>`; a organização interna é livre.)

- Comandos são expostos por symlinks **geridos pelo minitrue** em
  `/usr/bin/<cmd> -> /opt/<nome>/current/<caminho>` (precedente consagrado:
  é como o Chrome se expõe nas distros convencionais). Os links criados são
  registrados no manifesto do pacote (SPEC-0003 §6).
- Retenção: o `rectify` guarda a versão anterior (corrente + 1) para
  `rollback` de custo zero; não-pessoas (`unperson`) permanecem na árvore
  sem links. Ajuste via `KEEP_VERSIONS` (SPEC-0003 §5).
- Manuais de vendor (`share/man` dentro de `/opt/<nome>`): fora do farm no
  v0 — só `bin/` é linkado; exposição via `MANPATH` ou links fica para
  revisão futura.
- Reservas do FHS que o minitrue NÃO DEVE tocar: `/opt/bin`, `/opt/doc`,
  `/opt/include`, `/opt/info`, `/opt/lib`, `/opt/man` (pertencem ao
  administrador local).
- Configuração específica de host de pacote vendor: `/etc/opt/<nome>/`.
  Dados variáveis: `/var/opt/<nome>/`. `memoryhole` preserva ambos por
  padrão (SPEC-0003 §4.2).

## 3. Mundo B — `/usr` com manifesto

- Pacotes compilados instalam nos caminhos FHS canônicos (`/usr/bin`,
  `/usr/lib`, `/usr/share`, `/usr/include`…), via staging `DESTDIR` +
  sincronização (SPEC-0003 §3, passo 6). Sem subdiretório por pacote.
- A remoção limpa é garantida pelo manifesto (lista de caminhos), não por
  convenção de diretório. É o modelo clássico Slackware/CRUX.
- `/usr/local` é **inviolável**: o minitrue NUNCA escreve lá. É o espaço do
  usuário para experimentos manuais — parte concreta do "devolver a
  simplicidade" (o usuário compila o que quiser sem conflitar com o
  sistema).

## 4. usr-merge

A raiz adota o usr unificado, satisfazendo o FHS por resolução de symlink:

```
/bin  -> usr/bin
/sbin -> usr/bin
/lib  -> usr/lib
/lib64 -> usr/lib
```

`/lib64/ld-linux-x86-64.so.2` (exigido pelos binários vendor dinâmicos após
o Estágio 2) resolve para `/usr/lib/ld-linux-x86-64.so.2`.

## 5. Estado, cache e logs da ferramenta

| Caminho | Conteúdo | FHS |
|---------|----------|-----|
| `/var/lib/minitrue/records/<nome>/` | registro do pacote instalado: `meta`, `manifest`, cópia da `recipe` usada | §5.8 (state) |
| `/var/lib/minitrue/newspeak/` | árvore de receitas do sistema (atualizável; árvores extras via `NEWSPEAK_PATH`, SPEC-0003 §2) | §5.8 |
| `/var/cache/minitrue/` | artefatos baixados (nomeados por hash; sobrevivem a limpeza de pacote; `--offline` opera só daqui) | §5.5 |
| `/var/log/room101/<nome>-<versão>.log` | log integral de build que falhou | §5.10 |
| `/etc/minitrue/` | `conf` (chave=valor, poucas chaves) e `world` (pacotes desejados — SPEC-0003 §2) | §3.4 |

Todos os registros são texto puro, um fato por linha. O "banco de dados" é
greppável por construção.

## 6. Demais diretórios

- `/boot` — kernel e initramfs (a partir do Estágio 3).
- `/run` — tmpfs de runtime; diretório de serviços supervisionados ativos em
  `/run/service` (SPEC-0006 §4).
- `/etc` — **pertence ao administrador** (herança Clear Linux stateless +
  `.new` do Slackware): nenhum pacote é dono de arquivo em `/etc`. Os
  defaults de fábrica vivem em `/usr/share/factory/etc/`; a instalação
  copia para `/etc` apenas se ausente; upgrade nunca sobrescreve arquivo
  modificado — grava `<arquivo>.new` ao lado e avisa (fluxo: SPEC-0003
  §3). inittab, runit e sv vivem aqui como arquivos do administrador.
- `/home`, `/root`, `/srv`, `/tmp` — usos FHS convencionais.
- `/usr/src` — fontes em uso prolongado (ex.: kernel), opcional.
- `/etc/os-release` — `ID=distropica`, `NAME=Distrópica`.

## 7. Conformidade

- Desvios intencionais do FHS 3.0: **nenhum**.
- Notas de interpretação: usr-merge via symlinks (§4) é prática corrente e
  compatível; versões lado a lado dentro de `/opt/<nome>` são organização
  interna da árvore do pacote, permitida pelo §3.13;
  `/usr/share/factory/` é dado estático independente de arquitetura,
  regular sob o §4.11.

## 8. Questões em aberto

- Bibliotecas de vendor (`/opt/<nome>/lib`): nunca linkadas em `/usr/lib`
  (risco de *doublethink* com o mundo B); binário vendor que precisa delas
  usa rpath próprio ou wrapper. Confirmar caso a caso.
