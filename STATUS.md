# STATUS — o que está feito, testado e futuro

Fonte única da verdade sobre a maturidade. As `specs/` descrevem a **norma**;
este arquivo descreve o **estado**. Atualizado à mão (2026-07-21, após o canal
binário assinado, a instalação offline do perfil mínimo e o aceite final-v10
do BOOT EFI vivo com instalação, segundo boot sem ISO e recusa antes do wipe de
um `profile.lock` incoerente com `media.meta`).
Legenda: ✅ feito · 🟡 parcial · ⬜ design/futuro.

## minitrue (a ferramenta)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| `rectify` mundo A (vendor → /opt) | ✅ | 🟡 unit | fluxo real pouco coberto |
| `rectify` mundo B (fonte → /usr) | ✅ | 🟡 unit | exercido no E2 e numa execução E2-clean a frio |
| Perfis de toolchain (seed/cross/native) | ✅ | ✅ | parsing + seleção testados |
| Receitas de montagem (sem SRC) | ✅ | ✅ | `build()` gera o pacote (config, esqueleto de /etc) — nada a baixar; usada pela receita `base`, dogfooda a fábrica /etc |
| Runner mundo B em rootfs (bwrap, --unshare-net, --clearenv) | ✅ | ✅ | isola rede/ambiente do `build()`, mas o **rootfs fica gravável**; avaliação top-level da receita e mundo A ainda rodam no host |
| `retry` de ICE | ✅ | — | usado no E2 |
| `fingerprint` de build | ✅ | ✅ | **transitivo**; snapshot de `recipe`+`files/`, e o mesmo `files/` autocontido é materializado no `WORK` (symlinks auxiliares são recusados) |
| Supersessão provisional (`PROVISIONAL` + `SUPERSEDES=`) | ✅ | ✅ | declarativa; no mundo B a cessão volta se a instalação falha. `SUPERSEDES` fica no registro e prova cadeias provisional→provisional; mundo A e restauração ao remover sucessor ainda faltam |
| `pack` determinístico (v1) | ✅ | ✅ | a parte mais madura; falta xattr/ACL/cap/sparse |
| Manifesto v2 (conteúdo + tipo) | ✅ | ✅ | `f:` prende modo+conteúdo do regular, `l:` prende alvo, `d:` prende modo do diretório-raiz+árvore (payload A e vazios B); leitura v0/v1 mantida |
| `verify` (presença + integridade por claim) | ✅ | 🟡 | inspeção confinada ao rootfs; confere conteúdo/tipo/alvo/árvore e denuncia journal pendente/formato futuro; não varre regulares órfãos em /usr nem fecha o grafo de deps |
| `memoryhole` (+ preserva modificado) | ✅ | 🟡 | sem `--tudo`; sem rollback do payload |
| `explain` / `why` (proveniência) | ✅ | ✅ | ORIGIN/hash-arq; ABOUT/REPROCORR congelados no meta, com fallback literal legado sem executar receita histórica; corroboração e reprocorr |
| `--sync` (convergir ao world) | ⬜ | — | stub; SPEC-0011 |
| `rollback` / `unperson` / `lint` | ⬜ | — | stub |
| Canal binário assinado | ✅ | ✅ unit + E2E offline | config HTTPS/chave minisign pinada, índice canônico v2 assinado com `RECIPE_FINGERPRINT`, cache endereçado por conteúdo, `.tar.zst` com limites e conferência do tar interno; seleção exige que a identidade autenticada coincida com a receita efetiva. `/etc/minitrue/channels/` existente é autoritativo e, vazio, desativa a seed |
| Resolução `--no-binary` / `--only-binary` | ✅ | ✅ unit + E2E offline | binário de canal preserva mundo B; `--only-binary` falha sem artefato e não expande `BUILD_DEPS` |
| Lock de canal | ✅ | ✅ unit + E2E offline | `CHANNEL_LOCK_FORMAT=2`; seleção, chave, índice, pacote, fingerprint autenticado, caminho, hash de transporte, `reprocorr` e trust; persistido por hash em `/var/lib/minitrue/channel-locks/` e cotejado semanticamente por `verify` |
| `channel emit` | ✅ | ✅ unit | `CHANNEL_EMIT_FORMAT=2`; reutiliza o tar autenticado do cache para registros vindos de canal e só reconstrói registros locais quando topologia, metadados e `ARTIFACT_HASH` podem ser provados; emite pool + índice sem assinatura. Release deve emitir no próprio build |
| Gestão de canais (`add/remove/list/refresh`) | ⬜ | — | hoje a configuração é administrada por arquivos estritos; em especial, não há `channel refresh` auditável. A CLI administrativa da SPEC-0009 é gate de release |
| Lock global por rootfs (flock) | ✅ | ✅ | rectify/memoryhole; auto-libera na saída |
| Confinamento de caminhos destrutivos | 🟡 | ✅ unit | `openat2(RESOLVE_IN_ROOT)` em inspeção/remoção; Journal aceita usr-merge interno e recusa ancestral que resolve fora do rootfs, mas mutações do Journal ainda usam caminhos após o preflight. Converter tudo a operações fd-relative para fechar TOCTOU contra mutador concorrente é gate de release |
| Registro transacional do mundo B (meta = commit) | ✅ | ✅ | `manifest`/`recipe`/`meta` entram no journal; `TRANSACTION_ID` do meta, escrito por último, decide recovery |
| `RECORD_FORMAT=` | ✅ | ✅ | hoje 2; v0/v1 pode migrar in-place sob guardas ou reconstrói; provisional já cedido congela; formato futuro falha fechado |
| Journal + rollback do mundo B (STAGE→/) | ✅ | ✅ | formato 2 + `txid`; intenção antes da mutação; recovery **global** antes de nova operação; journal legado, >1 ativo ou rollback sobre claim posterior falha fechado e preserva backups. Sem promessa contra perda de energia: falta `fsync` |
| `SUPERSEDES=` explícito | ✅ | ✅ | declarado em 6 receitas do E2; colisão não-declarada = doublethink |
| Assinatura upstream por artefato (`SIG`) | ✅ | ✅ | minisign/signify; cache prende hash do artefato+chave+URL e é revalidado |
| Verificação OpenPGP / `SIGSUMS` | ⬜ | — | parser reconhece os campos, executor falha explicitamente; Marco 0.2, sem `gpg` externo |
| `reprocorr` (raiz de confiança) | ✅ | ✅ | build de fonte grava `ARTIFACT_HASH`=`pack(STAGE)`; receita que pina `REPROCORR` exige reprodução (crimestop). SPEC-0009 §8.1 |
| Attestation + corroboração (`attest`/`corroborate`) | ✅ | ✅ | `ATTEST_FORMAT=1`, ed25519-dalek; versão+fingerprint impedem replay e a emissão exige registro v2, txid, baseline, snapshots e claims íntegros. ≥2 builders pinados concordam. **Independência ainda simulada** (1 máquina) |

## minipax (perfil, instalação e mídia)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| CLI única (`install`, `media build`, `lock`) | ✅ | ✅ unit | binário Rust separado; `bootstrap/distropica-bootstrap` apenas o localiza/compila e delega |
| Perfil estrito + `profile.lock` | ✅ | ✅ unit | normaliza worlds; o lock prende hashes Newspeak/overlay/cache, arch, epoch, `MEDIA_SIZE_MIB`, `INSTALL_READY` e os três pinos oficiais. Release exige `INSTALL_READY=yes` e pinos `CONTENT`+`BOOT_EFI`+`MINITRUE`; conteúdo divergente vira `custom` |
| Instalação em rootfs (`--target`) | ✅ | ✅ unit + E2E dev offline | prepara FHS/usr-merge, congela Newspeak/cache, chama `rectify --only-binary` + `verify`, aplica overlay e promove pending→lock; perfil oficial + override de cache assinado fecha `base`+`linux` e recebe classe `custom` |
| Ingestão de mídia (`install-media`) | ✅ | ✅ unit | valida controles sem seguir symlinks, hashes de lock/EFI, coerência modo/cache e reconstitui o perfil byte a byte antes de tocar no target; `--export-boot-efi` cria sem sobrescrever o snapshot EFI validado e o remove se a instalação falhar |
| Executor e `install.manifest` | ✅ | 🟡 unit + E2E dev | copia Minitrue para `memfd` selado, mede o Minipax, persiste ambos em `/usr/bin`; manifesto prende hashes, classe e opções `OFFLINE`/`FROM_SOURCE`/`ONLY_BINARY`. O target mínimo exige executores estáticos para usá-los após o boot |
| Retomada e proteção do target | ✅ | ✅ unit | recusa `/`, target sujo e perfil divergente; `--resume` exige marca anterior do Minipax |
| IMG GPT+FAT32 | ✅ | ✅ unit local | GPT/FAT internos; GUIDs e serial FAT derivam do hash do payload completo. Duas composições da fixture dão o mesmo sha256; ainda não há prova entre builders nem de boot |
| ISO UEFI/El Torito | ✅ | ✅ unit local | fixa metadados; usa caminho absoluto do `xorriso`, hash antes/depois e ambiente fechado, registra versão+hash e pós-valida `CD001`. Reproduziu só localmente |
| Sidecars (`.sha256`, `.media.lock`, `.manifest`) | ✅ | ✅ unit | temporários publicados sem sobrescrever antes da imagem; não há transação multi-arquivo, logo corrida/falha pode deixar sidecars sem imagem |
| Classes de insumos de release | ✅ | 🟡 unit | `PROFILE_CLASS`, `MEDIA_CLASS` e `INSTALL_CLASS` podem ser `official-inputs` após os respectivos pinos; isso não declara reprodução oficial |
| Modos canônicos das árvores | ✅ | ✅ unit | dirs `0755`, `root/` do overlay `0700`, `shadow`/`gshadow` e backups `0600`, executáveis `0755`, demais regulares `0644`; não depende dos modos que o Git preserva |
| Limites das árvores | ✅ | 🟡 unit | 128 MiB e 50.000 entradas por árvore Newspeak/overlay/cache; conteúdo e tar ficam em memória. No canal, `.tar.zst` selado e tar descompactado coexistem, somando o pico de RAM; streaming é gate de release |
| Modo offline/cache | ✅ | ✅ unit + E2E dev | cache assinado fecha o perfil mínimo sem rede; ainda limitado a 128 MiB/50 mil entradas e materializado em memória |
| Modo online/bootstrap de canal | ✅ | ✅ unit | Minipax exige config + índice/assinatura pareados, rejeita objetos e semeia antes de `rectify`; Minitrue valida minisign no uso. Não há endpoint oficial para E2E |
| BOOT EFI vivo (kernel+initramfs+Minipax+Minitrue) | ✅ | ✅ E2E final-v10 | fixa Linux 7.1.4, BusyBox e executores musl `static-pie`. `CONFIG_MODULES=y`, nenhum `.ko` na mídia e release `7.1.4-distropica-live`; drivers necessários são built-in e deliberadamente estreitos |
| Instalação por ISO em QEMU/OVMF | ✅ | ✅ E2E final-v10 | antes de escolher disco, materializa closure em `/run` e exporta snapshot EFI validado; depois particiona, copia, verifica, instala EFI e publica o marcador completo por último. Segundo boot ocorreu sem ISO |
| Boot da IMG em QEMU/OVMF | 🟡 | — | compositor IMG existe e reproduziu localmente; o aceite funcional final-v10 exercitou somente a ISO |
| Particionamento/escrita destrutiva em disco | ✅ | ✅ QEMU/OVMF final-v10 | PID 1 só recebe/autoriza `/dev/vda` depois do preflight em `/run`; ISO com lock incoerente deixou um disco zerado intacto. Cria MBR com ESP FAT32 de 64 MiB + raiz ext2; não é ainda um particionador geral |

O perfil `profiles/official` continua com `STATUS=development`, mas agora
declara `INSTALL_READY=yes`: há uma closure mínima materializável com o cache
assinado de desenvolvimento. Como ele é passado por `--cache`, o E2E recebe
classe `custom`; isso não publica o cache nem cria um canal oficial. Mesmo uma
futura classe `official-inputs` não será, por si,
reprodução oficial: isso dependerá do sha256 final pinado num manifesto
oficial externo assinado.

O aceite final-v10 executou ISO → disco vazio → segundo boot sem ISO, com rede
ausente e TCG. Duas composições locais da ISO foram byte a byte idênticas. Uma
ISO cujo `profile.lock` não correspondia ao hash de `media.meta` foi recusada
ainda no preflight, e o disco de teste permaneceu igual a um arquivo zerado de
256 MiB. Esse probe negativo foi encerrado no shell de rescue pelo timeout; o
`RESULT=pass` abaixo pertence somente ao aceite positivo de duas fases:

```text
EVIDENCIA_FINAL_V10=local-development
ACCEPTANCE_META=target/qemu-acceptance-final-v10/acceptance.meta
RUN_STATE=completed
NETWORK=none
ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
REPEATED_ISO_SHA256=c48b43674ad17d9993862c8ce0fbb8dae4ec4622be35d1d07c750d6ee2e7dae8
BOOT_EFI_SHA256=c8a884845aa1568c4e51756f2a26c1b21652969367957387c5efdfb616e3204c
INSTALL_LOG_SHA256=d94ad6d3abdb99d29674c383f11106a0a23774f91b153dc1cee1b03b64d61540
BOOT_LOG_SHA256=f3e3a80d76bffd7bbb6a995a9186d1d66c4ae8902e645e48db2e3421ef69f133
CORRUPT_ISO_SHA256=c13e3d42ccc6e2129e73f8fa8df629c17803fff2a6ede756519c86791786dcf8
CORRUPT_INSTALL_LOG_SHA256=5c1004263db4ca6323ae8630cf51ceb7a313350424ad40d1886b75deadd0ebb3
CORRUPT_DISK_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
ZERO_256_MIB_SHA256=a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484
RESULT=pass
INCONSISTENT_PROFILE_LOCK_RESULT=refused-before-wipe
```

Mesmo quando preenchidos, esses hashes identificarão uma execução do workspace
de desenvolvimento; não serão pinos de release nem substituirão manifesto
externo assinado. Endpoint, chave e publicação oficiais continuam ausentes.

## Bootstrap (SPEC-0005)

| Estágio | Estado | Nota |
|---|---|---|
| E0 — chroot musl-estático | ✅ | |
| E1 — `./configure && make` | ✅ | |
| E2 — glibc + gcc nativo | ✅ | **E2-clean: reproduzido a frio** (rootfs novo, seed limpo, 16 pacotes, gcc nativo compila C/C++, libs finais em /usr/lib). Falta só repetir num 2º ambiente independente |
| E3 — kernel + boot QEMU | 🟡 | O smoke anterior bootou Linux 7.1.4 do E2 com raiz 9p e exercitou módulos assinados. Separadamente, o EFI-stub live passou no E2E ISO→disco→boot sem mídia. E3 segue parcial por faltar runit, `.config` de hardware geral e gestão completa de contas |
| — openssl 4.0.1 (base de confiança do kernel) | ✅ | mundo B, compilado pela toolchain nativa (libcrypto/libssl, `-DZLIB`); SHA conferido no download. Habilita geração/uso da chave de módulos; **attestation usa ed25519-dalek e independe de OpenSSL**. O materializador de `/etc` agora trata symlinks, com regressão coberta |
| — base 0.1 (config Fase B) | ✅ | — | receita de montagem: `/etc/inittab`+`rc.d/rcS`+`rcK`+`os-release`+`hostname` via fábrica; não cria `/etc/shadow`, portanto sozinha não fecha login autenticado |
| E4 — userland vendor / GUI | ⬜ | |

## Reprodutibilidade (SPEC-0010)

| Item | Estado |
|---|---|
| Ambiente determinístico (epoch/LC/TZ/umask) | ✅ |
| `ar` determinístico | ✅ |
| m4, gmp, **gcc**, **glibc** byte-idênticos (2 builds) | ✅ |
| Hash de artefato via `pack` = `reprocorr` | ✅ (m4/gcc/glibc) |
| `REPROCORR` pinado + verificado no build | ✅ (`m4` pina; build de fonte grava `ARTIFACT_HASH` e exige reproduzir o pinado — crimestop se divergir) |
| Cotejo do artefato completo produzido pelo E2-clean | ⬜ (passo posterior à primeira execução a frio) |
| Identidade declarativa do sistema (`profile.lock`) | ✅ (conteúdo normalizado; lock inclui tamanho, prontidão, hash calculado e os três pinos oficiais) |
| Executor da instalação medido = executado | ✅ local (`memfd` selado, ambiente fechado e hash no `install.manifest`) |
| Rootfs instalado byte-a-byte idêntico | ⬜ (`INSTALLED_AT`, uid/gid e demais metadados ainda impedem o claim) |
| IMG byte-idêntica em duas composições | ✅ local (fixture, mesmo binário/toolchain; GPT/FAT normalizados) |
| ISO byte-idêntica em duas composições | ✅ local para fixture e para a ISO final-v10 (mesmo binário e mesmo `xorriso`, cujo executável é medido) |
| IMG/ISO byte-idênticas entre builders independentes | ⬜ |
| Reprodução reconhecida contra manifesto oficial externo assinado | ⬜ (sidecars locais não são autoridade) |
| Boot e instalação funcionais da mídia de desenvolvimento | ✅ final-v10 em QEMU/OVMF; inclui segundo boot sem ISO e negativo fail-before-wipe |

## Limitações conhecidas (do parecer externo)

- **E2-clean feito (uma vez):** reproduzido a frio de um rootfs novo (seed
  limpo, grafo corrigido). Achou e consertou 2 bugs que o rootfs sujo mascarava
  (SUPERSEDES seed→busybox; libstdc++ lib64×lib usr-merge). Falta repetir num
  **2º ambiente independente** para "reproduzível ×2" e mover scripts, hashes
  e logs de prova hoje transitórios para um diretório versionado `proofs/e2/`.
- **Mídia instalável validada em QEMU/OVMF:** o aceite final-v10 cobriu a ordem
  atual. O PID 1 primeiro materializa e verifica toda a closure em
  `/run/distropica-prepared`, configura a conta e recebe de
  `install-media --export-boot-efi` um snapshot EFI medido. Somente depois pede
  ou aceita o disco, confere capacidade, particiona, copia, roda
  `minitrue verify`, grava o EFI e publica por último
  `disk-install.complete`. O teste negativo confirmou a recusa de um
  `profile.lock` incoerente com `media.meta` antes de qualquer wipe. Isso ainda
  não prova boot
  da IMG, hardware real, reprodução entre builders ou release oficial.
- **Gates do perfil oficial:** o canal e `--only-binary` estão implementados,
  e o perfil marca `INSTALL_READY=yes`, mas o cache usado no E2E é uma migração
  de desenvolvimento com `TRUST=builder`. Ainda não há endpoint, chave de
  release, índice ou artefatos oficiais publicados. A verdadeira meta-receita
  `base`, runit e a política uid/gid continuam abertos; `base` ainda é
  `base-config` de fato. `profiles/official` permanece
  `STATUS=development`, portanto nenhuma saída recebe a classe de insumos
  oficiais. `STATUS=release` já exige três pinos separados:
  `OFFICIAL_CONTENT_SHA256`, `OFFICIAL_BOOT_EFI_SHA256` e
  `OFFICIAL_MINITRUE_SHA256`. A coincidência gera apenas `official-inputs`; o
  claim de reprodução depende de comparar o sha256 final com um manifesto
  oficial externo assinado, cuja publicação ainda não existe.
- **Cobertura do kernel vivo:** o `.config` inicial cobre UEFI x86_64,
  virtio, CD/SCSI, AHCI/PIIX, ISO9660, ext2/ext4 e FAT. Isso é suficiente para o
  alvo QEMU, não para afirmar suporte genérico a controladores NVMe, USB,
  rede, vídeo e armazenamento encontrados em hardware real. O kernel mantém
  `CONFIG_MODULES=y`, mas o initramfs não leva módulos; tudo que a instalação
  precisa deve estar built-in. `LOCALVERSION=-distropica-live` produz o
  release `7.1.4-distropica-live`, isolando a busca automática de
  `/lib/modules/7.1.4` que pertence ao kernel do target.
- **Kernel EFI embutido:** o mesmo `BOOTX64.EFI` da mídia é copiado para a
  ESP do sistema instalado. Como kernel e initramfs estão incorporados, uma
  atualização de `/boot/vmlinuz-*` pelo canal não atualiza automaticamente o
  EFI de boot; retenção/rotação e atualização atômica do EFI são gates.
- **Publicação da mídia não é transação de conjunto:** os três sidecars são
  preparados e publicados sem substituição antes da imagem. Isso evita imagem
  publicada pelo Minipax sem sidecars, mas corrida ou falha pode deixar parte
  ou todos os sidecars sem imagem; não existe rollback multi-arquivo.
- **Escala do Minipax:** cada árvore Newspeak, overlay ou cache está limitada a
  128 MiB e 50.000 entradas e é materializada integralmente em memória, junto
  do tar normalizado. O consumo do canal mantém simultaneamente o transporte
  `.tar.zst` selado e o tar descompactado; o pico de RAM aproxima a soma dos
  dois. O instalador vivo acrescenta a raiz pré-validada em `/run`, trocando
  memória por garantia fail-before-wipe. O perfil mínimo offline cabe nesse
  envelope; ampliar o world exigirá streaming e provavelmente uma partição de
  dados separada.
- **Escala do canal:** o consumidor sela transporte e tar e limita cada um a
  16 GiB, mas ainda não limita a quantidade de entradas do tar. Um objeto
  assinado enorme pode esgotar memória no preflight — sem alcançar o wipe, mas
  tornando a instalação indisponível. Streaming e limite de entradas são gates.
- **Resgate depois do wipe:** falhas verificadas de cópia, hash, sync e
  desmontagem entram no shell de rescue e o marcador final continua fail-closed.
  Alguns comandos auxiliares pós-wipe ainda dependem apenas de `set -e`; se um
  deles falhar, PID 1 pode encerrar em vez de abrir o rescue. Uniformizar esse
  tratamento é gate de robustez do instalador.
- **Destino de `--export-boot-efi`:** a mídia viva usa um pai `0700` sob
  `/run`, mas a CLI genérica remove a exportação por pathname se a instalação
  falha. Chamadores privilegiados devem usar diretório de confiança até a
  limpeza ser convertida para operação fd-relative com identidade presa.
- **Bootstrap ainda é de desenvolvimento:** a casca versionada compila
  `minipax` e `minitrue` com Cargo (ou aceita binários indicados pelo ambiente)
  e delega. Por padrão usa `x86_64-unknown-linux-musl`, exige compilador C
  compatível + `readelf` e recusa executável com segmento `INTERP`: os binários
  produzidos são musl `static-pie`, não ligados ao host. Caminhos explícitos em
  `MINIPAX`/`MINITRUE` continuam insumos do usuário. Um bundle imutável e
  assinado para download direto em outra distribuição ainda não foi publicado.
- **Transacional (mundo B):** payload, registro e cessões de manifesto passam
  pelo journal por pacote. Cada intenção precede a mutação; o `TRANSACTION_ID`
  do `meta` é a marca final. Sob o lock, um sweep recupera o único journal antes
  de qualquer nova operação; estados antigos com mais de um journal, ou rollback
  que atingiria ownership commitado depois, falham fechado e preservam backups.
  `verify` continua somente diagnóstico. O mundo A não possui transação de
  conjunto. **Não há `fsync`**, portanto não se promete recuperação após perda
  de energia. Também falta restaurar o payload provisional ao remover sucessor.
  Além disso, o Journal ainda faz parte das mutações por caminhos após validar
  ancestrais. O `flock` impede apenas concorrentes cooperativos; um mutador
  hostil com acesso ao mesmo rootfs pode explorar uma janela TOCTOU. Operações
  integralmente fd-relative e confinadas são gate de release.
- **Registro v2:** o fast path exige `meta`, `manifest`/`manifest@` e
  `recipe`/`recipe@` coerentes com o snapshot corrente; prende conteúdo de
  regulares, alvo de links e modo+árvore de diretórios. `manifest@` é baseline
  de provisional e a exceção legado exige dono sucessor para cada claim
  removida (inclusive por sucessor provisional que registre `SUPERSEDES`).
  Ainda não registra xattrs/ACLs/capabilities, uid/gid ou timestamps.
- **Fidelidade de aplicação:** o mundo B sela o tar normalizado num `memfd`,
  indexa-o e copia regulares diretamente por offset; hash e instalação veem os
  mesmos bytes. Isso é Linux-only e custa RAM/swap proporcional ao artefato.
  `pack` preserva nomes não-UTF-8 e hardlinks, mas `rectify` os recusa até o
  Journal instalá-los sem mudar a topologia atestada. A aplicação reproduz
  tipo, bytes e modo, não uid/gid/mtime/xattrs/ACLs/caps; o fallback `EXDEV`
  também não preserva hardlinks e recusa diretórios/especiais entre mounts.
- **Diretórios compartilhados:** claims `d:` bloqueiam sobreposição
  pai×descendente entre pacotes. Remoção mundo B usa apenas `rmdir` e preserva
  diretório que ganhou filhos; mudança de modo de diretório vazio preexistente
  é recusada, não silenciosamente aceita.
- **Sandbox parcial:** no mundo B de outro rootfs, bwrap isola rede e ambiente,
  mas monta o rootfs gravável. A avaliação top-level da receita e o mundo A
  ainda executam no host. Ideal: parse declarativo ou sandbox de avaliação,
  rootfs read-only e binds graváveis apenas para WORK/STAGE.
- **Escala de memória:** `Command::output` acumula stdout/stderr de build e
  `install_pkg`; artefatos grandes também ficam integralmente no `memfd` selado.
  Logs/artefatos devem migrar para streaming antes de tratar imagens grandes.
- **Attestation local:** a emissão prova coerência do registro e do payload que
  ainda está instalado, mas `ARTIFACT_HASH`/`FINGERPRINT` sem pino externo ainda
  são campos locais. Provar contra adulteração privilegiada posterior exige
  retenção do artefato selado, índice/canal assinado ou attestation no build.
- **Confiança de canal vs P6:** o índice v2 assinado carrega o
  `recipe_fingerprint`, e a seleção exige que ele coincida com a receita
  efetiva; o lock v2 e o `CHANNEL_PATH` do registro preservam essa identidade,
  que `verify` coteja semanticamente. Sem `REPROCORR`, porém, o hash continua
  autenticando o publicador, não uma reprodução independente. Também não há
  monotonicidade externa para impedir que um servidor reapresente um índice
  antigo ainda corretamente assinado.
- **Atualização administrativa de canal:** consumo, lock v2 e emissão existem,
  mas `channel add/remove/list/refresh` não. Sem um `refresh` explícito que
  valide assinatura, produza diff auditável e só então avance o snapshot, a
  operação rolling do canal oficial não está fechada; é gate de release.
- **Nomes canônicos:** hoje `gcc` = scaffolding, `gcc-pass2` = o GCC real;
  renomeação final ainda pendente mesmo após o E2-clean.
- **`base` ainda não é a meta-receita normativa:** o nome hoje pertence à
  configuração de boot e o parser ainda não implementa `KIND=meta`. A migração
  precisa preservar ownership dos rootfs que já registraram `base` antes de
  renomeá-la para `base-config` e criar o agregador do instalador.
- **Kernel ainda não é reproduzível entre builders:** a receita gera uma nova
  chave de assinatura de módulos em cada build. A política de release precisa
  separar o artefato reprodutível da assinatura/chave operacional.
- **ABOUTs desatualizados:** alguns descrevem dívidas já resolvidas. O valor é
  congelado no `meta` para `explain`; corrigir exige atualizar a receita e
  reinstalar o pacote.

## Ferramentas de CI (estado local)

`cargo test`/Clippy/fmt no `minitrue` e no `minipax` · `sh -n` em
receitas e nos scripts de bootstrap/canal/live. O teste ISO usa `xorriso`
quando disponível. ShellCheck e `cargo-audit` não instalados.
