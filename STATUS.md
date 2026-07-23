# STATUS — o que está feito, testado e futuro

Fonte única da verdade sobre a maturidade. As `specs/` descrevem a **norma**;
este arquivo descreve o **estado**. Atualizado à mão em 2026-07-22 após
reconstruir a closure atual, emitir o canal local assinado, compor a ISO e
concluir o aceite automatizado `miniplenty-v1` no VirtualBox. Vim e ripgrep
começam instalados; jq foi instalado do binário upstream, tree foi compilado da
fonte e a toolchain final passou nas provas C/C++/arquivo/Make, tudo offline.
Legenda: ✅ feito · 🟡 parcial · ⬜ design/futuro.

## Licenciamento e publicação

| Peça | Estado | Nota |
|---|---|---|
| Código e documentação próprios | ✅ | `GPL-3.0-or-later`; texto integral, escopo e regra de contribuição versionados |
| Licença na base e no ambiente vivo | ✅ E2E local | `base` instala a GPL e o aviso de escopo em `/usr/share/licenses/distropica/`, `build-efi` os incorpora no initramfs e a mídia atual foi recomposta e aceita |
| Inventário completo de terceiros | ⬜ gate de release | gerar por artefato, a partir dos insumos efetivamente distribuídos; os payloads compostos de Zig e `gcc-pass2` usam `NOASSERTION` até o SBOM conclusivo, sem perder licenças nem avisos upstream |
| Bundle de fontes correspondentes | ⬜ gate de release | publicar junto de toda futura ISO/EFI/cache/canal: fontes exatas, configs, patches, crates vendorizadas, scripts, licenças e hashes de associação |

Os hashes QEMU final-v10 e VirtualBox network-v1 abaixo são evidência histórica
anterior à mudança de licença do pacote `base` (revisão funcional `7148ebd`).
Não são pinos de uma mídia recomposta a partir da árvore licenciada atual.

## Evidência integrada atual — `miniplenty-v1`

A closure foi reconstruída a partir das receitas atuais e emitida num canal
local assinado de desenvolvimento com 11 artefatos. Uma instalação direta
`--offline --only-binary` e a instalação interativa por ISO passaram; esta
última percorreu três boots automatizados no VirtualBox 7.2.6. A ISO foi
ejetada antes do wipe, o segundo boot ocorreu offline, e o terceiro comprovou
persistência e a rede local do NAT. Isso é evidência `local-custom`, não release
oficial, hardware real nem reprodução entre builders.

```text
ISO=target/distropica-miniplenty-v1.iso
ISO_SHA256=bd71b63aada991578f0b6d3d87f7d67c88d4715e19566690ef6925991eafabc7
BOOT_EFI_SHA256=a800e2aca03dd62cd9e7db3bb894c24f7bdb1fdc19a26abf91566b3b824771b9
PROFILE_LOCK_SHA256=c84d6424646c78204ee822ff0a7617f941419130ea3c05cc60f4b320dc952f67
CHANNEL_INDEX_SHA256=9451dfa340802ac9109eaed017d9ca5d08ca220ce1fd65ac72bac28ff27c9396
ACCEPTANCE_META=target/vbox-miniplenty-v6/evidence/acceptance.meta
ACCEPTANCE_META_SHA256=2a88b7853a410c6de0ccbc4462de74ef7a307028cbd7a3356c47d7e02eed1561
DISK_SHA256=53032ba2d241de40b8fe25853662879dc067b71cbed264137dd5aa64266f0b9f
FINAL_RESULT=passed
```

## minitrue (a ferramenta)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| `rectify` mundo A (vendor → /opt) | ✅ | ✅ unit + E2E local offline + VBox atual | o aceite instalou jq 1.8.2 do binário upstream, offline, e confirmou `ORIGIN=vendor` e persistência após reboot |
| `rectify` mundo B (fonte → /usr) | ✅ | ✅ unit + E2/E2-clean + VBox atual | o aceite compilou tree 2.3.2 da fonte, offline, com `ORIGIN=fonte`; a prova histórica também compilou Make 4.4.1 |
| Perfis de toolchain (`none`/`seed`/`cross`/`native`) | ✅ | ✅ unit + E2E local offline | `seed`/`cross` em receita fonte implicam Zig no fingerprint e no plano de compilação local; a prova Make instalou Zig antes do build e o manteve fora do `world`. Canal/binário e `none`/`native` não o instalam |
| Receitas de montagem (sem SRC) | ✅ | ✅ | `build()` gera o pacote (config, esqueleto de `/etc`) — nada a baixar; usada por `base` 0.2, com snapshot autocontido em `files/` e fábrica `/etc` |
| Metapacotes (`KIND=meta`, mundo M) | ✅ | ✅ unit + instalação direta + VBox atual | agregam somente `DEPS`, não têm SRC, funções de build, payload nem artefato de canal; registro v2 usa `KIND=meta`, `WORLD=M`, `ORIGIN=meta` e manifesto vazio. `miniplenty-buildbase` é o primeiro consumidor |
| Runner mundo B em rootfs (bwrap, --unshare-net, --clearenv) | ✅ | ✅ | isola rede/ambiente do `build()`, mas o **rootfs fica gravável**; avaliação top-level da receita e mundo A ainda rodam no host |
| `retry` de ICE | ✅ | — | usado no E2 |
| `fingerprint` de build | ✅ | ✅ | **transitivo**; inclui `DEPS`, `BUILD_DEPS` e Zig implícito para fonte `seed`/`cross`. Snapshot de `recipe`+`files/`, e o mesmo `files/` autocontido é materializado no `WORK` (symlinks auxiliares são recusados) |
| Supersessão provisional (`PROVISIONAL` + `SUPERSEDES=`) | ✅ | ✅ | declarativa; no mundo B a cessão volta se a instalação falha. `SUPERSEDES` fica no registro e prova cadeias provisional→provisional; mundo A e restauração ao remover sucessor ainda faltam |
| `pack` determinístico (v1) | ✅ | ✅ | a parte mais madura; falta xattr/ACL/cap/sparse |
| Manifesto v2 (conteúdo + tipo) | ✅ | ✅ | `f:` prende modo+conteúdo do regular, `l:` prende alvo, `d:` prende modo do diretório-raiz+árvore (payload A e vazios B); leitura v0/v1 mantida |
| `verify` (presença + integridade por claim) | ✅ | ✅ unit + instalação direta + VBox atual | inspeção confinada ao rootfs; confere conteúdo/tipo/alvo/árvore, denuncia journal pendente/formato futuro e exige que toda `DEPS` de registro v2 tenha registro factual válido. Não verifica `BUILD_DEPS` nem varre regulares órfãos em /usr |
| `cache verify` (disponibilidade sem instalação) | ✅ | ✅ unit + E2E local + VBox atual | força offline/sem TOFU, confere hashes e assinaturas dos artefatos já no cache e não cria registro, link ou entrada no `world`; conferiu jq, Make, tree e Zig na mídia atual |
| `memoryhole` (+ preserva modificado) | ✅ | 🟡 | sem `--tudo`; sem rollback do payload |
| `explain` / `why` (proveniência) | ✅ | ✅ | ORIGIN/hash-arq; ABOUT/REPROCORR congelados no meta, com fallback literal legado sem executar receita histórica; corroboração e reprocorr |
| `--sync` (convergir ao world) | ⬜ | — | stub; SPEC-0011 |
| `rollback` / `unperson` / `lint` | ⬜ | — | stub |
| Canal binário assinado | ✅ | ✅ unit + E2E offline | config HTTPS/chave minisign pinada, índice canônico v2 assinado com `RECIPE_FINGERPRINT`, cache endereçado por conteúdo, `.tar.zst` com limites e conferência do tar interno; seleção exige que a identidade autenticada coincida com a receita efetiva. `/etc/minitrue/channels/` existente é autoritativo e, vazio, desativa a seed |
| Resolução `--no-binary` / `--only-binary` | ✅ | ✅ unit + E2E offline histórico | binário de canal preserva mundo B; `--only-binary` resolve metapacotes locais sem artefato, mas exige artefato para cada dependência fonte e não expande `BUILD_DEPS` nem Zig implícito |
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
| Perfil estrito + `profile.lock` | ✅ | ✅ unit | `PROFILE_LOCK_FORMAT=2`/`PROFILE_CONTENT_FORMAT=2`; normaliza os três worlds e prende `cache.world` em `CACHE_WORLD_SHA256`, além de Newspeak/overlay/cache, arch, epoch, `MEDIA_SIZE_MIB=512`, `INSTALL_READY` e pinos oficiais. `MEDIA_SIZE_MIB` dimensiona a IMG, não fixa a ISO |
| Instalação em rootfs (`--target`) | ✅ | ✅ unit + E2E dev atual | prepara FHS/usr-merge, congela Newspeak/cache e, offline, executa `cache verify` antes de `rectify` + `verify`; o target atual inteiro foi materializado de canal numa raiz vazia e passou nas provas de toolchain |
| Ingestão de mídia (`install-media`) | ✅ | ✅ unit | valida controles sem seguir symlinks, hashes de lock/EFI, coerência modo/cache e reconstitui o perfil byte a byte antes de tocar no target; `--export-boot-efi` cria sem sobrescrever o snapshot EFI validado e o remove se a instalação falhar |
| Executor e `install.manifest` | ✅ | 🟡 unit + E2E dev | copia Minitrue para `memfd` selado, mede o Minipax, persiste ambos em `/usr/bin`; manifesto prende hashes, classe e opções `OFFLINE`/`FROM_SOURCE`/`ONLY_BINARY`. O target mínimo exige executores estáticos para usá-los após o boot |
| Retomada e proteção do target | ✅ | ✅ unit | recusa `/`, target sujo e perfil divergente; `--resume` exige marca anterior do Minipax |
| IMG GPT+FAT32 | ✅ | ✅ unit local | GPT/FAT internos; GUIDs e serial FAT derivam do hash do payload completo. Duas composições da fixture dão o mesmo sha256; ainda não há prova entre builders nem de boot |
| ISO UEFI/El Torito | ✅ | ✅ unit local | fixa metadados; usa caminho absoluto do `xorriso`, hash antes/depois e ambiente fechado, registra versão+hash e pós-valida `CD001`. Reproduziu só localmente |
| Sidecars (`.sha256`, `.media.lock`, `.manifest`) | ✅ | ✅ unit | temporários publicados sem sobrescrever antes da imagem; não há transação multi-arquivo, logo corrida/falha pode deixar sidecars sem imagem |
| Classes de insumos de release | ✅ | 🟡 unit | `PROFILE_CLASS`, `MEDIA_CLASS` e `INSTALL_CLASS` podem ser `official-inputs` após os respectivos pinos; isso não declara reprodução oficial |
| Modos canônicos das árvores | ✅ | ✅ unit | dirs `0755`, `root/` do overlay `0700`, `shadow`/`gshadow` e backups `0600`, executáveis `0755`, demais regulares `0644`; não depende dos modos que o Git preserva |
| Limites das árvores | ✅ | 🟡 unit | Newspeak e overlay: 128 MiB de conteúdo regular cada; cache: 384 MiB; 50.000 entradas por árvore; entrada `cache.tar`: até 416 MiB. Conteúdo e tar ficam em memória. No canal, `.tar.zst` selado e tar descompactado coexistem, somando o pico de RAM; streaming é gate de release |
| Modo offline/cache | ✅ | ✅ unit + E2E atual | `cache.world` exige jq, Make, tree e Zig. Make também é instalado por depender de `miniplenty-buildbase`; jq/tree começam ausentes para as provas e Zig fica somente no cache. A árvore atual tem cerca de 267 MB de regulares, abaixo do limite de 384 MiB |
| Modo online/bootstrap de canal | ✅ | ✅ unit | Minipax exige config + índice/assinatura pareados, rejeita objetos e semeia antes de `rectify`; Minitrue valida minisign no uso. Não há endpoint oficial para E2E |
| BOOT EFI vivo (kernel+initramfs+Minipax+Minitrue) | ✅ | ✅ E2E QEMU histórico + VirtualBox atual | fixa Linux 7.1.4, BusyBox e executores musl `static-pie`. `CONFIG_MODULES=y`, nenhum `.ko` na mídia e release `7.1.4-distropica-live`; o EFI atual inclui `simpledrm`+`fbcon` e VirtIO de rede built-in, sem fixar o disco |
| Instalação por ISO em QEMU/OVMF | ✅ | ✅ E2E final-v10 | aceite histórico e automatizado: antes de escolher disco, materializa closure em `/run` e exporta snapshot EFI validado; depois particiona, copia, verifica, instala EFI e publica o marcador completo por último. Segundo boot ocorreu sem ISO |
| Instalação por ISO no VirtualBox | ✅ | ✅ E2E local atual | `miniplenty-v1` provou EFI64/VMSVGA/SATA, ejeção antes do wipe, reboot sem ISO, Vim/ripgrep/toolchain por padrão, C/C++/arquivo/Make offline, jq binário, tree fonte, persistência, `verify` e VirtIO/NAT; Zig permaneceu só no cache |
| Boot da IMG em QEMU/OVMF | 🟡 | — | compositor IMG existe e reproduziu localmente; o aceite funcional final-v10 exercitou somente a ISO |
| Particionamento/escrita destrutiva em disco | ✅ | ✅ QEMU final-v10 + VirtualBox atual | PID 1 só recebe/autoriza o disco depois do preflight em `/run`: `/dev/vda` no aceite automatizado e `/dev/sda` no VirtualBox. O negativo final-v10 deixou um disco histórico de 256 MiB intacto; o aceite atual usou 4096 MiB. Cria MBR com ESP FAT32 de 64 MiB + raiz ext2; não é ainda um particionador geral |

O perfil `profiles/official` continua com `STATUS=development`, mas agora
declara `INSTALL_READY=yes`. Seu `target.world` contém `base`, `linux`,
`ripgrep`, `vim` e `miniplenty-buildbase`. A receita meta tem
`DEPS="base make gcc-pass2"`, registro `KIND=meta`/`WORLD=M` e nenhum payload;
o fecho final de GCC traz `linux-headers`, glibc, `mathlibs-glibc`, zlib e
`binutils-glibc`; Vim traz ncurses. Make, GCC/G++, assembler e linker ficam instalados desde o
primeiro boot, mas apenas `miniplenty-buildbase` é desejo top-level da
toolchain. Seu `cache.world` contém jq, Make, tree e Zig: essa declaração só
exige disponibilidade offline; Make é instalado por causa do metapacote,
jq/tree começam ausentes e Zig fica no cache/sob demanda. O lock v2 separa essas intenções com `TARGET_WORLD_SHA256` e
`CACHE_WORLD_SHA256`. O perfil fixa `MEDIA_SIZE_MIB=512` para dimensionar a
IMG; a ISO segue o tamanho do payload. Os runners atuais usam discos de
4096 MiB.

Como o cache de desenvolvimento é passado por `--cache`, o E2E recebe classe
`custom`; isso não o publica nem cria um canal oficial. Mesmo uma futura classe
`official-inputs` não será, por si,
reprodução oficial: isso dependerá do sha256 final pinado num manifesto
oficial externo assinado.

A closure atual foi reconstruída, exercitada, reemitida no canal local assinado
e integrada ao cache, lock, EFI e ISO aceitos no VirtualBox. O rebuild repetido
em ambiente independente ainda é necessário para o claim de reprodutibilidade.

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

Separadamente, o aceite **histórico** network-v1 iniciou a ISO numa VM
VirtualBox EFI64 com adaptador VirtIO/NAT e o cabo virtual desligado. Instalou em `/dev/sda`, ejetou
a ISO **antes** do wipe e concluiu a partir da closure pré-validada em RAM. O
segundo boot iniciou o mesmo VDI sem mídia óptica e ainda sem rede, chegando ao
login de `root`. No terceiro boot, com o cabo ligado, obteve DHCP IPv4, rota
padrão, `resolv.conf` com nameserver IPv4, resolução de `localhost` pelo host
resolver do NAT e resposta do gateway. O cabo foi então desligado: `ripgrep`,
ausente no sistema inicial, foi instalado explicitamente na versão 15.2.0 a
partir do objeto extra do cache, e `minitrue verify` passou. Esse probe de DNS é
local e não prova acesso à Internet. As duas composições locais dessa ISO foram
byte a byte idênticas. É um segundo hipervisor no mesmo host, não hardware real
nem builder independente:

```text
EVIDENCIA_VIRTUALBOX_NETWORK_V1=local-custom
ACCEPTANCE_META=target/vbox-acceptance-network-v1/evidence/acceptance.meta
VBOX_VERSION=7.2.6_Ubuntur172322
VBOXMANAGE_BINARY_SHA256=3d019f23c6d755ed1f6a3bb05f4481fd56015719bf51e4299dca0267fbcc021a
FIRMWARE=efi64
GRAPHICS=vmsvga
STORAGE=IntelAhci
GUEST_DISK=/dev/sda
NIC_TYPE=virtio
INSTALL_NETWORK=nat-cable-disconnected
THIRD_BOOT_NETWORK=nat-cable-connected
DNS_PROBE=localhost-via-vbox-nat-host-resolver
ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
REPEATED_ISO_SHA256=3616506afa26b790e932edf2489558582743865e137d29b98225cddffa176c2d
BOOT_EFI_SHA256=71b8977c55a3d0e25785c0299af32515e3dc71759e89f1f08d57d525f800fc88
OFFLINE_SERIAL_LOG_SHA256=d31045696f9996e269f25e1e97c8dfa69ea2821ca78804c850503bacac01ba3d
ONLINE_SERIAL_LOG_SHA256=f4691c6db2c4885bf93e58718d3cdfc57883ae1be185a0f4346e5aa92ac866b4
ISO_EJECTED_BEFORE_WIPE=yes
INSTALL_AND_SECOND_BOOT_OFFLINE=yes
SECOND_BOOT_WITHOUT_ISO=yes
ROOT_LOGIN=yes
THIRD_BOOT_WITH_NAT=yes
THIRD_BOOT_ROOT_LOGIN=yes
DHCP_IPV4=yes
DEFAULT_ROUTE=yes
RESOLV_CONF_IPV4_NAMESERVER=yes
DNS_LOCALHOST=yes
NAT_GATEWAY_PING=yes
NETWORK_DISCONNECTED_BEFORE_OFFLINE_RECTIFY=yes
RIPGREP_INITIAL_ABSENT=yes
RIPGREP_EXTRA_OFFLINE_RECTIFY=yes
RIPGREP_VERSION=15.2.0
MINITRUE_VERIFY_AFTER_RIPGREP=yes
MINITRUE_VERIFY=yes
RUN_STATE=passed
FINAL_RESULT=passed
```

O runner atual executou a prova: ripgrep 15.2.0, Vim 9.2.0837,
`miniplenty-buildbase`, GNU Make 4.4.1, binutils 2.45 e GCC/G++ 15.3.0 presentes
desde o primeiro boot; metapacote registrado no mundo M sem payload; componentes
da toolchain vindos do canal e fora do world explícito; Zig ausente; e, ainda
sem link, compilação/execução C e C++, criação e link de arquivo estático,
construção por Makefile e `verify` limpo. Também instalou jq 1.8.2 do binário
upstream e tree 2.3.2 da fonte, ambos offline, e comprovou sua persistência após
o terceiro boot. Os hashes da execução atual estão no início deste documento.

Esses hashes identificam uma execução do workspace
de desenvolvimento; não serão pinos de release nem substituirão manifesto
externo assinado. Endpoint, chave e publicação oficiais continuam ausentes.

## Bootstrap (SPEC-0005)

| Estágio | Estado | Nota |
|---|---|---|
| E0 — chroot musl-estático | ✅ | |
| E1 — `./configure && make` | ✅ | |
| E2 — glibc + gcc nativo | ✅ | **Evidência histórica E2-clean:** um rootfs novo, com seed limpo, construiu 16 pacotes. O grafo atual com zlib e `install-strip` também foi reconstruído uma vez e passou C/C++/arquivo/Make; falta comparação em dois ambientes limpos |
| E3 — kernel + boot | 🟡 | O smoke anterior bootou Linux 7.1.4 do E2 com raiz 9p. Separadamente, o EFI-stub live atual passou em ISO→disco→boot sem mídia no VirtualBox, cobrindo `simpledrm`/`fbcon`, PS/2, AHCI, `/dev/sda`, VirtIO/NAT, toolchain e `verify`; faltam runit, `.config` de hardware geral e gestão completa de contas |
| — openssl 4.0.1 (base de confiança do kernel) | ✅ | mundo B, compilado pela toolchain nativa (libcrypto/libssl, `-DZLIB`); SHA conferido no download. Habilita geração/uso da chave de módulos; **attestation usa ed25519-dalek e independe de OpenSSL**. O materializador de `/etc` agora trata symlinks, com regressão coberta |
| — base 0.2 (config Fase B) | ✅ E2E local | receita de montagem `GPL-3.0-or-later` com `TOOLCHAIN=none`: além de `/etc/inittab`, `rcS`, `rcK`, `os-release`, `hostname` e a cópia da GPL, sobe interfaces e tenta DHCP IPv4 sem tornar a falha fatal. O fingerprint atual entrou no canal/cache/ISO aceitos; DHCP, rota e DNS local passaram. Não cria `/etc/shadow`, portanto sozinha não fecha login autenticado |
| E4 — userland vendor / GUI | ⬜ | |

## Reprodutibilidade (SPEC-0010)

| Item | Estado |
|---|---|
| Ambiente determinístico (epoch/LC/TZ/umask) | ✅ |
| `ar` determinístico | ✅ |
| m4, gmp, **gcc**, **glibc** byte-idênticos (2 builds) | ✅ histórico para as receitas e os artefatos então medidos; o `gcc-pass2` atual com `install-strip` foi reconstruído uma vez, não ×2 |
| Hash de artefato via `pack` = `reprocorr` | ✅ histórico (m4/gcc/glibc); payloads atuais de GCC/binutils emitidos e exercitados, ainda sem comparação ×2 |
| `REPROCORR` pinado + verificado no build | ✅ (`m4` pina; build de fonte grava `ARTIFACT_HASH` e exige reproduzir o pinado — crimestop se divergir) |
| Cotejo do artefato completo produzido pelo E2-clean | ⬜ (passo posterior à primeira execução a frio) |
| Identidade declarativa do sistema (`profile.lock`) | ✅ (`PROFILE_LOCK_FORMAT=2`/`PROFILE_CONTENT_FORMAT=2`; inclui `CACHE_WORLD_SHA256`, tamanho, prontidão, hash calculado e os três pinos oficiais) |
| Executor da instalação medido = executado | ✅ local (`memfd` selado, ambiente fechado e hash no `install.manifest`) |
| Rootfs instalado byte-a-byte idêntico | ⬜ (`INSTALLED_AT`, uid/gid e demais metadados ainda impedem o claim) |
| IMG byte-idêntica em duas composições | ✅ local (fixture, mesmo binário/toolchain; GPT/FAT normalizados) |
| ISO byte-idêntica em duas composições | ✅ local para fixture, ISO final-v10 e ISO network-v1 do VirtualBox (mesmos insumos, binário e `xorriso`, cujo executável é medido) |
| IMG/ISO byte-idênticas entre builders independentes | ⬜ |
| Reprodução reconhecida contra manifesto oficial externo assinado | ⬜ (sidecars locais não são autoridade) |
| R4 — reprodução funcional da mídia de desenvolvimento | ✅ local para o perfil atual no VirtualBox: instalação, reboots, toolchain, jq binário, tree fonte, persistência, `verify` e rede NAT. Não prova Internet, hardware real, builders independentes nem release oficial |

## Limitações conhecidas (do parecer externo)

- **E2-clean histórico (uma vez):** um rootfs novo reproduziu a frio o fluxo
  com seed limpo e grafo corrigido. Achou e consertou 2 bugs que o rootfs sujo
  mascarava (SUPERSEDES seed→busybox; libstdc++ lib64×lib usr-merge). As
  receitas atuais com `install-strip` já tiveram um rebuild funcional; faltam
  dois ambientes limpos para a nova prova "reproduzível ×2" e mover scripts,
  hashes e logs hoje transitórios para um diretório versionado `proofs/e2/`.
- **Mídia instalável validada em QEMU/OVMF e VirtualBox/EFI:** o aceite
  automatizado final-v10 cobriu a ordem
  atual. O PID 1 primeiro materializa e verifica toda a closure em
  `/run/distropica-prepared`, configura a conta e recebe de
  `install-media --export-boot-efi` um snapshot EFI medido. Somente depois pede
  ou aceita o disco, confere capacidade, particiona, copia, roda
  `minitrue verify`, grava o EFI e publica por último
  `disk-install.complete`. O teste negativo confirmou a recusa de um
  `profile.lock` incoerente com `media.meta` antes de qualquer wipe. Isso ainda
  não prova boot da IMG, hardware real, reprodução entre builders ou release
  oficial. O aceite network-v1 separado repetiu o caminho positivo no
  VirtualBox 7.2.6: console, teclado PS/2, AHCI `/dev/sda`, ejeção da ISO antes
  do wipe, instalação e segundo boot com o cabo virtual desligado e login de
  root. No terceiro boot, VirtIO/NAT exerceu o DHCP IPv4 não fatal de `base`
  0.2, rota padrão, nameserver IPv4, resolução local e gateway. Depois de
  desligar novamente o cabo, instalou `ripgrep` 15.2.0 do cache e passou em
  `minitrue verify`. A execução atual `miniplenty-v1` substituiu esse passo pela
  presença inicial de ripgrep, Vim, metapacote M, Make e toolchain GCC final,
  seguida por provas C/C++/arquivo/Makefile, jq binário e tree fonte offline;
  Zig permaneceu apenas no cache. Isso não foi um probe da Internet.
- **Gates do perfil oficial:** o canal e `--only-binary` estão implementados,
  e o perfil marca `INSTALL_READY=yes`, mas o cache usado no E2E é de
  desenvolvimento com `TRUST=builder`. O superset network-v1 — a closure do
  target antigo mais o objeto pinado de `ripgrep` — foi testado historicamente.
  Agora `target.world` inclui ripgrep, Vim e `miniplenty-buildbase`; Make pertence
  tanto à closure instalada quanto à disponibilidade de `cache.world`, jq/tree
  ficam disponíveis para as provas e Zig pertence somente ao cache/sob demanda.
  A mídia integrada foi construída e aceita; GCC/binutils foram reemitidos com
  `install-strip`. Ainda não há
  endpoint, chave de release, índice ou artefatos oficiais publicados. A
  separação nominal de `base` 0.2 para `base-config`, runit e a política uid/gid
  continuam abertos; o agregador de produção agora é a verdadeira meta-receita
  `miniplenty-buildbase`. `profiles/official` permanece
  `STATUS=development`, portanto nenhuma saída recebe a classe de insumos
  oficiais. `STATUS=release` já exige três pinos separados:
  `OFFICIAL_CONTENT_SHA256`, `OFFICIAL_BOOT_EFI_SHA256` e
  `OFFICIAL_MINITRUE_SHA256`. A coincidência gera apenas `official-inputs`; o
  claim de reprodução depende de comparar o sha256 final com um manifesto
  oficial externo assinado, cuja publicação ainda não existe.
- **Cobertura do kernel vivo:** o `.config` cobre UEFI x86_64, virtio,
  CD/SCSI, AHCI/PIIX, teclado PS/2, ISO9660, ext2/ext4, FAT e o framebuffer EFI
  pelo caminho `simpledrm`/`fbcon`. Isso fechou o console, a entrada e o disco
  SATA do VirtualBox usado no aceite, além do alvo QEMU. O network-v1 também
  fechou o caminho local do adaptador VirtIO, DHCP IPv4, rota, DNS e gateway
  NAT nessa VM; não permite afirmar acesso à Internet nem suporte genérico a
  controladores NVMe, USB, outras placas de rede, GPUs ou armazenamento
  encontrados em hardware real. O kernel mantém
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
- **Escala do Minipax:** Newspeak e overlay estão limitadas a 128 MiB de
  conteúdo regular cada; cache, a 384 MiB; cada árvore admite 50.000 entradas,
  e `cache.tar` é aceito até 416 MiB. As árvores são materializadas
  integralmente em memória, junto do tar normalizado. O consumo do canal mantém simultaneamente o transporte
  `.tar.zst` selado e o tar descompactado; o pico de RAM aproxima a soma dos
  dois. O instalador vivo acrescenta a raiz pré-validada em `/run`, trocando
  memória por garantia fail-before-wipe. O cache do perfil atual mediu cerca de
  267 MB de regulares e coube nesses limites; ampliar o world
  exigirá streaming e provavelmente uma partição de dados separada.
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
- **Agregador e configuração-base agora são distintos:**
  `miniplenty-buildbase` implementa o agregador normativo `KIND=meta`/`WORLD=M`;
  `base` 0.2 continua sendo a receita com payload de configuração de boot. Uma
  eventual renomeação para `base-config` ainda precisará preservar ownership de
  rootfs já registrados.
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
