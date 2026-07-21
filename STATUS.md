# STATUS — o que está feito, testado e futuro

Fonte única da verdade sobre a maturidade. As `specs/` descrevem a **norma**;
este arquivo descreve o **estado**. Atualizado à mão (2026-07-21, após openssl
4.0.1 nativo e o kernel com MÓDULOS ASSINADOS bootado em QEMU — o Ministério do
Amor, SPEC-0012). Legenda: ✅ feito · 🟡 parcial · ⬜ design/futuro.

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
| Canais binários (`channel`, `--emit`) | ⬜ | — | SPEC-0009; protocolo de confiança a fixar |
| Lock global por rootfs (flock) | ✅ | ✅ | rectify/memoryhole; auto-libera na saída |
| Confinamento de caminhos destrutivos | ✅ | ✅ | `openat2(RESOLVE_IN_ROOT)` em inspeção/remoção; Journal aceita usr-merge interno e recusa ancestral que resolve fora do rootfs |
| Registro transacional do mundo B (meta = commit) | ✅ | ✅ | `manifest`/`recipe`/`meta` entram no journal; `TRANSACTION_ID` do meta, escrito por último, decide recovery |
| `RECORD_FORMAT=` | ✅ | ✅ | hoje 2; v0/v1 pode migrar in-place sob guardas ou reconstrói; provisional já cedido congela; formato futuro falha fechado |
| Journal + rollback do mundo B (STAGE→/) | ✅ | ✅ | formato 2 + `txid`; intenção antes da mutação; recovery **global** antes de nova operação; journal legado, >1 ativo ou rollback sobre claim posterior falha fechado e preserva backups. Sem promessa contra perda de energia: falta `fsync` |
| `SUPERSEDES=` explícito | ✅ | ✅ | declarado em 6 receitas do E2; colisão não-declarada = doublethink |
| Assinatura upstream por artefato (`SIG`) | ✅ | ✅ | minisign/signify; cache prende hash do artefato+chave+URL e é revalidado |
| Verificação OpenPGP / `SIGSUMS` | ⬜ | — | parser reconhece os campos, executor falha explicitamente; Marco 0.2, sem `gpg` externo |
| `reprocorr` (raiz de confiança) | ✅ | ✅ | build de fonte grava `ARTIFACT_HASH`=`pack(STAGE)`; receita que pina `REPROCORR` exige reprodução (crimestop). SPEC-0009 §8.1 |
| Attestation + corroboração (`attest`/`corroborate`) | ✅ | ✅ | `ATTEST_FORMAT=1`, ed25519-dalek; versão+fingerprint impedem replay e a emissão exige registro v2, txid, baseline, snapshots e claims íntegros. ≥2 builders pinados concordam. **Independência ainda simulada** (1 máquina) |

## Bootstrap (SPEC-0005)

| Estágio | Estado | Nota |
|---|---|---|
| E0 — chroot musl-estático | ✅ | |
| E1 — `./configure && make` | ✅ | |
| E2 — glibc + gcc nativo | ✅ | **E2-clean: reproduzido a frio** (rootfs novo, seed limpo, 16 pacotes, gcc nativo compila C/C++, libs finais em /usr/lib). Falta só repetir num 2º ambiente independente |
| E3 — kernel + boot QEMU | 🟡 | **smoke de laboratório**, não aceite completo da SPEC-0005: Linux 7.1.4 compilado pelo gcc nativo do E2 e bootado em QEMU/KVM, raiz 9p somente-leitura e `busybox init` PID 1. Módulos com `MODULE_SIG_FORCE` foram exercitados: assinado carrega; não-assinado/adulterado é recusado. O caminho `--login` chegou ao shell somente num rootfs com `/etc/shadow` pré-provisionado; a receita não cria a conta. Faltam initramfs/runit, `.config` enxuto, UKI/EFI-stub e gestão de contas |
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

## Limitações conhecidas (do parecer externo)

- **E2-clean feito (uma vez):** reproduzido a frio de um rootfs novo (seed
  limpo, grafo corrigido). Achou e consertou 2 bugs que o rootfs sujo mascarava
  (SUPERSEDES seed→busybox; libstdc++ lib64×lib usr-merge). Falta repetir num
  **2º ambiente independente** para "reproduzível ×2" e mover scripts, hashes
  e logs de prova hoje transitórios para um diretório versionado `proofs/e2/`.
- **Transacional (mundo B):** payload, registro e cessões de manifesto passam
  pelo journal por pacote. Cada intenção precede a mutação; o `TRANSACTION_ID`
  do `meta` é a marca final. Sob o lock, um sweep recupera o único journal antes
  de qualquer nova operação; estados antigos com mais de um journal, ou rollback
  que atingiria ownership commitado depois, falham fechado e preservam backups.
  `verify` continua somente diagnóstico. O mundo A não possui transação de
  conjunto. **Não há `fsync`**, portanto não se promete recuperação após perda
  de energia. Também falta restaurar o payload provisional ao remover sucessor.
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
- **Confiança de canal vs P6:** sem `REPROCORR`, o hash viria do índice assinado
  (autentica o publicador, não "pina na receita"). O índice precisa ligar o
  `recipe_fingerprint`; falta anti-replay/monotonicidade.
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

`cargo test` (suíte local) · `cargo clippy -D warnings` · `cargo fmt --check` ·
`sh -n` em receitas/scripts. ShellCheck e `cargo-audit` não instalados.
