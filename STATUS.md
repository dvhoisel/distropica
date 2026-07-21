# STATUS — o que está feito, testado e futuro

Fonte única da verdade sobre a maturidade. As `specs/` descrevem a **norma**;
este arquivo descreve o **estado**. Atualizado à mão (2026-07-21, após openssl
4.0.1 nativo e o kernel com MÓDULOS ASSINADOS bootado em QEMU — o Ministério do
Amor, SPEC-0012). Legenda: ✅ feito · 🟡 parcial · ⬜ design/futuro.

## minitrue (a ferramenta)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| `rectify` mundo A (vendor → /opt) | ✅ | 🟡 unit | fluxo real pouco coberto |
| `rectify` mundo B (fonte → /usr) | ✅ | 🟡 unit | exercido no E2 (rootfs trabalhado) |
| Perfis de toolchain (seed/cross/native) | ✅ | ✅ | parsing + seleção testados |
| Receitas de montagem (sem SRC) | ✅ | ✅ | `build()` gera o pacote (config, esqueleto de /etc) — nada a baixar; usada pela receita `base`, dogfooda a fábrica /etc |
| Runner hermético (bwrap, --unshare-net, --clearenv) | ✅ | ✅ | **rootfs montado gravável** (não read-only) |
| `retry` de ICE | ✅ | — | usado no E2 |
| `fingerprint` de build | ✅ | ✅ | **transitivo** (build-dep muda propaga aos dependentes) |
| Supersessão provisional (`PROVISIONAL` + `SUPERSEDES=`) | ✅ | ✅ | declarativa: só cede de provisional declarado; falta **restaurar payload** ao remover o sucessor (journal) |
| `pack` determinístico (v1) | ✅ | ✅ | a parte mais madura; falta xattr/ACL/cap/sparse |
| Manifesto v1 (hash por arquivo) | ✅ | ✅ | só hash+caminho; **falta tipo/modo/alvo de symlink** e `RECORD_FORMAT=` |
| `verify` (presença + integridade por arquivo) | ✅ | 🟡 | não varre regulares órfãos em /usr nem fecha o grafo de deps |
| `memoryhole` (+ preserva modificado) | ✅ | 🟡 | sem `--tudo`; sem rollback do payload |
| `explain` / `why` (proveniência) | ✅ | ✅ | ORIGIN/hash-arq; TRUST/corroboradores só quando houver canais |
| `--sync` (convergir ao world) | ⬜ | — | stub; SPEC-0011 |
| `rollback` / `unperson` / `lint` | ⬜ | — | stub |
| Canais binários (`channel`, `--emit`) | ⬜ | — | SPEC-0009; protocolo de confiança a fixar |
| Lock global por rootfs (flock) | ✅ | ✅ | rectify/memoryhole; auto-libera na saída |
| Registro atômico (temp+rename, meta = commit) | ✅ | ✅ | meta-less = não-instalado ⇒ reinstala |
| `RECORD_FORMAT=` | ✅ | — | versiona o esquema (hoje 1) |
| Journal + rollback do mundo B (STAGE→/) | ⬜ | — | cópia sobre / ainda não transacional |
| `SUPERSEDES=` explícito | ✅ | ✅ | declarado nas 5 receitas do E2; colisão não-declarada = doublethink |
| Verificação OpenPGP | ⬜ | — | minisign só; stub p/ .asc |

## Bootstrap (SPEC-0005)

| Estágio | Estado | Nota |
|---|---|---|
| E0 — chroot musl-estático | ✅ | |
| E1 — `./configure && make` | ✅ | |
| E2 — glibc + gcc nativo | ✅ | **E2-clean: reproduzido a frio** (rootfs novo, seed limpo, 16 pacotes, gcc nativo compila C/C++, libs finais em /usr/lib). Falta só repetir num 2º ambiente independente |
| E3 — kernel + boot QEMU | 🟡 | **kernel Linux 7.1.4 compilado pelo gcc NATIVO do E2 e BOOTADO ao vivo** (QEMU/KVM, root 9p read-only, init busybox PID 1, poweroff limpo). Prova recursiva: o banner diz "gcc 15.3.0 / ld 2.45" e o `/usr/bin/gcc` está no rootfs bootado. Build-tools novas: flex/bison/zlib/elfutils/**perl**/**openssl**. **MÓDULOS ASSINADOS (Miniluv):** religado o `SYSTEM_TRUSTED_KEYRING` que o E3 tinha desligado + `MODULE_SIG_FORCE`; chave gerada por `openssl req` (CN "Ministério da Verdade") embutida no chaveiro builtin; 12 módulos assinados no install. Provado em QEMU: assinado carrega, não-assinado o kernel recusa (`Loading of unsigned module is rejected`), adulterado dá `EKEYREJECTED`. **BOOT ATÉ LOGIN** (SPEC-0006 Fase B): `busybox init` → `/etc/inittab` → getty no ttyS0 → `login` autentica o root contra `/etc/shadow` (hash gerado pelo openssl da distro); config na receita `base`, `boot-qemu.sh --login`. Falta: `.config` enxuto (hoje defconfig), UKI/EFI-stub (SPEC-0008), contas de verdade (base-files/adduser/`doas`) |
| — openssl 4.0.1 (base de confiança) | ✅ | mundo B, compilado a frio pela toolchain nativa (libcrypto/libssl, `-DZLIB`, epoch reprodutível); SHA oficial corroborado (GitHub+openssl.org), verify-on-download. Destrava o Miniluv (módulos assinados, cripto de attestation). Revelou+consertou bug do minitrue: `materialize_etc` seguia symlinks de `/etc` via `fs::copy` (openssl é o 1º pacote com symlink lá → `tsget`) e dava ENOENT — agora symlink-aware, com teste de regressão |
| — base 0.1 (config Fase B) | ✅ | — | receita de montagem (sem SRC): `/etc/inittab`+`rc.d/rcS`+`rcK`+`os-release`+`hostname` via fábrica → materializam em `/etc`. Fecha o boot-até-login do E3 |
| E4 — userland vendor / GUI | ⬜ | |

## Reprodutibilidade (SPEC-0010)

| Item | Estado |
|---|---|
| Ambiente determinístico (epoch/LC/TZ/umask) | ✅ |
| `ar` determinístico | ✅ |
| m4, gmp, **gcc**, **glibc** byte-idênticos (2 builds) | ✅ |
| Hash de artefato via `pack` = `reprocorr` | ✅ (m4/gcc/glibc) |
| Nenhuma receita pina `REPROCORR` ainda | ⬜ |
| Cotejo do artefato do E2 produzido pelo `rectify` | ⬜ (parte do E2-clean) |

## Limitações conhecidas (do parecer externo)

- **E2-clean feito (uma vez):** reproduzido a frio de um rootfs novo (seed
  limpo, grafo corrigido). Achou e consertou 2 bugs que o rootfs sujo mascarava
  (SUPERSEDES seed→busybox; libstdc++ lib64×lib usr-merge). Falta repetir num
  **2º ambiente independente** para "reproduzível ×2".
- **Parcialmente transacional:** o **registro** já é atômico (temp+rename, meta
  = marca de commit) e há **lock global** (flock). Falta: a cópia mundo-B de
  `STAGE` para `/` ainda não é transacional (crash no meio deixa arquivos soltos
  sem registro) — precisa de journal + rollback.
- **Sandbox não isola escrita:** o rootfs é montado gravável; uma receita pode
  escrever fora de `STAGE`. Ideal: rootfs read-only + binds graváveis p/ WORK/STAGE.
- **Confiança de canal vs P6:** sem `REPROCORR`, o hash viria do índice assinado
  (autentica o publicador, não "pina na receita"). O índice precisa ligar o
  `recipe_fingerprint`; falta anti-replay/monotonicidade.
- **Nomes canônicos:** hoje `gcc` = scaffolding, `gcc-pass2` = o GCC real. O
  E2-clean deve dar nomes finais.
- **ABOUTs desatualizados:** alguns descrevem dívidas já resolvidas (afeta o
  `explain`); revisão pendente.

## Ferramentas de CI (estado local)

`cargo test` 24/24 · `cargo clippy -D warnings` ok · `cargo fmt --check` ok ·
`sh -n` em receitas/scripts ok · ShellCheck e `cargo-audit` não instalados.
