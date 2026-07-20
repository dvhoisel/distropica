# STATUS — o que está feito, testado e futuro

Fonte única da verdade sobre a maturidade. As `specs/` descrevem a **norma**;
este arquivo descreve o **estado**. Atualizado à mão (2026-07-20, HEAD após o
parecer externo). Legenda: ✅ feito · 🟡 parcial · ⬜ design/futuro.

## minitrue (a ferramenta)

| Recurso | Estado | Testado | Nota |
|---|---|---|---|
| `rectify` mundo A (vendor → /opt) | ✅ | 🟡 unit | fluxo real pouco coberto |
| `rectify` mundo B (fonte → /usr) | ✅ | 🟡 unit | exercido no E2 (rootfs trabalhado) |
| Perfis de toolchain (seed/cross/native) | ✅ | ✅ | parsing + seleção testados |
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
| E2 — glibc + gcc nativo | 🟡 | **executado** pelo `rectify` num rootfs trabalhado; **E2-clean a frio** (rootfs novo, grafo corrigido, ×2 ambientes) é o próximo marco |
| E3 — boot QEMU até login | ⬜ | kernel EFI-stub/UKI desenhado (SPEC-0008) |
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

- **E2 não é "a frio":** o rootfs de prova tem resíduo da investigação manual
  (libstdcxx intermediária em lib64, libgmpxx-seed libc++, órfãos musl). O grafo
  ganhou a aresta `gcc → binutils-cross` que faltava; falta o E2-clean.
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

`cargo test` 20/20 · `cargo clippy -D warnings` ok · `cargo fmt --check` ok ·
`sh -n` em receitas/scripts ok · ShellCheck e `cargo-audit` não instalados.
