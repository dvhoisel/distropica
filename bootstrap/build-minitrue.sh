#!/bin/sh
# Constrói o minitrue de forma REPRODUTÍVEL — o mesmo fonte deve dar o mesmo
# binário, byte a byte, em qualquer máquina e em qualquer diretório.
#
# Isto existe porque a Distrópica publica o minitrue como binário (SPEC-0001
# P2: o que não tem binário upstream, o projeto compila uma vez e publica). Um
# binário publicado só é defensável se qualquer pessoa puder reconstruí-lo e
# comparar; sem reprodutibilidade, "confie em nós" seria a única garantia — e
# ainda por cima na ferramenta que decide o que é confiável no resto do sistema.
#
# Uso: bootstrap/build-minitrue.sh [--musl] [diretório-de-saída]
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
MUSL=
OUT=
while [ $# -gt 0 ]; do
    case $1 in
        --musl) MUSL=1 ;;
        *) OUT=$1 ;;
    esac
    shift
done

command -v cargo >/dev/null 2>&1 || {
    echo "erro: cargo ausente. Este script é o caminho DE FONTE; para o binário" >&2
    echo "      publicado, use bootstrap/stage0.sh sem --from-source." >&2
    exit 1
}
[ -d "$REPO/vendor" ] || {
    echo "erro: $REPO/vendor ausente. Gere com:" >&2
    echo "      cargo vendor --manifest-path minitrue/Cargo.toml -s minipax/Cargo.toml vendor" >&2
    exit 1
}

# Os três pilares da reprodutibilidade aqui:
#
#   --locked   recusa mexer no Cargo.lock; a resolução é a pinada, não a "mais
#              nova que satisfaz".
#   --offline  não consulta o crates.io; a entrada é só o vendor/ do repo.
#   --remap-path-prefix
#              troca o caminho absoluto do repositório por um caminho fixo.
#              Sem isto o binário embute /caminho/de/quem/construiu/... em cada
#              referência de fonte (medidas 139 ocorrências), e dois builders em
#              diretórios diferentes produziriam binários diferentes — o que
#              destruiria a única forma de conferir o binário publicado.
#
# Não se usa `trim-paths` do perfil: a opção ainda não está estabilizada e o
# cargo 1.94 recusa o manifesto inteiro se ela estiver presente.
export RUSTFLAGS="--remap-path-prefix=$REPO=/distropica"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

set -- --release --locked --offline --manifest-path "$REPO/minitrue/Cargo.toml"
if [ -n "$MUSL" ]; then
    rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$' || {
        echo "erro: alvo musl ausente (rustup target add x86_64-unknown-linux-musl)" >&2
        exit 1
    }
    set -- "$@" --target x86_64-unknown-linux-musl
fi

cargo build "$@"

# CARGO_TARGET_DIR, se definido, manda no lugar de $REPO/target — foi assim que
# a primeira versão deste script procurou o binário no diretório errado depois
# de um build bem-sucedido.
TARGETDIR=${CARGO_TARGET_DIR:-$REPO/target}
built=$TARGETDIR/release/minitrue
[ -n "$MUSL" ] && built=$TARGETDIR/x86_64-unknown-linux-musl/release/minitrue
[ -x "$built" ] || { echo "erro: build não produziu $built" >&2; exit 1; }

# A guarda que prova que o remapeamento funcionou. Se um caminho de builder
# vazar para dentro do binário, a reprodutibilidade entre máquinas cai em
# silêncio — e o sintoma seria alguém reconstruindo, obtendo hash diferente e
# concluindo que o binário publicado foi adulterado.
if strings -a "$built" 2>/dev/null | grep -q "$REPO"; then
    echo "FATAL: o caminho do builder vazou para o binário:" >&2
    strings -a "$built" | grep "$REPO" | head -3 >&2
    exit 1
fi

echo "sha256: $(sha256sum "$built" | cut -d' ' -f1)  $(basename "$built")"
if [ -n "$OUT" ]; then
    mkdir -p "$(dirname "$OUT")"
    cp -p "$built" "$OUT"
    echo "copiado para $OUT"
fi
