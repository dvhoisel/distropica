#!/bin/sh
# Constrói o minitrue — ou o minipax — de forma REPRODUTÍVEL: o mesmo fonte deve
# dar o mesmo binário, byte a byte, em qualquer máquina e em qualquer diretório.
#
# Isto existe porque a Distrópica publica o minitrue como binário (SPEC-0001
# P2: o que não tem binário upstream, o projeto compila uma vez e publica). Um
# binário publicado só é defensável se qualquer pessoa puder reconstruí-lo e
# comparar; sem reprodutibilidade, "confie em nós" seria a única garantia — e
# ainda por cima na ferramenta que decide o que é confiável no resto do sistema.
#
# O MINIPAX ENTRA PELA MESMA PORTA desde a 0.17, quando os dois executores
# viraram pacotes do canal e a receita de cada um passou a fixar por sha256 o
# binário que este script produz. Até ali o minipax só nascia dentro do
# build-efi, compilado no diretório de trabalho do EFI e sem remapeamento de
# caminho — o binário que a mídia embutia não era reconstruível por ninguém.
#
# Uso: bootstrap/build-minitrue.sh [--pacote minitrue|minipax] [--musl]
#          [--authoring] [arquivo-de-saída]
#
# Sem --authoring produz o ÚNICO perfil distribuível: sem a feature Cargo que
# expõe TOFU. A variante explícita é ferramenta do autor da receita, só existe
# no minitrue e usa um target separado por padrão, para nunca substituir por
# acidente o binário que stage0/publicação esperam em target/release/minitrue.
#
# --musl produz o estático que roda dentro do rootfs e do initramfs. O ring, de
# que o rustls depende, traz C e assembly, e o compilador C do alvo musl precisa
# ser musl de verdade: um cc do hospedeiro compilaria contra os cabeçalhos da
# glibc e o resultado ainda passaria por estático. Aqui ele é o zig cc (SPEC-0003
# §10), por dois invólucros que traduzem o triple do crate cc para o do zig.
# Exporte ZIG=/caminho/do/zig; a árvore o traz em /opt/zig/<versão>/zig de toda
# raiz construída.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PACOTE=minitrue
MUSL=
AUTHORING=
OUT=
uso() {
    echo "uso: bootstrap/build-minitrue.sh [--pacote minitrue|minipax] [--musl] [--authoring] [arquivo-de-saída]"
}
while [ $# -gt 0 ]; do
    case $1 in
        --pacote) PACOTE=${2:?}; shift ;;
        --musl) MUSL=1 ;;
        --authoring) AUTHORING=1 ;;
        -h|--help) uso; exit 0 ;;
        -*) echo "erro: opção desconhecida: $1" >&2; exit 1 ;;
        *)
            [ -z "$OUT" ] || {
                echo "erro: informe no máximo um arquivo-de-saída" >&2
                exit 1
            }
            OUT=$1
            ;;
    esac
    shift
done
case "$PACOTE" in
    minitrue|minipax) ;;
    *) echo "erro: --pacote aceita minitrue ou minipax, não '$PACOTE'" >&2; exit 1 ;;
esac
[ -z "$AUTHORING" ] || [ "$PACOTE" = minitrue ] || {
    echo "erro: --authoring só existe no minitrue" >&2; exit 1; }

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
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

# CARGO_TARGET_DIR é FIXADO aqui, e não deduzido depois. Com --manifest-path o
# cargo escreve em minitrue/target/, não em $REPO/target/ — e a primeira versão
# deste script supunha o segundo, lia um binário de uma hora atrás e imprimia o
# hash DELE como se fosse o do build recém-feito. Um script cujo trabalho é
# provar reprodutibilidade não pode errar qual arquivo acabou de produzir.
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    if [ -n "$AUTHORING" ]; then
        CARGO_TARGET_DIR=$REPO/target/minitrue-authoring
    else
        CARGO_TARGET_DIR=$REPO/target
    fi
fi
export CARGO_TARGET_DIR

# O DIRETÓRIO DE ALVO TAMBÉM É REMAPEADO, e a segunda regra vem depois da
# primeira porque, quando as duas casam, o rustc aplica a última. O
# sequoia-openpgp gera a gramática no OUT_DIR do build script e o local de
# pânico dela entra no .rodata com o caminho inteiro: dois builds idênticos
# com CARGO_TARGET_DIR diferentes deram binários diferentes em 353 mil bytes,
# todos desse deslocamento. Medido em 2026-09-24 — e com isto o "qualquer
# diretório" do cabeçalho passa a valer também para o diretório de alvo.
export RUSTFLAGS="--remap-path-prefix=$REPO=/distropica --remap-path-prefix=$CARGO_TARGET_DIR=/distropica/target"

set -- --release --locked --offline --manifest-path "$REPO/$PACOTE/Cargo.toml"
if [ "$PACOTE" = minitrue ]; then
    set -- "$@" --no-default-features
    [ -z "$AUTHORING" ] || set -- "$@" --features tofu-authoring
fi
if [ -n "$MUSL" ]; then
    rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$' || {
        echo "erro: alvo musl ausente (rustup target add x86_64-unknown-linux-musl)" >&2
        exit 1
    }
    [ -n "${ZIG:-}" ] && [ -x "$ZIG" ] || {
        echo "erro: --musl exige ZIG=/caminho/do/zig (o C do ring precisa de um cc musl)" >&2
        exit 1
    }
    # Os invólucros moram no diretório de alvo, que o remapeamento cobre, e são
    # reescritos a cada build: um zig trocado não pode sobreviver num invólucro
    # velho.
    shims=$CARGO_TARGET_DIR/musl-shims
    mkdir -p "$shims"
    cat > "$shims/zcc" <<EOF
#!/bin/sh
# traduz o triple LLVM do crate cc para o do zig (SPEC-0003 §10)
n=\$#; i=0; skip=
while [ "\$i" -lt "\$n" ]; do
  a=\$1; shift; i=\$((i+1))
  if [ -n "\$skip" ]; then skip=; continue; fi
  case "\$a" in
    --target=*) continue ;;
    -target) skip=1; continue ;;
  esac
  set -- "\$@" "\$a"
done
exec "$ZIG" cc -target x86_64-linux-musl "\$@"
EOF
    cat > "$shims/zar" <<EOF
#!/bin/sh
exec "$ZIG" ar "\$@"
EOF
    chmod +x "$shims/zcc" "$shims/zar"
    export CC_x86_64_unknown_linux_musl="$shims/zcc"
    export AR_x86_64_unknown_linux_musl="$shims/zar"
    set -- "$@" --target x86_64-unknown-linux-musl
fi

cargo build "$@"

built=$CARGO_TARGET_DIR/release/$PACOTE
[ -n "$MUSL" ] && built=$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/$PACOTE
[ -x "$built" ] || { echo "erro: build não produziu $built" >&2; exit 1; }

# Guarda contra ler artefato velho: se o binário não é mais novo que o fonte
# mais recente, ele não é deste build. Sem isto o script imprime o hash de um
# arquivo antigo e a "prova" de reprodutibilidade vira ficção.
mais_novo=$(find "$REPO/$PACOTE/src" "$REPO/$PACOTE/Cargo.toml" -newer "$built" 2>/dev/null | head -1)
if [ -n "$mais_novo" ]; then
    echo "FATAL: $built é mais antigo que $mais_novo — o build não o regravou." >&2
    exit 1
fi

# A guarda que prova que o remapeamento funcionou. Se um caminho de builder
# vazar para dentro do binário, a reprodutibilidade entre máquinas cai em
# silêncio — e o sintoma seria alguém reconstruindo, obtendo hash diferente e
# concluindo que o binário publicado foi adulterado.
if strings -a "$built" 2>/dev/null | grep -q "$REPO"; then
    echo "FATAL: o caminho do builder vazou para o binário:" >&2
    strings -a "$built" | grep "$REPO" | head -3 >&2
    exit 1
fi
# E o estático tem de SER estático: sem intérprete, não há ld.so dentro do
# initramfs para carregá-lo.
if [ -n "$MUSL" ] && readelf -l "$built" 2>/dev/null | grep -q INTERP; then
    echo "FATAL: $built pede intérprete dinâmico; não é estático" >&2
    exit 1
fi

echo "sha256: $(sha256sum "$built" | cut -d' ' -f1)  $(basename "$built")"
if [ -n "$OUT" ]; then
    mkdir -p "$(dirname "$OUT")"
    cp -p "$built" "$OUT"
    echo "copiado para $OUT"
fi
