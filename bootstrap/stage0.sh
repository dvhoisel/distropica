#!/bin/sh
# stage0: monta o rootfs E0 da Distrópica (SPEC-0005 §2) usando o minitrue.
#
# Uso: bootstrap/stage0.sh [--from-source] [dir-do-rootfs]
#
# O minitrue vem do CANAL BINÁRIO por padrão, e é compilado só com
# --from-source. A razão é a P2 da SPEC-0001 — "se existir binário elegível, a
# receita DEVE usá-lo; o que não tem binário upstream, a Distrópica compila uma
# vez e publica como binário do próprio projeto". O minitrue é exatamente esse
# caso, e até aqui a distro violava a própria regra no ponto mais crítico dela:
# exigia binário para todo o resto e mandava cada pessoa compilar do zero a
# ferramenta que decide o que é confiável.
#
# Isso também remove a dependência de Rust no hospedeiro. A SPEC-0005 §1.1
# rejeitou o gcc do host como semente porque "só construível sobre o Ubuntu é
# dependência permanente do Ubuntu"; exigir cargo era a mesma dependência, num
# lugar onde ninguém tinha olhado.
#
# O binário publicado é verificável por reconstrução: o build é reprodutível
# byte a byte entre máquinas e diretórios (bootstrap/build-minitrue.sh), então
# quem tiver cargo confere em vez de confiar.
set -eu
umask 022

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FROM_SOURCE=
ROOTFS=
while [ $# -gt 0 ]; do
    case $1 in
        --from-source) FROM_SOURCE=1 ;;
        *) ROOTFS=$1 ;;
    esac
    shift
done
ROOTFS=${ROOTFS:-"$REPO/rootfs"}
export CARGO_TARGET_DIR="$REPO/target"

# Onde o canal publica o minitrue, e o hash que ele DEVE ter.
#
# A conferência é por hash pinado no REPOSITÓRIO, não por assinatura, e a razão
# é dura: verificar assinatura exige um verificador, e o nosso mora dentro do
# binário que se quer verificar. Exigir o minisign do hospedeiro reintroduziria
# justamente a dependência de host que este caminho existe para eliminar.
#
# Hash pinado é o mesmo mecanismo que toda receita da árvore usa no seu
# SHA256=, e a âncora de confiança é a mesma: o clone do repositório. Quem
# confia no git de onde clonou confia neste número; quem não confia, reconstrói
# com bootstrap/build-minitrue.sh e compara — o build é reprodutível byte a
# byte entre máquinas, então os dois caminhos devem convergir no mesmo valor.
# Base do canal, SEM o nome do binário: os arquivos são $MINITRUE_CHANNEL/minitrue
# e $MINITRUE_CHANNEL/minitrue-musl.
MINITRUE_CHANNEL=${MINITRUE_CHANNEL:-https://distropica.com.br/canal}
MINITRUE_SHA256=5175a372dd218991c9d9234b58bbd01d09e7bbcf1c9fc8c366b04602e5ba115a
# O estático musl, que roda DENTRO do rootfs. Construído com o zig como CC
# (SPEC-0003 §10) e o mesmo --remap-path-prefix, e por isso também reprodutível.
MINITRUE_MUSL_SHA256=c8d8c23a8e177aa58ec03ec873b3f9fc5722b6d4f13ce26e628c2cd8a5db191f

# O runner mundo-B entra no rootfs por bwrap e precisa que todos os caminhos
# de trabalho derivados daqui continuem válidos depois do chroot. Aceitar um
# argumento relativo sem o tornar absoluto fazia a receita procurar
# `target/.../tmp` de dentro do próprio target.
mkdir -p "$ROOTFS"
ROOTFS=$(CDPATH= cd -- "$ROOTFS" && pwd -P)

echo "== distrópica stage0 → $ROOTFS =="
command -v bwrap >/dev/null 2>&1 || echo "aviso: bwrap ausente — a entrada rootless (enter.sh) não vai funcionar"

echo "-- [1/6] minitrue --"
MT="$CARGO_TARGET_DIR/release/minitrue"
if [ -n "$FROM_SOURCE" ]; then
    command -v cargo >/dev/null 2>&1 || {
        echo "erro: --from-source exige cargo (instale via rustup.rs)" >&2; exit 1; }
    echo "   compilando do fonte (reprodutível)"
    "$REPO/bootstrap/build-minitrue.sh"
else
    mkdir -p "$CARGO_TARGET_DIR/release"
    tmp=$CARGO_TARGET_DIR/release/.minitrue.download
    echo "   baixando do canal: $MINITRUE_CHANNEL"
    if ! curl -fsSL -o "$tmp" "$MINITRUE_CHANNEL/minitrue"; then
        rm -f "$tmp"
        echo "erro: não consegui baixar o minitrue do canal." >&2
        echo "      Se o canal ainda não foi publicado, compile do fonte:" >&2
        echo "        bootstrap/stage0.sh --from-source $ROOTFS" >&2
        exit 1
    fi
    got=$(sha256sum "$tmp" | cut -d' ' -f1)
    # Sem escape por flag: este é o binário que vai auditar todo o resto do
    # sistema. Hash diferente do pinado = para aqui.
    if [ "$got" != "$MINITRUE_SHA256" ]; then
        rm -f "$tmp"
        echo "erro: hash do minitrue NÃO confere — download recusado." >&2
        echo "      esperado: $MINITRUE_SHA256" >&2
        echo "      obtido:   $got" >&2
        exit 1
    fi
    chmod 0755 "$tmp"
    mv -f "$tmp" "$MT"
    echo "   hash confere: $got"
    echo "   para conferir por reconstrução: bootstrap/build-minitrue.sh"
fi
[ -x "$MT" ] || { echo "erro: minitrue indisponível em $MT" >&2; exit 1; }

echo "-- [2/6] esqueleto FHS (usr-merge) --"
mkdir -p "$ROOTFS/usr/bin" "$ROOTFS/usr/lib" "$ROOTFS/usr/share" \
    "$ROOTFS/etc/minitrue" "$ROOTFS/opt" "$ROOTFS/proc" "$ROOTFS/dev" \
    "$ROOTFS/tmp" "$ROOTFS/run" "$ROOTFS/root" "$ROOTFS/home" "$ROOTFS/srv" "$ROOTFS/boot" \
    "$ROOTFS/var/cache/minitrue" "$ROOTFS/var/lib/minitrue" "$ROOTFS/var/log/room101"
chmod 0755 "$ROOTFS/usr" "$ROOTFS/usr/bin" "$ROOTFS/usr/lib" "$ROOTFS/usr/share" \
    "$ROOTFS/etc" "$ROOTFS/etc/minitrue" "$ROOTFS/opt" "$ROOTFS/proc" \
    "$ROOTFS/dev" "$ROOTFS/run" "$ROOTFS/root" "$ROOTFS/home" "$ROOTFS/srv" \
    "$ROOTFS/boot" "$ROOTFS/var" "$ROOTFS/var/cache" \
    "$ROOTFS/var/cache/minitrue" "$ROOTFS/var/lib" "$ROOTFS/var/lib/minitrue" \
    "$ROOTFS/var/log" "$ROOTFS/var/log/room101"
chmod 1777 "$ROOTFS/tmp"
[ -e "$ROOTFS/bin" ]   || ln -s usr/bin "$ROOTFS/bin"
[ -e "$ROOTFS/sbin" ]  || ln -s usr/bin "$ROOTFS/sbin"
[ -e "$ROOTFS/lib" ]   || ln -s usr/lib "$ROOTFS/lib"
[ -e "$ROOTFS/lib64" ] || ln -s usr/lib "$ROOTFS/lib64"
# usr-merge também DENTRO de /usr: o sistema é /usr/lib (glibc libc_cv_slibdir),
# então /usr/lib64 → lib, senão pacotes que instalam em lib64 (gcc/libstdc++)
# ficam num diretório real separado e o -L/usr/lib não os acha (E2-clean).
[ -e "$ROOTFS/usr/lib64" ] || ln -s lib "$ROOTFS/usr/lib64"

cat > "$ROOTFS/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
EOF
cat > "$ROOTFS/etc/group" <<'EOF'
root:x:0:
EOF
echo airstrip1 > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/hosts" <<'EOF'
127.0.0.1 localhost airstrip1
EOF
cat > "$ROOTFS/etc/os-release" <<'EOF'
NAME="Distrópica"
ID=distropica
VERSION_ID=0.1
PRETTY_NAME="Distrópica 0.1 (Airstrip One)"
EOF
cat > "$ROOTFS/etc/profile" <<'EOF'
export PATH=/usr/bin:/bin
export PS1='airstrip1# '
EOF
cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf" 2>/dev/null \
    || echo "nameserver 9.9.9.9" > "$ROOTFS/etc/resolv.conf"

echo "-- [3/6] árvore newspeak --"
rm -rf "$ROOTFS/var/lib/minitrue/newspeak"
cp -a "$REPO/newspeak" "$ROOTFS/var/lib/minitrue/newspeak"

echo "-- [4/6] rectify busybox zig + make (make é a ferramenta essencial do E1) --"
"$MT" --root "$ROOTFS" rectify busybox zig
"$MT" --root "$ROOTFS" rectify make

echo "-- [5/6] minitrue musl estático (para dentro do rootfs) --"
# Mesmo raciocínio do passo [1/6]: por padrão vem do canal, com hash pinado
# aqui, e só é compilado com --from-source. Este é o minitrue que roda DENTRO
# do rootfs, então precisa ser estático — o rootfs recém-criado não tem libc.
if [ -z "$FROM_SOURCE" ] && curl -fsSL -o "$CARGO_TARGET_DIR/.minitrue-musl.download" \
        "$MINITRUE_CHANNEL/minitrue-musl" 2>/dev/null; then
    got=$(sha256sum "$CARGO_TARGET_DIR/.minitrue-musl.download" | cut -d' ' -f1)
    if [ "$got" != "$MINITRUE_MUSL_SHA256" ]; then
        rm -f "$CARGO_TARGET_DIR/.minitrue-musl.download"
        echo "erro: hash do minitrue-musl NÃO confere — download recusado." >&2
        echo "      esperado: $MINITRUE_MUSL_SHA256" >&2
        echo "      obtido:   $got" >&2
        exit 1
    fi
    install -m0755 "$CARGO_TARGET_DIR/.minitrue-musl.download" "$ROOTFS/usr/bin/minitrue"
    rm -f "$CARGO_TARGET_DIR/.minitrue-musl.download"
    echo "minitrue estático instalado do canal (hash confere)"
elif rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
    SHIMS="$CARGO_TARGET_DIR/shims"
    mkdir -p "$SHIMS"
    cat > "$SHIMS/zcc" <<EOF
#!/bin/sh
# traduz o triple LLVM do crate cc para o do zig (SPEC-0003 §10)
ZIG="$ROOTFS/opt/zig/current/zig"
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
exec "\$ZIG" cc -target x86_64-linux-musl "\$@"
EOF
    cat > "$SHIMS/zar" <<EOF
#!/bin/sh
exec "$ROOTFS/opt/zig/current/zig" ar "\$@"
EOF
    chmod +x "$SHIMS/zcc" "$SHIMS/zar"
    CC_x86_64_unknown_linux_musl="$SHIMS/zcc" AR_x86_64_unknown_linux_musl="$SHIMS/zar" \
        cargo build --release --quiet --no-default-features \
        --target x86_64-unknown-linux-musl \
        --manifest-path "$REPO/minitrue/Cargo.toml"
    cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/minitrue" "$ROOTFS/usr/bin/minitrue"
    echo "minitrue estático instalado em /usr/bin do rootfs"
else
    echo "aviso: target musl ausente (rustup target add x86_64-unknown-linux-musl);"
    echo "       o rootfs fica sem minitrue interno — aceite 3 do Marco 0.1 indisponível"
fi

echo "-- [6/6] registros --"
"$MT" --root "$ROOTFS" archives
echo
echo "pronto. entre com: bootstrap/enter.sh $ROOTFS"
