#!/bin/sh
# stage0: monta o rootfs E0 da Distrópica (SPEC-0005 §2) usando o minitrue.
# Uso: bootstrap/stage0.sh [dir-do-rootfs]   (padrão: ./rootfs na raiz do repo)
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOTFS=${1:-"$REPO/rootfs"}
export CARGO_TARGET_DIR="$REPO/target"

echo "== distrópica stage0 → $ROOTFS =="
command -v cargo >/dev/null 2>&1 || { echo "erro: cargo ausente (instale via rustup.rs)"; exit 1; }
command -v bwrap >/dev/null 2>&1 || echo "aviso: bwrap ausente — a entrada rootless (enter.sh) não vai funcionar"

echo "-- [1/6] minitrue do host --"
cargo build --release --quiet --manifest-path "$REPO/minitrue/Cargo.toml"
MT="$CARGO_TARGET_DIR/release/minitrue"

echo "-- [2/6] esqueleto FHS (usr-merge) --"
mkdir -p "$ROOTFS/usr/bin" "$ROOTFS/usr/lib" "$ROOTFS/usr/share" \
    "$ROOTFS/etc/minitrue" "$ROOTFS/opt" "$ROOTFS/proc" "$ROOTFS/dev" \
    "$ROOTFS/tmp" "$ROOTFS/run" "$ROOTFS/root" "$ROOTFS/home" "$ROOTFS/srv" "$ROOTFS/boot" \
    "$ROOTFS/var/cache/minitrue" "$ROOTFS/var/lib/minitrue" "$ROOTFS/var/log/room101"
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
if rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
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
        cargo build --release --quiet --target x86_64-unknown-linux-musl \
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
