#!/bin/sh
# Entra no rootfs E0 sem root, via bwrap (SPEC-0005 §2; ver Registro do spike
# sobre a morte do unshare -r em hosts com AppArmor userns restrito).
# Uso: enter.sh <rootfs> [comando…]   — sem comando, abre shell interativo.
set -eu

ROOTFS=${1:?uso: enter.sh <rootfs> [comando]}
shift

command -v bwrap >/dev/null 2>&1 || {
    echo "bwrap ausente; alternativa com root: sudo chroot '$ROOTFS' /bin/sh -l" >&2
    exit 1
}

BW="bwrap --bind $ROOTFS / --proc /proc --dev /dev --unshare-pid --die-with-parent"
if [ "$#" -gt 0 ]; then
    exec $BW --setenv PATH /usr/bin:/bin --setenv HOME /root --setenv TERM "${TERM:-vt100}" \
        /bin/sh -lc "$*"
else
    exec $BW --setenv PATH /usr/bin:/bin --setenv HOME /root --setenv TERM "${TERM:-vt100}" \
        /bin/sh -l
fi
