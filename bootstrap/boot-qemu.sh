#!/bin/sh
# boot-qemu.sh: boota o kernel do E3 em QEMU (SPEC-0005 §E3, SPEC-0008).
# O bzImage (mundo B, compilado pelo gcc NATIVO do E2) sobe sob KVM com o
# rootfs montado por 9p read-only — sem imagem de disco nem initramfs, porque
# o .config tem virtio+9p+ext4 built-in (=y). Por padrão um init de prova
# imprime a identidade do sistema e desliga; com --shell, cai num shell.
#
# Uso:  bootstrap/boot-qemu.sh [dir-do-rootfs]      (padrão: ./rootfs-clean)
#         --login            boot real até o login (busybox init → getty; requer 'rectify base')
#         --shell            boota num shell interativo (init=/bin/sh, sem timeout)
#       MEM=2048 TIMEOUT=100 bootstrap/boot-qemu.sh    (via ambiente)
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

SHELL_MODE=0
LOGIN_MODE=0
ROOTFS=""
for a in "$@"; do
    case "$a" in
        --login) LOGIN_MODE=1 ;;
        --shell) SHELL_MODE=1 ;;
        -*) echo "erro: opção desconhecida: $a"; exit 2 ;;
        *)  ROOTFS=$a ;;
    esac
done
ROOTFS=${ROOTFS:-"$REPO/rootfs-clean"}
MEM=${MEM:-1024}
TIMEOUT=${TIMEOUT:-100}

command -v qemu-system-x86_64 >/dev/null 2>&1 || {
    echo "erro: qemu-system-x86_64 ausente (instale: sudo apt install qemu-system-x86)"; exit 1; }

# o kernel mais recente instalado no rootfs
KERNEL=$(ls -1 "$ROOTFS"/boot/vmlinuz-* 2>/dev/null | sort -V | tail -1 || true)
[ -n "$KERNEL" ] || { echo "erro: nenhum vmlinuz-* em $ROOTFS/boot — rode o E3 (rectify linux) antes"; exit 1; }
VER=${KERNEL##*vmlinuz-}
echo "== distrópica boot → kernel $VER de $ROOTFS =="

# KVM se o /dev/kvm for acessível; senão TCG (emulação pura, mais lento)
ACCEL=tcg
[ -w /dev/kvm ] && ACCEL=kvm:tcg
echo "-- acel: $ACCEL --"

# init: login real (--login), shell (--shell) ou prova (padrão, auto-poweroff)
if [ "$LOGIN_MODE" = 1 ]; then
    # sem init= → o kernel roda /sbin/init (busybox) → /etc/inittab → getty →
    # login. Requer a config da receita 'base' + uma conta em /etc/shadow.
    INIT=""
    TIMEOUT=0
    echo "-- boot real até login (Ctrl-A X encerra o QEMU) --"
elif [ "$SHELL_MODE" = 1 ]; then
    INIT=/bin/sh
    TIMEOUT=0
    echo "-- shell interativo (Ctrl-A X encerra o QEMU) --"
else
    # init de prova escrito no rootfs; removido ao sair (trap)
    INIT=/.boot-init.sh
    cat > "$ROOTFS/.boot-init.sh" <<'INITEOF'
#!/bin/busybox sh
/bin/busybox mount -t proc  proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sys  /sys  2>/dev/null
echo ""
echo "################ DISTROPICA VIVA ################"
/bin/busybox uname -a
/bin/busybox cat /proc/version
echo "gcc no rootfs: $(/bin/busybox ls /usr/bin/gcc 2>/dev/null || echo ausente)"
echo "################################################"
/bin/busybox sync
/bin/busybox poweroff -f
INITEOF
    chmod +x "$ROOTFS/.boot-init.sh"
    trap 'rm -f "$ROOTFS/.boot-init.sh"' EXIT
fi

# 9p-root read-only: protege a árvore do host; msize=512000 é o máximo do
# transporte virtio (o kernel corta acima disso).
INITARG=""
[ -n "$INIT" ] && INITARG="init=$INIT"
APPEND="root=/dev/root rootfstype=9p rootflags=trans=virtio,version=9p2000.L,cache=loose,msize=512000 ro console=ttyS0 $INITARG panic=1"

set -- qemu-system-x86_64 \
    -machine "accel=$ACCEL" -m "$MEM" \
    -kernel "$KERNEL" \
    -fsdev "local,id=r,path=$ROOTFS,security_model=none,readonly=on" \
    -device virtio-9p-pci,fsdev=r,mount_tag=/dev/root \
    -append "$APPEND" \
    -no-reboot -display none -serial mon:stdio

if [ "$TIMEOUT" -gt 0 ]; then
    timeout "$TIMEOUT" "$@"
else
    "$@"
fi
