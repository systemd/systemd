#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test systemd-vmspawn support for .mstack machine images.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which doesn't work under ASan, skipping"
    exit 77
fi

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping"
    exit 77
fi

if ! command -v busybox >/dev/null 2>&1; then
    echo "busybox not found, skipping"
    exit 77
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "mstack vmspawn test requires root, skipping"
    exit 77
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 77
fi

# --mstack= is exported through virtiofs, just like --directory=.
if ! command -v virtiofsd >/dev/null 2>&1 &&
   ! test -x /usr/libexec/virtiofsd &&
   ! test -x /usr/lib/virtiofsd; then
    echo "virtiofsd not found, skipping"
    exit 77
fi

KERNEL=""
for k in /usr/lib/modules/"$(uname -r)"/vmlinuz /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz; do
    if [[ -f "$k" ]]; then
        KERNEL="$k"
        break
    fi
done

if [[ -z "$KERNEL" ]]; then
    echo "No kernel found for direct VM boot, skipping"
    exit 77
fi

WORKDIR="$(mktemp -d)"
MACHINE="test-vmspawn-mstack-$$"
MACHINE_AUTO="test-vmspawn-mstack-auto-$$"
AUTO_MSTACK="/var/lib/machines/$MACHINE_AUTO.mstack"

at_exit() {
    set +e

    for m in "$MACHINE" "$MACHINE_AUTO"; do
        if machinectl status "$m" &>/dev/null; then
            machinectl terminate "$m" 2>/dev/null
            timeout 10 bash -c "while machinectl status '$m' &>/dev/null; do sleep .5; done" 2>/dev/null
        fi
    done

    [[ -n "${VMSPAWN_PID:-}" ]] && kill "$VMSPAWN_PID" 2>/dev/null && wait "$VMSPAWN_PID" 2>/dev/null
    [[ -n "${VMSPAWN_AUTO_PID:-}" ]] && kill "$VMSPAWN_AUTO_PID" 2>/dev/null && wait "$VMSPAWN_AUTO_PID" 2>/dev/null
    rm -rf "$AUTO_MSTACK"
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# Argument validation must happen before any image or kernel inspection. Keep these
# checks independent of the host's available kernel and image files.
if systemd-vmspawn --mstack=/tmp --image=/tmp --linux=/dev/null >"$WORKDIR/conflict-image.log" 2>&1; then
    echo "--mstack= unexpectedly combined with --image=" >&2
    exit 1
fi
grep -- '--directory=, --image= and --mstack= may not be combined.' "$WORKDIR/conflict-image.log" >/dev/null

if systemd-vmspawn --mstack=/tmp --directory=/tmp --linux=/dev/null >"$WORKDIR/conflict-directory.log" 2>&1; then
    echo "--mstack= unexpectedly combined with --directory=" >&2
    exit 1
fi
grep -- '--directory=, --image= and --mstack= may not be combined.' "$WORKDIR/conflict-directory.log" >/dev/null

if systemd-vmspawn --mstack=/tmp --ephemeral --linux=/dev/null >"$WORKDIR/conflict-ephemeral.log" 2>&1; then
    echo "--mstack= unexpectedly combined with --ephemeral" >&2
    exit 1
fi
grep -- '--ephemeral and --mstack= may not be combined.' "$WORKDIR/conflict-ephemeral.log" >/dev/null

# A directory layer plus an empty rw layer exercises mstack_load(), overlayfs
# preparation, and vmspawn's virtiofs export path without requiring a DDI image.
mkdir -p "$WORKDIR/image.mstack/layer@0/sbin"
mkdir -p "$WORKDIR/image.mstack/rw"
touch "$WORKDIR/image.mstack/layer@0/mstack-layer-marker"
mkdir -p "$WORKDIR/image.mstack/layer@0/bin"
cp -a "$(command -v busybox)" "$WORKDIR/image.mstack/layer@0/bin/busybox"
while read -r dependency; do
    [[ "$dependency" == /* ]] || continue
    mkdir -p "$WORKDIR/image.mstack/layer@0$(dirname "$dependency")"
    cp -a "$dependency" "$WORKDIR/image.mstack/layer@0$dependency"
done < <(ldd "$(command -v busybox)" | sed -n -e 's/.*=> \(\/[^ ]*\).*/\1/p' -e 's/^[[:space:]]*\(\/[^ ]*\).*/\1/p')
cat >"$WORKDIR/image.mstack/layer@0/sbin/init" <<'EOF'
#!/bin/busybox sh
test -e /mstack-layer-marker
exec /bin/busybox sleep infinity
EOF
chmod +x "$WORKDIR/image.mstack/layer@0/sbin/init"

systemd-vmspawn \
    --machine="$MACHINE" \
    --ram=256M \
    --mstack="$WORKDIR/image.mstack" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
echo ".mstack VM '$MACHINE' registered with machined"

# Registration only happens after setup_mstack_root() has loaded the stack,
# mounted its layers, and started virtiofsd for the resulting root directory.

if grep -E '(Failed to (load|open|prepare|mount) \.mstack|virtiofsd.*failed)' "$WORKDIR/vmspawn.log" >/dev/null; then
    echo "mstack setup failed:" >&2
    cat "$WORKDIR/vmspawn.log"
    exit 1
fi

machinectl terminate "$MACHINE"
timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"

# -M automatically discovers IMAGE_MSTACK entries in /var/lib/machines. Use a
# separate instance to verify that this path takes the same setup_mstack_root()
# code as an explicit --mstack= argument.
mkdir -p "$AUTO_MSTACK"
cp -a "$WORKDIR/image.mstack/." "$AUTO_MSTACK/"

systemd-vmspawn \
    --machine="$MACHINE_AUTO" \
    --ram=256M \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    &>"$WORKDIR/vmspawn-auto.log" &
VMSPAWN_AUTO_PID=$!

wait_for_machine "$MACHINE_AUTO" "$VMSPAWN_AUTO_PID" "$WORKDIR/vmspawn-auto.log"
echo "Automatically discovered .mstack VM '$MACHINE_AUTO' registered with machined"

machinectl terminate "$MACHINE_AUTO"
timeout 10 bash -c "while machinectl status '$MACHINE_AUTO' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_AUTO_PID' 2>/dev/null; do sleep .5; done"
echo "All vmspawn .mstack tests passed"
