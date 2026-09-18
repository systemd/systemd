#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test systemd-vmspawn support for .mstack machine images.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping"
    exit 77
fi

WORKDIR="$(mktemp -d)"
MACHINE="test-vmspawn-mstack-$$"
MACHINE_AUTO="test-vmspawn-mstack-auto-$$"
MACHINES_DIR=""
MACHINES_MOUNTED=false
VMSPAWN_PID=""
VMSPAWN_AUTO_PID=""
AUTO_MSTACK=""

copy_binary_with_libraries() {
    local binary="$1"
    local path

    install -D "$binary" "$MSTACK/layer@0$binary"
    while read -r path; do
        [[ -n "$path" ]] || continue
        install -D "$path" "$MSTACK/layer@0$path"
    done < <(ldd "$binary" | sed -nE 's/.*=> ([^ ]+) .*/\1/p; s|^[[:space:]]*(/[^ ]+) .*|\1|p')
}

wait_for_guest_mstack() {
    local mstack="$1"
    local log="$2"
    local rw_marker="$mstack/rw/data/usr/mstack-write-marker"

    if ! timeout 30 bash -c "until test -f '$rw_marker'; do sleep .5; done"; then
        echo "Guest did not report successful .mstack validation" >&2
        cat "$log" >&2
        return 1
    fi

    grep --fixed-strings --line-regexp "mstack guest initialized" "$rw_marker" >/dev/null
}

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
    [[ -z "$AUTO_MSTACK" ]] || rm -rf "$AUTO_MSTACK"
    if [[ "$MACHINES_MOUNTED" == true ]]; then
        umount /var/lib/machines
        MACHINES_MOUNTED=false
    fi
    [[ -z "$MACHINES_DIR" ]] || rm -rf "$MACHINES_DIR"
    [[ -z "$WORKDIR" ]] || rm -rf "$WORKDIR"
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

if systemd-vmspawn --mstack=/tmp >"$WORKDIR/missing-linux.log" 2>&1; then
    echo "--mstack= unexpectedly accepted without --linux=" >&2
    exit 1
fi
grep -- '--mstack= requires --linux= to be specified.' "$WORKDIR/missing-linux.log" >/dev/null

# mstack assembly uses mountfsd/nsresourced and the newer overlayfs mount API.
# Skip gracefully when the test environment does not provide these facilities.
if [[ ! -f /usr/lib/systemd/system/systemd-mountfsd.socket ]] ||
   [[ ! -f /usr/lib/systemd/system/systemd-nsresourced.socket ]] ||
   [[ ! -e /sys/kernel/security/lsm ]] ||
   ! grep bpf /sys/kernel/security/lsm >/dev/null ||
   ! find /usr/lib* -name 'libbpf.so.*' 2>/dev/null | grep . >/dev/null ||
   systemd-analyze compare-versions "$(uname -r)" lt 6.13; then
    echo "Skipping .mstack VM test: mountfsd, nsresourced, BPF LSM, libbpf, and kernel 6.13+ are required"
    exit 77
fi

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which doesn't work under ASan, skipping"
    exit 77
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "Automatic image discovery isolation requires root, skipping"
    exit 77
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 77
fi

# --mstack= is exported through virtiofs, just like --directory=.
if ! find_virtiofsd; then
    echo "virtiofsd not found, skipping"
    exit 77
fi

if ! KERNEL="$(find_kernel_image)"; then
    echo "No kernel found for direct VM boot, skipping"
    exit 77
fi

if ! systemctl start systemd-mountfsd.socket systemd-nsresourced.socket; then
    echo "Skipping .mstack VM test: failed to start mountfsd/nsresourced sockets"
    exit 77
fi
if [[ ! -S /run/systemd/io.systemd.MountFileSystem ]] ||
   [[ ! -S /run/systemd/userdb/io.systemd.NamespaceResource ]]; then
    echo "Skipping .mstack VM test: mountfsd/nsresourced interfaces unavailable"
    exit 77
fi

MACHINES_DIR="$(mktemp --tmpdir=/var/tmp -d)"
mkdir -p /var/lib/machines
mount --bind "$MACHINES_DIR" /var/lib/machines
MACHINES_MOUNTED=true

MSTACK_V="$WORKDIR/image.mstack.v"
MSTACK="$MSTACK_V/image_1.mstack"
AUTO_MSTACK="/var/lib/machines/$MACHINE_AUTO.mstack"

# Keep this VM fixture free of root/bind/robind entries. Those entries create virtiofs submounts, which
# QEMU cannot currently announce to the guest. The guest can still verify layer composition and rw overlay
# writes through the single overlayfs root exported by virtiofsd.
mkdir -p "$MSTACK/layer@0/usr" "$MSTACK/layer@1/usr"
mkdir -p "$MSTACK/rw"
copy_binary_with_libraries /bin/sh
copy_binary_with_libraries /bin/sleep
echo "mstack layer visible" >"$MSTACK/layer@1/usr/mstack-layer-marker"
cat >"$MSTACK/layer@0/usr/mstack-test-init" <<'EOF'
#!/bin/sh
set -eu

read -r marker </usr/mstack-layer-marker
test "$marker" = "mstack layer visible"
echo "mstack guest initialized" >/usr/mstack-write-marker
exec /bin/sleep infinity
EOF
chmod +x "$MSTACK/layer@0/usr/mstack-test-init"

systemd-dissect --shift "$MSTACK/layer@1" foreign
systemd-dissect --shift "$MSTACK/rw" foreign
systemd-dissect --shift "$MSTACK/layer@0" foreign

systemd-vmspawn \
    --machine="$MACHINE" \
    --ram=256M \
    --mstack="$MSTACK_V" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=read-only \
    init=/usr/mstack-test-init \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
echo ".mstack VM '$MACHINE' registered with machined"

[[ "$(machinectl show --property=Class --value "$MACHINE")" == vm ]]
wait_for_guest_mstack "$MSTACK" "$WORKDIR/vmspawn.log"

machinectl terminate "$MACHINE"
timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
test ! -e "/run/systemd/vmspawn/$MACHINE"

# -M automatically discovers IMAGE_MSTACK entries in /var/lib/machines. Use a
# separate instance to verify that this path takes the same mstack preparation
# and virtiofs export path as an explicit --mstack= argument.
mkdir -p "$AUTO_MSTACK"
cp -a "$MSTACK/." "$AUTO_MSTACK/"

systemd-vmspawn \
    --machine="$MACHINE_AUTO" \
    --ram=256M \
    --linux="$KERNEL" \
    --tpm=no \
    --console=read-only \
    init=/usr/mstack-test-init \
    &>"$WORKDIR/vmspawn-auto.log" &
VMSPAWN_AUTO_PID=$!

wait_for_machine "$MACHINE_AUTO" "$VMSPAWN_AUTO_PID" "$WORKDIR/vmspawn-auto.log"
echo "Automatically discovered .mstack VM '$MACHINE_AUTO' registered with machined"
[[ "$(machinectl show --property=Class --value "$MACHINE_AUTO")" == vm ]]
wait_for_guest_mstack "$AUTO_MSTACK" "$WORKDIR/vmspawn-auto.log"

machinectl terminate "$MACHINE_AUTO"
timeout 10 bash -c "while machinectl status '$MACHINE_AUTO' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_AUTO_PID' 2>/dev/null; do sleep .5; done"
test ! -e "/run/systemd/vmspawn/$MACHINE_AUTO"
echo "All vmspawn .mstack tests passed"
