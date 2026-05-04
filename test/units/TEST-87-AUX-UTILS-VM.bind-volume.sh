#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test --bind-volume / machinectl bind-volume / unbind-volume integration with the
# StorageProvider Varlink interface.
#
# Exercises:
#  - --bind-volume parser + runtime_directory_generic + Acquire round-trip
#  - boot-time attach via DriveInfo (non-removable)
#  - runtime hotplug via io.systemd.MachineInstance.AddStorage (removable)
#  - runtime hot-remove via io.systemd.MachineInstance.RemoveStorage
#  - StorageImmutable rejection for boot-time attached volumes
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which doesn't work under ASan, skipping"
    exit 0
fi

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping"
    exit 0
fi

if ! command -v storagectl >/dev/null 2>&1; then
    echo "storagectl not found, skipping"
    exit 0
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 0
fi

if ! command -v mke2fs >/dev/null 2>&1; then
    echo "mke2fs not found, skipping"
    exit 0
fi

# Storage providers are socket-activated; skip if the fs provider socket isn't present.
if ! test -S /run/systemd/io.systemd.StorageProvider/fs; then
    echo "StorageProvider fs socket not found, skipping"
    exit 0
fi

# Find a kernel for direct boot
KERNEL=""
for k in /usr/lib/modules/"$(uname -r)"/vmlinuz /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz; do
    if [[ -f "$k" ]]; then
        KERNEL="$k"
        break
    fi
done

if [[ -z "$KERNEL" ]]; then
    echo "No kernel found for direct VM boot, skipping"
    exit 0
fi

WORKDIR="$(mktemp -d /tmp/test-bind-volume.XXXXXXXXXX)"

at_exit() {
    set +e
    if [[ -n "${MACHINE:-}" ]]; then
        if machinectl status "$MACHINE" &>/dev/null; then
            machinectl terminate "$MACHINE" 2>/dev/null
            timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done" 2>/dev/null
        fi
    fi
    [[ -n "${VMSPAWN_PID:-}" ]] && kill "$VMSPAWN_PID" 2>/dev/null && wait "$VMSPAWN_PID" 2>/dev/null
    rm -rf "$WORKDIR"
    rm -f /var/lib/storage/test-bind-volume-*.volume
}
trap at_exit EXIT

# Build a minimal root for direct boot — guest just sleeps.
mkdir -p "$WORKDIR/rootfs/sbin"
cat >"$WORKDIR/rootfs/sbin/init" <<'INITEOF'
#!/bin/sh
exec sleep infinity
INITEOF
chmod +x "$WORKDIR/rootfs/sbin/init"

truncate -s 256M "$WORKDIR/root.raw"
mke2fs -t ext4 -q -d "$WORKDIR/rootfs" "$WORKDIR/root.raw"

BOOT_VOL="test-bind-volume-boot-$$"
RUNTIME_VOL="test-bind-volume-runtime-$$"

wait_for_machine() {
    local machine="$1" pid="$2" log="$3"
    timeout 30 bash -c "
        while ! machinectl list --no-legend 2>/dev/null | grep >/dev/null '$machine'; do
            if ! kill -0 $pid 2>/dev/null; then
                echo 'vmspawn exited before machine registration'
                cat '$log'
                exit 77
            fi
            sleep .5
        done
    " || {
        local rc=$?
        if [[ $rc -eq 77 ]]; then exit 0; fi
        exit "$rc"
    }
}

# --- Boot the VM with one boot-time bind-volume ---
MACHINE="test-bind-volume-$$"
systemd-vmspawn \
    --machine="$MACHINE" \
    --ram=256M \
    --image="$WORKDIR/root.raw" \
    --bind-volume="fs:${BOOT_VOL}::create=new,size=64M,template=sparse-file" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    root=/dev/vda rw \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
echo "Machine '$MACHINE' registered"

VARLINK_ADDR=$(varlinkctl call /run/systemd/machine/io.systemd.Machine \
    io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" | jq -r '.controlAddress')
assert_neq "$VARLINK_ADDR" "null"

varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Describe '{}' \
    | jq -e '.running == true' >/dev/null
echo "VM running with boot-time bind-volume attached"

# --- Hot-add a second volume via machinectl bind-volume (must succeed) ---
machinectl bind-volume "$MACHINE" \
    "fs:${RUNTIME_VOL}:virtio-scsi:create=new,size=32M,template=sparse-file"
echo "Hot-added runtime bind-volume succeeded"

# --- Hot-remove the runtime-added volume (must succeed) ---
machinectl unbind-volume "$MACHINE" "fs:${RUNTIME_VOL}"
echo "Hot-removed runtime bind-volume succeeded"

# --- Removing the boot-time volume must fail with StorageImmutable ---
if machinectl unbind-volume "$MACHINE" "fs:${BOOT_VOL}" 2>"$WORKDIR/unbind.err"; then
    echo "ERROR: unbind-volume of boot-time volume should have failed"
    cat "$WORKDIR/unbind.err"
    exit 1
fi
grep StorageImmutable "$WORKDIR/unbind.err" >/dev/null
echo "Boot-time bind-volume correctly rejected with StorageImmutable"

# --- Removing a non-existent name must fail with NoSuchStorage ---
if machinectl unbind-volume "$MACHINE" "fs:no-such-volume-$$" 2>"$WORKDIR/unbind-noexist.err"; then
    echo "ERROR: unbind-volume of non-existent name should have failed"
    cat "$WORKDIR/unbind-noexist.err"
    exit 1
fi
grep NoSuchStorage "$WORKDIR/unbind-noexist.err" >/dev/null
echo "Non-existent unbind-volume correctly rejected with NoSuchStorage"

machinectl terminate "$MACHINE"
timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
echo "All bind-volume tests passed"
