#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test io.systemd.MachineInstance.ReplaceStorage — runtime hot-swap of an
# attached storage volume's backing file via QMP blockdev-reopen.
#
# Exercises:
#  - happy-path replace of a runtime-attached drive
#  - successive replaces (file_generation rotation, no node-name collisions)
#  - StorageImmutable rejection for boot-time attached volumes
#  - NoSuchStorage rejection for unknown names
#  - clean RemoveStorage after a replace (proves both old and new file nodes
#    are monitor-owned and properly cleaned up)
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

if ! test -S /run/systemd/io.systemd.StorageProvider/fs; then
    echo "StorageProvider fs socket not found, skipping"
    exit 0
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
    exit 0
fi

WORKDIR="$(mktemp -d /tmp/test-replace-storage.XXXXXXXXXX)"

at_exit() {
    set +e
    if [[ -n "${MACHINE:-}" ]]; then
        if machinectl status "$MACHINE" &>/dev/null; then
            machinectl terminate "$MACHINE" 2>/dev/null
            timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done" 2>/dev/null
        fi
    fi
    [[ -n "${VMSPAWN_PID:-}" ]] && { kill "$VMSPAWN_PID" 2>/dev/null; wait "$VMSPAWN_PID" 2>/dev/null; }
    rm -rf "$WORKDIR"
    rm -f /var/lib/storage/test-replace-storage-*.volume
}
trap at_exit EXIT

mkdir -p "$WORKDIR/rootfs/sbin"
cat >"$WORKDIR/rootfs/sbin/init" <<'INITEOF'
#!/bin/sh
exec sleep infinity
INITEOF
chmod +x "$WORKDIR/rootfs/sbin/init"

truncate -s 256M "$WORKDIR/root.raw"
mke2fs -t ext4 -q -d "$WORKDIR/rootfs" "$WORKDIR/root.raw"

BOOT_VOL="test-replace-storage-boot-$$"
RUNTIME_VOL="test-replace-storage-runtime-$$"

# Backing files for ReplaceStorage. Regular files; --push-fd opens read-only.
truncate -s 32M "$WORKDIR/new-backing-1.raw"
truncate -s 32M "$WORKDIR/new-backing-2.raw"

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

MACHINE="test-replace-storage-$$"
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

# --- Hot-add a runtime volume (target for ReplaceStorage) ---
# virtio-scsi: vmspawn's hot-add path only allocates a PCIe root port for the
# scsi controller; bare virtio-blk hot-add fails on QEMU builds that don't
# auto-pick a free slot. Same backend code path either way.
machinectl bind-volume "$MACHINE" \
    "fs:${RUNTIME_VOL}:virtio-scsi:create=new,size=32M,template=sparse-file"
echo "Hot-added runtime bind-volume"

# varlinkctl --push-fd=<path> opens O_RDONLY; the runtime drive is RW so the
# server rejects an RO fd with EROFS. Open RW via bash and pass the numeric fd.

# --- Test 1: happy-path replace ---
exec {NEW_FD}<>"$WORKDIR/new-backing-1.raw"
varlinkctl --push-fd="$NEW_FD" call "$VARLINK_ADDR" \
    io.systemd.MachineInstance.ReplaceStorage \
    "{\"fileDescriptorIndex\":0,\"name\":\"fs:${RUNTIME_VOL}\"}"
exec {NEW_FD}<&-
echo "Replace #1 succeeded"

# --- Test 2: replace again (verify file_generation rotation) ---
exec {NEW_FD}<>"$WORKDIR/new-backing-2.raw"
varlinkctl --push-fd="$NEW_FD" call "$VARLINK_ADDR" \
    io.systemd.MachineInstance.ReplaceStorage \
    "{\"fileDescriptorIndex\":0,\"name\":\"fs:${RUNTIME_VOL}\"}"
exec {NEW_FD}<&-
echo "Replace #2 succeeded"

# --- Test 3: replace boot-time drive must fail with StorageImmutable ---
if varlinkctl --push-fd="$WORKDIR/new-backing-1.raw" call "$VARLINK_ADDR" \
        io.systemd.MachineInstance.ReplaceStorage \
        "{\"fileDescriptorIndex\":0,\"name\":\"fs:${BOOT_VOL}\"}" 2>"$WORKDIR/replace-immutable.err"; then
    echo "ERROR: ReplaceStorage of boot-time drive should have failed"
    cat "$WORKDIR/replace-immutable.err"
    exit 1
fi
grep StorageImmutable "$WORKDIR/replace-immutable.err" >/dev/null
echo "Boot-time drive correctly rejected with StorageImmutable"

# --- Test 4: replace non-existent name must fail with NoSuchStorage ---
if varlinkctl --push-fd="$WORKDIR/new-backing-1.raw" call "$VARLINK_ADDR" \
        io.systemd.MachineInstance.ReplaceStorage \
        "{\"fileDescriptorIndex\":0,\"name\":\"fs:does-not-exist-$$\"}" 2>"$WORKDIR/replace-nosuch.err"; then
    echo "ERROR: ReplaceStorage of non-existent drive should have failed"
    cat "$WORKDIR/replace-nosuch.err"
    exit 1
fi
grep NoSuchStorage "$WORKDIR/replace-nosuch.err" >/dev/null
echo "Non-existent drive correctly rejected with NoSuchStorage"

# --- Test 5: RO fd to RW drive must fail with EROFS ---
# varlinkctl --push-fd=<path> opens RO; runtime drive is RW.
# Capture both stdout and stderr: errnoName "EROFS" is in the JSON reply on
# stdout; stderr only carries the human-readable strerror.
if varlinkctl --push-fd="$WORKDIR/new-backing-1.raw" call "$VARLINK_ADDR" \
        io.systemd.MachineInstance.ReplaceStorage \
        "{\"fileDescriptorIndex\":0,\"name\":\"fs:${RUNTIME_VOL}\"}" &>"$WORKDIR/replace-rofs.err"; then
    echo "ERROR: ReplaceStorage with RO fd should have failed"
    cat "$WORKDIR/replace-rofs.err"
    exit 1
fi
grep EROFS "$WORKDIR/replace-rofs.err" >/dev/null
echo "RO fd to RW drive correctly rejected with EROFS"

# --- Test 6: unbind after replace (proves new file node is monitor-owned and
# the format-then-file teardown order correctly cleans up both nodes) ---
machinectl unbind-volume "$MACHINE" "fs:${RUNTIME_VOL}"
echo "Unbind after replace succeeded (cleanup of both nodes works)"

machinectl terminate "$MACHINE"
timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
echo "All ReplaceStorage tests passed"
