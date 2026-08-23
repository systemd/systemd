#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test vmspawn QMP-based multi-drive setup and ephemeral overlay.
#
# Exercises the async QMP command pipeline with multiple drives:
# - Multiple fdset allocations (counter correctness)
# - Pipelined blockdev-add commands (FIFO ordering)
# - io_uring retry callbacks (if QEMU lacks io_uring support)
# - Multiple device_add commands
# - blockdev-create job watching with deferred continuation (ephemeral)
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

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 77
fi

if ! command -v mke2fs >/dev/null 2>&1; then
    echo "mke2fs not found, skipping"
    exit 77
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
    exit 77
fi
echo "Using kernel: $KERNEL"

WORKDIR="$(mktemp -d)"

at_exit() {
    set +e
    for m in "${MACHINE_MULTI:-}" "${MACHINE_EPHEMERAL:-}" "${MACHINE_GROW:-}"; do
        [[ -n "$m" ]] || continue
        if machinectl status "$m" &>/dev/null; then
            machinectl terminate "$m" 2>/dev/null
            timeout 10 bash -c "while machinectl status '$m' &>/dev/null; do sleep .5; done" 2>/dev/null
        fi
    done
    [[ -n "${VMSPAWN_MULTI_PID:-}" ]] && kill "$VMSPAWN_MULTI_PID" 2>/dev/null && wait "$VMSPAWN_MULTI_PID" 2>/dev/null
    [[ -n "${VMSPAWN_EPHEMERAL_PID:-}" ]] && kill "$VMSPAWN_EPHEMERAL_PID" 2>/dev/null && wait "$VMSPAWN_EPHEMERAL_PID" 2>/dev/null
    [[ -n "${VMSPAWN_GROW_PID:-}" ]] && kill "$VMSPAWN_GROW_PID" 2>/dev/null && wait "$VMSPAWN_GROW_PID" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# Create a minimal root filesystem directory, then bake it into a raw ext4 image.
# The guest doesn't need to fully boot — 'sleep infinity' keeps QEMU alive for QMP testing.
mkdir -p "$WORKDIR/rootfs/sbin"
cat >"$WORKDIR/rootfs/sbin/init" <<'INITEOF'
#!/bin/sh
exec sleep infinity
INITEOF
chmod +x "$WORKDIR/rootfs/sbin/init"

truncate -s 256M "$WORKDIR/root.raw"
mke2fs -t ext4 -q -d "$WORKDIR/rootfs" "$WORKDIR/root.raw"

# Create extra raw drive images (different sizes to be distinguishable)
truncate -s 64M "$WORKDIR/extra1.raw"
truncate -s 32M "$WORKDIR/extra2.raw"

# --- Test 1: Multi-drive setup (root + 2 extra drives) ---
# Verifies that --image with multiple --extra-drive flags works with the async
# QMP pipeline. Three drives means three fdset allocations, three blockdev-add
# file nodes (each with io_uring retry), three blockdev-add format nodes, and
# three device_add commands — all pipelined without waiting for responses.

MACHINE_MULTI="test-vmspawn-drives-$$"
systemd-vmspawn \
    --machine="$MACHINE_MULTI" \
    --ram=256M \
    --image="$WORKDIR/root.raw" \
    --extra-drive="$WORKDIR/extra1.raw" \
    --extra-drive="$WORKDIR/extra2.raw" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    root=/dev/vda rw \
    &>"$WORKDIR/vmspawn-multi.log" &
VMSPAWN_MULTI_PID=$!

wait_for_machine "$MACHINE_MULTI" "$VMSPAWN_MULTI_PID" "$WORKDIR/vmspawn-multi.log"
echo "Multi-drive machine '$MACHINE_MULTI' registered with machined"

# Verify varlink control address is present and the VM is running
VARLINK_ADDR=$(varlinkctl call /run/systemd/machine/io.systemd.Machine \
    io.systemd.Machine.List "{\"name\":\"$MACHINE_MULTI\"}" | jq -r '.controlAddress')
assert_neq "$VARLINK_ADDR" "null"

STATUS=$(varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Describe '{}')
echo "$STATUS" | jq -e '.running == true'
echo "Multi-drive VM running — async QMP drive pipeline succeeded"

# Verify no on_setup_complete failures in the vmspawn log
if grep -E '(add-fd|blockdev-add|blockdev-create|device_add|getfd|netdev_add|chardev-add) failed:' "$WORKDIR/vmspawn-multi.log"; then
    echo "Full vmspawn log:"
    cat "$WORKDIR/vmspawn-multi.log"
    exit 1
fi
echo "No QMP device setup errors in log"

machinectl terminate "$MACHINE_MULTI"
timeout 10 bash -c "while machinectl status '$MACHINE_MULTI' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_MULTI_PID' 2>/dev/null; do sleep .5; done"
echo "Multi-drive VM terminated cleanly"

# --- Test 2: Ephemeral overlay (blockdev-create job continuation) ---
# Verifies that --image with --ephemeral works. This is the most complex async
# path: blockdev-create returns immediately, the qcow2 overlay is formatted in a
# background job, JOB_STATUS_CHANGE events are watched, and when the job
# concludes the deferred continuation fires blockdev-add (overlay format) +
# device_add. If any step fails, the root drive is never attached and the kernel
# panics — vmspawn exits without registering.

MACHINE_EPHEMERAL="test-vmspawn-ephemeral-$$"
systemd-vmspawn \
    --machine="$MACHINE_EPHEMERAL" \
    --ram=256M \
    --image="$WORKDIR/root.raw" \
    --ephemeral \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    root=/dev/vda rw \
    &>"$WORKDIR/vmspawn-ephemeral.log" &
VMSPAWN_EPHEMERAL_PID=$!

wait_for_machine "$MACHINE_EPHEMERAL" "$VMSPAWN_EPHEMERAL_PID" "$WORKDIR/vmspawn-ephemeral.log"
echo "Ephemeral machine '$MACHINE_EPHEMERAL' registered with machined"

VARLINK_ADDR_E=$(varlinkctl call /run/systemd/machine/io.systemd.Machine \
    io.systemd.Machine.List "{\"name\":\"$MACHINE_EPHEMERAL\"}" | jq -r '.controlAddress')
assert_neq "$VARLINK_ADDR_E" "null"

STATUS_E=$(varlinkctl call "$VARLINK_ADDR_E" io.systemd.MachineInstance.Describe '{}')
echo "$STATUS_E" | jq -e '.running == true'
echo "Ephemeral VM running — blockdev-create job continuation succeeded"

if grep -E '(add-fd|blockdev-add|blockdev-create|device_add|getfd|netdev_add|chardev-add) failed:' "$WORKDIR/vmspawn-ephemeral.log"; then
    echo "Full vmspawn log:"
    cat "$WORKDIR/vmspawn-ephemeral.log"
    exit 1
fi
echo "No QMP device setup errors in ephemeral log"

machinectl terminate "$MACHINE_EPHEMERAL"
timeout 10 bash -c "while machinectl status '$MACHINE_EPHEMERAL' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_EPHEMERAL_PID' 2>/dev/null; do sleep .5; done"
echo "Ephemeral VM terminated cleanly"

# --- Test 3: Ephemeral overlay grown with --grow-image= ---
# In ephemeral mode the requested size has to land on the qcow2 overlay. The
# image passed to --image= is opened read-only and has to come out of the run
# at its original size.

MACHINE_GROW="test-vmspawn-grow-$$"
GROW_SIZE=$((512 * 1024 * 1024))
IMAGE_SIZE="$(stat -c %s "$WORKDIR/root.raw")"

systemd-vmspawn \
    --machine="$MACHINE_GROW" \
    --ram=256M \
    --image="$WORKDIR/root.raw" \
    --ephemeral \
    --grow-image="$GROW_SIZE" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    root=/dev/vda rw \
    &>"$WORKDIR/vmspawn-grow.log" &
VMSPAWN_GROW_PID=$!

wait_for_machine "$MACHINE_GROW" "$VMSPAWN_GROW_PID" "$WORKDIR/vmspawn-grow.log"
echo "Grown ephemeral machine '$MACHINE_GROW' registered with machined"

assert_eq "$(stat -c %s "$WORKDIR/root.raw")" "$IMAGE_SIZE"
echo "Image passed to --image= was left at its original size"

# The overlay is unlinked, so QEMU's fd is the only way to reach it. vmspawn
# registers QEMU itself as the machine leader, so machined knows its PID.
QEMU_PID="$(varlinkctl call /run/systemd/machine/io.systemd.Machine \
    io.systemd.Machine.List "{\"name\":\"$MACHINE_GROW\"}" | jq -r '.leader.pid')"

OVERLAY=""
for fd in /proc/"$QEMU_PID"/fd/*; do
    target="$(readlink "$fd" 2>/dev/null)" || continue
    # O_TMPFILE in the runtime directory, or the memfd fallback.
    [[ "$target" == */vmspawn/"$MACHINE_GROW"/#* || "$target" == /memfd:vmspawn-overlay* ]] || continue
    OVERLAY="$fd"
    break
done
assert_neq "$OVERLAY" ""
echo "Ephemeral overlay is QEMU fd ${OVERLAY##*/}"

# qcow2 header: the magic, followed by the virtual size as a big endian u64 at
# offset 24. Read it out of the header directly, qemu-img may not be installed.
assert_eq "$(od -An -tx1 -N4 "$OVERLAY" | tr -d ' ')" "514649fb"
assert_eq "$(od -An -tu8 -j24 -N8 --endian=big "$OVERLAY" | tr -d ' ')" "$GROW_SIZE"
echo "Ephemeral overlay was created at the requested size"

machinectl terminate "$MACHINE_GROW"
timeout 10 bash -c "while machinectl status '$MACHINE_GROW' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_GROW_PID' 2>/dev/null; do sleep .5; done"
echo "Grown ephemeral VM terminated cleanly"

echo "All vmspawn drive setup tests passed"
