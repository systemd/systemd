#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test machinectl attach-disk / detach-disk / list-disks for vmspawn.
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

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 0
fi

if ! command -v virtiofsd >/dev/null 2>&1 &&
   ! test -x /usr/libexec/virtiofsd &&
   ! test -x /usr/lib/virtiofsd; then
    echo "virtiofsd not found, skipping"
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
echo "Using kernel: $KERNEL"

MACHINE="test-vmspawn-disk-$$"
WORKDIR="$(mktemp -d)"

at_exit() {
    set +e
    if machinectl status "$MACHINE" &>/dev/null; then
        machinectl terminate "$MACHINE" 2>/dev/null
        timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done" 2>/dev/null
    fi
    [[ -n "${VMSPAWN_PID:-}" ]] && kill "$VMSPAWN_PID" 2>/dev/null && wait "$VMSPAWN_PID" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# The guest has to actually boot Linux (ACPI hotplug detach requires the
# guest's acpiphp driver, and on q35 the eject SCI is dropped unless OSPM
# has finished initialising). Fedora's kernel keeps virtio_fs + fuse as
# modules and we don't ship an initramfs, so --directory= (virtiofs) panics
# at mount-root. Build a tiny ext4 rootfs instead — ext4 + virtio_blk are
# built into the kernel.
mkdir -p "$WORKDIR/root"/{sbin,proc,sys,dev,etc,bin,lib64}
# Copy /bin/sh + a few helpers plus the libraries ldd reports. Fedora's /bin
# is typically a symlink to /usr/bin, so pull through `command -v`.
HOSTLIB=""
for d in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /usr/lib64 /lib64; do
    [[ -d "$d" ]] || continue
    HOSTLIB="$d"
    break
done
mkdir -p "$WORKDIR/root$HOSTLIB"
copy_with_libs() {
    local bin="$1" lib dest
    cp --reflink=auto -L "$bin" "$WORKDIR/root/bin/"
    while read -r lib; do
        dest=$(awk '{ for (i=1;i<=NF;i++) if ($i ~ /^\//) { print $i; exit } }' <<<"$lib")
        [[ -n "$dest" && -f "$dest" ]] || continue
        cp --reflink=auto -L -n "$dest" "$WORKDIR/root$HOSTLIB/" 2>/dev/null || true
    done < <(ldd "$bin" 2>/dev/null)
}
for b in sh sleep; do
    src=$(command -v "$b" 2>/dev/null) || continue
    copy_with_libs "$src"
done
# ld-linux must live at /lib64 on x86_64 regardless of where the rest is.
for ld in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2; do
    if [[ -f "$ld" ]]; then
        cp --reflink=auto -L "$ld" "$WORKDIR/root/lib64/"
        break
    fi
done
# ld.so.cache helps ld-linux find libraries without writing ld.so.conf.
[[ -e /etc/ld.so.cache ]] && cp --reflink=auto -L /etc/ld.so.cache "$WORKDIR/root/etc/"
# The "[init] start" marker lets the test barrier on actual guest userspace
# rather than on machinectl registration alone. Without the barrier, the first
# attach+detach can race ahead of guest ACPI OSPM init: QEMU queues the eject
# SCI, but OSPM clears pending GPE status bits during boot and the unplug
# event is silently dropped — see hw/acpi/pcihp.c acpi_pcihp_eject_request().
cat >"$WORKDIR/root/sbin/init" <<'INITEOF'
#!/bin/sh
echo "[init] start"
exec /bin/sleep infinity
INITEOF
chmod +x "$WORKDIR/root/sbin/init"

# Pack into a GPT-ful raw image for vmspawn's --image= dissect logic.
mkdir -p "$WORKDIR/repart.d"
cat >"$WORKDIR/repart.d/10-root.conf" <<'EOF'
[Partition]
Type=root
Format=ext4
CopyFiles=/
SizeMinBytes=128M
SizeMaxBytes=128M
EOF
systemd-repart \
    --definitions="$WORKDIR/repart.d" \
    --empty=create \
    --size=auto \
    --root="$WORKDIR/root" \
    "$WORKDIR/rootfs.raw" >/dev/null

# Reuse wait_for_machine from the main vmspawn test
wait_for_machine() {
    local machine="$1" pid="$2" log="$3"
    timeout 30 bash -c "
        while ! machinectl list --no-legend 2>/dev/null | grep >/dev/null '$machine'; do
            if ! kill -0 $pid 2>/dev/null; then
                if grep >/dev/null 'virtiofs.*QMP\|vhost-user-fs-pci' '$log'; then
                    echo 'vhost-user-fs not supported (nested VM?), skipping'
                    exit 77
                fi
                echo 'vmspawn exited before registering'
                cat '$log'
                exit 1
            fi
            sleep .5
        done
    " || {
        local rc=$?
        if [[ $rc -eq 77 ]]; then exit 0; fi
        exit "$rc"
    }
}

# Create test disk images. bootdisk is opened by QEMU at boot (taking its
# image lock), so it must be distinct from the disks re-attached below.
truncate -s 64M "$WORKDIR/disk1.raw"
truncate -s 32M "$WORKDIR/disk2.raw"
truncate -s 16M "$WORKDIR/bootdisk.raw"

# Launch vmspawn with a boot-time extra drive so Test 1 has something to see.
# 1G of RAM because the EFI stub decompressing the kernel needs some headroom.
# A second -serial captures the guest console so the barrier below can wait
# for "[init] start" and the failure diagnostic can dump kernel messages.
SYSTEMD_VMSPAWN_QEMU_EXTRA="-serial file:$WORKDIR/guest-console.log" \
systemd-vmspawn \
    --machine="$MACHINE" \
    --ram=1G \
    --image="$WORKDIR/rootfs.raw" \
    --linux="$KERNEL" \
    --extra-drive="$WORKDIR/bootdisk.raw" \
    --tpm=no \
    --console=headless \
    console=ttyS0 \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
echo "Machine '$MACHINE' registered"

# Wait for the guest to actually reach /sbin/init. Without this, the first
# attach+detach in Test 2 can race ahead of guest ACPI OSPM and the eject
# SCI gets dropped (see hw/acpi/pcihp.c acpi_pcihp_eject_request). The init
# script above emits "[init] start" as its first echo to /dev/console.
echo "--- Waiting for guest init to reach userspace ---"
if ! timeout 45 bash -c "
    while ! grep >/dev/null '\[init\] start' '$WORKDIR/guest-console.log' 2>/dev/null; do
        sleep 0.5
    done
"; then
    echo "=== guest never reached /sbin/init; console log ==="
    tail -200 "$WORKDIR/guest-console.log" 2>/dev/null || echo "(no console log)"
    exit 1
fi
echo "Guest init reached userspace"

# --- Test 1: Boot-time drives visible in list-disks ---
# Machine registration races with the async blockdev-add + device_add dispatch
# at boot, so poll for the boot-time drive to appear rather than querying once.
echo "--- Test 1: list-disks shows boot-time drives ---"
timeout 10 bash -c "
    while ! machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'bd0'; do
        sleep 0.5
    done
"
echo "Boot-time drives listed"

# --- Test 2: Basic attach-disk / list-disks / detach-disk ---
echo "--- Test 2: Basic attach/list/detach cycle ---"
machinectl attach-disk "$MACHINE" "$WORKDIR/disk1.raw" --disk-id=scratch-01
machinectl list-disks "$MACHINE" --no-legend | grep >/dev/null "scratch-01"
echo "Disk attached and visible"

machinectl detach-disk "$MACHINE" scratch-01
# Wait for removal. If this hangs, guest OSPM probably wasn't up by the time
# we fired device_del and the guest silently dropped the pending GPE — dump
# the guest console so the regression is self-diagnosing.
if ! timeout 10 bash -c "
    while machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'scratch-01'; do
        sleep 0.5
    done
"; then
    echo "=== detach timed out; guest-console.log tail ==="
    tail -80 "$WORKDIR/guest-console.log" 2>/dev/null || echo "(no console log)"
    exit 1
fi
echo "Disk detached"

# --- Test 3: Attach with --read-only ---
echo "--- Test 3: Read-only attach ---"
machinectl attach-disk "$MACHINE" "$WORKDIR/disk1.raw" --read-only --disk-id=ro-disk
machinectl list-disks "$MACHINE" --no-legend | grep >/dev/null "ro-disk"
machinectl detach-disk "$MACHINE" ro-disk
timeout 10 bash -c "
    while machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'ro-disk'; do
        sleep 0.5
    done
"
echo "Read-only disk attached and detached"

# --- Test 4: Two disks concurrently ---
echo "--- Test 4: Concurrent attach ---"
machinectl attach-disk "$MACHINE" "$WORKDIR/disk1.raw" --disk-id=concurrent-a
machinectl attach-disk "$MACHINE" "$WORKDIR/disk2.raw" --disk-id=concurrent-b
machinectl list-disks "$MACHINE" --no-legend | grep >/dev/null "concurrent-a"
machinectl list-disks "$MACHINE" --no-legend | grep >/dev/null "concurrent-b"
echo "Both concurrent disks visible"

machinectl detach-disk "$MACHINE" concurrent-a
machinectl detach-disk "$MACHINE" concurrent-b
timeout 10 bash -c "
    while machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'concurrent-'; do
        sleep 0.5
    done
"
echo "Both concurrent disks detached"

# --- Test 5: Duplicate id rejected ---
echo "--- Test 5: Duplicate id error ---"
machinectl attach-disk "$MACHINE" "$WORKDIR/disk1.raw" --disk-id=dup-test
(! machinectl attach-disk "$MACHINE" "$WORKDIR/disk2.raw" --disk-id=dup-test)
echo "Duplicate id correctly rejected"

machinectl detach-disk "$MACHINE" dup-test
timeout 10 bash -c "
    while machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'dup-test'; do
        sleep 0.5
    done
"

# --- Test 6: Detach nonexistent id rejected ---
echo "--- Test 6: Detach nonexistent id ---"
(! machinectl detach-disk "$MACHINE" does-not-exist-12345)
echo "Detach nonexistent id correctly rejected"

# --- Test 7: Reattach after detach ---
echo "--- Test 7: Reattach ---"
machinectl attach-disk "$MACHINE" "$WORKDIR/disk1.raw" --disk-id=reattach-test
machinectl detach-disk "$MACHINE" reattach-test
timeout 10 bash -c "
    while machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'reattach-test'; do
        sleep 0.5
    done
"
machinectl attach-disk "$MACHINE" "$WORKDIR/disk1.raw" --disk-id=reattach-test
machinectl list-disks "$MACHINE" --no-legend | grep >/dev/null "reattach-test"
echo "Reattach succeeded"

machinectl detach-disk "$MACHINE" reattach-test
timeout 10 bash -c "
    while machinectl list-disks '$MACHINE' --no-legend 2>/dev/null | grep >/dev/null 'reattach-test'; do
        sleep 0.5
    done
"

# --- The remaining tests exercise the varlink IDL directly, bypassing
#     machinectl, so they can cover driver/format combinations that
#     machinectl doesn't expose. ---
CTRL=$(varlinkctl call --json=short \
        /run/systemd/machine/io.systemd.Machine \
        io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" 2>/dev/null |
        sed -n 's/.*"controlAddress":"\([^"]*\)".*/\1/p')

if [[ -z "$CTRL" ]]; then
    echo "Could not determine control address; skipping direct varlink tests"
else
    echo "Control socket: $CTRL"

    # --- Test 8: Direct varlink attach/list/remove cycle ---
    echo "--- Test 8: Direct varlink IDL ---"
    exec 3<"$WORKDIR/disk1.raw"
    varlinkctl --push-fd=3 call "$CTRL" \
        io.systemd.VirtualMachineInstance.AddBlockDevice \
        '{"fileDescriptor": 0, "format": "raw", "driver": "virtio_blk", "id": "vl-direct"}' >/dev/null
    exec 3<&-

    varlinkctl call --more "$CTRL" \
        io.systemd.VirtualMachineInstance.ListBlockDevices '{}' |
        grep >/dev/null '"id" *: *"vl-direct"'

    varlinkctl call "$CTRL" \
        io.systemd.VirtualMachineInstance.RemoveBlockDevice \
        '{"id": "vl-direct"}' >/dev/null

    timeout 10 bash -c "
        while varlinkctl call --more '$CTRL' \
                io.systemd.VirtualMachineInstance.ListBlockDevices '{}' 2>/dev/null |
                grep >/dev/null '\"id\" *: *\"vl-direct\"'; do
            sleep 0.5
        done
    "
    echo "Direct varlink attach/list/remove passed"

    # --- Test 9: NVMe driver attach ---
    echo "--- Test 9: NVMe driver ---"
    exec 3<"$WORKDIR/disk1.raw"
    varlinkctl --push-fd=3 call "$CTRL" \
        io.systemd.VirtualMachineInstance.AddBlockDevice \
        '{"fileDescriptor": 0, "format": "raw", "driver": "nvme", "id": "nvme-test"}' >/dev/null
    exec 3<&-
    varlinkctl call --more "$CTRL" \
        io.systemd.VirtualMachineInstance.ListBlockDevices '{}' |
        grep >/dev/null '"id" *: *"nvme-test"'
    varlinkctl call "$CTRL" \
        io.systemd.VirtualMachineInstance.RemoveBlockDevice \
        '{"id": "nvme-test"}' >/dev/null
    timeout 10 bash -c "
        while varlinkctl call --more '$CTRL' \
                io.systemd.VirtualMachineInstance.ListBlockDevices '{}' 2>/dev/null |
                grep >/dev/null '\"id\" *: *\"nvme-test\"'; do
            sleep 0.5
        done
    "
    echo "NVMe attach/detach passed"

    # --- Test 10: SCSI driver attach (exercises on-demand controller) ---
    echo "--- Test 10: SCSI driver ---"
    exec 3<"$WORKDIR/disk1.raw"
    varlinkctl --push-fd=3 call "$CTRL" \
        io.systemd.VirtualMachineInstance.AddBlockDevice \
        '{"fileDescriptor": 0, "format": "raw", "driver": "scsi_hd", "id": "scsi-test", "serial": "SCSI01"}' >/dev/null
    exec 3<&-
    varlinkctl call --more "$CTRL" \
        io.systemd.VirtualMachineInstance.ListBlockDevices '{}' |
        grep >/dev/null '"id" *: *"scsi-test"'
    varlinkctl call "$CTRL" \
        io.systemd.VirtualMachineInstance.RemoveBlockDevice \
        '{"id": "scsi-test"}' >/dev/null
    timeout 10 bash -c "
        while varlinkctl call --more '$CTRL' \
                io.systemd.VirtualMachineInstance.ListBlockDevices '{}' 2>/dev/null |
                grep >/dev/null '\"id\" *: *\"scsi-test\"'; do
            sleep 0.5
        done
    "
    echo "SCSI attach/detach passed"

    # --- Test 11: qcow2 format attach (needs qemu-img) ---
    if command -v qemu-img >/dev/null 2>&1; then
        echo "--- Test 11: qcow2 format ---"
        qemu-img create -f qcow2 "$WORKDIR/test.qcow2" 32M >/dev/null
        exec 3<"$WORKDIR/test.qcow2"
        varlinkctl --push-fd=3 call "$CTRL" \
            io.systemd.VirtualMachineInstance.AddBlockDevice \
            '{"fileDescriptor": 0, "format": "qcow2", "driver": "virtio_blk", "id": "qcow2-test"}' >/dev/null
        exec 3<&-
        varlinkctl call --more "$CTRL" \
            io.systemd.VirtualMachineInstance.ListBlockDevices '{}' |
            grep >/dev/null '"id" *: *"qcow2-test"'
        varlinkctl call --more "$CTRL" \
            io.systemd.VirtualMachineInstance.ListBlockDevices '{}' |
            grep >/dev/null '"format" *: *"qcow2"'
        varlinkctl call "$CTRL" \
            io.systemd.VirtualMachineInstance.RemoveBlockDevice \
            '{"id": "qcow2-test"}' >/dev/null
        timeout 10 bash -c "
            while varlinkctl call --more '$CTRL' \
                    io.systemd.VirtualMachineInstance.ListBlockDevices '{}' 2>/dev/null |
                    grep >/dev/null '\"id\" *: *\"qcow2-test\"'; do
                sleep 0.5
            done
        "
        echo "qcow2 attach/detach passed"
    else
        echo "qemu-img not found; skipping qcow2 test"
    fi

    # --- Test 12: BlockDeviceRemoved event fires on detach ---
    echo "--- Test 12: BlockDeviceRemoved event ---"
    varlinkctl call --more "$CTRL" \
        io.systemd.MachineInstance.SubscribeEvents \
        '{"filter":["BlockDeviceRemoved"]}' >"$WORKDIR/events.log" 2>&1 &
    SUB_PID=$!
    # Let the subscription register (READY notifier from server).
    timeout 10 bash -c "while ! grep >/dev/null 'READY' '$WORKDIR/events.log'; do sleep 0.2; done"

    exec 3<"$WORKDIR/disk1.raw"
    varlinkctl --push-fd=3 call "$CTRL" \
        io.systemd.VirtualMachineInstance.AddBlockDevice \
        '{"fileDescriptor": 0, "format": "raw", "driver": "virtio_blk", "id": "event-test"}' >/dev/null
    exec 3<&-
    varlinkctl call "$CTRL" \
        io.systemd.VirtualMachineInstance.RemoveBlockDevice \
        '{"id": "event-test"}' >/dev/null

    timeout 10 bash -c "
        while ! grep >/dev/null 'BlockDeviceRemoved' '$WORKDIR/events.log' ||
              ! grep >/dev/null 'event-test' '$WORKDIR/events.log'; do
            sleep 0.5
        done
    "
    # `wait` on a signal-terminated child returns 128+sig (143 for SIGTERM);
    # with `set -e` that'd abort the script before Test 13 runs.
    kill "$SUB_PID" 2>/dev/null || true
    wait "$SUB_PID" 2>/dev/null || true
    echo "BlockDeviceRemoved event observed"

    # --- Test 13: Auto-assigned id (no id supplied) ---
    echo "--- Test 13: Auto-assigned id ---"
    exec 3<"$WORKDIR/disk1.raw"
    AUTO_REPLY=$(varlinkctl --push-fd=3 call --json=short "$CTRL" \
        io.systemd.VirtualMachineInstance.AddBlockDevice \
        '{"fileDescriptor": 0, "format": "raw", "driver": "virtio_blk"}')
    exec 3<&-
    AUTO_ID=$(echo "$AUTO_REPLY" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
    [[ -n "$AUTO_ID" ]] || { echo "No auto id returned"; exit 1; }
    [[ "$AUTO_ID" =~ ^bd[0-9]+$ ]] || { echo "Unexpected auto id: $AUTO_ID"; exit 1; }
    echo "Auto-assigned id: $AUTO_ID"

    varlinkctl call "$CTRL" \
        io.systemd.VirtualMachineInstance.RemoveBlockDevice \
        "{\"id\":\"$AUTO_ID\"}" >/dev/null
    timeout 10 bash -c "
        while varlinkctl call --more '$CTRL' \
                io.systemd.VirtualMachineInstance.ListBlockDevices '{}' 2>/dev/null |
                grep >/dev/null '\"id\" *: *\"$AUTO_ID\"'; do
            sleep 0.5
        done
    "
    echo "Auto-id attach/detach passed"
fi

# Clean up
machinectl terminate "$MACHINE"
timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done"
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done" 2>/dev/null

echo "All vmspawn disk hotplug tests passed"
