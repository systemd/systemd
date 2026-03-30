#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test vmspawn QMP-varlink bridge and machinectl VM control verbs.
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

if ! command -v qemu-system-x86_64 >/dev/null 2>&1 &&
   ! command -v qemu-system-aarch64 >/dev/null 2>&1 &&
   ! command -v qemu >/dev/null 2>&1 &&
   ! command -v qemu-kvm >/dev/null 2>&1; then
    echo "QEMU not found, skipping"
    exit 0
fi

# --directory= needs virtiofsd (on Fedora it lives in /usr/libexec, not in PATH)
if ! command -v virtiofsd >/dev/null 2>&1 &&
   ! test -x /usr/libexec/virtiofsd &&
   ! test -x /usr/lib/virtiofsd; then
    echo "virtiofsd not found, skipping"
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
echo "Using kernel: $KERNEL"

MACHINE="test-vmspawn-qmp-$$"
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

# Create a minimal root filesystem. The guest does not need to fully boot -- we only need QEMU running
# with QMP. A trivial init that sleeps is sufficient.
mkdir -p "$WORKDIR/root/sbin"
cat >"$WORKDIR/root/sbin/init" <<'EOF'
#!/bin/sh
exec sleep infinity
EOF
chmod +x "$WORKDIR/root/sbin/init"

# Wait for a vmspawn machine to register with machined.
# Skips the test gracefully if vmspawn fails due to missing vhost-user-fs support (nested VM).
wait_for_machine() {
    local machine="$1" pid="$2" log="$3"
    timeout 30 bash -c "
        while ! machinectl list --no-legend 2>/dev/null | grep >/dev/null '$machine'; do
            if ! kill -0 $pid 2>/dev/null; then
                if grep -q 'virtiofs.*QMP\|vhost-user-fs-pci' '$log'; then
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

# Launch vmspawn in the background with direct kernel boot and headless console.
systemd-vmspawn \
    --machine="$MACHINE" \
    --directory="$WORKDIR/root" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
echo "Machine '$MACHINE' registered with machined"

# Verify that controlAddress is present in Machine.List output
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" | grep >/dev/null controlAddress
echo "controlAddress exposed in Machine.List"

# Exercise the MachineInstance varlink interface directly via varlinkctl.
# Look up the varlink address from machined. Do this BEFORE machinectl poweroff since poweroff
# is destructive (either kills the machine via signal or sends ACPI shutdown).
VARLINK_ADDR=$(varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" | jq -r '.controlAddress')
assert_neq "$VARLINK_ADDR" "null"

# QueryStatus should reflect a running VM
STATUS=$(varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.QueryStatus '{}')
echo "$STATUS" | jq -e '.running == true'
echo "$STATUS" | jq -e '.status == "running"'
echo "QueryStatus returned running state"

# Pause, verify, resume via varlinkctl
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Pause '{}'
STATUS=$(varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.QueryStatus '{}')
echo "$STATUS" | jq -e '.running == false'
echo "Verified paused state via QueryStatus"

varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Resume '{}'
STATUS=$(varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.QueryStatus '{}')
echo "$STATUS" | jq -e '.running == true'
echo "Verified resumed state via QueryStatus"

# --- SubscribeEvents tests ---
# Subscribe to all events in the background, collect output
varlinkctl call --more --timeout=10 "$VARLINK_ADDR" io.systemd.MachineInstance.SubscribeEvents '{}' \
    >"$WORKDIR/events-all.json" 2>&1 &
SUBSCRIBE_ALL_PID=$!
sleep 0.5

# Trigger STOP + RESUME events via pause/resume
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Pause '{}'
sleep 0.2
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Resume '{}'
sleep 0.5

# Kill the subscriber and check output
kill "$SUBSCRIBE_ALL_PID" 2>/dev/null; wait "$SUBSCRIBE_ALL_PID" 2>/dev/null || true
cat "$WORKDIR/events-all.json"

# Verify initial ready notification
grep >/dev/null '"ready"' "$WORKDIR/events-all.json"
echo "SubscribeEvents sent ready notification"

# Verify we got both STOP and RESUME events
grep >/dev/null '"STOP"' "$WORKDIR/events-all.json"
grep >/dev/null '"RESUME"' "$WORKDIR/events-all.json"
echo "SubscribeEvents received STOP and RESUME events"

# Test filtered subscription: only STOP events
varlinkctl call --more --timeout=10 "$VARLINK_ADDR" io.systemd.MachineInstance.SubscribeEvents '{"filter":["STOP"]}' \
    >"$WORKDIR/events-filtered.json" 2>&1 &
SUBSCRIBE_FILTER_PID=$!
sleep 0.5

# Trigger both events again
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Pause '{}'
sleep 0.2
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Resume '{}'
sleep 0.5

kill "$SUBSCRIBE_FILTER_PID" 2>/dev/null; wait "$SUBSCRIBE_FILTER_PID" 2>/dev/null || true
cat "$WORKDIR/events-filtered.json"

# Should have STOP but not RESUME
grep >/dev/null '"STOP"' "$WORKDIR/events-filtered.json"
(! grep >/dev/null '"RESUME"' "$WORKDIR/events-filtered.json")
echo "Filtered subscription correctly received only STOP events"

# Test machinectl pause/resume
machinectl pause "$MACHINE"
echo "machinectl pause succeeded"

machinectl resume "$MACHINE"
echo "machinectl resume succeeded"

# Test machinectl poweroff -- sends ACPI powerdown via QMP (system_powerdown).
# The guest won't handle it (our init is just 'sleep infinity'), but the QMP command should succeed.
machinectl poweroff "$MACHINE"
echo "machinectl poweroff succeeded"

