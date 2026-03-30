#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test vmspawn QMP-varlink bridge and machinectl VM control verbs.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping"
    exit 0
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1 &&
   ! command -v qemu-system-aarch64 >/dev/null 2>&1 &&
   ! command -v qemu >/dev/null 2>&1; then
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

# Launch vmspawn in the background with direct kernel boot and headless console.
systemd-vmspawn \
    --machine="$MACHINE" \
    --directory="$WORKDIR/root" \
    --linux="$KERNEL" \
    --console=headless \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

# Wait for the machine to register with machined
timeout 30 bash -c "
    while ! machinectl list --no-legend 2>/dev/null | grep >/dev/null '$MACHINE'; do
        if ! kill -0 $VMSPAWN_PID 2>/dev/null; then
            echo 'vmspawn exited before registering'
            cat '$WORKDIR/vmspawn.log'
            exit 1
        fi
        sleep .5
    done
"
echo "Machine '$MACHINE' registered with machined"

# Verify that varlinkAddress is present in Machine.List output
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" | grep >/dev/null varlinkAddress
echo "varlinkAddress exposed in Machine.List"

# Exercise the MachineInstance varlink interface directly via varlinkctl.
# Look up the varlink address from machined. Do this BEFORE machinectl poweroff since poweroff
# is destructive (either kills the machine via signal or sends ACPI shutdown).
VARLINK_ADDR=$(varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" | jq -r '.varlinkAddress')
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

# Test machinectl pause/resume
machinectl pause "$MACHINE"
echo "machinectl pause succeeded"

machinectl resume "$MACHINE"
echo "machinectl resume succeeded"

# Test machinectl poweroff -- sends ACPI powerdown via QMP (system_powerdown).
# The guest won't handle it (our init is just 'sleep infinity'), but the QMP command should succeed.
machinectl poweroff "$MACHINE"
echo "machinectl poweroff succeeded"

# Test machinectl terminate -- sends QMP quit which forcefully kills QEMU.
# Verify the VM actually goes away.
machinectl terminate "$MACHINE"
timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done"
echo "machinectl terminate succeeded, VM is gone"

# vmspawn should have exited too
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
echo "vmspawn process exited"

echo "All vmspawn QMP-varlink bridge tests passed"
