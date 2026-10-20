#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Balloon: shrink a running guest below its boot RAM through SetMemory() and grow it back.

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

MACHINE="vmspawn-memory-balloon-$$"
WORKDIR="$(mktemp -d)"
VMSPAWN_PID=""
IMAGE_DIR="$(vmspawn_images_dir)"

RAM=$((1024 * 1024 * 1024))
HALF=$((RAM / 2))

at_exit() {
    local rc=$?
    set +e
    if [[ $rc -ne 0 && -f "$WORKDIR/vmspawn.log" ]]; then
        cat "$WORKDIR/vmspawn.log"
    fi
    if machinectl status "$MACHINE" &>/dev/null; then
        machinectl terminate "$MACHINE" 2>/dev/null
        timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done" 2>/dev/null
    fi
    [[ -n "$VMSPAWN_PID" ]] && kill "$VMSPAWN_PID" 2>/dev/null && wait "$VMSPAWN_PID" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# memory FIELD: one field of the Describe() memory object.
memory() {
    varlinkctl call "$CTL" io.systemd.MachineInstance.Describe '{}' | jq -r ".memory.${1:?}"
}

# wait_for_actual BYTES: wait until the guest has converged to BYTES.
wait_for_actual() {
    local want="${1:?}" deadline=$((SECONDS + 30))
    until [[ "$(memory actualBytes)" -eq "$want" ]]; do
        if (( SECONDS >= deadline )); then
            echo >&2 "Timed out waiting for actualBytes == $want, got $(memory actualBytes)"
            return 1
        fi
        sleep 1
    done
}

# Direct kernel boot of the built image on an ephemeral overlay, guest console into the log.
systemd-vmspawn \
    --machine="$MACHINE" \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --ephemeral \
    --ram=1G \
    --tpm=no \
    --console=read-only \
    selinux=0 systemd.firstboot=no rw \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
CTL="$(machine_control_address "$MACHINE")"

# Before anything moves, all three sizes agree with --ram=.
assert_eq "$(memory configuredBytes)" "$RAM"
assert_eq "$(memory targetBytes)" "$RAM"
assert_eq "$(memory actualBytes)" "$RAM"

# Shrink to half. The target moves immediately, the guest follows asynchronously.
varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$HALF}"
assert_eq "$(memory targetBytes)" "$HALF"
wait_for_actual "$HALF"

# Grow back. The guest reclaims its pages by faulting them in, nothing has to be handed over.
varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$RAM}"
assert_eq "$(memory targetBytes)" "$RAM"
wait_for_actual "$RAM"

# Out of range: zero, and anything above the boot RAM the balloon cannot grow past. varlinkctl renders
# org.varlink.service.InvalidParameter as "Invalid argument" and prints the error payload after it.
assert_in '"parameter":"bytes"' "$(varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory '{"bytes":0}' 2>&1 || :)"
assert_in '"parameter":"bytes"' "$(varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$((2 * RAM))}" 2>&1 || :)"
