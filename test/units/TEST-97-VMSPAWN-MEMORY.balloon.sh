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

# A modest step: what the guest keeps after the shrink decides whether it deflates the balloon on its
# own under memory pressure, and 1G is enough even for an instrumented build still booting.
RAM=$((1280 * 1024 * 1024))
SMALL=$((1024 * 1024 * 1024))

at_exit() {
    local rc=$?
    set +e
    if [[ $rc -ne 0 ]]; then
        echo "Guest console and vmspawn log are in the journal: journalctl -t $MACHINE"
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

# wait_for_actual BYTES: wait until the guest has converged to BYTES. Used for the first shrink only, which
# also covers the nested guest booting far enough to load its balloon driver, possibly slow without KVM.
wait_for_actual() {
    local want="${1:?}" deadline=$((SECONDS + 120))
    until [[ "$(memory actualBytes)" -eq "$want" ]]; do
        if (( SECONDS >= deadline )); then
            echo >&2 "Timed out waiting for actualBytes == $want, got $(memory actualBytes)"
            return 1
        fi
        sleep 1
    done
}

# set_memory_and_wait BYTES: SetMemory() with 'more', which follows the guest until it settles. Its final
# reply must report BYTES as both the target and the current size. How many notifications precede it depends
# on how fast the guest moves, so the count is only printed. varlinkctl prints the replies of a 'more' call as
# a JSON text sequence, each starting with a record separator, hence jq --seq.
set_memory_and_wait() {
    local bytes="${1:?}" out="$WORKDIR/set-memory.json"
    timeout 60 varlinkctl call --more "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$bytes}" >"$out"
    echo "SetMemory($bytes) sent $(grep -c $'^\x1e' "$out") message(s)"
    jq --seq -s -e "last | .targetBytes == $bytes and .actualBytes == $bytes" "$out"
}

# Direct kernel boot of the built image on an ephemeral overlay. The serial console carries guest output
# from early boot on. It goes, together with vmspawn's debug log, into the log file and into the journal
# under the machine name, which ends up in the CI artifacts: journalctl -t vmspawn-memory-balloon-<pid>
SYSTEMD_LOG_LEVEL=debug systemd-vmspawn \
    --machine="$MACHINE" \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --ephemeral \
    --ram=1280M \
    --tpm=no \
    --console=read-only \
    --console-transport=serial \
    selinux=0 systemd.firstboot=no rw \
    &> >(tee "$WORKDIR/vmspawn.log" | systemd-cat --identifier="$MACHINE") &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
CTL="$(machine_control_address "$MACHINE")"

# Before anything moves, all three sizes agree with --ram=.
assert_eq "$(memory configuredBytes)" "$RAM"
assert_eq "$(memory targetBytes)" "$RAM"
assert_eq "$(memory actualBytes)" "$RAM"

# Shrink to an unaligned size. Without 'more' the call returns once QEMU accepted the target, which is rounded
# up to the balloon's granularity so that the guest can settle exactly on it. The guest follows
# asynchronously, once it has loaded its balloon driver.
ROUNDED=$((SMALL + 64 * 1024))
assert_eq "$(varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$((SMALL + 1))}" | jq -r .targetBytes)" "$ROUNDED"
assert_eq "$(memory targetBytes)" "$ROUNDED"
wait_for_actual "$ROUNDED"

# Grow back. The guest reclaims its pages by faulting them in, nothing has to be handed over.
set_memory_and_wait "$RAM"

# Shrink again, now following the guest with 'more'.
set_memory_and_wait "$SMALL"

# A newer request replaces the target and ends a still pending call. With the vCPUs paused the guest cannot
# follow, so the first call stays pending until its 5s stall timeout, which starts once QEMU accepted the
# target. Waiting for that and sending the second call has to fit well within it.
varlinkctl call "$CTL" io.systemd.MachineInstance.Pause '{}'
varlinkctl call --more "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$RAM}" &>"$WORKDIR/superseded.log" &
PENDING_PID=$!
timeout 3 bash -c "until [[ \"\$(varlinkctl call '$CTL' io.systemd.MachineInstance.Describe '{}' | jq -r .memory.targetBytes)\" -eq $RAM ]]; do sleep .2; done"
varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$SMALL}"
rc=0
wait "$PENDING_PID" || rc=$?
assert_neq "$rc" 0
assert_in Superseded "$(cat "$WORKDIR/superseded.log")"
varlinkctl call "$CTL" io.systemd.MachineInstance.Resume '{}'

# Out of range: zero, and anything above the boot RAM the balloon cannot grow past. varlinkctl renders
# org.varlink.service.InvalidParameter as "Invalid argument" and prints the error payload after it.
assert_in '"parameter":"bytes"' "$(varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory '{"bytes":0}' 2>&1 || :)"
assert_in '"parameter":"bytes"' "$(varlinkctl call "$CTL" io.systemd.MachineInstance.SetMemory "{\"bytes\":$((2 * RAM))}" 2>&1 || :)"
