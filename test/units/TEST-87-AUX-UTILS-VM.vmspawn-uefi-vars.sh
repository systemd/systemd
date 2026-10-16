#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test vmspawn with firmware that keeps its UEFI variables in QEMU's uefi-vars device
# ("host-uefi-vars" firmware feature) instead of pflash.
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

if ! systemd-vmspawn --firmware-features=host-uefi-vars --firmware=describe &>/dev/null; then
    echo "No firmware with a host-side UEFI variable store found, skipping"
    exit 77
fi

WORKDIR="$(mktemp -d)"
MACHINE="test-vmspawn-uefi-vars-$$"

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

# The disk doesn't need to be bootable: the firmware creates a boot option for it and tries it.
truncate -s 64M "$WORKDIR/disk.raw"

# Starts the VM with firmware that keeps its variables on the host. Temporary files go to $WORKDIR/tmp, so
# that leaks can be checked.
mkdir "$WORKDIR/tmp"
start_vm() {
    TMPDIR="$WORKDIR/tmp" systemd-vmspawn \
        --machine="$MACHINE" \
        --ram=256M \
        --image="$WORKDIR/disk.raw" \
        --tpm=no \
        --console=read-only \
        "$@" \
        &>"$WORKDIR/vmspawn.log" &
    VMSPAWN_PID=$!

    wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
    # When the firmware's boot manager tries the first boot option, it has stored the boot options in the
    # variable store. The firmware is slow under nested virtualization in CI, so give it plenty of time.
    if ! timeout 300 bash -c "until grep -a -E >/dev/null 'BdsDxe: (loading|failed to load) Boot[0-9A-F]{4}' '$WORKDIR/vmspawn.log'; do sleep .5; done"; then
        echo "Firmware did not reach its boot manager. Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi
}

stop_vm() {
    machinectl terminate "$MACHINE"
    timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
    wait "$VMSPAWN_PID"
    VMSPAWN_PID=
}

boot_firmware() {
    start_vm --firmware-features=host-uefi-vars "$@"
    stop_vm
}

has_variable() {
    jq -e --arg name "${2:?}" 'any(.variables[]; .name == $name)' "${1:?}" >/dev/null
}

# --- An explicit state file is created from the template and filled by QEMU ---
boot_firmware --efi-nvram-state="$WORKDIR/vars.json"
has_variable "$WORKDIR/vars.json" BootOrder
# The default template has no Secure Boot keys enrolled, i.e. the firmware is in setup mode.
(! has_variable "$WORKDIR/vars.json" PK)

# --- An existing state file is used as is, not reset from the template ---
jq '.variables += [{"name": "VmspawnTest", "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c", "attr": 7, "data": "2a"}]' \
    "$WORKDIR/vars.json" >"$WORKDIR/vars.json.new"
mv "$WORKDIR/vars.json.new" "$WORKDIR/vars.json"
boot_firmware --efi-nvram-state="$WORKDIR/vars.json"
has_variable "$WORKDIR/vars.json" VmspawnTest
has_variable "$WORKDIR/vars.json" BootOrder

# --- The state file can't be shared by concurrently running VMs ---
start_vm --firmware-features=host-uefi-vars --efi-nvram-state="$WORKDIR/vars.json"
truncate -s 64M "$WORKDIR/disk2.raw"
(! timeout 30 systemd-vmspawn \
    --machine="$MACHINE-2" \
    --image="$WORKDIR/disk2.raw" \
    --tpm=no \
    --console=read-only \
    --firmware-features=host-uefi-vars \
    --efi-nvram-state="$WORKDIR/vars.json" \
    &>"$WORKDIR/vmspawn-2.log")
grep >/dev/null "is in use by another VM" "$WORKDIR/vmspawn-2.log"
stop_vm

# --- With --ephemeral, the state is not kept ---
boot_firmware --ephemeral
test ! -e "$WORKDIR/disk.raw.efivarstate.json"
[[ -z "$(ls -A "$WORKDIR/tmp")" ]]

# --- By default, the state is kept next to the image, apart from pflash NVRAM state ---
echo garbage >"$WORKDIR/disk.raw.efinvramstate"
boot_firmware
has_variable "$WORKDIR/disk.raw.efivarstate.json" BootOrder
[[ "$(cat "$WORKDIR/disk.raw.efinvramstate")" == garbage ]]
rm "$WORKDIR/disk.raw.efinvramstate"

# --- A descriptor without a template needs one from --efi-nvram-template=, which overrides the descriptor's ---
systemd-vmspawn --firmware-features=host-uefi-vars --firmware=describe >"$WORKDIR/firmware.json"
jq 'del(.mapping."uefi-vars")' "$WORKDIR/firmware.json" >"$WORKDIR/firmware-no-template.json"
(! systemd-vmspawn \
    --image="$WORKDIR/disk.raw" \
    --tpm=no \
    --firmware="$WORKDIR/firmware-no-template.json" \
    &>"$WORKDIR/vmspawn-no-template.log")
grep >/dev/null "declares no template" "$WORKDIR/vmspawn-no-template.log"

jq '.variables += [{"name": "VmspawnTemplate", "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c", "attr": 7, "data": "2a"}]' \
    "$(jq -r '.mapping."uefi-vars".template' "$WORKDIR/firmware.json")" >"$WORKDIR/template.json"
start_vm \
    --firmware="$WORKDIR/firmware-no-template.json" \
    --efi-nvram-template="$WORKDIR/template.json" \
    --efi-nvram-state="$WORKDIR/vars-template.json"
stop_vm
has_variable "$WORKDIR/vars-template.json" VmspawnTemplate
has_variable "$WORKDIR/vars-template.json" BootOrder

echo "All vmspawn host-side UEFI variable store tests passed"
