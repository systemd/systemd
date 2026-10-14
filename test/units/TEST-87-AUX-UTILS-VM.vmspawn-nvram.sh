#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test that pflash firmware without SMM support can write its UEFI variables.
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

FEATURES="~secure-boot,~requires-smm"
if ! systemd-vmspawn --firmware-features="$FEATURES" --firmware=describe &>/dev/null; then
    echo "No pflash firmware without SMM found, skipping"
    exit 77
fi

WORKDIR="$(mktemp -d)"
MACHINE="test-vmspawn-nvram-$$"

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

systemd-vmspawn --firmware-features="$FEATURES" --firmware=describe >"$WORKDIR/firmware.json"
TEMPLATE="$(jq -r '.mapping."nvram-template".filename' "$WORKDIR/firmware.json")"

# The disk doesn't need to be bootable: the firmware creates a boot option for it and tries it.
truncate -s 64M "$WORKDIR/disk.raw"

systemd-vmspawn \
    --machine="$MACHINE" \
    --ram=256M \
    --image="$WORKDIR/disk.raw" \
    --tpm=no \
    --console=read-only \
    --firmware-features="$FEATURES" \
    --efi-nvram-state="$WORKDIR/nvram" \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
# When the firmware's boot manager tries the first boot option, it has stored the boot options in NVRAM.
# The firmware is slow under nested virtualization in CI, so give it plenty of time.
if ! timeout 300 bash -c "until grep -a -E >/dev/null 'BdsDxe: (loading|failed to load) Boot[0-9A-F]{4}' '$WORKDIR/vmspawn.log'; do sleep .5; done"; then
    echo "Firmware did not reach its boot manager. Full vmspawn log:"
    cat "$WORKDIR/vmspawn.log"
    exit 1
fi

machinectl terminate "$MACHINE"
timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
wait "$VMSPAWN_PID"
VMSPAWN_PID=

# Without SMM, write protection of the NVRAM pflash for non-SMM accesses would silently drop all writes.
(! cmp "$TEMPLATE" "$WORKDIR/nvram")

echo "vmspawn NVRAM test passed"
