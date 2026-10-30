#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test that systemd-boot erases its EFI variables when LoaderFactoryResetVariables is set, using a VM whose
# UEFI variables are kept in a host-side JSON file, so that they can be inspected from the outside.
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

if ! command -v mkfs.vfat >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
    echo "mkfs.vfat or mcopy not found, skipping"
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

SD_BOOT="$(find /usr/lib/systemd/boot/efi/ -name "systemd-boot*.efi" | head -n1)"
if [[ -z "$SD_BOOT" ]]; then
    echo "systemd-boot not found, skipping"
    exit 77
fi

# systemd-bootx64.efi → BOOTX64.EFI
EFI_ARCH="$(basename "$SD_BOOT" .efi)"
EFI_ARCH="${EFI_ARCH#systemd-boot}"

LOADER_GUID=4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
SYSTEMD_GUID=8cf2644b-4b0b-428f-9387-6d876050dc67
GLOBAL_GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c

WORKDIR="$(mktemp -d)"
MACHINE="test-sd-boot-factory-reset-$$"

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

# Build a disk with an ESP that contains systemd-boot as the fallback boot loader. There are no boot entries
# (and auto-entries are turned off), hence once systemd-boot is done with the variables it fails with "No
# loader found", which we use as the marker that it ran.
mkdir -p "$WORKDIR/definitions" "$WORKDIR/esp/loader"

cat >"$WORKDIR/esp/loader/loader.conf" <<EOF
auto-entries no
auto-firmware no
EOF

cat >"$WORKDIR/definitions/esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=64M
CopyFiles=$SD_BOOT:/EFI/BOOT/BOOT${EFI_ARCH^^}.EFI
CopyFiles=$WORKDIR/esp/loader:/loader
EOF
systemd-repart \
    --empty=create \
    --size=auto \
    --dry-run=no \
    --offline=yes \
    --definitions="$WORKDIR/definitions" \
    "$WORKDIR/disk.raw"

# systemd-boot asks for confirmation on the console before erasing anything, hence pass the console input
# through a FIFO, so that we can answer once the question shows up. Keep the FIFO open for writing, so that
# vmspawn never sees EOF on it.
mkfifo "$WORKDIR/console"
exec {CONSOLE_FD}<>"$WORKDIR/console"

start_vm() {
    systemd-vmspawn \
        --machine="$MACHINE" \
        --ram=256M \
        --image="$WORKDIR/disk.raw" \
        --tpm=no \
        --console=native \
        --firmware-features=host-uefi-vars \
        "$@" \
        <"$WORKDIR/console" &>"$WORKDIR/vmspawn.log" &
    VMSPAWN_PID=$!

    wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
}

stop_vm() {
    machinectl terminate "$MACHINE"
    timeout 10 bash -c "while kill -0 '$VMSPAWN_PID' 2>/dev/null; do sleep .5; done"
    wait "$VMSPAWN_PID"
    VMSPAWN_PID=
}

wait_for_sd_boot() {
    # The firmware is slow under nested virtualization in CI, so give it plenty of time.
    if ! timeout 300 bash -c "until grep -a >/dev/null 'No loader found' '$WORKDIR/vmspawn.log'; do sleep .5; done"; then
        echo "systemd-boot did not finish. Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi
}

answer_question() {
    if ! timeout 300 bash -c "until grep -a >/dev/null 'Erase these EFI variables?' '$WORKDIR/vmspawn.log'; do sleep .5; done"; then
        echo "systemd-boot did not ask for confirmation. Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi

    printf '%s' "${1:?}" >&"$CONSOLE_FD"
}

has_variable() {
    jq -e --arg name "${2:?}" --arg guid "${3:?}" \
       'any(.variables[]; .name == $name and (.guid | ascii_downcase) == $guid)' "${1:?}" >/dev/null
}

add_variable() {
    jq --arg name "${2:?}" --arg guid "${3:?}" --arg data "${4:?}" \
       '.variables += [{"name": $name, "guid": $guid, "attr": 7, "data": $data}]' \
       "${1:?}" >"$1.new"
    mv "$1.new" "$1"
}

# Boot once to get a populated variable store
start_vm --efi-nvram-state="$WORKDIR/vars.json"
wait_for_sd_boot
stop_vm

# --- Without the request nothing is erased ---
add_variable "$WORKDIR/vars.json" LoaderEntryDefault "$LOADER_GUID" 6100620063000000
add_variable "$WORKDIR/vars.json" HibernateLocation "$SYSTEMD_GUID" 7b7d00
start_vm --efi-nvram-state="$WORKDIR/vars.json"
wait_for_sd_boot
stop_vm
has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$LOADER_GUID"
has_variable "$WORKDIR/vars.json" HibernateLocation "$SYSTEMD_GUID"

# --- If the request is declined, it is dropped, but nothing else is erased ---
# "yes" as NUL-terminated UTF-16LE, to check that any boolean string is accepted
add_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$LOADER_GUID" 7900650073000000
start_vm --efi-nvram-state="$WORKDIR/vars.json"
answer_question n
wait_for_sd_boot
stop_vm
has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$LOADER_GUID"
has_variable "$WORKDIR/vars.json" HibernateLocation "$SYSTEMD_GUID"
(! has_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$LOADER_GUID")

# --- If the request is confirmed, everything in our namespaces except FactoryResetRequest is erased ---
add_variable "$WORKDIR/vars.json" FactoryResetRequest "$SYSTEMD_GUID" 7b7d00
add_variable "$WORKDIR/vars.json" FactoryResetTestOther "$GLOBAL_GUID" 2a
# "1" as NUL-terminated UTF-16LE
add_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$LOADER_GUID" 31000000
start_vm --efi-nvram-state="$WORKDIR/vars.json"
answer_question y
# systemd-boot reboots after erasing, and then fails with "No loader found" on the second boot
wait_for_sd_boot
stop_vm
(! has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$LOADER_GUID")
(! has_variable "$WORKDIR/vars.json" HibernateLocation "$SYSTEMD_GUID")
(! has_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$LOADER_GUID")
has_variable "$WORKDIR/vars.json" FactoryResetRequest "$SYSTEMD_GUID"
has_variable "$WORKDIR/vars.json" FactoryResetTestOther "$GLOBAL_GUID"
has_variable "$WORKDIR/vars.json" BootOrder "$GLOBAL_GUID"

# --- An invalid request is dropped without asking, and nothing else is erased ---
add_variable "$WORKDIR/vars.json" LoaderEntryDefault "$LOADER_GUID" 6100620063000000
# "maybe" as NUL-terminated UTF-16LE
add_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$LOADER_GUID" 6d0061007900620065000000
start_vm --efi-nvram-state="$WORKDIR/vars.json"
wait_for_sd_boot
stop_vm
has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$LOADER_GUID"
(! has_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$LOADER_GUID")

echo "All systemd-boot factory reset variable tests passed"
