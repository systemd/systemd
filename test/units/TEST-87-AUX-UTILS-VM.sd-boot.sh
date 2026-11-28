#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Test systemd-boot in a nested VM using systemd-vmspawn.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

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

if ! systemd-vmspawn --firmware=describe &>/dev/null; then
    echo "No UEFI firmware found, skipping"
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

WORKDIR="$(mktemp -d)"
MACHINE="test-sd-boot-$$"

cleanup_vm() {
    set +e
    if machinectl status "$MACHINE" &>/dev/null; then
        machinectl terminate "$MACHINE" 2>/dev/null
        timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done" 2>/dev/null
    fi
    [[ -n "${VMSPAWN_PID:-}" ]] && kill "$VMSPAWN_PID" 2>/dev/null && wait "$VMSPAWN_PID" 2>/dev/null
    VMSPAWN_PID=
}

at_exit() {
    cleanup_vm
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# Build a disk with an ESP that contains systemd-boot as the fallback boot loader. There are no on-disk boot
# entries (and auto-entries are turned off), hence by default systemd-boot fails with "No loader found".
# Test cases that need boot entries can pass them via SMBIOS Type #11 without rebuilding the disk image.
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

# Pass the console input through a FIFO so that test cases can interact with systemd-boot. Keep the FIFO
# open for writing so that vmspawn never sees EOF on it.
mkfifo "$WORKDIR/console"
exec {CONSOLE_FD}<>"$WORKDIR/console"

start_vm() {
    local image="${VM_IMAGE:-$WORKDIR/disk.raw}"

    systemd-vmspawn \
        --machine="$MACHINE" \
        --ram=256M \
        --image="$image" \
        --tpm=no \
        --console=native \
        "$@" \
        <"$WORKDIR/console" &>"$WORKDIR/vmspawn.log" &
    VMSPAWN_PID=$!

    wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
    touch "$WORKDIR/ran"
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

testcase_factory_reset_variables() {
    # Test that systemd-boot erases its EFI variables when LoaderFactoryResetVariables is set, using a VM
    # whose UEFI variables are kept in a host-side JSON file, so that they can be inspected from the outside.
    if ! systemd-vmspawn --firmware-features=host-uefi-vars --firmware=describe &>/dev/null; then
        echo "No firmware with a host-side UEFI variable store found, skipping"
        return 0
    fi

    trap cleanup_vm EXIT

    local loader_guid=4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
    local systemd_guid=8cf2644b-4b0b-428f-9387-6d876050dc67
    local global_guid=8be4df61-93ca-11d2-aa0d-00e098032b8c

    # Boot once to get a populated variable store
    start_vm --firmware-features=host-uefi-vars --efi-nvram-state="$WORKDIR/vars.json"
    wait_for_sd_boot
    stop_vm

    # --- Without the request nothing is erased ---
    add_variable "$WORKDIR/vars.json" LoaderEntryDefault "$loader_guid" 6100620063000000
    add_variable "$WORKDIR/vars.json" HibernateLocation "$systemd_guid" 7b7d00
    start_vm --firmware-features=host-uefi-vars --efi-nvram-state="$WORKDIR/vars.json"
    wait_for_sd_boot
    stop_vm
    has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$loader_guid"
    has_variable "$WORKDIR/vars.json" HibernateLocation "$systemd_guid"

    # --- If the request is declined, it is dropped, but nothing else is erased ---
    # "yes" as NUL-terminated UTF-16LE, to check that any boolean string is accepted
    add_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$loader_guid" 7900650073000000
    start_vm --firmware-features=host-uefi-vars --efi-nvram-state="$WORKDIR/vars.json"
    answer_question n
    wait_for_sd_boot
    stop_vm
    has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$loader_guid"
    has_variable "$WORKDIR/vars.json" HibernateLocation "$systemd_guid"
    (! has_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$loader_guid")

    # --- If the request is confirmed, everything in our namespaces except FactoryResetRequest is erased ---
    add_variable "$WORKDIR/vars.json" FactoryResetRequest "$systemd_guid" 7b7d00
    add_variable "$WORKDIR/vars.json" FactoryResetTestOther "$global_guid" 2a
    # "1" as NUL-terminated UTF-16LE
    add_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$loader_guid" 31000000
    start_vm --firmware-features=host-uefi-vars --efi-nvram-state="$WORKDIR/vars.json"
    answer_question y
    # systemd-boot reboots after erasing, and then fails with "No loader found" on the second boot
    wait_for_sd_boot
    stop_vm
    (! has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$loader_guid")
    (! has_variable "$WORKDIR/vars.json" HibernateLocation "$systemd_guid")
    (! has_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$loader_guid")
    has_variable "$WORKDIR/vars.json" FactoryResetRequest "$systemd_guid"
    has_variable "$WORKDIR/vars.json" FactoryResetTestOther "$global_guid"
    has_variable "$WORKDIR/vars.json" BootOrder "$global_guid"

    # --- An invalid request is dropped without asking, and nothing else is erased ---
    add_variable "$WORKDIR/vars.json" LoaderEntryDefault "$loader_guid" 6100620063000000
    # "maybe" as NUL-terminated UTF-16LE
    add_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$loader_guid" 6d0061007900620065000000
    start_vm --firmware-features=host-uefi-vars --efi-nvram-state="$WORKDIR/vars.json"
    wait_for_sd_boot
    stop_vm
    has_variable "$WORKDIR/vars.json" LoaderEntryDefault "$loader_guid"
    (! has_variable "$WORKDIR/vars.json" LoaderFactoryResetVariables "$loader_guid")

    echo "All systemd-boot factory reset variable tests passed"
}

testcase_stub_profile_uint_max() {
    # Test that systemd-stub rejects @4294967295 (UINT_MAX) instead of colliding with its internal sentinel
    # for base-only sections, which would otherwise skip per-profile .cmdline sections.
    local features="secure-boot,~enrolled-keys"
    if ! systemd-vmspawn --firmware-features="$features" --firmware=describe &>/dev/null; then
        echo "No Secure-Boot-capable UEFI firmware in setup mode found, skipping"
        return 0
    fi

    local stub="/usr/lib/systemd/boot/efi/linux${EFI_ARCH}.efi.stub"
    local sbsign="/usr/lib/systemd/systemd-sbsign"
    if [[ ! -f "$stub" ]] || [[ ! -x "$sbsign" ]] ||
       ! command -v ukify >/dev/null 2>&1 ||
       ! command -v openssl >/dev/null 2>&1 ||
       ! command -v python3 >/dev/null 2>&1 ||
       ! command -v mmd >/dev/null 2>&1 ||
       ! command -v sfdisk >/dev/null 2>&1; then
        echo "Required tools or systemd-stub not found, skipping"
        return 0
    fi

    local kernel="" k
    for k in /usr/lib/modules/"$(uname -r)"/vmlinuz /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz; do
        if [[ -f "$k" ]]; then
            kernel="$k"
            break
        fi
    done
    if [[ -z "$kernel" ]]; then
        echo "No kernel found for UKI test, skipping"
        return 0
    fi

    trap cleanup_vm EXIT

    local sbdir="$WORKDIR/sb"
    mkdir -p "$sbdir/auth"

    # Generate an ephemeral Secure Boot keypair and unsigned .auth blobs for systemd-boot auto-enrollment.
    openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=sd-stub-test" \
        -keyout "$sbdir/sb.key" -out "$sbdir/sb.crt"
    openssl x509 -in "$sbdir/sb.crt" -outform DER -out "$sbdir/sb.der"

    python3 - "$sbdir/sb.der" "$sbdir/auth" <<'EOF'
import pathlib, struct, sys, uuid

der = pathlib.Path(sys.argv[1]).read_bytes()
outdir = pathlib.Path(sys.argv[2])

efi_time = struct.pack('<HBBBBBBIhBB', 2026, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0)
assert len(efi_time) == 16
pkcs7_guid = uuid.UUID('4aafd29d-68df-49ee-8aa9-347d375665a7').bytes_le
x509_guid = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le
owner_guid = uuid.UUID('77fa9abd-0359-4d32-bd60-28f4e78f784b').bytes_le

auth_hdr = efi_time + struct.pack('<IHH', 24, 0x0200, 0x0EF1) + pkcs7_guid
sig_size = 16 + len(der)
esl = x509_guid + struct.pack('<III', 28 + sig_size, 0, sig_size) + owner_guid + der

for name in ('PK.auth', 'KEK.auth', 'db.auth'):
    (outdir / name).write_bytes(auth_hdr + esl)
EOF

    local console="ttyS0"
    if [[ "$(uname -m)" == "aarch64" ]]; then
        console="ttyAMA0"
    fi

    # Build a UKI that has NO .cmdline in the base sections, only inside profile @0, and sign both
    # systemd-boot and the UKI with the test key. Use root= markers because the kernel always prints the
    # effective root= value on the serial console in "VFS: Cannot open root device ...".
    ukify build \
        --linux="$kernel" \
        --stub="$stub" \
        --section=".profile:ID=p0" \
        --section=".cmdline:console=$console root=signed_profile_cmdline" \
        --output="$sbdir/test-uki.unsigned.efi"

    "$sbsign" sign \
        --certificate="$sbdir/sb.crt" \
        --private-key="$sbdir/sb.key" \
        --output="$sbdir/test-uki.efi" \
        "$sbdir/test-uki.unsigned.efi"

    "$sbsign" sign \
        --certificate="$sbdir/sb.crt" \
        --private-key="$sbdir/sb.key" \
        --output="$sbdir/sd-boot.efi" \
        "$SD_BOOT"

    # Copy the shared disk image and populate Secure Boot enrollment keys, signed systemd-boot, and the UKI.
    cp --reflink=auto "$WORKDIR/disk.raw" "$sbdir/disk.raw"
    local esp_offset
    esp_offset=$(( $(sfdisk --json "$sbdir/disk.raw" | jq -r '.partitiontable.partitions[0].start') * 512 ))
    mmd -i "$sbdir/disk.raw@@$esp_offset" ::/loader/keys ::/loader/keys/auto
    mcopy -o -i "$sbdir/disk.raw@@$esp_offset" "$sbdir/sd-boot.efi" "::/EFI/BOOT/BOOT${EFI_ARCH^^}.EFI"
    mcopy -o -i "$sbdir/disk.raw@@$esp_offset" \
        "$sbdir/auth/PK.auth" "$sbdir/auth/KEK.auth" "$sbdir/auth/db.auth" ::/loader/keys/auto/
    mcopy -o -i "$sbdir/disk.raw@@$esp_offset" "$sbdir/test-uki.efi" ::/test-uki.efi

    local entry
    entry=$'io.systemd.boot.entries-extra:uki.conf=title Stub Profile UINT_MAX Test\nefi /test-uki.efi\noptions @4294967295 console='"$console"$' root=attacker_cmdline'

    # Boot once: systemd-boot auto-enrolls the test Secure Boot keys and reboots into enforcing Secure Boot,
    # then shows the menu for our entry.
    VM_IMAGE="$sbdir/disk.raw" start_vm \
        --firmware-features="$features" \
        --efi-nvram-state="$sbdir/nvram" \
        --smbios11="$entry"

    if ! timeout 300 bash -c "
        until grep -a >/dev/null 'Custom Secure Boot keys successfully enrolled' '$WORKDIR/vmspawn.log'; do
            if grep -a >/dev/null 'Failed to write .* secure boot variable' '$WORKDIR/vmspawn.log'; then
                exit 1
            fi
            sleep .5
        done
    "; then
        echo "systemd-boot did not enroll Secure Boot keys. Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi

    if ! timeout 300 bash -c "until grep -a >/dev/null 'Stub Profile UINT_MAX Test' '$WORKDIR/vmspawn.log'; do sleep .5; done"; then
        echo "systemd-boot did not show UKI menu entry after Secure Boot enrollment. Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi

    # Boot the entry and wait for the Linux kernel to report the effective root= option.
    send_key '\r'
    if ! timeout 300 bash -c "until grep -a >/dev/null 'VFS: Cannot open root device' '$WORKDIR/vmspawn.log'; do sleep .5; done"; then
        echo "Kernel did not boot or print root= option. Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi

    stop_vm

    if grep -a >/dev/null 'VFS: Cannot open root device "attacker_cmdline"' "$WORKDIR/vmspawn.log"; then
        echo "Secure Boot cmdline lock bypassed via @4294967295! Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi
    if ! grep -a >/dev/null 'VFS: Cannot open root device "signed_profile_cmdline"' "$WORKDIR/vmspawn.log"; then
        echo "Expected signed profile cmdline not found! Full vmspawn log:"
        cat "$WORKDIR/vmspawn.log"
        exit 1
    fi

    echo "systemd-stub @UINT_MAX Secure Boot cmdline test passed"
}

run_testcases

if [[ ! -e "$WORKDIR/ran" ]]; then
    echo "All systemd-boot test cases skipped"
    exit 77
fi
