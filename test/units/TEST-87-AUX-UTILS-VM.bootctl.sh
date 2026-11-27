#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v bootctl >/dev/null; then
    echo "bootctl not found, skipping."
    exit 77
fi

if [[ ! -d /usr/lib/systemd/boot/efi ]]; then
    echo "sd-boot is not installed, skipping."
    exit 77
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

(! systemd-detect-virt -cq)

restore_esp() {
    if [ ! -d /tmp/esp.bak ]; then
        return
    fi

    if [ -d /tmp/esp.bak/EFI/ ]; then
        mkdir -p "$(bootctl --print-esp-path)/EFI/"
        cp -r /tmp/esp.bak/EFI/* "$(bootctl --print-esp-path)/EFI/"
    fi
    if [ -d /tmp/esp.bak/loader/ ]; then
        mkdir -p "$(bootctl --print-esp-path)/loader/"
        cp -r /tmp/esp.bak/loader/* "$(bootctl --print-esp-path)/loader/"
    fi
    rm -rf /tmp/esp.bak
}

backup_esp() {
    if [ -d /tmp/esp.bak ]; then
        return
    fi

    # make a backup of the two key dirs in the ESP, and delete them

    if [[ -d "$(bootctl --print-esp-path)/EFI" ]]; then
        mkdir -p /tmp/esp.bak
        cp -r "$(bootctl --print-esp-path)/EFI/" /tmp/esp.bak/
        rm -rf "$(bootctl --print-esp-path)/EFI"
        mkdir "$(bootctl --print-esp-path)/EFI"
    fi
    if [[ -d "$(bootctl --print-esp-path)/loader" ]]; then
        mkdir -p /tmp/esp.bak
        cp -r "$(bootctl --print-esp-path)/loader/" /tmp/esp.bak/
        rm -rf "$(bootctl --print-esp-path)/loader"
        mkdir "$(bootctl --print-esp-path)/loader"
    fi
}

basic_tests() {
    # Ensure the system's ESP (no --image/--root args) is still available for the next tests
    if [ $# -eq 0 ]; then
        backup_esp
        trap restore_esp RETURN ERR
    fi

    bootctl "$@" --help
    bootctl "$@" --version

    bootctl "$@" install --make-entry-directory=yes
    bootctl "$@" remove  --make-entry-directory=yes

    bootctl "$@" install --all-architectures
    bootctl "$@" remove  --all-architectures

    bootctl "$@" install --make-entry-directory=yes --all-architectures
    bootctl "$@" remove  --make-entry-directory=yes --all-architectures

    bootctl "$@" install
    (! bootctl "$@" update)
    bootctl "$@" update --graceful

    bootctl "$@" is-installed
    bootctl "$@" is-installed --graceful
    bootctl "$@" random-seed

    bootctl "$@"
    bootctl "$@" status
    bootctl "$@" status --quiet
    bootctl "$@" list
    bootctl "$@" list --quiet
    bootctl "$@" list --json=short
    bootctl "$@" list --json=pretty

    bootctl "$@" remove
    (! bootctl "$@" is-installed)
    (! bootctl "$@" is-installed --graceful)
}

testcase_bootctl_basic() {
    assert_in "$(bootctl --print-esp-path)" "^(/boot/|/efi)$"
    assert_in "$(bootctl --print-boot-path)" "^(/boot/|/efi)$"

    bootctl --print-root-device
    bootctl --print-root-device --print-root-device
    bootctl --print-esp-path
    bootctl --print-boot-path
    bootctl --print-loader-path
    bootctl --print-stub-path
    bootctl --print-efi-architecture

    basic_tests
}

cleanup_file_version() {
    if [[ -n "${FILE_VERSION_GARBAGE:-}" ]]; then
        rm -f "$FILE_VERSION_GARBAGE"
        unset FILE_VERSION_GARBAGE
    fi
    restore_esp
}

testcase_bootctl_file_version() {
    # Exercise get_file_version() (src/bootctl/bootctl-util.c), which reads the
    # version marker that systemd-boot/-stub store in their ".sdmagic" PE
    # section, e.g. "#### LoaderInfo: systemd-boot 257 ####". 'bootctl status'
    # surfaces the inner part next to each .efi file it finds in the ESP, e.g.
    # ".../systemd-bootx64.efi (systemd-boot 257)".

    backup_esp
    trap cleanup_file_version RETURN ERR

    bootctl install

    local ESP
    ESP="$(bootctl --print-esp-path)"

    # The freshly installed systemd-boot binary must be listed with the version
    # extracted from its ".sdmagic" section.
    bootctl status | grep -E "systemd-boot[a-z0-9]*\.efi \(systemd-boot [^)]+\)" >/dev/null

    # A non-PE/non-systemd file must be handled gracefully (get_file_version()
    # returns -ESRCH): it is still listed, but without a version annotation, and
    # 'bootctl status' must not fail.
    FILE_VERSION_GARBAGE="$ESP/EFI/systemd/not-a-loader.efi"
    echo "this is not a PE binary" >"$FILE_VERSION_GARBAGE"

    local status
    status="$(bootctl status)"
    grep -F "not-a-loader.efi" <<<"$status" >/dev/null
    (! grep -E "not-a-loader\.efi .*\(" <<<"$status" >/dev/null)

    rm -f "$FILE_VERSION_GARBAGE"
    unset FILE_VERSION_GARBAGE
}

cleanup_image() (
    set +e

    if [[ -z "${IMAGE_DIR:-}" ]]; then
        return 0
    fi

    umount "${IMAGE_DIR}/root"

    if [[ -n "${LOOPDEV:-}" ]]; then
        losetup -d "${LOOPDEV}"
        unset LOOPDEV
    fi

    udevadm settle --timeout=30

    rm -rf "${IMAGE_DIR}"
    unset IMAGE_DIR

    return 0
)

testcase_bootctl_image() {
    IMAGE_DIR="$(mktemp --directory /tmp/test-bootctl.XXXXXXXXXX)"
    trap cleanup_image RETURN

    truncate -s 256m "${IMAGE_DIR}/image"

    cat >"${IMAGE_DIR}/partscript" <<EOF
label: gpt
type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B name=esp  size=64M
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4 name=root size=64M bootable
type=BC13C2FF-59E6-4262-A352-B275FD6F7172 name=boot
EOF

    LOOPDEV="$(losetup --show -P -f "${IMAGE_DIR}/image")"
    sfdisk "$LOOPDEV" <"${IMAGE_DIR}/partscript"

    udevadm settle --timeout=30

    mkfs.vfat -n esp  "${LOOPDEV}p1"
    mkfs.ext4 -L root "${LOOPDEV}p2"
    mkfs.ext4 -L boot "${LOOPDEV}p3"

    mkdir -p "${IMAGE_DIR}/root"
    mount -t ext4 "${LOOPDEV}p2" "${IMAGE_DIR}/root"

    mkdir -p "${IMAGE_DIR}/root/efi"
    mkdir -p "${IMAGE_DIR}/root/boot"
    mkdir -p "${IMAGE_DIR}/root/etc"
    mkdir -p "${IMAGE_DIR}/root/usr/lib"
    if [[ -f /usr/lib/os-release ]]; then
        cp /usr/lib/os-release "${IMAGE_DIR}/root/usr/lib/."
        ln -s ../usr/lib/os-release "${IMAGE_DIR}/root/etc/os-release"
    else
        cp -a /etc/os-release "${IMAGE_DIR}/root/etc/."
    fi

    umount "${IMAGE_DIR}/root"

    export SYSTEMD_DISSECT_FSTYPE_XBOOTLDR=ext4

    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-esp-path)" "/run/systemd/mount-rootfs/efi"
    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-esp-path --esp-path=/efi)" "/run/systemd/mount-rootfs/efi"
    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-boot-path)" "/run/systemd/mount-rootfs/boot"
    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-boot-path --boot-path=/boot)" "/run/systemd/mount-rootfs/boot"

    # FIXME: This provides spurious result.
    bootctl --image "${IMAGE_DIR}/image" --print-root-device || :

    basic_tests --image "${IMAGE_DIR}/image"

    unset SYSTEMD_DISSECT_FSTYPE_XBOOTLDR
}

cleanup_raid() (
    set +e

    if [[ -z "${IMAGE_DIR:-}" ]]; then
        return 0
    fi

    systemd-umount "${IMAGE_DIR}/root/efi"
    systemd-umount "${IMAGE_DIR}/root/boot"
    systemd-umount "${IMAGE_DIR}/root"

    mdadm --misc --stop /dev/md/raid-esp
    mdadm --misc --stop /dev/md/raid-root

    if [[ -n "${LOOPDEV1:-}" ]]; then
        mdadm --misc --force --zero-superblock "${LOOPDEV1}p1"
        mdadm --misc --force --zero-superblock "${LOOPDEV1}p2"
    fi

    if [[ -n "${LOOPDEV2:-}" ]]; then
        mdadm --misc --force --zero-superblock "${LOOPDEV2}p1"
        mdadm --misc --force --zero-superblock "${LOOPDEV2}p2"
    fi

    udevadm settle --timeout=30

    if [[ -n "${LOOPDEV1:-}" ]]; then
        mdadm --misc --force --zero-superblock "${LOOPDEV1}p1"
        mdadm --misc --force --zero-superblock "${LOOPDEV1}p2"
        losetup -d "${LOOPDEV1}"
        unset LOOPDEV1
    fi

    if [[ -n "${LOOPDEV2:-}" ]]; then
        mdadm --misc --force --zero-superblock "${LOOPDEV2}p1"
        mdadm --misc --force --zero-superblock "${LOOPDEV2}p2"
        losetup -d "${LOOPDEV2}"
        unset LOOPDEV2
    fi

    udevadm settle --timeout=30

    rm -rf "${IMAGE_DIR}"

    return 0
)

testcase_bootctl_raid() {
    if ! command -v mdadm >/dev/null; then
        echo "mdadm not found, skipping."
        return 0
    fi

    if ! command -v mkfs.btrfs >/dev/null; then
        echo "mkfs.btrfs not found, skipping."
        return 0
    fi

    IMAGE_DIR="$(mktemp --directory /tmp/test-bootctl.XXXXXXXXXX)"
    trap cleanup_raid RETURN

    truncate -s 256m "${IMAGE_DIR}/image1"
    truncate -s 256m "${IMAGE_DIR}/image2"

    cat >"${IMAGE_DIR}/partscript" <<EOF
label: gpt
type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B name=esp  size=64M
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4 name=root size=64M bootable
type=BC13C2FF-59E6-4262-A352-B275FD6F7172 name=boot
EOF

    LOOPDEV1="$(losetup --show -P -f "${IMAGE_DIR}/image1")"
    LOOPDEV2="$(losetup --show -P -f "${IMAGE_DIR}/image2")"
    sfdisk "$LOOPDEV1" <"${IMAGE_DIR}/partscript"
    sfdisk "$LOOPDEV2" <"${IMAGE_DIR}/partscript"

    udevadm settle --timeout=30

    printf 'y\ny\n' | mdadm --create /dev/md/raid-esp --name "raid-esp" "${LOOPDEV1}p1" "${LOOPDEV2}p1" -v -f --level=1 --raid-devices=2
    mkfs.vfat /dev/md/raid-esp
    printf 'y\ny\n' | mdadm --create /dev/md/raid-root --name "raid-root" "${LOOPDEV1}p2" "${LOOPDEV2}p2" -v -f --level=1 --raid-devices=2
    mkfs.ext4 /dev/md/raid-root
    mkfs.btrfs -f -M -d raid1 -m raid1 -L "raid-boot" "${LOOPDEV1}p3" "${LOOPDEV2}p3"

    mkdir -p "${IMAGE_DIR}/root"
    mount -t ext4 /dev/md/raid-root "${IMAGE_DIR}/root"
    mkdir -p "${IMAGE_DIR}/root/efi"
    mount -t vfat /dev/md/raid-esp "${IMAGE_DIR}/root/efi"
    mkdir -p "${IMAGE_DIR}/root/boot"
    mount -t btrfs "${LOOPDEV1}p3" "${IMAGE_DIR}/root/boot"

    mkdir -p "${IMAGE_DIR}/root/etc"
    mkdir -p "${IMAGE_DIR}/root/usr/lib"
    if [[ -f /usr/lib/os-release ]]; then
        cp /usr/lib/os-release "${IMAGE_DIR}/root/usr/lib/."
        ln -s ../usr/lib/os-release "${IMAGE_DIR}/root/etc/os-release"
    else
        cp -a /etc/os-release "${IMAGE_DIR}/root/etc/."
    fi

    # find_esp() does not support md RAID partition.
    (! bootctl --root "${IMAGE_DIR}/root" --print-esp-path)
    (! bootctl --root "${IMAGE_DIR}/root" --print-esp-path --esp-path=/efi)

    # If the verification is relaxed, it accepts md RAID partition.
    assert_eq "$(SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-esp-path)" "${IMAGE_DIR}/root/efi"
    assert_eq "$(SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-esp-path --esp-path=/efi)" "${IMAGE_DIR}/root/efi"

    # find_xbootldr() does not support btrfs RAID, and bootctl tries to fall back to use ESP.
    # (but as in the above, the ESP verification is also failed in this case).
    (! bootctl --root "${IMAGE_DIR}/root" --print-boot-path)
    (! bootctl --root "${IMAGE_DIR}/root" --print-boot-path --boot-path=/boot)

    # If the verification for ESP is relaxed, bootctl falls back to use ESP.
    assert_eq "$(SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-boot-path)" "${IMAGE_DIR}/root/efi"

    # If the verification is relaxed, it accepts the xbootldr partition.
    assert_eq "$(SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-boot-path)" "${IMAGE_DIR}/root/boot"
    assert_eq "$(SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-boot-path --boot-path=/boot)" "${IMAGE_DIR}/root/boot"

    # FIXME: This provides spurious result.
    bootctl --root "${IMAGE_DIR}/root" --print-root-device || :

    SYSTEMD_RELAX_ESP_CHECKS=yes SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes basic_tests --root "${IMAGE_DIR}/root"
}

testcase_bootctl_varlink() {
    varlinkctl call --collect /run/systemd/io.systemd.BootControl io.systemd.BootControl.ListBootEntries '{}' --graceful=io.systemd.BootControl.NoSuchBootEntry

    # We may have UEFI in the test environment.
    # If we don't have UEFI then we can test whether bootctl's varlink API fails cleanly.
    # If we do have UEFI then the rest of the clean fail tests should be skipped.
    if ! (SYSTEMD_LOG_TARGET=console varlinkctl call --json=short /run/systemd/io.systemd.BootControl io.systemd.BootControl.GetRebootToFirmware '{}' || true) |& grep -q io.systemd.BootControl.RebootToFirmwareNotSupported; then
        return 0
    fi
    SYSTEMD_LOG_TARGET=console varlinkctl call --json=short /run/systemd/io.systemd.BootControl io.systemd.BootControl.SetRebootToFirmware '{"state":true}' --graceful=io.systemd.BootControl.RebootToFirmwareNotSupported
    SYSTEMD_LOG_TARGET=console varlinkctl call --json=short /run/systemd/io.systemd.BootControl io.systemd.BootControl.SetRebootToFirmware '{"state":false}' --graceful=io.systemd.BootControl.RebootToFirmwareNotSupported
}

testcase_bootctl_secure_boot_auto_enroll() {
    # mkosi can also add keys here, so back them up and restored them
    backup_esp
    trap restore_esp RETURN ERR

    cat >/tmp/openssl.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = DE
ST = Test State
L = Test Locality
O = Org Name
OU = Org Unit Name
CN = Common Name
emailAddress = test@email.com
EOF

    openssl req -config /tmp/openssl.conf -subj="/CN=waldo" \
            -x509 -sha256 -nodes -days 365 -newkey rsa:4096 \
            -keyout /tmp/sb.key -out /tmp/sb.crt

    # This will fail if there are already keys in the ESP, so we remove them first
    rm -rf "$(bootctl --print-esp-path)/loader/keys/auto"

    bootctl install --make-entry-directory=yes --secure-boot-auto-enroll=yes --certificate /tmp/sb.crt --private-key /tmp/sb.key
    for var in PK KEK db; do
        test -f "$(bootctl --print-esp-path)/loader/keys/auto/$var.auth"
    done
    bootctl remove
}

# Order this first, as other test cases mess with the ESP and might break 'bootctl status' output
testcase_00_secureboot() {
    if [ ! -d /sys/firmware/efi ]; then
        echo "Not booted with EFI, skipping secureboot tests."
        return 0
    fi

    # Ensure secure boot is enabled and not in setup mode
    cmp /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\1')
    cmp /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\0')
    bootctl status | grep "Secure Boot: enabled" >/dev/null

    # Ensure the addon is fully loaded and parsed
    bootctl status | grep "extra: /boot//loader/addons/test.addon.efi" >/dev/null
    bootctl status | grep "cmdline" | grep addonfoobar >/dev/null
    grep -q addonfoobar /proc/cmdline
}

remove_root_dir() {
    rm -rf "$ROOTDIR"
}

cleanup_install_varlink() {
    if [[ -n "${FAKE_ESP:-}" ]]; then
        rm -rf "$FAKE_ESP"
        unset FAKE_ESP
    fi
    if [[ -n "${FAKE_BOOT:-}" ]]; then
        rm -rf "$FAKE_BOOT"
        unset FAKE_BOOT
    fi
    restore_esp
}

testcase_install_varlink() {

    varlinkctl introspect "$(type -p bootctl)"

    if [ $# -eq 0 ]; then
        backup_esp
        trap cleanup_install_varlink RETURN ERR
    fi

    (! bootctl is-installed )
    SYSTEMD_LOG_TARGET=console varlinkctl call "$(type -p bootctl)" io.systemd.BootControl.Install "{\"operation\":\"new\",\"touchVariables\":false}"
    bootctl is-installed

    # Verify that espPath/xbootldrPath override auto-discovery: install into fresh empty
    # directories (with relaxed checks so verify_esp()/verify_xbootldr() accept a non-vfat
    # non-mountpoint path) and check the loader files land there. If the parameters were ignored
    # the call would auto-discover the real partitions instead and the directories would stay
    # empty.
    FAKE_ESP="$(mktemp --directory /tmp/test-bootctl-esp.XXXXXXXXXX)"
    FAKE_BOOT="$(mktemp --directory /tmp/test-bootctl-boot.XXXXXXXXXX)"
    SYSTEMD_RELAX_ESP_CHECKS=yes SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes SYSTEMD_LOG_TARGET=console \
            varlinkctl call --quiet "$(type -p bootctl)" io.systemd.BootControl.Install \
            "{\"operation\":\"new\",\"touchVariables\":false,\"espPath\":\"$FAKE_ESP\",\"xbootldrPath\":\"$FAKE_BOOT\",\"makeEntryDirectory\":false}"
    test -f "$FAKE_ESP/EFI/systemd/systemd-boot$(bootctl --print-efi-architecture).efi"
    test -f "$FAKE_BOOT/loader/entries.srel"
    # makeEntryDirectory:false means loader.conf must not gain a "default" line and no entry
    # token directory is created under $BOOT.
    (! grep '^default ' "$FAKE_ESP/loader/loader.conf" >/dev/null)

    # Same again into fresh directories with makeEntryDirectory:true, and check loader.conf now
    # gets a "default <entry-token>-*" line and the entry token directory shows up under $BOOT.
    rm -rf "$FAKE_ESP" "$FAKE_BOOT"
    FAKE_ESP="$(mktemp --directory /tmp/test-bootctl-esp.XXXXXXXXXX)"
    FAKE_BOOT="$(mktemp --directory /tmp/test-bootctl-boot.XXXXXXXXXX)"
    SYSTEMD_RELAX_ESP_CHECKS=yes SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes SYSTEMD_LOG_TARGET=console \
            varlinkctl call --quiet "$(type -p bootctl)" io.systemd.BootControl.Install \
            "{\"operation\":\"new\",\"touchVariables\":false,\"espPath\":\"$FAKE_ESP\",\"xbootldrPath\":\"$FAKE_BOOT\",\"makeEntryDirectory\":true}"
    local TOKEN
    TOKEN="$(sed -n 's/^default \(.*\)-\*$/\1/p' "$FAKE_ESP/loader/loader.conf")"
    test -n "$TOKEN"
    test -d "$FAKE_BOOT/$TOKEN"
}

cleanup_link() {
    if [[ -n "${LINK_WORKDIR:-}" ]]; then
        rm -rf "$LINK_WORKDIR"
        unset LINK_WORKDIR
    fi
    restore_esp
}

testcase_bootctl_link() {
    if ! command -v ukify >/dev/null; then
        echo "ukify not found, skipping."
        return 0
    fi

    backup_esp
    LINK_WORKDIR="$(mktemp --directory /tmp/test-bootctl-link.XXXXXXXXXX)"
    trap cleanup_link RETURN ERR

    # Ensure loader/entries directory is present
    bootctl install --make-entry-directory=yes

    local ESP
    ESP="$(bootctl --print-esp-path)"

    # Build a minimal UKI via ukify. The .linux content does not need to be a
    # real kernel — bootctl link only requires a valid PE with .osrel (and the
    # systemd-stub SBAT marker that pe_is_uki() checks for).
    cat >"$LINK_WORKDIR/os-release" <<'EOF'
ID=testos
NAME="Test OS"
PRETTY_NAME="Test OS"
EOF
    echo "fake-kernel"       >"$LINK_WORKDIR/vmlinuz"
    echo "fake-initrd"       >"$LINK_WORKDIR/initrd"
    echo "fake-sysext-data"  >"$LINK_WORKDIR/hello.sysext.raw"
    echo "fake-confext-data" >"$LINK_WORKDIR/hello.confext.raw"
    echo "fake-credential"   >"$LINK_WORKDIR/hello.cred"

    ukify build \
        --linux "$LINK_WORKDIR/vmlinuz" \
        --initrd "$LINK_WORKDIR/initrd" \
        --os-release "@$LINK_WORKDIR/os-release" \
        --uname "1.2.3-testkernel" \
        --cmdline "quiet" \
        --output "$LINK_WORKDIR/testuki.efi"

    # Without --linux ukify builds a PE addon
    ukify build \
        --cmdline "addon=test" \
        --output "$LINK_WORKDIR/hello.addon.efi"
    # An addon for a different kernel than testuki.efi, which systemd-stub would skip
    ukify build \
        --cmdline "other" \
        --uname "4.5.6-otherkernel" \
        --output "$LINK_WORKDIR/other.addon.efi"
    # An addon for the same kernel as testuki.efi
    ukify build \
        --cmdline "match" \
        --uname "1.2.3-testkernel" \
        --output "$LINK_WORKDIR/match.addon.efi"
    ukify build \
        --cmdline "debug" \
        --output "$LINK_WORKDIR/debug.addon.efi"

    # Pin an explicit entry token so the resulting filenames are deterministic
    local TOKEN="systemdtest"
    local BOOTCTL=(bootctl "--entry-token=literal:$TOKEN")

    # --- Test 1: basic link/unlink ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi"

    # Exactly one entry file should exist, named "${TOKEN}-commit_1.conf"
    local ENTRY="$ESP/loader/entries/${TOKEN}-commit_1.conf"
    test -f "$ENTRY"
    test -f "$ESP/$TOKEN/testuki.efi"

    # Verify the entry file contents
    grep "^title "                        "$ENTRY" >/dev/null
    grep "^uki /${TOKEN}/testuki.efi\$"   "$ENTRY" >/dev/null
    grep "^version 1\$"                   "$ENTRY" >/dev/null

    # Make sure bootctl list sees it
    bootctl list --json=short | grep -F "${TOKEN}-commit_1.conf" >/dev/null

    # Remove it again using the ID (entry IDs include the .conf suffix)
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_1.conf"
    test ! -e "$ENTRY"
    test ! -e "$ESP/$TOKEN/testuki.efi"

    # --- Test 2: link with --entry-title/--entry-version/--entry-commit/--tries-left ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" \
        --entry-title="My Funky Entry" \
        --entry-version="9.8.7" \
        --entry-commit=42 \
        --tries-left=3

    ENTRY="$ESP/loader/entries/${TOKEN}-commit_42.9.8.7+3.conf"
    test -f "$ENTRY"
    test -f "$ESP/$TOKEN/testuki.efi"

    grep "^title My Funky Entry\$"       "$ENTRY" >/dev/null
    grep "^version 42.9.8.7\$"           "$ENTRY" >/dev/null
    grep "^uki /${TOKEN}/testuki.efi\$"  "$ENTRY" >/dev/null

    # Unlink using the ID (the tries counter "+3" is stripped from the canonical ID)
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_42.9.8.7.conf"
    test ! -e "$ENTRY"
    test ! -e "$ESP/$TOKEN/testuki.efi"

    # --- Test 3: link with extras (-X and --extra=) ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" \
        --entry-commit=50 \
        -X "$LINK_WORKDIR/hello.sysext.raw" \
        --extra="$LINK_WORKDIR/hello.confext.raw" \
        -X "$LINK_WORKDIR/hello.cred"

    ENTRY="$ESP/loader/entries/${TOKEN}-commit_50.conf"
    test -f "$ENTRY"
    test -f "$ESP/$TOKEN/testuki.efi"
    test -f "$ESP/$TOKEN/hello.sysext.raw"
    test -f "$ESP/$TOKEN/hello.confext.raw"
    test -f "$ESP/$TOKEN/hello.cred"

    grep "^extra /${TOKEN}/hello.sysext.raw\$"  "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello.confext.raw\$" "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello.cred\$"        "$ENTRY" >/dev/null

    # Unlink must also clean up the extra resources
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_50.conf"
    test ! -e "$ENTRY"
    test ! -e "$ESP/$TOKEN/testuki.efi"
    test ! -e "$ESP/$TOKEN/hello.sysext.raw"
    test ! -e "$ESP/$TOKEN/hello.confext.raw"
    test ! -e "$ESP/$TOKEN/hello.cred"

    # --- Test 4: --oldest drops the lowest commit first ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=10
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=20
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=30

    test -f "$ESP/loader/entries/${TOKEN}-commit_10.conf"
    test -f "$ESP/loader/entries/${TOKEN}-commit_20.conf"
    test -f "$ESP/loader/entries/${TOKEN}-commit_30.conf"
    test -f "$ESP/$TOKEN/testuki.efi"

    "${BOOTCTL[@]}" unlink --oldest=yes
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_10.conf"
    test -f  "$ESP/loader/entries/${TOKEN}-commit_20.conf"
    test -f  "$ESP/loader/entries/${TOKEN}-commit_30.conf"
    test -f "$ESP/$TOKEN/testuki.efi"

    "${BOOTCTL[@]}" unlink --oldest=yes
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_20.conf"
    test -f  "$ESP/loader/entries/${TOKEN}-commit_30.conf"
    test -f "$ESP/$TOKEN/testuki.efi"

    # --- Test 5: --dry-run leaves everything in place ---
    "${BOOTCTL[@]}" -n unlink "${TOKEN}-commit_30.conf"
    test -f "$ESP/loader/entries/${TOKEN}-commit_30.conf"
    test -f "$ESP/$TOKEN/testuki.efi"

    # Actually remove it now
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_30.conf"
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_30.conf"
    test ! -e "$ESP/$TOKEN/testuki.efi"

    # --- Test 6: invalid combinations are rejected ---
    # Neither an ID nor --oldest
    (! "${BOOTCTL[@]}" unlink)
    # Both an ID and --oldest
    (! "${BOOTCTL[@]}" unlink --oldest=yes "${TOKEN}-commit_1.conf")

    # --- Test 7: refusing to link when --keep-free cannot be satisfied ---
    (! "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=99 --keep-free=1T)
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_99.conf"

    # --- Test 8: refusing to re-link the same commit number ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=77
    (! "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=77)
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_77.conf"

    # --- Test 9: passing a non-UKI is rejected ---
    (! "${BOOTCTL[@]}" link "$LINK_WORKDIR/vmlinuz")

    # --- Test 9a: link with an addon, whose .cmdline shows up in bootctl list ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" \
        --entry-commit=60 \
        --extra="$LINK_WORKDIR/hello.addon.efi"

    ENTRY="$ESP/loader/entries/${TOKEN}-commit_60.conf"
    test -f "$ENTRY"
    test -f "$ESP/$TOKEN/hello.addon.efi"
    grep "^extra /${TOKEN}/hello.addon.efi\$" "$ENTRY" >/dev/null

    bootctl list --json=short |
        jq -e --arg id "${TOKEN}-commit_60.conf" --arg addon "/${TOKEN}/hello.addon.efi" \
           '.[] | select(.id == $id) | .addons[] | select(.localAddon == $addon and .options == "addon=test")' >/dev/null

    # Unlink must also clean up the addon
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_60.conf"
    test ! -e "$ENTRY"
    test ! -e "$ESP/$TOKEN/hello.addon.efi"

    # --- Test 9b: *.addon.efi extras that are not PE addons are rejected ---
    cp "$LINK_WORKDIR/vmlinuz" "$LINK_WORKDIR/notpe.addon.efi"
    cp "$LINK_WORKDIR/testuki.efi" "$LINK_WORKDIR/uki.addon.efi"
    (! "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=61 --extra="$LINK_WORKDIR/notpe.addon.efi")
    (! "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=61 --extra="$LINK_WORKDIR/uki.addon.efi")
    (! "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=61 --extra="$LINK_WORKDIR/other.addon.efi")
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_61.conf"
    test ! -e "$ESP/$TOKEN/notpe.addon.efi"
    test ! -e "$ESP/$TOKEN/uki.addon.efi"
    test ! -e "$ESP/$TOKEN/other.addon.efi"

    # An addon for the same kernel as the UKI is accepted
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" --entry-commit=62 --extra="$LINK_WORKDIR/match.addon.efi"
    grep "^extra /${TOKEN}/match.addon.efi\$" "$ESP/loader/entries/${TOKEN}-commit_62.conf" >/dev/null
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_62.conf"
    test ! -e "$ESP/$TOKEN/match.addon.efi"

    # --- Test 9c: unlink keeps addons (and other resources) still referenced by other entries ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" \
        --entry-commit=70 \
        --extra="$LINK_WORKDIR/hello.addon.efi" \
        --extra="$LINK_WORKDIR/hello.cred"
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" \
        --entry-commit=71 \
        --extra="$LINK_WORKDIR/hello.addon.efi" \
        --extra="$LINK_WORKDIR/debug.addon.efi"

    grep "^extra /${TOKEN}/hello.addon.efi\$" "$ESP/loader/entries/${TOKEN}-commit_70.conf" >/dev/null
    grep "^extra /${TOKEN}/hello.addon.efi\$" "$ESP/loader/entries/${TOKEN}-commit_71.conf" >/dev/null
    grep "^extra /${TOKEN}/debug.addon.efi\$" "$ESP/loader/entries/${TOKEN}-commit_71.conf" >/dev/null

    # The UKI and hello.addon.efi are still referenced by commit 71, hello.cred is not
    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_70.conf"
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_70.conf"
    test -f "$ESP/loader/entries/${TOKEN}-commit_71.conf"
    test -f "$ESP/$TOKEN/testuki.efi"
    test -f "$ESP/$TOKEN/hello.addon.efi"
    test -f "$ESP/$TOKEN/debug.addon.efi"
    test ! -e "$ESP/$TOKEN/hello.cred"

    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_71.conf"
    test ! -e "$ESP/loader/entries/${TOKEN}-commit_71.conf"
    test ! -e "$ESP/$TOKEN/testuki.efi"
    test ! -e "$ESP/$TOKEN/hello.addon.efi"
    test ! -e "$ESP/$TOKEN/debug.addon.efi"

    # --- Test 9d: cleanup removes unreferenced files, but keeps referenced addons ---
    "${BOOTCTL[@]}" link "$LINK_WORKDIR/testuki.efi" \
        --entry-commit=72 \
        --extra="$LINK_WORKDIR/hello.addon.efi"
    cp "$LINK_WORKDIR/debug.addon.efi" "$ESP/$TOKEN/orphan.addon.efi"
    cp "$LINK_WORKDIR/testuki.efi" "$ESP/$TOKEN/orphan.efi"
    cp "$LINK_WORKDIR/hello.cred" "$ESP/$TOKEN/orphan.cred"

    # --dry-run leaves everything in place
    "${BOOTCTL[@]}" -n cleanup
    test -f "$ESP/$TOKEN/orphan.addon.efi"
    test -f "$ESP/$TOKEN/orphan.efi"
    test -f "$ESP/$TOKEN/orphan.cred"

    "${BOOTCTL[@]}" cleanup
    test ! -e "$ESP/$TOKEN/orphan.addon.efi"
    test ! -e "$ESP/$TOKEN/orphan.efi"
    test ! -e "$ESP/$TOKEN/orphan.cred"
    test -f "$ESP/loader/entries/${TOKEN}-commit_72.conf"
    test -f "$ESP/$TOKEN/testuki.efi"
    test -f "$ESP/$TOKEN/hello.addon.efi"

    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_72.conf"
    test ! -e "$ESP/$TOKEN/testuki.efi"
    test ! -e "$ESP/$TOKEN/hello.addon.efi"

    # === Varlink coverage ===
    #
    # Exercise io.systemd.BootControl.Link/Unlink by forking bootctl as a
    # varlink server via 'varlinkctl call <binary>'. Note the Varlink schema
    # has no way to supply a literal entry token (unlike --entry-token= on
    # the command line), so the token is chosen by bootctl from
    # machine-id/os-release — we recover it from the returned id.
    local BOOTCTL_BIN vreply vid vtoken
    BOOTCTL_BIN="$(type -p bootctl)"

    # --- Test 10: Link + Unlink via varlink ---
    vreply="$(varlinkctl call --json=short \
                  --push-fd="$LINK_WORKDIR/testuki.efi" \
                  "$BOOTCTL_BIN" io.systemd.BootControl.Link \
                  '{"kernelFilename":"vluki.efi","kernelFileDescriptor":0}')"
    vid="$(echo "$vreply" | jq -r '.ids[0]')"
    test -n "$vid"
    test "$vid" != "null"
    vtoken="${vid%%-commit_*}"
    test -n "$vtoken"

    test -f "$ESP/loader/entries/$vid"
    test -f "$ESP/$vtoken/vluki.efi"
    grep "^uki /$vtoken/vluki.efi\$" "$ESP/loader/entries/$vid" >/dev/null

    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                    "{\"id\":\"$vid\"}"
    test ! -e "$ESP/loader/entries/$vid"
    test ! -e "$ESP/$vtoken/vluki.efi"

    # --- Test 11: Link with entryTitle/entryVersion/entryCommit/triesLeft + extraFiles via varlink ---
    vreply="$(varlinkctl call --json=short \
                  --push-fd="$LINK_WORKDIR/testuki.efi" \
                  --push-fd="$LINK_WORKDIR/hello.sysext.raw" \
                  --push-fd="$LINK_WORKDIR/hello.cred" \
                  "$BOOTCTL_BIN" io.systemd.BootControl.Link \
                  '{"kernelFilename":"vluki2.efi","kernelFileDescriptor":0,"entryTitle":"Varlink Title","entryVersion":"2.3.4","entryCommit":111,"triesLeft":2,"extraFiles":[{"filename":"hello.sysext.raw","fileDescriptor":1},{"filename":"hello.cred","fileDescriptor":2}]}')"
    vid="$(echo "$vreply" | jq -r '.ids[0]')"
    # The returned id has the tries counter ("+2") stripped
    assert_eq "$vid" "$vtoken-commit_111.2.3.4.conf"
    # The on-disk entry filename includes the tries counter
    local VENTRY="$ESP/loader/entries/$vtoken-commit_111.2.3.4+2.conf"
    test -f "$VENTRY"
    test -f "$ESP/$vtoken/vluki2.efi"
    test -f "$ESP/$vtoken/hello.sysext.raw"
    test -f "$ESP/$vtoken/hello.cred"

    grep "^title Varlink Title\$"             "$VENTRY" >/dev/null
    grep "^version 111.2.3.4\$"               "$VENTRY" >/dev/null
    grep "^extra /$vtoken/hello.sysext.raw\$" "$VENTRY" >/dev/null
    grep "^extra /$vtoken/hello.cred\$"       "$VENTRY" >/dev/null

    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                    "{\"id\":\"$vid\"}"
    test ! -e "$VENTRY"
    test ! -e "$ESP/$vtoken/vluki2.efi"
    test ! -e "$ESP/$vtoken/hello.sysext.raw"
    test ! -e "$ESP/$vtoken/hello.cred"

    # --- Test 12: Unlink oldest via varlink ---
    local c
    for c in 210 220 230; do
        varlinkctl call --quiet \
                       --push-fd="$LINK_WORKDIR/testuki.efi" \
                       "$BOOTCTL_BIN" io.systemd.BootControl.Link \
                       "{\"kernelFilename\":\"vluki3.efi\",\"kernelFileDescriptor\":0,\"entryCommit\":$c}"
    done
    test -f "$ESP/loader/entries/$vtoken-commit_210.conf"
    test -f "$ESP/loader/entries/$vtoken-commit_220.conf"
    test -f "$ESP/loader/entries/$vtoken-commit_230.conf"

    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                    '{"oldest":true}'
    test ! -e "$ESP/loader/entries/$vtoken-commit_210.conf"
    test -f "$ESP/loader/entries/$vtoken-commit_220.conf"
    test -f "$ESP/loader/entries/$vtoken-commit_230.conf"
    test -f "$ESP/$vtoken/vluki3.efi"

    # Clean up remaining entries
    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                    "{\"id\":\"$vtoken-commit_220.conf\"}"
    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                    "{\"id\":\"$vtoken-commit_230.conf\"}"
    test ! -e "$ESP/loader/entries/$vtoken-commit_220.conf"
    test ! -e "$ESP/loader/entries/$vtoken-commit_230.conf"
    test ! -e "$ESP/$vtoken/vluki3.efi"

    # --- Test 13: Link with a non-UKI via varlink returns InvalidKernelImage ---
    varlinkctl call --quiet \
                   --push-fd="$LINK_WORKDIR/vmlinuz" \
                   --graceful=io.systemd.BootControl.InvalidKernelImage \
                   "$BOOTCTL_BIN" io.systemd.BootControl.Link \
                   '{"kernelFilename":"notauki.efi","kernelFileDescriptor":0}'

    # --- Test 13a: addons passed as literal data via varlink are validated too ---
    vreply="$(varlinkctl call --json=short \
                  --push-fd="$LINK_WORKDIR/testuki.efi" \
                  "$BOOTCTL_BIN" io.systemd.BootControl.Link \
                  "{\"kernelFilename\":\"vluki4.efi\",\"kernelFileDescriptor\":0,\"entryCommit\":300,\"extraFiles\":[{\"filename\":\"hello.addon.efi\",\"data\":\"$(base64 -w0 "$LINK_WORKDIR/hello.addon.efi")\"}]}")"
    vid="$(echo "$vreply" | jq -r '.ids[0]')"
    assert_eq "$vid" "$vtoken-commit_300.conf"
    cmp "$LINK_WORKDIR/hello.addon.efi" "$ESP/$vtoken/hello.addon.efi"
    grep "^extra /$vtoken/hello.addon.efi\$" "$ESP/loader/entries/$vid" >/dev/null
    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink "{\"id\":\"$vid\"}"
    test ! -e "$ESP/$vtoken/hello.addon.efi"

    # A bad addon is reported as an invalid extraFiles parameter
    varlinkctl call --quiet \
                   --push-fd="$LINK_WORKDIR/testuki.efi" \
                   --graceful=org.varlink.service.InvalidParameter \
                   "$BOOTCTL_BIN" io.systemd.BootControl.Link \
                   "{\"kernelFilename\":\"vluki4.efi\",\"kernelFileDescriptor\":0,\"entryCommit\":301,\"extraFiles\":[{\"filename\":\"bad.addon.efi\",\"data\":\"$(echo notanaddon | base64 -w0)\"}]}"
    test ! -e "$ESP/loader/entries/$vtoken-commit_301.conf"
    test ! -e "$ESP/$vtoken/bad.addon.efi"

    # --- Test 14: Unlink with invalid argument combinations is rejected ---
    # Both id and oldest=true
    (! varlinkctl call "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                 '{"id":"foo.conf","oldest":true}')
    # Neither id nor oldest
    (! varlinkctl call "$BOOTCTL_BIN" io.systemd.BootControl.Unlink '{}')
    # Invalid id characters (e.g. a glob)
    (! varlinkctl call "$BOOTCTL_BIN" io.systemd.BootControl.Unlink \
                 '{"id":"foo*.conf"}')
}

cleanup_link_auto() {
    rm -rf /run/systemd/uki /etc/systemd/uki
    if [[ -n "${LINK_WORKDIR:-}" ]]; then
        rm -rf "$LINK_WORKDIR"
        unset LINK_WORKDIR
    fi
    restore_esp
}

testcase_bootctl_link_auto() {
    if ! command -v ukify >/dev/null; then
        echo "ukify not found, skipping."
        return 0
    fi

    backup_esp
    LINK_WORKDIR="$(mktemp --directory /tmp/test-bootctl-link-auto.XXXXXXXXXX)"
    trap cleanup_link_auto RETURN ERR

    # Ensure loader/entries directory is present
    bootctl install --make-entry-directory=yes

    local ESP
    ESP="$(bootctl --print-esp-path)"

    cat >"$LINK_WORKDIR/os-release" <<'EOF'
ID=testos
NAME="Test OS"
PRETTY_NAME="Test OS"
EOF
    echo "fake-kernel" >"$LINK_WORKDIR/vmlinuz"
    echo "fake-initrd" >"$LINK_WORKDIR/initrd"

    # Two distinct UKIs, so we can tell which one was picked up.
    ukify build \
        --linux "$LINK_WORKDIR/vmlinuz" \
        --initrd "$LINK_WORKDIR/initrd" \
        --os-release "@$LINK_WORKDIR/os-release" \
        --uname "1.2.3-testkernel" \
        --cmdline "quiet uki=a" \
        --output "$LINK_WORKDIR/uki_a.efi"
    ukify build \
        --linux "$LINK_WORKDIR/vmlinuz" \
        --initrd "$LINK_WORKDIR/initrd" \
        --os-release "@$LINK_WORKDIR/os-release" \
        --uname "1.2.3-testkernel" \
        --cmdline "quiet uki=b" \
        --output "$LINK_WORKDIR/uki_b.efi"
    ukify build \
        --cmdline "addon=test" \
        --output "$LINK_WORKDIR/hello.addon.efi"
    ukify build \
        --cmdline "other" \
        --uname "4.5.6-otherkernel" \
        --output "$LINK_WORKDIR/other.addon.efi"

    local TOKEN="systemdtest"
    local BOOTCTL=(bootctl "--entry-token=literal:$TOKEN")
    local ENTRY="$ESP/loader/entries/${TOKEN}-commit_1.conf"

    # --- Test 1: link-auto picks up kernel.efi + extras.d/ from /run/systemd/uki/ ---
    rm -rf /run/systemd/uki
    mkdir -p /run/systemd/uki/extras.d
    cp "$LINK_WORKDIR/uki_a.efi"     /run/systemd/uki/kernel.efi
    echo "sysext-data"  >/run/systemd/uki/extras.d/hello.sysext.raw
    echo "confext-data" >/run/systemd/uki/extras.d/hello.confext.raw
    echo "cred-data"    >/run/systemd/uki/extras.d/hello.cred
    cp "$LINK_WORKDIR/hello.addon.efi" /run/systemd/uki/extras.d/hello.addon.efi

    "${BOOTCTL[@]}" link-auto

    test -f "$ENTRY"
    test -f "$ESP/$TOKEN/kernel.efi"
    cmp "$LINK_WORKDIR/uki_a.efi" "$ESP/$TOKEN/kernel.efi"
    test -f "$ESP/$TOKEN/hello.sysext.raw"
    test -f "$ESP/$TOKEN/hello.confext.raw"
    test -f "$ESP/$TOKEN/hello.cred"
    test -f "$ESP/$TOKEN/hello.addon.efi"
    grep "^uki /${TOKEN}/kernel.efi\$"          "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello.sysext.raw\$"  "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello.confext.raw\$" "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello.cred\$"        "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello.addon.efi\$"   "$ENTRY" >/dev/null

    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_1.conf"
    test ! -e "$ENTRY"
    test ! -e "$ESP/$TOKEN/kernel.efi"
    test ! -e "$ESP/$TOKEN/hello.addon.efi"

    # --- Test 2: versioned kernel.efi.v/ and extras .v/ are resolved via vpick ---
    rm -rf /run/systemd/uki
    mkdir -p /run/systemd/uki/kernel.efi.v /run/systemd/uki/extras.d/hello.sysext.raw.v
    cp "$LINK_WORKDIR/uki_a.efi" /run/systemd/uki/kernel.efi.v/kernel_1.0.efi
    cp "$LINK_WORKDIR/uki_a.efi" /run/systemd/uki/kernel.efi.v/kernel_2.0.efi
    echo "sysext-1" >/run/systemd/uki/extras.d/hello.sysext.raw.v/hello_1.0.sysext.raw
    echo "sysext-2" >/run/systemd/uki/extras.d/hello.sysext.raw.v/hello_2.0.sysext.raw

    "${BOOTCTL[@]}" link-auto

    test -f "$ENTRY"
    # vpick must select the newest version
    test -f "$ESP/$TOKEN/kernel_2.0.efi"
    test ! -e "$ESP/$TOKEN/kernel_1.0.efi"
    test -f "$ESP/$TOKEN/hello_2.0.sysext.raw"
    test ! -e "$ESP/$TOKEN/hello_1.0.sysext.raw"
    grep "^uki /${TOKEN}/kernel_2.0.efi\$"         "$ENTRY" >/dev/null
    grep "^extra /${TOKEN}/hello_2.0.sysext.raw\$" "$ENTRY" >/dev/null

    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_1.conf"

    # --- Test 3: priority — /etc/systemd/uki/ wins over /run/systemd/uki/ ---
    rm -rf /run/systemd/uki /etc/systemd/uki
    mkdir -p /run/systemd/uki/extras.d /etc/systemd/uki/extras.d
    cp "$LINK_WORKDIR/uki_b.efi" /run/systemd/uki/kernel.efi
    cp "$LINK_WORKDIR/uki_a.efi" /etc/systemd/uki/kernel.efi
    echo "run-cred" >/run/systemd/uki/extras.d/hello.cred
    echo "etc-cred" >/etc/systemd/uki/extras.d/hello.cred

    "${BOOTCTL[@]}" link-auto

    test -f "$ESP/$TOKEN/kernel.efi"
    # The /etc copy (uki_a) must win over the /run copy (uki_b)
    cmp "$LINK_WORKDIR/uki_a.efi" "$ESP/$TOKEN/kernel.efi"
    cmp <(echo "etc-cred") "$ESP/$TOKEN/hello.cred"

    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_1.conf"
    rm -rf /etc/systemd/uki

    # --- Test 3a: addons in extras.d/ are validated: a non-PE one makes link-auto fail, while one for another
    # kernel is skipped, as systemd-stub would skip it too ---
    rm -rf /run/systemd/uki
    mkdir -p /run/systemd/uki/extras.d
    cp "$LINK_WORKDIR/uki_a.efi" /run/systemd/uki/kernel.efi
    echo "not-a-pe" >/run/systemd/uki/extras.d/notpe.addon.efi

    (! "${BOOTCTL[@]}" link-auto)
    test ! -e "$ENTRY"
    test ! -e "$ESP/$TOKEN/notpe.addon.efi"

    rm /run/systemd/uki/extras.d/notpe.addon.efi
    cp "$LINK_WORKDIR/other.addon.efi" /run/systemd/uki/extras.d/other.addon.efi

    "${BOOTCTL[@]}" link-auto
    test -f "$ENTRY"
    test ! -e "$ESP/$TOKEN/other.addon.efi"
    (! grep "other.addon.efi" "$ENTRY" >/dev/null)

    "${BOOTCTL[@]}" unlink "${TOKEN}-commit_1.conf"

    # --- Test 4: with nothing staged, link-auto is a successful no-op ---
    rm -rf /run/systemd/uki
    "${BOOTCTL[@]}" link-auto
    # No entries referencing our token should remain.
    local leftover
    leftover="$(find "$ESP/loader/entries/" -name "*$TOKEN*" -print -quit 2>/dev/null)"
    test -z "$leftover"

    # === Varlink coverage: io.systemd.BootControl.LinkAuto ===
    local BOOTCTL_BIN vreply vid vtoken
    BOOTCTL_BIN="$(type -p bootctl)"

    # --- Test 5: LinkAuto discovers kernel.efi + extras ---
    rm -rf /run/systemd/uki
    mkdir -p /run/systemd/uki/extras.d
    cp "$LINK_WORKDIR/uki_a.efi" /run/systemd/uki/kernel.efi
    echo "cred-data" >/run/systemd/uki/extras.d/hello.cred

    vreply="$(varlinkctl call --json=short "$BOOTCTL_BIN" io.systemd.BootControl.LinkAuto '{}')"
    vid="$(echo "$vreply" | jq -r '.ids[0]')"
    test -n "$vid"
    test "$vid" != "null"
    vtoken="${vid%%-commit_*}"
    test -n "$vtoken"

    test -f "$ESP/loader/entries/$vid"
    test -f "$ESP/$vtoken/kernel.efi"
    test -f "$ESP/$vtoken/hello.cred"
    grep "^uki /$vtoken/kernel.efi\$" "$ESP/loader/entries/$vid" >/dev/null

    varlinkctl call --quiet "$BOOTCTL_BIN" io.systemd.BootControl.Unlink "{\"id\":\"$vid\"}"
    test ! -e "$ESP/loader/entries/$vid"
    test ! -e "$ESP/$vtoken/kernel.efi"
    test ! -e "$ESP/$vtoken/hello.cred"

    # --- Test 6: LinkAuto with nothing staged returns an empty id list ---
    rm -rf /run/systemd/uki
    vreply="$(varlinkctl call --json=short "$BOOTCTL_BIN" io.systemd.BootControl.LinkAuto '{}')"
    assert_eq "$(echo "$vreply" | jq -r '.ids | length')" "0"
}

cleanup_install_extra() {
    if [[ -n "${EXTRA_ROOT:-}" ]]; then
        rm -rf "$EXTRA_ROOT"
        unset EXTRA_ROOT
    fi
}

# Prints the files that a UAPI.16 manifest lists, in the format of sha256sum(1).
extra_manifest_sums() {
    tr --delete '\036' <"$1" | jq --raw-output 'select(.sha256) | "\(.sha256)  \(.name)"'
}

# Prints the number of files that a UAPI.16 manifest lists, without the systemd-boot binaries in EFI/systemd/.
extra_manifest_count() {
    extra_manifest_sums "$1" | { grep --invert-match "  EFI/systemd/systemd-boot" || :; } | wc -l
}

# Compares the files in the ESP with the hashes that the manifest of the extra files lists.
extra_manifest_check() {
    extra_manifest_sums "$1/EFI/systemd/installed.Uapi16Manifest" | (cd "$1" && sha256sum --check --strict)
}

testcase_install_extra() {
    local arch arch_upper bootlibdir extra esp manifest pending sd_boot
    arch="$(bootctl --print-efi-architecture)"
    arch_upper="${arch^^}"
    bootlibdir=/usr/lib/systemd/boot/efi

    # Operate on a scratch root directory, so that the test does not depend on the ESP and the extra files of
    # the image.
    EXTRA_ROOT="$(mktemp --directory /tmp/test-bootctl-extra.XXXXXXXXXX)"
    trap cleanup_install_extra RETURN ERR

    extra="$EXTRA_ROOT$bootlibdir/extra"
    esp="$EXTRA_ROOT/efi"
    manifest="$esp/EFI/systemd/installed.Uapi16Manifest"
    pending="$esp/EFI/systemd/installed-pending.Uapi16Manifest"
    sd_boot="$EXTRA_ROOT$bootlibdir/systemd-boot$arch.efi"

    mkdir -p "$extra/EFI/Boot" "$extra/EFI/systemd" "$EXTRA_ROOT/usr/lib/first-stage" "$EXTRA_ROOT/etc" "$esp"
    echo "ID=test" >"$EXTRA_ROOT/etc/os-release"
    if [[ -e "$bootlibdir/systemd-boot$arch.efi.signed" ]]; then
        cp "$bootlibdir/systemd-boot$arch.efi.signed" "$sd_boot"
    else
        cp "$bootlibdir/systemd-boot$arch.efi" "$sd_boot"
    fi
    # bootctl prefers the .signed file. Data after the last section makes the file differ from the unsigned
    # one without changing its version.
    cp "$sd_boot" "$sd_boot.signed"
    echo "signed" >>"$sd_boot.signed"

    # loader.efi and helper.efi are installed like a first stage boot loader such as shim. Absolute symlinks
    # are resolved inside of the root directory. The directory is spelled "EFI/Boot" on purpose: it has to
    # end up in "EFI/BOOT".
    echo "first stage v1" >"$EXTRA_ROOT/usr/lib/first-stage/loader.efi"
    echo "helper v1" >"$EXTRA_ROOT/usr/lib/first-stage/helper.efi"
    ln -s /usr/lib/first-stage/loader.efi "$extra/EFI/Boot/BOOT$arch_upper.EFI"
    ln -s /usr/lib/first-stage/helper.efi "$extra/EFI/Boot/helper.efi"
    ln -s "../../../systemd-boot$arch.efi" "$extra/EFI/Boot/second-stage$arch.efi"
    ln -s /usr/lib/first-stage/loader.efi "$extra/EFI/systemd/boot$arch.efi"
    ln -s "../../../systemd-boot$arch.efi" "$extra/EFI/systemd/second-stage$arch.efi"
    # A name that looks like a backup file is installed like any other file.
    echo "config v1" >"$extra/EFI/Boot/first-stage.cfg.bak"

    local -a cmd=(env SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root="$EXTRA_ROOT" --esp-path=/efi
                  --install-source=image --no-variables --make-entry-directory=no --random-seed=no)

    "${cmd[@]}" install
    test ! -e "$esp/EFI/Boot"
    # The extra file is the default boot loader, systemd-boot is only installed under its own name.
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v1"
    assert_eq "$(cat "$esp/EFI/systemd/boot$arch.efi")" "first stage v1"
    assert_eq "$(cat "$esp/EFI/BOOT/helper.efi")" "helper v1"
    assert_eq "$(cat "$esp/EFI/BOOT/first-stage.cfg.bak")" "config v1"
    # A symlink to systemd-boot$arch.efi installs systemd-boot$arch.efi.signed, like for systemd-boot itself.
    cmp "$esp/EFI/systemd/systemd-boot$arch.efi" "$sd_boot.signed"
    cmp "$esp/EFI/BOOT/second-stage$arch.efi" "$sd_boot.signed"
    cmp "$esp/EFI/systemd/second-stage$arch.efi" "$sd_boot.signed"
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_count "$manifest")" "6"
    # The manifest lists systemd-boot as well.
    extra_manifest_sums "$manifest" | grep "  EFI/systemd/systemd-boot$arch.efi\$" >/dev/null

    # The symlink also works if only the .signed file exists.
    mv "$sd_boot" "$sd_boot.away"
    "${cmd[@]}" --graceful update
    mv "$sd_boot.away" "$sd_boot"

    # A regular file called .efi.signed is installed without the .signed suffix, and it replaces the .efi
    # file next to it.
    mkdir "$extra/EFI/tools"
    echo "tool unsigned" >"$extra/EFI/tools/tool.efi"
    echo "tool signed" >"$extra/EFI/tools/tool.efi.signed"
    echo "only signed" >"$extra/EFI/tools/other.efi.signed"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/tools/tool.efi")" "tool signed"
    assert_eq "$(cat "$esp/EFI/tools/other.efi")" "only signed"
    test ! -e "$esp/EFI/tools/tool.efi.signed"
    test ! -e "$esp/EFI/tools/other.efi.signed"
    assert_eq "$(extra_manifest_count "$manifest")" "8"
    # Without the .efi.signed file, the .efi file is installed.
    rm "$extra/EFI/tools/tool.efi.signed"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/tools/tool.efi")" "tool unsigned"
    rm -r "$extra/EFI/tools"
    "${cmd[@]}" --graceful update
    test ! -e "$esp/EFI/tools/tool.efi"
    test ! -e "$esp/EFI/tools/other.efi"
    rmdir "$esp/EFI/tools"
    assert_eq "$(extra_manifest_count "$manifest")" "6"

    # An update replaces a file whose contents changed, although it has no version information.
    echo "first stage v2" >"$EXTRA_ROOT/usr/lib/first-stage/loader.efi"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v2"
    assert_eq "$(cat "$esp/EFI/systemd/boot$arch.efi")" "first stage v2"
    extra_manifest_check "$esp"

    # A dangling symlink is an error, and the ESP is left alone.
    mv "$EXTRA_ROOT/usr/lib/first-stage/helper.efi" "$EXTRA_ROOT/usr/lib/first-stage/helper.away"
    (! "${cmd[@]}" --graceful update)
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v2"
    assert_eq "$(cat "$esp/EFI/BOOT/helper.efi")" "helper v1"
    assert_eq "$(extra_manifest_count "$manifest")" "6"
    mv "$EXTRA_ROOT/usr/lib/first-stage/helper.away" "$EXTRA_ROOT/usr/lib/first-stage/helper.efi"

    # If the systemd-boot binaries are gone, the extra files in the ESP are not treated as obsolete.
    mv "$sd_boot" "$sd_boot.away"
    mv "$sd_boot.signed" "$sd_boot.signed.away"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v2"
    assert_eq "$(extra_manifest_count "$manifest")" "6"
    mv "$sd_boot.away" "$sd_boot"
    mv "$sd_boot.signed.away" "$sd_boot.signed"

    # If the extra directory is a symlink whose target does not exist, the update fails and the extra files
    # in the ESP are not treated as obsolete.
    mv "$extra" "$extra.away"
    ln -s /does/not/exist "$extra"
    (! "${cmd[@]}" --graceful update)
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v2"
    assert_eq "$(extra_manifest_count "$manifest")" "6"
    rm "$extra"
    mv "$extra.away" "$extra"

    # If a file cannot be copied, the entry points are not updated, and the manifest keeps listing the files
    # that are still in place. installed-pending.Uapi16Manifest lists the file that could not be copied
    # with the new hash. The file size limit makes the copy of the 256K helper fail.
    head -c 262144 /dev/urandom >"$EXTRA_ROOT/usr/lib/first-stage/helper.efi"
    echo "first stage v3" >"$EXTRA_ROOT/usr/lib/first-stage/loader.efi"
    (trap '' XFSZ; ulimit -f 64; ! "${cmd[@]}" --graceful update)
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v2"
    assert_eq "$(cat "$esp/EFI/systemd/boot$arch.efi")" "first stage v2"
    assert_eq "$(cat "$esp/EFI/BOOT/helper.efi")" "helper v1"
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_count "$manifest")" "6"
    assert_eq "$(extra_manifest_sums "$pending")" "$(sha256sum <"$EXTRA_ROOT/usr/lib/first-stage/helper.efi" | cut -d' ' -f1)  EFI/BOOT/helper.efi"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v3"
    cmp "$esp/EFI/BOOT/helper.efi" "$EXTRA_ROOT/usr/lib/first-stage/helper.efi"
    extra_manifest_check "$esp"
    test ! -e "$pending"
    assert_eq "$(extra_manifest_count "$manifest")" "6"

    # Without --graceful, "update" fails if systemd-boot is up-to-date and nothing else changed. It
    # succeeds if it installed an extra file.
    (! "${cmd[@]}" update)
    echo "first stage v3b" >"$EXTRA_ROOT/usr/lib/first-stage/loader.efi"
    "${cmd[@]}" update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v3b"
    echo "first stage v3" >"$EXTRA_ROOT/usr/lib/first-stage/loader.efi"
    "${cmd[@]}" update

    # A path that was a file is a directory now, and the other way around.
    echo "vendor" >"$extra/EFI/vendor"
    mkdir "$extra/EFI/tools"
    echo "tool" >"$extra/EFI/tools/tool.cfg"
    "${cmd[@]}" --graceful update
    rm -r "$extra/EFI/vendor" "$extra/EFI/tools"
    mkdir "$extra/EFI/vendor"
    echo "vendor" >"$extra/EFI/vendor/vendor.cfg"
    echo "tools" >"$extra/EFI/tools"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/vendor/vendor.cfg")" "vendor"
    assert_eq "$(cat "$esp/EFI/tools")" "tools"
    extra_manifest_check "$esp"
    rm -r "$extra/EFI/vendor" "$extra/EFI/tools"
    "${cmd[@]}" --graceful update
    test ! -e "$esp/EFI/tools"
    assert_eq "$(extra_manifest_count "$manifest")" "6"

    # An update leaves a file alone that something else replaced, and does not list it anymore.
    echo "other boot loader" >"$esp/EFI/BOOT/BOOT$arch_upper.EFI"
    echo "first stage v4" >"$EXTRA_ROOT/usr/lib/first-stage/loader.efi"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "other boot loader"
    assert_eq "$(cat "$esp/EFI/systemd/boot$arch.efi")" "first stage v4"
    (! grep "EFI/BOOT/BOOT$arch_upper.EFI" "$manifest" >/dev/null)
    assert_eq "$(extra_manifest_count "$manifest")" "5"

    # An update does not take over a file that something else placed in the ESP, even if it is identical.
    echo "identical" >"$extra/EFI/Boot/identical.cfg"
    echo "identical" >"$esp/EFI/BOOT/identical.cfg"
    "${cmd[@]}" --graceful update
    (! grep "identical.cfg" "$manifest" >/dev/null)
    rm "$extra/EFI/Boot/identical.cfg"
    "${cmd[@]}" --graceful update
    test -f "$esp/EFI/BOOT/identical.cfg"

    # An update removes a file that is not provided anymore.
    rm "$extra/EFI/Boot/helper.efi"
    "${cmd[@]}" --graceful update
    test ! -e "$esp/EFI/BOOT/helper.efi"
    assert_eq "$(extra_manifest_count "$manifest")" "4"

    # Two files that only differ in case are the same file on VFAT.
    echo "collision" >"$extra/EFI/systemd/SECOND-STAGE$arch_upper.EFI"
    (! "${cmd[@]}" --graceful update 2>&1 | tee "$EXTRA_ROOT/bootctl.log")
    grep "only differ in case" "$EXTRA_ROOT/bootctl.log" >/dev/null
    rm "$extra/EFI/systemd/SECOND-STAGE$arch_upper.EFI"

    # A file and a directory whose names only differ in case collide as well.
    mkdir -p "$extra/efi/boot/FIRST-STAGE.CFG.BAK"
    echo "collision" >"$extra/efi/boot/FIRST-STAGE.CFG.BAK/file"
    (! "${cmd[@]}" --graceful update 2>&1 | tee "$EXTRA_ROOT/bootctl.log")
    grep "a file and a directory of the same name" "$EXTRA_ROOT/bootctl.log" >/dev/null
    rm -r "$extra/efi"

    # File names that are reserved for systemd-boot are refused.
    echo "reserved" >"$extra/EFI/systemd/systemd-boot-test.efi"
    (! "${cmd[@]}" --graceful update)
    rm "$extra/EFI/systemd/systemd-boot-test.efi"

    # A file name that is not valid UTF-8 cannot be listed in the manifest and is refused.
    echo "latin1" >"$extra/EFI/Boot/caf"$'\xe9'".cfg"
    (! "${cmd[@]}" --graceful update)
    rm "$extra/EFI/Boot/caf"$'\xe9'".cfg"

    # An update that was interrupted after it copied a file leaves the old hash of the file in
    # installed.Uapi16Manifest and the new hash in installed-pending.Uapi16Manifest. The next update
    # still replaces the file.
    echo "config v2" >"$esp/EFI/BOOT/first-stage.cfg.bak"
    printf '\x1e%s\n' \
           '{"features":["sha256"],"mediaType":"application/vnd.uapi.16.manifest"}' \
           '{"name":"EFI","type":"dir"}' \
           '{"name":"EFI/BOOT","type":"dir"}' \
           "{\"name\":\"EFI/BOOT/first-stage.cfg.bak\",\"sha256\":\"$(sha256sum <"$esp/EFI/BOOT/first-stage.cfg.bak" | cut -d' ' -f1)\"}" \
           '{"mediaType":"application/vnd.uapi.16.trailer"}' >"$pending"
    echo "config v3" >"$extra/EFI/Boot/first-stage.cfg.bak"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/first-stage.cfg.bak")" "config v3"
    test ! -e "$pending"
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_count "$manifest")" "4"

    # If something replaced a file that is not provided anymore with a directory, the update leaves the
    # directory alone and still succeeds.
    echo "obsolete" >"$extra/EFI/Boot/obsolete.cfg"
    "${cmd[@]}" --graceful update
    rm "$extra/EFI/Boot/obsolete.cfg" "$esp/EFI/BOOT/obsolete.cfg"
    mkdir "$esp/EFI/BOOT/obsolete.cfg"
    "${cmd[@]}" --graceful update
    test -d "$esp/EFI/BOOT/obsolete.cfg"
    assert_eq "$(extra_manifest_count "$manifest")" "4"
    rmdir "$esp/EFI/BOOT/obsolete.cfg"

    # An update touches neither the extra files nor the manifest if the manifest cannot be parsed.
    cp "$manifest" "$EXTRA_ROOT/manifest.bak"
    echo "not a manifest line" >>"$manifest"
    cp "$manifest" "$EXTRA_ROOT/manifest.damaged"
    echo "config v4" >"$extra/EFI/Boot/first-stage.cfg.bak"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/first-stage.cfg.bak")" "config v3"
    cmp "$manifest" "$EXTRA_ROOT/manifest.damaged"
    cp "$EXTRA_ROOT/manifest.bak" "$manifest"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/first-stage.cfg.bak")" "config v4"

    # "remove" deletes the files that were installed, but neither the file that something else replaced
    # nor a file that was modified.
    echo "edited" >>"$esp/EFI/BOOT/first-stage.cfg.bak"
    "${cmd[@]}" remove
    test ! -e "$esp/EFI/systemd"
    test ! -e "$esp/EFI/BOOT/second-stage$arch.efi"
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "other boot loader"
    test -f "$esp/EFI/BOOT/first-stage.cfg.bak"
    test -f "$esp/EFI/BOOT/identical.cfg"

    # Without extra files systemd-boot is the default boot loader, and the manifest only lists systemd-boot.
    rm -rf "$extra" "$esp"
    mkdir "$esp"
    "${cmd[@]}" install
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_sums "$manifest" | cut -d' ' -f3 | sort | paste --serial --delimiters=' ')" \
              "EFI/BOOT/BOOT$arch_upper.EFI EFI/systemd/systemd-boot$arch.efi"
    test ! -e "$pending"

    # An ESP that an older bootctl installed has no manifest. An update writes the manifest, and it does not
    # replace systemd-boot, which the manifest did not list, with a first stage boot loader. "install" does.
    rm "$manifest"
    mkdir -p "$extra/EFI/BOOT" "$extra/EFI/systemd"
    echo "first stage v5" >"$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    echo "first stage v5" >"$extra/EFI/systemd/boot$arch.efi"
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"
    assert_eq "$(cat "$esp/EFI/systemd/boot$arch.efi")" "first stage v5"
    (! grep "EFI/BOOT/BOOT$arch_upper.EFI" "$manifest" >/dev/null)
    extra_manifest_sums "$manifest" | grep "  EFI/systemd/systemd-boot$arch.efi\$" >/dev/null
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"
    "${cmd[@]}" install
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v5"
    assert_eq "$(extra_manifest_count "$manifest")" "2"

    # An update replaces a systemd-boot that the manifest lists as the default boot loader with a first stage
    # boot loader, and the other way around.
    rm "$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"
    grep "EFI/BOOT/BOOT$arch_upper.EFI" "$manifest" >/dev/null
    echo "first stage v5" >"$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v5"
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_count "$manifest")" "2"

    # If the default boot loader is not provided anymore, an update replaces it with systemd-boot.
    rm "$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"
    assert_eq "$(cat "$esp/EFI/systemd/boot$arch.efi")" "first stage v5"
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_count "$manifest")" "2"

    # An update that changes nothing does not write the manifest again.
    local inode
    inode="$(stat --format=%i "$manifest")"
    "${cmd[@]}" --graceful update
    assert_eq "$(stat --format=%i "$manifest")" "$inode"

    # An update replaces a copy of systemd-boot that was installed as an extra file like any other extra
    # file.
    ln -s "../../../systemd-boot$arch.efi" "$extra/EFI/systemd/second-stage.efi"
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/systemd/second-stage.efi" "$sd_boot.signed"
    rm "$extra/EFI/systemd/second-stage.efi"
    echo "second stage" >"$extra/EFI/systemd/second-stage.efi"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/systemd/second-stage.efi")" "second stage"
    rm "$extra/EFI/systemd/second-stage.efi"

    # If "install" cannot copy a file that an earlier invocation installed, the old file stays in the
    # manifest. The file size limit is larger than systemd-boot and smaller than the extra file.
    head --bytes=8M /dev/zero >"$extra/EFI/systemd/large.bin"
    "${cmd[@]}" install
    grep "EFI/systemd/large.bin" "$manifest" >/dev/null
    echo "changed" >>"$extra/EFI/systemd/large.bin"
    (trap '' XFSZ; ulimit -f 4096; ! "${cmd[@]}" install)
    extra_manifest_sums "$manifest" | grep "^$(sha256sum <"$esp/EFI/systemd/large.bin" | cut -d' ' -f1)  EFI/systemd/large.bin\$" >/dev/null
    rm "$extra/EFI/systemd/large.bin"
    "${cmd[@]}" --graceful update
    test ! -e "$esp/EFI/systemd/large.bin"

    # "install" does not report the default boot loader as modified after systemd-boot replaced it.
    echo "first stage v6" >"$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" install
    rm "$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" install 2>&1 | tee "$EXTRA_ROOT/bootctl.log"
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"
    (! grep "modified since" "$EXTRA_ROOT/bootctl.log" >/dev/null)

    # If systemd-boot cannot replace a default boot loader that is not provided anymore, the update fails
    # and the default boot loader stays in the ESP. The file size limit is smaller than systemd-boot.
    echo "first stage v6" >"$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" install
    rm "$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    (trap '' XFSZ; ulimit -f 16; ! "${cmd[@]}" --graceful update)
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v6"
    grep "EFI/BOOT/BOOT$arch_upper.EFI" "$manifest" >/dev/null
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"

    # If the manifest cannot be parsed, an update does not replace a default boot loader that is not provided
    # anymore.
    echo "first stage v7" >"$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    "${cmd[@]}" install
    rm "$extra/EFI/BOOT/BOOT$arch_upper.EFI"
    echo "not a manifest line" >>"$manifest"
    "${cmd[@]}" --graceful update
    assert_eq "$(cat "$esp/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage v7"
    sed -i '$d' "$manifest"
    "${cmd[@]}" --graceful update
    cmp "$esp/EFI/BOOT/BOOT$arch_upper.EFI" "$sd_boot.signed"

    # A manifest that cannot be read does not block the update of systemd-boot.
    mv "$manifest" "$EXTRA_ROOT/manifest.bak"
    mkdir "$manifest"
    "${cmd[@]}" --graceful update
    rmdir "$manifest"

    # "install" replaces a manifest that cannot be parsed, even if no extra file is provided.
    rm -r "$extra"
    echo "not a manifest line" >"$manifest"
    "${cmd[@]}" install
    extra_manifest_check "$esp"
    assert_eq "$(extra_manifest_count "$manifest")" "1"
}

efi_boot_entries() {
    # Print the file of each entry in the firmware's boot loader list, in boot order.
    bootctl status | sed -n '/Boot Loaders Listed in EFI Variables/,/^[^ ]/p' | { grep "File:" || :; }
}

assert_no_efi_boot_entry() {
    local entries pattern
    entries="$(efi_boot_entries)"

    for pattern in "$@"; do
        (! grep -i "$pattern" <<<"$entries" >/dev/null)
    done
}

cleanup_install_extra_variables() {
    if mountpoint /usr/lib/systemd/boot/efi >/dev/null; then
        umount /usr/lib/systemd/boot/efi
    fi
    if [[ -n "${EXTRA_BOOTLIBDIR:-}" ]]; then
        rm -rf "$EXTRA_BOOTLIBDIR"
        unset EXTRA_BOOTLIBDIR
    fi
    if [[ -n "${FAKE_ESP:-}" ]]; then
        rm -rf "$FAKE_ESP"
        unset FAKE_ESP
    fi
    if [[ -n "${FAKE_BOOT:-}" ]]; then
        rm -rf "$FAKE_BOOT"
        unset FAKE_BOOT
    fi
    bootctl remove || :
    restore_esp
}

testcase_install_extra_variables() {
    if [ ! -d /sys/firmware/efi ]; then
        echo "Not booted with EFI, skipping the test of the firmware's boot loader list."
        return 0
    fi

    local arch arch_upper bootlibdir dir entry_point sd_boot_entry
    arch="$(bootctl --print-efi-architecture)"
    arch_upper="${arch^^}"
    bootlibdir=/usr/lib/systemd/boot/efi
    entry_point="/EFI/systemd/boot$arch.efi"
    sd_boot_entry="/EFI/systemd/systemd-boot$arch.efi"

    backup_esp
    trap cleanup_install_extra_variables RETURN ERR

    # The extra files are taken from the host here, hence mount a writable copy of the directory with the
    # systemd-boot binaries over the original. A copy of systemd-boot is installed as the first stage boot
    # loader, so that the firmware can start the registered binary.
    EXTRA_BOOTLIBDIR="$(mktemp --directory /tmp/test-bootctl-bootlibdir.XXXXXXXXXX)"
    cp -r "$bootlibdir/." "$EXTRA_BOOTLIBDIR/"
    ln -s "../../../systemd-boot$arch.efi" "$EXTRA_BOOTLIBDIR/extra/EFI/systemd/boot$arch.efi"
    mount --bind "$EXTRA_BOOTLIBDIR" "$bootlibdir"

    # systemd installs options.csv for shim in UTF-16LE, with a byte order mark.
    for dir in BOOT systemd; do
        assert_eq "$(iconv --from-code=UTF-16 --to-code=UTF-8 "$bootlibdir/extra/EFI/$dir/options.csv")" \
                  "\\EFI\\systemd\\systemd-boot$arch.efi,"
    done

    # The extra entry point is registered instead of systemd-boot, at the top of the boot order.
    bootctl install
    cmp "$(bootctl --print-esp-path)/EFI/BOOT/options.csv" "$bootlibdir/extra/EFI/BOOT/options.csv"
    cmp "$(bootctl --print-esp-path)/EFI/systemd/options.csv" "$bootlibdir/extra/EFI/systemd/options.csv"
    efi_boot_entries | sed -n 1p | grep -i "$entry_point" >/dev/null
    assert_no_efi_boot_entry "$sd_boot_entry"

    # If the entry point is not provided anymore, systemd-boot takes its position in the boot order.
    rm "$bootlibdir/extra/EFI/systemd/boot$arch.efi"
    bootctl update --graceful
    test ! -e "$(bootctl --print-esp-path)$entry_point"
    efi_boot_entries | sed -n 1p | grep -i "$sd_boot_entry" >/dev/null
    assert_no_efi_boot_entry "$entry_point"

    # An update does not register an entry point in the ESP that bootctl did not install.
    ln -s "../../../systemd-boot$arch.efi" "$bootlibdir/extra/EFI/systemd/boot$arch.efi"
    echo "other boot loader" >"$(bootctl --print-esp-path)$entry_point"
    bootctl update --graceful
    efi_boot_entries | sed -n 1p | grep -i "$sd_boot_entry" >/dev/null
    assert_no_efi_boot_entry "$entry_point"
    rm "$(bootctl --print-esp-path)$entry_point"

    # An update that does not touch the EFI variables installs the entry point, and the next update
    # registers it, even if systemd-boot itself is up-to-date.
    bootctl update --graceful --variables=no
    test -f "$(bootctl --print-esp-path)$entry_point"
    efi_boot_entries | sed -n 1p | grep -i "$sd_boot_entry" >/dev/null
    bootctl update
    (! bootctl update)
    efi_boot_entries | sed -n 1p | grep -i "$entry_point" >/dev/null
    assert_no_efi_boot_entry "$sd_boot_entry"

    # An update that does not touch the EFI variables keeps an entry point that is not provided anymore,
    # because its boot entry still refers to it. The next update replaces the boot entry and removes the file.
    rm "$bootlibdir/extra/EFI/systemd/boot$arch.efi"
    bootctl update --graceful --variables=no
    test -f "$(bootctl --print-esp-path)$entry_point"
    efi_boot_entries | sed -n 1p | grep -i "$entry_point" >/dev/null
    bootctl update --graceful
    test ! -e "$(bootctl --print-esp-path)$entry_point"
    efi_boot_entries | sed -n 1p | grep -i "$sd_boot_entry" >/dev/null
    assert_no_efi_boot_entry "$entry_point"

    # The Varlink method installs the extra files of the host as well.
    ln -s "../../../systemd-boot$arch.efi" "$bootlibdir/extra/EFI/systemd/boot$arch.efi"
    echo "first stage" >"$bootlibdir/extra/EFI/BOOT/BOOT$arch_upper.EFI"
    FAKE_ESP="$(mktemp --directory /tmp/test-bootctl-esp.XXXXXXXXXX)"
    FAKE_BOOT="$(mktemp --directory /tmp/test-bootctl-boot.XXXXXXXXXX)"
    SYSTEMD_RELAX_ESP_CHECKS=yes SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes SYSTEMD_LOG_TARGET=console \
            varlinkctl call --quiet "$(type -p bootctl)" io.systemd.BootControl.Install \
            "{\"operation\":\"new\",\"touchVariables\":false,\"espPath\":\"$FAKE_ESP\",\"xbootldrPath\":\"$FAKE_BOOT\",\"makeEntryDirectory\":false}"
    assert_eq "$(cat "$FAKE_ESP/EFI/BOOT/BOOT$arch_upper.EFI")" "first stage"
    test -f "$FAKE_ESP/EFI/systemd/boot$arch.efi"
    extra_manifest_check "$FAKE_ESP"
    rm "$bootlibdir/extra/EFI/BOOT/BOOT$arch_upper.EFI"

    # "remove" deletes the boot entry of the extra entry point.
    bootctl update --graceful
    efi_boot_entries | sed -n 1p | grep -i "$entry_point" >/dev/null
    bootctl remove
    assert_no_efi_boot_entry "$entry_point" "$sd_boot_entry"
}

run_testcases
