#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v bootctl >/dev/null; then
    echo "bootctl not found, skipping."
    exit 0
fi

if [[ ! -d /usr/lib/systemd/boot/efi ]]; then
    echo "sd-boot is not installed, skipping."
    exit 0
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

    basic_tests
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
    bootctl status | grep "global-addon: loader/addons/test.addon.efi" >/dev/null
    bootctl status | grep "cmdline" | grep addonfoobar >/dev/null
    grep -q addonfoobar /proc/cmdline
}

remove_root_dir() {
    rm -rf "$ROOTDIR"
}

testcase_install_varlink() {

    varlinkctl introspect "$(type -p bootctl)"

    if [ $# -eq 0 ]; then
        backup_esp
        trap restore_esp RETURN ERR
    fi

    (! bootctl is-installed )
    SYSTEMD_LOG_TARGET=console varlinkctl call "$(type -p bootctl)" io.systemd.BootControl.Install "{\"operation\":\"new\",\"touchVariables\":false}"
    bootctl is-installed
}

run_testcases
