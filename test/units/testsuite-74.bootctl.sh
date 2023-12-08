#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-detect-virt --quiet --container; then
    echo "running on container, skipping."
    exit 0
fi

if ! command -v bootctl >/dev/null; then
    echo "bootctl not found, skipping."
    exit 0
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

basic_tests() {
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
    assert_eq "$(bootctl --print-esp-path)" "/efi"
    assert_eq "$(bootctl --print-boot-path)" "/boot"
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

    udevadm settle

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

    udevadm settle

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

    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-esp-path)" "/run/systemd/mount-rootfs/efi"
    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-esp-path --esp-path=/efi)" "/run/systemd/mount-rootfs/efi"
    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-boot-path)" "/run/systemd/mount-rootfs/boot"
    assert_eq "$(bootctl --image "${IMAGE_DIR}/image" --print-boot-path --boot-path=/boot)" "/run/systemd/mount-rootfs/boot"

    # FIXME: This provides spurious result.
    bootctl --image "${IMAGE_DIR}/image" --print-root-device || :

    basic_tests --image "${IMAGE_DIR}/image"
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

    udevadm settle

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

    udevadm settle

    # If mail address is not set for the service, it may fail, and
    # testsuite-74.machine-id-setup.sh detects the failure.
    systemctl reset-failed mdmonitor.service

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

    udevadm settle

    echo y | mdadm --create /dev/md/raid-esp --name "raid-esp" "${LOOPDEV1}p1" "${LOOPDEV2}p1" -v -f --level=1 --raid-devices=2
    mkfs.vfat /dev/md/raid-esp
    echo y | mdadm --create /dev/md/raid-root --name "raid-root" "${LOOPDEV1}p2" "${LOOPDEV2}p2" -v -f --level=1 --raid-devices=2
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

    # If the verification is relaxed, md RAID partition is approved.
    assert_eq "$(SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-esp-path)" "${IMAGE_DIR}/root/efi"
    assert_eq "$(SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-esp-path --esp-path=/efi)" "${IMAGE_DIR}/root/efi"

    # find_xbootldr() does not support btrfs RAID, and bootctl falls back to use ESP.
    # (but as in the above, the ESP verification is also failed in this case).
    (! bootctl --root "${IMAGE_DIR}/root" --print-boot-path)

    # If the verification for ESP is relaxed, bootctl falls back to use ESP.
    assert_eq "$(SYSTEMD_RELAX_ESP_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-boot-path)" "${IMAGE_DIR}/root/efi"

    # When the boot path is explicitly specified, the verification will be failed.
    (! bootctl --root "${IMAGE_DIR}/root" --print-boot-path --boot-path=/boot)

    # If the verification is relaxed, it accepts the xbootldr partition.
    assert_eq "$(SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-boot-path)" "${IMAGE_DIR}/root/boot"
    assert_eq "$(SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes bootctl --root "${IMAGE_DIR}/root" --print-boot-path --boot-path=/boot)" "${IMAGE_DIR}/root/boot"

    # FIXME: This provides spurious result.
    bootctl --root "${IMAGE_DIR}/root" --print-root-device || :

    SYSTEMD_RELAX_ESP_CHECKS=yes SYSTEMD_RELAX_XBOOTLDR_CHECKS=yes basic_tests --root "${IMAGE_DIR}/root"
}

run_testcases
