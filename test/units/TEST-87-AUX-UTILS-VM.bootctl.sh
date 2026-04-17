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
    bootctl --print-root-device --print-root-device
    bootctl --print-esp-path
    bootctl --print-boot-path
    bootctl --print-loader-path
    bootctl --print-stub-path
    bootctl --print-efi-architecture

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

    bootctl status

    # Ensure the addon is fully loaded and parsed
    bootctl status | grep "extra: /boot//loader/addons/test.addon.efi" >/dev/null
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

    # Locate the systemd-stub to embed into the generated UKI
    local stub
    stub="/usr/lib/systemd/boot/efi/linux$(bootctl --print-efi-architecture).efi.stub"

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
    echo "fake-kernel"      >"$LINK_WORKDIR/vmlinuz"
    echo "fake-initrd"      >"$LINK_WORKDIR/initrd"
    echo "fake-sysext-data" >"$LINK_WORKDIR/hello.sysext.raw"
    echo "fake-confext-data">"$LINK_WORKDIR/hello.confext.raw"
    echo "fake-credential"  >"$LINK_WORKDIR/hello.cred"

    ukify build \
        --stub "$stub" \
        --linux "$LINK_WORKDIR/vmlinuz" \
        --initrd "$LINK_WORKDIR/initrd" \
        --os-release "@$LINK_WORKDIR/os-release" \
        --uname "1.2.3-testkernel" \
        --cmdline "quiet" \
        --output "$LINK_WORKDIR/testuki.efi"

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
    "${BOOTCTL[@]}" --dry-run unlink "${TOKEN}-commit_30.conf"
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

run_testcases
