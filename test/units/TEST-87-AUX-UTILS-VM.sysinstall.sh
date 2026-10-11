#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-sysinstall >/dev/null; then
    echo "systemd-sysinstall not found, skipping."
    exit 77
fi

if ! command -v systemd-repart >/dev/null; then
    echo "systemd-repart not found, skipping."
    exit 77
fi

if ! command -v bootctl >/dev/null; then
    echo "bootctl not found, skipping."
    exit 77
fi

if ! command -v ukify >/dev/null; then
    echo "ukify not found, skipping."
    exit 77
fi

if [[ ! -d /usr/lib/systemd/boot/efi ]]; then
    echo "sd-boot is not installed, skipping."
    exit 77
fi

# We need a real environment to fiddle with loop devices.
if systemd-detect-virt -cq; then
    echo "Running in a container, skipping."
    exit 77
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh


CRED_VALUE="systemd-sysinstall test credential payload"
CRED_VALUE_BASE64=$(echo -n "$CRED_VALUE" | base64 -w0)

cleanup() {
    set +e
    # Stop the installer first: it might still be writing to the devices and files removed below.
    if [[ -n "${UNIT:-}" ]]; then
        systemctl stop "$UNIT"
        systemctl reset-failed "$UNIT"
        UNIT=""
    fi
    if [[ "$MOUNTED" -eq 1 ]]; then
        umount -R "$WORKDIR/mnt"
        MOUNTED=0
    fi
    if [[ -n "$LOOPDEV" ]]; then
        systemd-dissect --detach "$LOOPDEV"
        LOOPDEV=""
    fi
    if [[ -n "${TARGETDEV:-}" ]]; then
        systemd-dissect --detach "$TARGETDEV"
        TARGETDEV=""
    fi
    if [[ -n "${TARGETDEV2:-}" ]]; then
        systemd-dissect --detach "$TARGETDEV2"
        TARGETDEV2=""
    fi
    rm -rf "$WORKDIR"
}

check_device_auto_environment() {
    # Safety check for the --device-auto testcases: systemd-sysinstall must be able to determine the disk
    # the running system is booted from (it refuses the automatic pick otherwise), and no candidate disk
    # may be around initially, since the testcases rely on the disks they attach themselves being the only
    # candidates — otherwise the automatic pick would either fail or – worse – install to some unexpected
    # disk. Query the candidate list the same way systemd-sysinstall does (i.e. with the very same filter
    # set, except that systemd-sysinstall additionally ignores loopback devices unless
    # $SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP is set, which the testcases do), instead of approximating
    # the filters here.
    #
    # Returns non-zero (and the testcase is to be skipped) only if the booted disk cannot be determined,
    # i.e. if the feature is genuinely unusable in this environment. Stray candidate disks on the other
    # hand mean the test environment is broken (e.g. a loopback device leaked by an earlier testcase),
    # which must not silently turn the --device-auto testcases into no-ops, hence fail hard in that case.
    local out

    if ! bootctl -RR >/dev/null; then
        echo "Cannot determine the disk the system is booted from." >&2
        return 1
    fi

    if out="$(varlinkctl call --more "exec:$(command -v systemd-repart)" io.systemd.Repart.ListCandidateDevices '{"ignoreRoot":true,"ignoreEmpty":true}' 2>&1)"; then
        echo "Unexpected candidate disks present, test environment is broken: $out" >&2
        exit 1
    fi

    if [[ "$out" != *"io.systemd.Repart.NoCandidateDevices"* ]]; then
        echo "Failed to enumerate candidate disks: $out" >&2
        exit 1
    fi
}

start_device_auto_installer() {
    # Starts the installer as a notify service with --device-auto and the specified settle timeout (plus
    # any further arguments). systemd-sysinstall sends READY=1 once its device monitor is set up, hence
    # systemd-run only returns once we can be sure that a disk appearing from now on will be noticed.
    # Loopback devices are not considered as candidates by default, hence explicitly permit them, the
    # target disks of the testcases are loopback devices.
    local settle_timeout="${1:?}"
    shift

    UNIT="sysinstall-device-auto-$RANDOM.service"
    systemd-run \
        --unit="$UNIT" \
        --service-type=notify \
        --property=RemainAfterExit=yes \
        --setenv=SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP=1 \
        --quiet \
        -- \
        systemd-sysinstall \
            --welcome=no \
            --chrome=no \
            --confirm=no \
            --summary=no \
            --erase=yes \
            --variables=no \
            --reboot=no \
            --mute-console=no \
            --copy-locale=no \
            --copy-keymap=no \
            --copy-timezone=no \
            --device-auto \
            --device-auto-timeout="$settle_timeout" \
            "$@"
}

wait_for_device_auto_installer() {
    # Waits for the installer started by start_device_auto_installer() to finish, and dumps its output, so
    # that it ends up in the test log whatever happened — hence don't abort right away if the wait times
    # out, the assertions of the caller will catch that case after the output has been dumped.
    timeout "${1:?}" bash -c "while [[ \"\$(systemctl show -P SubState '$UNIT')\" == running ]]; do sleep 1; done" || :
    journalctl --sync
    journalctl --no-pager -u "$UNIT"
}

create_fake_os_source_tree() {
    # 1) Build a small fake "OS source" tree. systemd-sysinstall picks this up via
    #    the repart.sysinstall.d definitions: CopyFiles= seeds the new root
    #    partition with these files.
    SOURCE_ROOT="$WORKDIR/sourceroot"
    mkdir -p "$SOURCE_ROOT/usr/lib" "$SOURCE_ROOT/etc"

    cat >"$SOURCE_ROOT/usr/lib/os-release" <<'EOF'
ID=testos
NAME="Test OS"
PRETTY_NAME="Test OS for systemd-sysinstall"
VERSION_ID=1
EOF
    ln -s ../usr/lib/os-release "$SOURCE_ROOT/etc/os-release"

    # 2) Build a minimal UKI. bootctl link only requires a valid PE with .osrel and
    #    the systemd-stub SBAT marker, so the .linux/.initrd contents do not need
    #    to be a real kernel.
    echo "fake-kernel" >"$WORKDIR/vmlinuz"
    echo "fake-initrd" >"$WORKDIR/initrd"

    ukify build \
        --linux "$WORKDIR/vmlinuz" \
        --initrd "$WORKDIR/initrd" \
        --os-release "@$SOURCE_ROOT/usr/lib/os-release" \
        --uname "1.2.3-testkernel" \
        --cmdline "quiet" \
        --output "$WORKDIR/testuki.efi"

    # 3) Build a sysinstall partition definition: a single ESP plus a root
    #    partition seeded from the fake source tree.
    DEFS="$WORKDIR/sysinstall.d"
    mkdir -p "$DEFS"

    cat >"$DEFS/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=64M
SizeMaxBytes=64M
EOF

    cat >"$DEFS/20-root.conf" <<EOF
[Partition]
Type=root
Format=ext4
SizeMinBytes=128M
CopyFiles=$SOURCE_ROOT:/
EOF

    # 4) Allocate a sparse target file. systemd-sysinstall accepts a regular file
    #    path here — systemd-repart and the in-process dissect logic transparently
    #    handle the loop attach during install. We can't pre-attach the empty file
    #    via systemd-dissect --attach since that requires a valid DDI.
    truncate -s 512M "$WORKDIR/target.img"
}

validate_image() {
    # 1) Attach the freshly installed image as a loopback device for inspection.
    LOOPDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"

    # Verify the resulting on-disk layout. The disk must now carry a GPT with at
    # least an ESP partition.
    sfdisk_dump="$(sfdisk --dump "$LOOPDEV")"
    assert_in "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" "$sfdisk_dump"

    # 2) Mount the image read-only and verify the installed artifacts: an entry
    #    file referencing the UKI on the ESP, the UKI itself, and the systemd-boot
    #    binary.
    MNT="$WORKDIR/mnt"
    mkdir -p "$MNT"

    systemd-dissect --mount --read-only "$LOOPDEV" "$MNT"
    MOUNTED=1

    ESP="$MNT/efi"
    test -d "$ESP/loader/entries"

    # Exactly one entry should have been linked, and it should reference the UKI
    # we passed via --kernel=.
    ENTRY=$(find "$ESP/loader/entries" -maxdepth 1 -name '*.conf' -type f | head -n1)
    test -n "$ENTRY"
    grep -E "^uki /[^/]+/testuki\.efi$" "$ENTRY" >/dev/null

    # The UKI file referenced in the entry must exist on the ESP.
    UKI_PATH=$(awk '/^uki / { print $2 }' "$ENTRY")
    test -n "$UKI_PATH"
    test -f "$ESP$UKI_PATH"

    # bootctl install should have placed sd-boot on the ESP.
    find "$ESP/EFI/systemd" -type f -iname 'systemd-boot*.efi' | grep . >/dev/null

    # The credential we passed via --set-credential= must have been encrypted and
    # placed next to the UKI, and must be referenced as 'extra' from the entry.
    UKI_DIR="$(dirname "$ESP$UKI_PATH")"
    TOKEN_DIR="$(basename "$UKI_DIR")"
    test -s "$UKI_DIR/marker.cred"
    grep -E "^extra /$TOKEN_DIR/marker\.cred$" "$ENTRY" >/dev/null

    # Locale/keymap/timezone propagation is off, so those .cred files must NOT
    # exist on the ESP.
    test ! -e "$UKI_DIR/firstboot.locale.cred"
    test ! -e "$UKI_DIR/firstboot.keymap.cred"
    test ! -e "$UKI_DIR/firstboot.timezone.cred"

    # 3) The seeded files from the fake source tree must end up in the new root.
    test -f "$MNT/usr/lib/os-release"
    grep '^ID=testos$' "$MNT/usr/lib/os-release" >/dev/null
}

testcase_sysinstall_basic() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    create_fake_os_source_tree

    # Run the installer non-interactively against the target image. Also stash a
    # literal credential ('marker') so we can verify it ends up next to the UKI
    # and is referenced from the boot loader entry.
    systemd-sysinstall \
        --welcome=no \
        --chrome=no \
        --confirm=no \
        --summary=no \
        --erase=yes \
        --variables=no \
        --reboot=no \
        --mute-console=no \
        --copy-locale=no \
        --copy-keymap=no \
        --copy-timezone=no \
        --set-credential="marker:$CRED_VALUE" \
        --kernel="$WORKDIR/testuki.efi" \
        --definitions="$DEFS" \
        "$WORKDIR/target.img"

    validate_image

    cleanup
}

testcase_sysinstall_varlink_basic() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    create_fake_os_source_tree

    # Run the installer via varlink against the target image. Also stash a
    # literal credential ('marker') so we can verify it ends up next to the UKI
    # and is referenced from the boot loader entry.
    varlinkctl call /run/systemd/io.systemd.SysInstall io.systemd.SysInstall.Run "{\"erase\": true, \"variables\": false, \"credentials\" : [{ \"id\" : \"marker\", \"value\" : \"$CRED_VALUE_BASE64\" }], \"kernelImagePath\" : \"$WORKDIR/testuki.efi\", \"node\": \"$WORKDIR/target.img\", \"definitions\" : [\"$DEFS\"] }" --more

    validate_image
}

testcase_sysinstall_device_auto() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    TARGETDEV=""
    UNIT=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    if ! check_device_auto_environment; then
        echo "Environment not suitable for --device-auto tests, skipping." >&2
        return 0
    fi

    create_fake_os_source_tree

    # Put a bare file system on the target image, so that systemd-dissect --attach accepts it as an
    # image later on (an all-zero file is not a valid image). Don't put a partition table on it though:
    # the resulting loopback device shall have no partition block devices, so that nothing is in the
    # way when systemd-repart adds the new ones. systemd-sysinstall erases the file system anyway.
    mkfs.ext4 -q -F "$WORKDIR/target.img"

    # Start the installer while no candidate disk exists yet.
    start_device_auto_installer 30s \
        --set-credential="marker:$CRED_VALUE" \
        --kernel="$WORKDIR/testuki.efi" \
        --definitions="$DEFS"

    # Only now, 5s later, make the target disk appear: a partition-scanning loopback device backed by
    # the target image. It's the sole candidate disk in the VM, hence it must be picked.
    sleep 5

    # The installer must still be waiting at this point, there was nothing to install to so far.
    assert_eq "$(systemctl show -P SubState "$UNIT")" "running"

    TARGETDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"
    udevadm wait --settle "$TARGETDEV"

    # Wait for the installation to finish, and check that it succeeded.
    wait_for_device_auto_installer 180
    assert_eq "$(systemctl show -P SubState "$UNIT")" "exited"
    assert_eq "$(systemctl show -P Result "$UNIT")" "success"

    # Release our loopback device again, validate_image attaches the image on its own.
    systemd-dissect --detach "$TARGETDEV"
    TARGETDEV=""

    validate_image
}

testcase_sysinstall_device_auto_two_candidates() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    TARGETDEV=""
    TARGETDEV2=""
    UNIT=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    if ! check_device_auto_environment; then
        echo "Environment not suitable for --device-auto tests, skipping." >&2
        return 0
    fi

    create_fake_os_source_tree

    # Attach two candidate disks, both carrying a bare file system (see testcase_sysinstall_device_auto
    # for why), so that we can verify below that neither of them was touched.
    mkfs.ext4 -q -F "$WORKDIR/target.img"
    truncate -s 512M "$WORKDIR/target2.img"
    mkfs.ext4 -q -F "$WORKDIR/target2.img"

    TARGETDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"
    TARGETDEV2="$(systemd-dissect --attach "$WORKDIR/target2.img")"
    udevadm wait --settle "$TARGETDEV" "$TARGETDEV2"

    # With two candidate disks present the automatic pick must refuse right away, i.e. well before the
    # settle timeout expires, and without installing anywhere.
    local start="$SECONDS" rc=0 out
    out="$(SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP=1 timeout 60 systemd-sysinstall \
        --welcome=no \
        --chrome=no \
        --confirm=no \
        --summary=no \
        --erase=yes \
        --variables=no \
        --reboot=no \
        --mute-console=no \
        --copy-locale=no \
        --copy-keymap=no \
        --copy-timezone=no \
        --set-credential="marker:$CRED_VALUE" \
        --kernel="$WORKDIR/testuki.efi" \
        --definitions="$DEFS" \
        --device-auto \
        --device-auto-timeout=30s 2>&1)" || rc=$?
    echo "$out"
    assert_neq "$rc" 0
    assert_neq "$rc" 124
    assert_in "Multiple candidate block devices found" "$out"
    assert_le "$((SECONDS - start))" 10

    # Neither disk may have been touched: the bare file systems must have survived unmodified, in
    # particular no partition table may have been written.
    assert_eq "$(blkid -p -o value -s TYPE "$TARGETDEV")" "ext4"
    assert_eq "$(blkid -p -o value -s TYPE "$TARGETDEV2")" "ext4"
}

testcase_sysinstall_device_auto_late_second_candidate() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    TARGETDEV=""
    TARGETDEV2=""
    UNIT=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    if ! check_device_auto_environment; then
        echo "Environment not suitable for --device-auto tests, skipping." >&2
        return 0
    fi

    # Same as testcase_sysinstall_device_auto_two_candidates, but the second disk shows up only while the
    # installer is already waiting for the settle timeout, i.e. the refusal must come via the uevent path
    # rather than the initial enumeration.
    truncate -s 512M "$WORKDIR/target.img"
    mkfs.ext4 -q -F "$WORKDIR/target.img"
    truncate -s 512M "$WORKDIR/target2.img"
    mkfs.ext4 -q -F "$WORKDIR/target2.img"

    start_device_auto_installer 30s

    TARGETDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"
    udevadm wait --settle "$TARGETDEV"
    sleep 5

    # A single candidate must not have been picked yet, the settle timeout is far from expired.
    assert_eq "$(systemctl show -P SubState "$UNIT")" "running"

    # Now make the second disk appear. This must make the installer refuse right away.
    local start="$SECONDS" out
    TARGETDEV2="$(systemd-dissect --attach "$WORKDIR/target2.img")"
    udevadm wait --settle "$TARGETDEV2"

    wait_for_device_auto_installer 60
    assert_le "$((SECONDS - start))" 10
    assert_neq "$(systemctl show -P SubState "$UNIT")" "running"
    assert_neq "$(systemctl show -P Result "$UNIT")" "success"
    out="$(journalctl --no-pager -o cat -u "$UNIT")"
    assert_in "Multiple candidate block devices found" "$out"

    # Neither disk may have been touched.
    assert_eq "$(blkid -p -o value -s TYPE "$TARGETDEV")" "ext4"
    assert_eq "$(blkid -p -o value -s TYPE "$TARGETDEV2")" "ext4"
}

testcase_sysinstall_device_auto_candidate_disappears() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    TARGETDEV=""
    UNIT=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    if ! check_device_auto_environment; then
        echo "Environment not suitable for --device-auto tests, skipping." >&2
        return 0
    fi

    # A candidate that appears and disappears again while the installer is waiting must be forgotten
    # about: the installer must not pick the stale device node, but restart the settle clock and
    # eventually fail for lack of a candidate.
    truncate -s 512M "$WORKDIR/target.img"
    mkfs.ext4 -q -F "$WORKDIR/target.img"

    start_device_auto_installer 10s

    TARGETDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"
    udevadm wait --settle "$TARGETDEV"
    sleep 3

    assert_eq "$(systemctl show -P SubState "$UNIT")" "running"

    local start="$SECONDS" out
    systemd-dissect --detach "$TARGETDEV"
    TARGETDEV=""

    # The removal restarts the settle clock, hence the failure may come no earlier than a full settle
    # timeout after the disk disappeared.
    wait_for_device_auto_installer 60
    assert_ge "$((SECONDS - start))" 10
    assert_neq "$(systemctl show -P SubState "$UNIT")" "running"
    assert_neq "$(systemctl show -P Result "$UNIT")" "success"
    out="$(journalctl --no-pager -o cat -u "$UNIT")"
    assert_in "disappeared" "$out"
    assert_in "No suitable block device" "$out"
}

testcase_sysinstall_device_auto_no_candidate() {
    if ! check_device_auto_environment; then
        echo "Environment not suitable for --device-auto tests, skipping." >&2
        return 0
    fi

    # With no candidate disk around the automatic pick must fail once the settle timeout expires — not
    # before it expires, and not by hanging around forever either.
    local start="$SECONDS" rc=0 out
    out="$(timeout 60 systemd-sysinstall \
        --welcome=no \
        --chrome=no \
        --confirm=no \
        --summary=no \
        --erase=yes \
        --variables=no \
        --reboot=no \
        --mute-console=no \
        --device-auto \
        --device-auto-timeout=5s 2>&1)" || rc=$?
    echo "$out"
    assert_neq "$rc" 0
    assert_neq "$rc" 124
    assert_in "No suitable block device" "$out"
    assert_ge "$((SECONDS - start))" 5
}

testcase_sysinstall_device_auto_loop_ignored() {
    WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
    LOOPDEV=""
    TARGETDEV=""
    UNIT=""
    MOUNTED=0

    echo "WORKDIR=$WORKDIR"

    trap cleanup RETURN

    if ! check_device_auto_environment; then
        echo "Environment not suitable for --device-auto tests, skipping." >&2
        return 0
    fi

    # Unless $SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP is set, loopback devices must not be considered as
    # candidates, i.e. a lone loopback disk must not be picked, and the automatic pick must fail once the
    # settle timeout expires, exactly as if no disk was around.
    truncate -s 512M "$WORKDIR/target.img"
    mkfs.ext4 -q -F "$WORKDIR/target.img"
    TARGETDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"
    udevadm wait --settle "$TARGETDEV"

    local start="$SECONDS" rc=0 out
    out="$(timeout 60 systemd-sysinstall \
        --welcome=no \
        --chrome=no \
        --confirm=no \
        --summary=no \
        --erase=yes \
        --variables=no \
        --reboot=no \
        --mute-console=no \
        --device-auto \
        --device-auto-timeout=5s 2>&1)" || rc=$?
    echo "$out"
    assert_neq "$rc" 0
    assert_neq "$rc" 124
    assert_in "No suitable block device" "$out"
    assert_ge "$((SECONDS - start))" 5

    # The loopback disk must not have been touched.
    assert_eq "$(blkid -p -o value -s TYPE "$TARGETDEV")" "ext4"
}

testcase_sysinstall_device_auto_argument_errors() {
    local rc out

    # --device-auto cannot be combined with an explicitly specified target device...
    rc=0
    out="$(timeout 30 systemd-sysinstall --device-auto /dev/null 2>&1)" || rc=$?
    echo "$out"
    assert_neq "$rc" 0
    assert_neq "$rc" 124
    assert_in "Cannot combine --device-auto with an explicitly specified device" "$out"

    # ...and the settle timeout cannot be infinite.
    rc=0
    out="$(timeout 30 systemd-sysinstall --device-auto --device-auto-timeout=infinity 2>&1)" || rc=$?
    echo "$out"
    assert_neq "$rc" 0
    assert_neq "$rc" 124
    assert_in "--device-auto-timeout= cannot be infinite" "$out"
}

run_testcases
