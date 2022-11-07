#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# We're going to play around with block/loop devices, so bail out early
# if we're running in nspawn
if systemd-detect-virt --container >/dev/null; then
    echo "Container detected, skipping the test"
    exit 0
fi

at_exit() {
    set +e

    [[ -n "${LOOP:-}" ]] && losetup -d "$LOOP"
    [[ -n "${WORK_DIR:-}" ]] && rm -fr "$WORK_DIR"
}

trap at_exit EXIT

WORK_DIR="$(mktemp -d)"

systemd-mount --list
systemd-mount --list --full
systemd-mount --list --no-legend
systemd-mount --list --no-pager
systemd-mount --list --quiet

# Set up a simple block device for further tests
dd if=/dev/zero of="$WORK_DIR/simple.img" bs=1M count=16
LOOP="$(losetup --show --find "$WORK_DIR/simple.img")"
mkfs.ext4 -L sd-mount-test "$LOOP"
mkdir "$WORK_DIR/mnt"
mount "$LOOP" "$WORK_DIR/mnt"
touch "$WORK_DIR/mnt/foo.bar"
umount "$LOOP"
(! mountpoint "$WORK_DIR/mnt")

# Mount with both source and destination set
systemd-mount "$LOOP" "$WORK_DIR/mnt"
systemctl status "$WORK_DIR/mnt"
systemd-mount --list --full
test -e "$WORK_DIR/mnt/foo.bar"
systemd-umount "$WORK_DIR/mnt"
# Same thing, but with explicitly specified filesystem and disabled filesystem check
systemd-mount --type=ext4 --fsck=no --collect "$LOOP" "$WORK_DIR/mnt"
systemctl status "$(systemd-escape --path "$WORK_DIR/mnt").mount"
test -e "$WORK_DIR/mnt/foo.bar"
systemd-mount --umount "$LOOP"
# Discover additional metadata (unit description should now contain filesystem label)
systemd-mount --no-ask-password --discover "$LOOP" "$WORK_DIR/mnt"
test -e "$WORK_DIR/mnt/foo.bar"
systemctl show -P Description "$WORK_DIR/mnt" | grep -q sd-mount-test
systemd-umount "$WORK_DIR/mnt"
# Set a property
systemd-mount --property="Description=Foo Bar" "$LOOP" "$WORK_DIR/mnt"
test -e "$WORK_DIR/mnt/foo.bar"
systemctl show -P Description "$WORK_DIR/mnt" | grep -q "Foo Bar"
systemd-umount "$WORK_DIR/mnt"
# Set mount options
systemd-mount --options ro,x-foo-bar "$LOOP" "$WORK_DIR/mnt"
test -e "$WORK_DIR/mnt/foo.bar"
systemctl show -P Options "$WORK_DIR/mnt" | grep -Eq "(^ro|,ro)"
systemctl show -P Options "$WORK_DIR/mnt" | grep -q "x-foo-bar"
systemd-umount "$WORK_DIR/mnt"

# Mount with only source set
systemd-mount "$LOOP"
systemctl status /run/media/system/sd-mount-test
systemd-mount --list --full
test -e /run/media/system/sd-mount-test/foo.bar
systemd-umount LABEL=sd-mount-test

# Automount
systemd-mount --automount=yes "$LOOP" "$WORK_DIR/mnt"
systemd-mount --list --full
systemctl status "$(systemd-escape --path "$WORK_DIR/mnt").automount"
[[ "$(systemctl show -P ActiveState "$WORK_DIR/mnt")" == inactive ]]
test -e "$WORK_DIR/mnt/foo.bar"
systemctl status "$WORK_DIR/mnt"
systemd-umount "$WORK_DIR/mnt"
# Automount + automount-specific property
systemd-mount --automount=yes --automount-property="Description=Bar Baz" "$LOOP" "$WORK_DIR/mnt"
systemctl show -P Description "$(systemd-escape --path "$WORK_DIR/mnt").automount" | grep -q "Bar Baz"
test -e "$WORK_DIR/mnt/foo.bar"
systemd-umount "$WORK_DIR/mnt"

# Automount + --bind-device
systemd-mount --automount=yes --bind-device --timeout-idle-sec=1 "$LOOP" "$WORK_DIR/mnt"
systemctl status "$(systemd-escape --path "$WORK_DIR/mnt").automount"
# Trigger the automount
test -e "$WORK_DIR/mnt/foo.bar"
# Wait until it's idle again
sleep 1.5
# Safety net for slower/overloaded systems
timeout 10s bash -c "while systemctl is-active -q $WORK_DIR/mnt; do sleep .2; done"
systemctl status "$(systemd-escape --path "$WORK_DIR/mnt").automount"
# Disassemble the underlying block device
losetup -d "$LOOP"
unset LOOP
# The automount unit should be gone at this point
(! systemctl status "$(systemd-escape --path "$WORK_DIR/mnt").automount")

# Mount a disk image
systemd-mount "$WORK_DIR/simple.img"
systemd-mount --list --full
test -e /run/media/system/simple.img/foo.bar
systemd-umount "$WORK_DIR/simple.img"

# --owner + vfat
#
# Create a vfat image, as ext4 doesn't support uid=/gid= fixating for all
# files/directories
dd if=/dev/zero of="$WORK_DIR/owner-vfat.img" bs=1M count=16
LOOP="$(losetup --show --find "$WORK_DIR/owner-vfat.img")"
mkfs.vfat -n owner-vfat "$LOOP"
# Mount it and check the UID/GID
[[ "$(stat -c "%U:%G" "$WORK_DIR/mnt")" == "root:root" ]]
systemd-mount --owner testuser "$LOOP" "$WORK_DIR/mnt"
systemctl status "$WORK_DIR/mnt"
[[ "$(stat -c "%U:%G" "$WORK_DIR/mnt")" == "testuser:testuser" ]]
touch "$WORK_DIR/mnt/hello"
[[ "$(stat -c "%U:%G" "$WORK_DIR/mnt/hello")" == "testuser:testuser" ]]
systemd-umount LABEL=owner-vfat
