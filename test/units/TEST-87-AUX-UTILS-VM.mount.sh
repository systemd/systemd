#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e

    [[ -n "${LOOP:-}" ]] && losetup -d "$LOOP"
    [[ -n "${WORK_DIR:-}" ]] && rm -fr "$WORK_DIR"
}

(! systemd-detect-virt -cq)

trap at_exit EXIT

WORK_DIR="$(mktemp -d)"
mkdir -p "$WORK_DIR/mnt"

systemd-mount --list
systemd-mount --list --full
systemd-mount --list --no-legend
systemd-mount --list --no-pager
systemd-mount --list --quiet
systemd-mount --list --json=pretty

# tmpfs
mkdir -p "$WORK_DIR/mnt/foo/bar"
systemd-mount --tmpfs "$WORK_DIR/mnt/foo"
test ! -d "$WORK_DIR/mnt/foo/bar"
touch "$WORK_DIR/mnt/foo/baz"
systemd-umount "$WORK_DIR/mnt/foo"
test -d "$WORK_DIR/mnt/foo/bar"
test ! -e "$WORK_DIR/mnt/foo/baz"

# overlay
systemd-mount --type=overlay --options="lowerdir=/etc,upperdir=$WORK_DIR/upper,workdir=$WORK_DIR/work" /etc "$WORK_DIR/overlay"
touch "$WORK_DIR/overlay/foo"
test -e "$WORK_DIR/upper/foo"
systemd-umount "$WORK_DIR/overlay"

# Set up a simple block device for further tests
truncate -s 16M "$WORK_DIR/simple.img"
mkfs.ext4 -L sd-mount-test "$WORK_DIR/simple.img"
LOOP="$(losetup --show --find "$WORK_DIR/simple.img")"
udevadm wait --timeout=60 --settle "$LOOP"
# Also wait for the .device unit for the loop device is active. Otherwise, the .device unit activation
# that is triggered by the .mount unit introduced by systemd-mount below may time out.
timeout 60 bash -c "until systemctl is-active $LOOP; do sleep 1; done"
mount "$LOOP" "$WORK_DIR/mnt"
touch "$WORK_DIR/mnt/foo.bar"
umount "$LOOP"
(! mountpoint "$WORK_DIR/mnt")
# Wait for the mount unit to be unloaded. Otherwise, creation of the transient unit below may fail.
MOUNT_UNIT=$(systemd-escape --path --suffix=mount "$WORK_DIR/mnt")
timeout 60 bash -c "while [[ -n \$(systemctl list-units --all --no-legend $MOUNT_UNIT) ]]; do sleep 1; done"

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
systemctl show -P Description "$WORK_DIR/mnt" | grep sd-mount-test >/dev/null
systemd-umount "$WORK_DIR/mnt"
# Set a unit description
systemd-mount --description="Very Important Unit" "$LOOP" "$WORK_DIR/mnt"
test -e "$WORK_DIR/mnt/foo.bar"
systemctl show -P Description "$WORK_DIR/mnt" | grep "Very Important Unit" >/dev/null
systemd-umount "$WORK_DIR/mnt"
# Set a property
systemd-mount --property="Description=Foo Bar" "$LOOP" "$WORK_DIR/mnt"
test -e "$WORK_DIR/mnt/foo.bar"
systemctl show -P Description "$WORK_DIR/mnt" | grep "Foo Bar" >/dev/null
systemd-umount "$WORK_DIR/mnt"
# Set mount options
systemd-mount --options=ro,x-foo-bar "$LOOP" "$WORK_DIR/mnt"
test -e "$WORK_DIR/mnt/foo.bar"
systemctl show -P Options "$WORK_DIR/mnt" | grep -E "(^ro|,ro)" >/dev/null
systemctl show -P Options "$WORK_DIR/mnt" | grep "x-foo-bar" >/dev/null
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
systemd-mount -A --automount-property="Description=Bar Baz" "$LOOP" "$WORK_DIR/mnt"
systemctl show -P Description "$(systemd-escape --path "$WORK_DIR/mnt").automount" | grep "Bar Baz" >/dev/null
test -e "$WORK_DIR/mnt/foo.bar"
# Call --umount via --machine=, first with a relative path (bad) and then with
# an absolute one (good)
(! systemd-umount --machine=.host "$(realpath --relative-to=. "$WORK_DIR/mnt")")
systemd-umount --machine=.host "$WORK_DIR/mnt"

# ext4 doesn't support uid=/gid=
(! systemd-mount -t ext4 --owner=testuser "$LOOP" "$WORK_DIR/mnt")

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
# The automount unit should disappear once the underlying blockdev is gone
timeout 10s bash -c "while systemctl status '$(systemd-escape --path "$WORK_DIR/mnt".automount)'; do sleep .2; done"

# Mount a disk image
systemd-mount --discover "$WORK_DIR/simple.img"
# We can access files in the image even if the loopback block device is not initialized by udevd.
test -e /run/media/system/simple.img/foo.bar
# systemd-mount --list and systemd-umount require the loopback block device is initialized by udevd.
udevadm settle --timeout=30
assert_in "/dev/loop.* ext4 +sd-mount-test" "$(systemd-mount --list --full)"
LOOP_AUTO=$(systemd-mount --list --full --no-legend | awk '$7 == "sd-mount-test" { print $1 }')
LOOP_AUTO_DEVPATH=$(udevadm info --query property --property DEVPATH --value "$LOOP_AUTO")
systemd-umount "$WORK_DIR/simple.img"
# Wait for 'change' uevent for the device with DISK_MEDIA_CHANGE=1.
# After the event, the backing_file attribute should be removed.
timeout 60 bash -c "while [[ -e /sys/$LOOP_AUTO_DEVPATH/loop/backing_file ]]; do sleep 1; done"

# --owner + vfat
#
# Create a vfat image, as ext4 doesn't support uid=/gid= fixating for all
# files/directories
dd if=/dev/zero of="$WORK_DIR/owner-vfat.img" bs=1M count=16
mkfs.vfat -n owner-vfat "$WORK_DIR/owner-vfat.img"
LOOP="$(losetup --show --find "$WORK_DIR/owner-vfat.img")"
# If the synthesized uevent triggered by inotify event has been processed earlier than the kernel finishes to
# attach the backing file, then SYSTEMD_READY=0 is set for the device. As a workaround, monitor sysattr
# and re-trigger uevent after that.
LOOP_DEVPATH=$(udevadm info --query property --property DEVPATH --value "$LOOP")
timeout 60 bash -c "until [[ -e /sys/$LOOP_DEVPATH/loop/backing_file ]]; do sleep 1; done"
udevadm trigger --settle "$LOOP"
# Also wait for the .device unit for the loop device is active. Otherwise, the .device unit activation
# that is triggered by the .mount unit introduced by systemd-mount below may time out.
if ! timeout 60 bash -c "until systemctl is-active $LOOP; do sleep 1; done"; then
    # For debugging issue like
    # https://github.com/systemd/systemd/issues/32680#issuecomment-2120959238
    # https://github.com/systemd/systemd/issues/32680#issuecomment-2122074805
    udevadm info "$LOOP"
    udevadm info --attribute-walk "$LOOP"
    cat /sys/"$(udevadm info --query property --property DEVPATH --value "$LOOP")"/loop/backing_file || :
    false
fi
# Mount it and check the UID/GID
[[ "$(stat -c "%U:%G" "$WORK_DIR/mnt")" == "root:root" ]]
systemd-mount --owner=testuser "$LOOP" "$WORK_DIR/mnt"
systemctl status "$WORK_DIR/mnt"
[[ "$(stat -c "%U:%G" "$WORK_DIR/mnt")" == "testuser:testuser" ]]
touch "$WORK_DIR/mnt/hello"
[[ "$(stat -c "%U:%G" "$WORK_DIR/mnt/hello")" == "testuser:testuser" ]]
systemd-umount LABEL=owner-vfat

# Make sure that graceful mount options work
GRACEFULTEST="/tmp/graceful/$RANDOM"
systemd-mount --tmpfs --options="x-systemd.graceful-option=idefinitelydontexist,x-systemd.graceful-option=nr_inodes=4711,x-systemd.graceful-option=idonexisteither" "$GRACEFULTEST"
findmnt -n -o options "$GRACEFULTEST"
findmnt -n -o options "$GRACEFULTEST" | grep nr_inodes=4711 >/dev/null
umount "$GRACEFULTEST"
