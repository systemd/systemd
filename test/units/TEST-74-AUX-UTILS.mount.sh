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
systemd-mount --remount=append --options="size=10240k" "$WORK_DIR/mnt/foo"
assert_in "size=10240k" "$(systemctl show "$WORK_DIR/mnt/foo" -P Options)"
assert_in "size=10240k" "$(findmnt -no FS-OPTIONS "$WORK_DIR/mnt/foo")"
systemd-mount --remount=replace --options="ro" "$WORK_DIR/mnt/foo"
assert_in "ro" "$(systemctl show "$WORK_DIR/mnt/foo" -P Options)"
assert_in "ro" "$(findmnt -no FS-OPTIONS "$WORK_DIR/mnt/foo")"
systemd-umount "$WORK_DIR/mnt/foo"
test -d "$WORK_DIR/mnt/foo/bar"
test ! -e "$WORK_DIR/mnt/foo/baz"

# Remount should work for unmanaged mounts too
mkdir -p "$WORK_DIR/mnt/unmanaged"
mount -t tmpfs tmpfs "$WORK_DIR/mnt/unmanaged"
timeout 30 bash -c "until systemctl -q is-active '$WORK_DIR/mnt/unmanaged'; do sleep 1; done"
assert_in "rw" "$(findmnt -no OPTIONS "$WORK_DIR/mnt/unmanaged")"
systemd-mount --remount --options="ro" "$WORK_DIR/mnt/unmanaged"
assert_in "ro" "$(findmnt -no OPTIONS "$WORK_DIR/mnt/unmanaged")"
(! touch "$WORK_DIR/mnt/unmanaged/bogus")
umount "$WORK_DIR/mnt/unmanaged"

# overlay
systemd-mount --type=overlay --options="lowerdir=/etc,upperdir=$WORK_DIR/upper,workdir=$WORK_DIR/work" /etc "$WORK_DIR/overlay"
touch "$WORK_DIR/overlay/foo"
test -e "$WORK_DIR/upper/foo"
systemd-umount "$WORK_DIR/overlay"

# Validate that we cannot mount through a symlink or ..
mkdir "$WORK_DIR"/flurb
ln -s flurb "$WORK_DIR"/knarb
systemd-mount --canonicalize=no --tmpfs "$WORK_DIR"/flurb/shlum
systemd-umount "$WORK_DIR/"/flurb/shlum
(! systemd-mount --canonicalize=no --tmpfs "$WORK_DIR"/knarb/shlum)
systemd-mount --canonicalize=yes --tmpfs "$WORK_DIR"/knarb/shlum
systemd-umount "$WORK_DIR/"/flurb/shlum
(! systemd-mount --canonicalize=no --tmpfs "$WORK_DIR"/flurb/../flurb/shlum)
systemd-mount --canonicalize=yes --tmpfs "$WORK_DIR"/flurb/../flurb/shlum
systemd-umount "$WORK_DIR/"/flurb/shlum

# Validate that we can correctly create dir and reg files inodes if needed
systemd-mount --tmpfs "$WORK_DIR"/flurb/shlum/some/more/dirs
systemd-umount "$WORK_DIR/"/flurb/shlum/some/more/dirs
systemd-mount /bin/ls "$WORK_DIR"/flurb/shlum/some/more/dirs/file -o bind
systemd-umount "$WORK_DIR/"/flurb/shlum/some/more/dirs/file
