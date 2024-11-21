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
systemd-umount "$WORK_DIR/mnt/foo"
test -d "$WORK_DIR/mnt/foo/bar"
test ! -e "$WORK_DIR/mnt/foo/baz"

# overlay
systemd-mount --type=overlay --options="lowerdir=/etc,upperdir=$WORK_DIR/upper,workdir=$WORK_DIR/work" /etc "$WORK_DIR/overlay"
touch "$WORK_DIR/overlay/foo"
test -e "$WORK_DIR/upper/foo"
systemd-umount "$WORK_DIR/overlay"
