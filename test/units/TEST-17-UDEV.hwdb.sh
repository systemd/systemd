#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-hwdb >/dev/null; then
    echo "systemd-hwdb not found, skipping."
    exit 0
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() (
    [[ -d "$ROOTFS" ]] && rm -rf "$ROOTFS"
)
trap at_exit EXIT

ROOTFS="$(mktemp -d -t test-17-udev-hwdb.XXXX)"
HWDB=$ROOTFS/usr/lib/udev/hwdb.d

mkdir --parents "$HWDB"
cat >"$HWDB/99-test.hwdb" <<EOF
scsi:*
  ID_TEST=test
EOF

systemd-hwdb update --root "$ROOTFS" --usr

# check the rootfs path does not appear in hwdb.bin
run_and_grep -n "$ROOTFS" strings "$ROOTFS/usr/lib/udev/hwdb.bin"
# check the path in the rootfs does appear in hwdb.bin
run_and_grep 99-test.hwdb strings "$ROOTFS/usr/lib/udev/hwdb.bin"
