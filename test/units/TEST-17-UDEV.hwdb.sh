#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-hwdb >/dev/null; then
    echo "systemd-hwdb not found, skipping."
    exit 77
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() (
    set +e

    [[ -d "$ROOTFS" ]] && rm -rf "$ROOTFS"
)
trap at_exit EXIT

ROOTFS="$(mktemp -d -t test-17-udev-hwdb.XXXX)"
HWDB=$ROOTFS/usr/lib/udev/hwdb.d

mkdir -p "$HWDB"
cat >"$HWDB/99-test.hwdb" <<EOF
scsi:*
  ID_TEST=test
EOF

systemd-hwdb update --root "$ROOTFS" --usr

# check the rootfs path does not appear in hwdb.bin
run_and_grep -n "$ROOTFS" strings "$ROOTFS/usr/lib/udev/hwdb.bin"
# check the path in the rootfs does appear in hwdb.bin
run_and_grep 99-test.hwdb strings "$ROOTFS/usr/lib/udev/hwdb.bin"

# '#' starts a comment, "\#" is a literal '#'
cat >"$HWDB/99-comment.hwdb" <<EOF
usb:v1234p5678*  # comment after a match
 ID_MODEL_FROM_DATABASE=SB200 OHCI USB Controller \#1
 ID_TEST_BACKSLASH=CD\RW
 ID_TEST_COMMENT=value # comment after a property
 ID_TEST_ESCAPED=a\#b\# # comment after escaped '#'
 ID_TEST_NO_SPACE=value# comment without a space
EOF

# Syntax warnings do not make --strict fail, so check that none are printed
assert_eq "$(SYSTEMD_LOG_LEVEL=info systemd-hwdb update --root "$ROOTFS" --usr --strict 2>&1 >/dev/null)" ""
assert_eq "$(systemd-hwdb query --root "$ROOTFS" usb:v1234p5678)" \
          "ID_MODEL_FROM_DATABASE=SB200 OHCI USB Controller #1
ID_TEST_BACKSLASH=CD\RW
ID_TEST_COMMENT=value
ID_TEST_ESCAPED=a#b#
ID_TEST_NO_SPACE=value"
