#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

TEST_BTRFS=/usr/lib/systemd/tests/unit-tests/manual/test-btrfs-physical-offset

SWAPFILE=/var/tmp/swapfile

btrfs filesystem mkswapfile -s 10m "$SWAPFILE"
sync -f "$SWAPFILE"

offset_btrfs_progs="$(btrfs inspect-internal map-swapfile -r "$SWAPFILE")"
echo "btrfs-progs: $offset_btrfs_progs"

offset_btrfs_util="$("$TEST_BTRFS" "$SWAPFILE")"
echo "btrfs-util: $offset_btrfs_util"

(( offset_btrfs_progs == offset_btrfs_util ))

rm -f "$SWAPFILE"

touch /testok
