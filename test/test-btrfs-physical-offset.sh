#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

if ! command -v btrfs >/dev/null; then
    echo "Missing btrfs tools, skipping the test"
    exit 77
fi

if [[ "$(stat -f -c %T /var/tmp/)" != "btrfs" ]]; then
    echo "/var/tmp/ not on btrfs, skipping the test"
    exit 77
fi

if [[ "$1" ]]; then
    TEST_BTRFS="$1"
else
    TEST_BTRFS="$(basename "$0")"/manual/test-btrfs-physical-offset
fi

SWAPFILE=/var/tmp/swapfile

btrfs filesystem mkswapfile -s 1m "$SWAPFILE"
sync -f "$SWAPFILE"

offset_btrfs_progs="$(btrfs inspect-internal map-swapfile -r "$SWAPFILE")"
echo "btrfs-progs: $offset_btrfs_progs"

offset_btrfs_util="$("$TEST_BTRFS" "$SWAPFILE")"
echo "btrfs-util: $offset_btrfs_util"

(( offset_btrfs_progs == offset_btrfs_util )) || exit 1
