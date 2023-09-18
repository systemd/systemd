#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

if [[ "$1" ]]; then
    TEST_BTRFS="$1"
else
    TEST_BTRFS="$(basename "$0")"/manual/test-btrfs-physical-offset
fi

[[ "$(stat -f -c %T /var/tmp/)" = "btrfs" ]] || exit 0

SWAPFILE=/var/tmp/swapfile

btrfs filesystem mkswapfile -s 1m "$SWAPFILE"

sync -f "$SWAPFILE"
sleep 1

offset_btrfs_progs="$(btrfs inspect-internal map-swapfile -r "$SWAPFILE")"
offset_btrfs_util="$("$TEST_BTRFS" "$SWAPFILE")"

(( offset_btrfs_progs == offset_btrfs_util )) || exit 1
