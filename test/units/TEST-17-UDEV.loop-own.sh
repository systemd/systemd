#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2317
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() (
    set +e

    [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"
)

trap at_exit EXIT

TMPDIR="$(mktemp -d)"
truncate -s 16M "$TMPDIR"/foo.raw
mkfs.ext4 "$TMPDIR"/foo.raw

D="$(systemd-dissect --attach --loop-ref=schlumpf "$TMPDIR"/foo.raw)"

udevadm wait --timeout=30 --settle /dev/disk/by-loop-ref/schlumpf

SAVED_GROUP="$(stat -c "%g" "$D")"
SAVED_MODE="$(stat -c "%a" "$D")"

chmod 705 "$D"
chown root:65534 "$D"

test "$(stat -c "%g %a" "$D")" = "65534 705"

losetup -d "$D"

for _ in {0..4}; do
    udevadm settle --timeout=5

    if [[ "$(stat -c "%g" "$D")" = "$SAVED_GROUP" && "$(stat -c "%a" "$D")" = "$SAVED_MODE" ]] ; then
        exit 0
    fi

    sleep 1
done

exit 1
