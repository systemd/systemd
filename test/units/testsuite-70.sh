#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

LONGPATH="$(printf "/$(printf "x%0.s" {1..255})%0.s" {1..7})"
LONGMNT="$(systemd-escape --suffix=mount --path $LONGPATH)"
TS="$(date '+%H:%M:%S')"

mkdir -p $LONGPATH
mount -t tmpfs tmpfs $LONGPATH
systemctl daemon-reload

# Check that unit is active(mounted)
systemctl --no-pager show -p SubState --value $LONGPATH | grep -q mounted

# Check that relevant part of journal doesn't contain any errors related to unit
[ "$(journalctl -b --since=$TS --priority=err | grep -c "$LONGMNT")" = "0" ]

# Check that we can successfully stop the mount unit
systemctl stop "$LONGPATH"

systemd-analyze log-level info
echo OK >/testok

exit 0
