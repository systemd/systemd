#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

IFNAME=test-udev-aaa
ip link add "$IFNAME" type dummy
IFINDEX=$(ip -json link show "$IFNAME" | jq '.[].ifindex')
udevadm wait --timeout=10 "/sys/class/net/$IFNAME"
# Check if the database file is created.
[[ -e "/run/udev/data/n$IFINDEX" ]]

ip link del "$IFNAME"
udevadm wait --timeout=10 --removed --settle "/sys/class/net/$IFNAME"
# CHeck if the database file is removed.
[[ ! -e "/run/udev/data/n$IFINDEX" ]]

exit 0
