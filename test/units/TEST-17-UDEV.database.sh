#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

IFNAME=test-udev-aaa
UNIT_ADD="TEST-17-UDEV-database-wait-add.service"
UNIT_DEL="TEST-17-UDEV-database-wait-del.service"

# shellcheck disable=SC2329
at_exit() {
    set +e

    systemctl stop "$UNIT_ADD" "$UNIT_DEL"
    systemctl reset-failed "$UNIT_ADD" "$UNIT_DEL"
    ip link del "$IFNAME"
}
trap at_exit EXIT

start_wait() {
    local unit="$1"
    shift

    systemd-run --unit="$unit" \
                --service-type=notify \
                udevadm wait --timeout=10 --notify "$@"
}

# Start watching before the interface is created, so that the creation cannot be missed.
start_wait "$UNIT_ADD" "/sys/class/net/$IFNAME"
ip link add "$IFNAME" type dummy
IFINDEX=$(ip -json link show "$IFNAME" | jq '.[].ifindex')
systemctl wait --timeout=30 "$UNIT_ADD"
# Check if the database file is created.
[[ -e "/run/udev/data/n$IFINDEX" ]]

# Start watching before the interface is removed, so that the removal cannot be missed.
start_wait "$UNIT_DEL" --removed --settle "/sys/class/net/$IFNAME"
ip link del "$IFNAME"
systemctl wait --timeout=30 "$UNIT_DEL"
# Check if the database file is removed.
[[ ! -e "/run/udev/data/n$IFINDEX" ]]

unshare --mount --propagation private bash -eux <<'EOF'
mount -t tmpfs tmpfs /run/udev
mkdir -p /run/udev/links/test /run/udev/tags/test
touch /run/udev/links/test/stale /run/udev/tags/test/stale

udevadm info --cleanup-db

[[ ! -e /run/udev/links/test ]]
[[ ! -e /run/udev/tags/test ]]
EOF

exit 0
