#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

IFNAME=test-udev-aaa
UNIT_ADD="TEST-17-UDEV-database-wait-add.service"
UNIT_DEL="TEST-17-UDEV-database-wait-del.service"
WORKDIR="$(mktemp -d)"

# shellcheck disable=SC2329
at_exit() {
    set +e

    systemctl stop "$UNIT_ADD" "$UNIT_DEL"
    systemctl reset-failed "$UNIT_ADD" "$UNIT_DEL"
    ip link del "$IFNAME"
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

cat >"$WORKDIR/marker.sh" <<'EOF'
#!/usr/bin/env bash
[[ "$SERVICE_RESULT" == success ]] || exit 0
touch "$1"
EOF
chmod +x "$WORKDIR/marker.sh"

start_wait() {
    local unit="$1"
    shift

    systemd-run --unit="$unit" \
                --service-type=notify \
                --property="ExecStopPost=$WORKDIR/marker.sh $WORKDIR/$unit" \
                udevadm wait --timeout=10 --notify "$@"
}

finish_wait() {
    local unit="$1"

    # shellcheck disable=SC2016
    timeout 30 bash -c 'until [[ -e "$1" ]] || systemctl is-failed --quiet "$2"; do sleep 0.1; done' _ "$WORKDIR/$unit" "$unit"

    [[ -e "$WORKDIR/$unit" ]]
}

# Start watching before the interface is created, so that the creation cannot be missed.
start_wait "$UNIT_ADD" "/sys/class/net/$IFNAME"
ip link add "$IFNAME" type dummy
IFINDEX=$(ip -json link show "$IFNAME" | jq '.[].ifindex')
finish_wait "$UNIT_ADD"
# Check if the database file is created.
[[ -e "/run/udev/data/n$IFINDEX" ]]

# Start watching before the interface is removed, so that the removal cannot be missed.
start_wait "$UNIT_DEL" --removed --settle "/sys/class/net/$IFNAME"
ip link del "$IFNAME"
finish_wait "$UNIT_DEL"
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
