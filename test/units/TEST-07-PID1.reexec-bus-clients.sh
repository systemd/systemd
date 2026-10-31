#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# After a daemon-reexec, the bus clients of units and jobs are only tracked again once the API bus is set
# up (see bus_init_api()). Looking them up before that blocks until the bus daemon answers, which used to
# keep the reexec from finishing for up to BUS_AUTH_TIMEOUT when the bus daemon was slow.

unit=TEST-07-PID1-reexec-bus-clients.service
device="$(systemd-escape --path --suffix=device /dev/testreexecbusclients)"
gone="$(systemd-escape --path --suffix=device /dev/testreexecbusclientsgone)"
DBUS_CGROUP=
pids=()

at_exit() {
    if [[ -n "$DBUS_CGROUP" ]]; then
        echo 0 >"$DBUS_CGROUP/cgroup.freeze"
    fi
    kill "${pids[@]}" 2>/dev/null || :
    systemctl stop "$unit" 2>/dev/null || :
}

trap at_exit EXIT

has_job() {
    [[ -n "$(systemctl list-jobs --no-legend "${1:?}")" ]]
}

reload_count() {
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}' | jq -r '.runtime.ReloadCount'
}

export -f has_job reload_count

# All of these go through the bus daemon and stay connected. systemd-run --wait references the unit, and
# systemctl waits for the start job of a device that never shows up, which nothing but the client keeps
# from being garbage collected.
systemd-run --unit="$unit" --wait --collect -p Type=oneshot sleep infinity &
pids+=("$!")
SYSTEMCTL_FORCE_BUS=1 systemctl start "$device" &
device_client=$!
pids+=("$device_client")
SYSTEMCTL_FORCE_BUS=1 systemctl start "$gone" &
gone_client=$!
pids+=("$gone_client")

timeout 30 bash -c "until [[ -n \$(systemctl show -P Refs $unit) ]]; do sleep .2; done"
timeout 30 bash -c "until has_job '$device' && has_job '$gone'; do sleep .2; done"
refs="$(systemctl show -P Refs "$unit")"

# Freeze the bus daemon, so that the reexecuted manager can't get past authenticating its new API bus
# connection. "systemctl freeze" goes through the bus daemon itself.
DBUS_CGROUP="/sys/fs/cgroup$(systemctl show -P ControlGroup dbus.service)"
echo 1 >"$DBUS_CGROUP/cgroup.freeze"
timeout 10 bash -c "until grep -Fx 'frozen 1' $DBUS_CGROUP/cgroup.events >/dev/null; do sleep .1; done"
timeout 30 systemctl daemon-reexec
has_job "$device"

# Until then the names have to survive a reload too. Its reply may only come once the bus is set up.
count="$(reload_count)"
systemctl daemon-reload &
reload=$!
timeout 30 bash -c "until (( \$(reload_count) > $count )); do sleep .1; done"
has_job "$device"
has_job "$gone"

# A client that goes away in the meantime shouldn't keep its job around once the bus is set up.
kill "$gone_client"

echo 0 >"$DBUS_CGROUP/cgroup.freeze"
DBUS_CGROUP=
wait "$reload"

# The manager requests its name in bus_setup_api(), so once that's done, the clients are tracked again.
timeout 30 bash -c 'until busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Peer Ping >/dev/null 2>&1; do sleep .2; done'
# systemd-run calls Ref() again on the same connection if it noticed the manager going away, so the name
# may be listed twice.
assert_eq "$(systemctl show -P Refs "$unit" | tr ' ' '\n' | sort -u)" "$refs"
has_job "$device"
timeout 30 bash -c "until ! has_job '$gone'; do sleep .2; done"

kill "$device_client"
timeout 30 bash -c "until ! has_job '$device'; do sleep .2; done"
