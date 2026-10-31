#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# A daemon-reload while the API bus is connected but not set up yet (see bus_init_api()) loads BusName=
# units again. Their NameOwnerChanged matches are installed by bus_setup_api(), which used to log an error
# for every one of them since the reload had already installed them.

holder=/usr/lib/systemd/tests/unit-tests/manual/test-dbus-name-holder
name=systemd.test.WatchBusName
unit=TEST-07-PID1-watch-bus-name.service
marker=/run/TEST-07-PID1-watch-bus-name-marker
release=/run/TEST-07-PID1-watch-bus-name-release
DBUS_CGROUP=

at_exit() {
    if [[ -n "$DBUS_CGROUP" ]]; then
        echo 0 >"$DBUS_CGROUP/cgroup.freeze"
    fi
    systemctl stop "$unit" 2>/dev/null || :
    rm -f "$marker" "$release"
}

trap at_exit EXIT

reload_count() {
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}' | jq -r '.runtime.ReloadCount'
}

export -f reload_count

systemd-run --unit="$unit" -p Type=dbus -p BusName="$name" -p Restart=no "$holder" "$name" "$marker" "$release"
assert_eq "$(systemctl show -P SubState "$unit")" running

cursor="$(journalctl -q -n 0 --show-cursor | awk '{ print $3 }')"

# Freeze the bus daemon, so that the reexecuted manager is still waiting for the GetId() reply of its new
# API bus connection when the reload happens. "systemctl freeze" goes through the bus daemon itself.
DBUS_CGROUP="/sys/fs/cgroup$(systemctl show -P ControlGroup dbus.service)"
echo 1 >"$DBUS_CGROUP/cgroup.freeze"
timeout 10 bash -c "until grep -Fx 'frozen 1' $DBUS_CGROUP/cgroup.events >/dev/null; do sleep .1; done"
systemctl daemon-reexec

# The reply may only come once the bus is set up, so just wait for the reload itself.
count="$(reload_count)"
systemctl daemon-reload &
reload=$!
timeout 30 bash -c "until (( \$(reload_count) > $count )); do sleep .1; done"

echo 0 >"$DBUS_CGROUP/cgroup.freeze"
DBUS_CGROUP=
wait "$reload"

# The manager only requests its name in bus_setup_api(), after installing the matches.
timeout 30 bash -c 'until busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Peer Ping >/dev/null 2>&1; do sleep .2; done'

journalctl --sync
(! journalctl -q --after-cursor="$cursor" -p err | grep -F "Failed to subscribe to NameOwnerChanged" >/dev/null)

# And the match still works: dropping the name on a live connection stops the service right away.
touch "$release"
timeout 30 bash -c "until [[ \$(systemctl show -P ActiveState $unit) == inactive ]]; do sleep .2; done"
