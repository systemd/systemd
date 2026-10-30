#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# A job that finishes after a daemon-reexec, but before the API bus is set up again (see bus_init_api()),
# used to send JobRemoved before we owned our name on the bus again, so bus clients waiting for the job never
# got it.

unit=TEST-07-PID1-reexec-job-removed.service
go=/run/TEST-07-PID1-reexec-job-removed-go
DBUS_CGROUP=
client=

at_exit() {
    if [[ -n "$DBUS_CGROUP" ]]; then
        echo 0 >"$DBUS_CGROUP/cgroup.freeze"
    fi
    if [[ -n "$client" ]]; then
        kill "$client" 2>/dev/null || :
    fi
    systemctl stop "$unit" 2>/dev/null || :
    rm -f "/run/systemd/system/$unit" "$go"
    systemctl daemon-reload
}

trap at_exit EXIT

cat >"/run/systemd/system/$unit" <<EOF
[Service]
Type=oneshot
ExecStart=bash -c 'until [[ -e $go ]]; do sleep .1; done'
EOF
systemctl daemon-reload

# This goes through the bus daemon, and waits for JobRemoved.
SYSTEMCTL_FORCE_BUS=1 systemctl start "$unit" &
client=$!
timeout 30 bash -c "until systemctl list-jobs --no-legend $unit | grep -F running >/dev/null; do sleep .2; done"
cgroup="/sys/fs/cgroup$(systemctl show -P ControlGroup "$unit")"

# Freeze the bus daemon, so that the reexecuted manager can't set up the API bus yet. "systemctl freeze" goes
# through the bus daemon itself.
DBUS_CGROUP="/sys/fs/cgroup$(systemctl show -P ControlGroup dbus.service)"
echo 1 >"$DBUS_CGROUP/cgroup.freeze"
timeout 10 bash -c "until grep -Fx 'frozen 1' $DBUS_CGROUP/cgroup.events >/dev/null; do sleep .1; done"

cursor="$(journalctl -q -n 0 --show-cursor | awk '{ print $3 }')"
systemctl daemon-reexec &
reexec=$!

# Only let the job finish once the old manager is done, so that it's up to the new one to send JobRemoved.
timeout 30 bash -c "until journalctl -q --after-cursor='$cursor' _PID=1 MESSAGE=Reexecuting. | grep . >/dev/null; do sleep .1; done"
touch "$go"
timeout 30 bash -c "until [[ ! -e $cgroup/cgroup.events ]] || grep -Fx 'populated 0' $cgroup/cgroup.events >/dev/null; do sleep .1; done"

echo 0 >"$DBUS_CGROUP/cgroup.freeze"
DBUS_CGROUP=
wait "$reexec"

timeout 30 bash -c "while kill -0 $client 2>/dev/null; do sleep .2; done"
wait "$client"
client=
