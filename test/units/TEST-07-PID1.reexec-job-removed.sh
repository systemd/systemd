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
monitor_log=/run/TEST-07-PID1-reexec-job-removed-monitor.log
monitor_unit=
dbus_cgroup=
client=

at_exit() {
    if [[ -n "$dbus_cgroup" ]]; then
        echo 0 >"$dbus_cgroup/cgroup.freeze"
    fi
    if [[ -n "$client" ]]; then
        kill "$client" 2>/dev/null || :
    fi
    if [[ -n "$monitor_unit" ]]; then
        systemctl stop "$monitor_unit" 2>/dev/null || :
    fi
    systemctl stop "$unit" 2>/dev/null || :
    rm -f "/run/systemd/system/$unit" "$go" "$monitor_log"
    systemctl daemon-reload
}

trap at_exit EXIT

# Freeze the bus daemon, so that the reexecuted manager can't set up the API bus yet. "systemctl freeze" goes
# through the bus daemon itself.
bus_freeze() {
    dbus_cgroup="/sys/fs/cgroup$(systemctl show -P ControlGroup dbus.service)"
    echo 1 >"$dbus_cgroup/cgroup.freeze"
    timeout 10 bash -c "until grep -Fx 'frozen 1' $dbus_cgroup/cgroup.events >/dev/null; do sleep .1; done"
}

bus_thaw() {
    echo 0 >"$dbus_cgroup/cgroup.freeze"
    dbus_cgroup=
}

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

bus_freeze
cursor="$(journalctl -q -n 0 --show-cursor | awk '{ print $3 }')"
systemctl daemon-reexec &
reexec=$!

# Only let the job finish once the old manager is done, so that it's up to the new one to send JobRemoved.
# We can't count on the new one answering us while the bus daemon is frozen, so watch the cgroup instead.
# The new manager handles the exit before anything that comes in on the API bus.
timeout 30 bash -c "until journalctl -q --after-cursor='$cursor' _PID=1 MESSAGE=Reexecuting. | grep . >/dev/null; do sleep .1; done"
touch "$go"
timeout 30 bash -c "until [[ ! -e $cgroup/cgroup.events ]] || grep -Fx 'populated 0' $cgroup/cgroup.events >/dev/null; do sleep .1; done"

bus_thaw
wait "$reexec"

timeout 30 bash -c "while kill -0 $client 2>/dev/null; do sleep .2; done"
wait "$client"
client=

# Subscribers that are yet to be tracked again have to get the signal too, even if the manager is reexecuted
# once more before the API bus is set up. logind is subscribed, and busctl shows us what goes out.
rm -f "$go"
systemctl start systemd-logind.service
monitor_unit=TEST-07-PID1-reexec-job-removed-monitor.service
systemd-run --unit="$monitor_unit" --service-type=notify --quiet \
    --property=StandardOutput=file:"$monitor_log" \
    busctl monitor \
        --match="type=signal,path=/org/freedesktop/systemd1,interface=org.freedesktop.systemd1.Manager,member=JobRemoved"

# These signals only go out on the API bus if somebody is subscribed, so wait until logind is.
timeout 30 bash -c "until grep -F Member=JobRemoved $monitor_log >/dev/null; do systemd-run --quiet true; sleep 1; done"

# This doesn't go through the bus daemon, so nobody is tracked for the job.
systemctl start --no-block "$unit"
timeout 30 bash -c "until systemctl list-jobs --no-legend $unit | grep -F running >/dev/null; do sleep .2; done"

bus_freeze
systemctl daemon-reexec
touch "$go"
timeout 30 bash -c "until [[ \"\$(systemctl is-active $unit)\" == inactive ]]; do sleep .1; done"
systemctl daemon-reexec
bus_thaw

timeout 30 bash -c "until grep -F '\"$unit\"' $monitor_log >/dev/null; do sleep .2; done"
