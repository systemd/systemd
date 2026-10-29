#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# After a daemon-reexec, nothing goes out on the API bus until the bus daemon has answered GetId() (see
# bus_init_api()). JobRemoved for a job that finishes before that, and the change signal of its unit, used to
# be lost, so bus clients waiting for the job never returned.

unit=TEST-07-PID1-reexec-job-removed.service
unit_path=/org/freedesktop/systemd1/unit/TEST_2d07_2dPID1_2dreexec_2djob_2dremoved_2eservice
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

wait_for_job() {
    timeout 30 bash -c "until systemctl list-jobs --no-legend $unit | grep -F running >/dev/null; do sleep .2; done"
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
wait_for_job

# Let the job finish while the reexecuted manager is waiting for the bus daemon, and reexecute once more
# before it answers, so that the signal has to be passed on to the next manager too.
bus_freeze
timeout 30 systemctl daemon-reexec
touch "$go"
timeout 30 bash -c "until [[ \"\$(systemctl is-active $unit)\" == inactive ]]; do sleep .1; done"
timeout 30 systemctl daemon-reexec
bus_thaw

timeout 30 bash -c "while kill -0 $client 2>/dev/null; do sleep .2; done"
wait "$client"
client=

# Subscribers that are yet to be tracked again have to get the signal too, and the change of the unit before
# it. logind is subscribed, and busctl shows us what goes out.
rm -f "$go"
systemctl start systemd-logind.service
monitor_unit=TEST-07-PID1-reexec-job-removed-monitor.service
systemd-run --unit="$monitor_unit" --service-type=notify --quiet \
    --property=StandardOutput=file:"$monitor_log" \
    busctl monitor --json=short \
        --match="type=signal,path=/org/freedesktop/systemd1,interface=org.freedesktop.systemd1.Manager,member=JobRemoved" \
        --match="type=signal,path=$unit_path,interface=org.freedesktop.DBus.Properties,member=PropertiesChanged"

# These signals only go out on the API bus if somebody is subscribed, so wait until logind is.
timeout 30 bash -c "until grep -F '\"member\":\"JobRemoved\"' $monitor_log >/dev/null; do systemd-run --quiet true; sleep 1; done"

# This doesn't go through the bus daemon, so nobody is tracked for the job.
systemctl start --no-block "$unit"
wait_for_job

bus_freeze
timeout 30 systemctl daemon-reexec
cursor="$(journalctl -q -n 0 --show-cursor | awk '{ print $3 }')"
touch "$go"
# Units are queued for their change signal anyway as long as somebody is connected to the private bus, so
# don't ask the manager whether the job is done this time.
timeout 30 bash -c "until journalctl -q --after-cursor='$cursor' _PID=1 UNIT=$unit JOB_RESULT=done | grep . >/dev/null; do sleep .1; done"
bus_thaw

timeout 30 bash -c "until grep -F '\"$unit\",\"done\"]' $monitor_log >/dev/null; do sleep .2; done"
# The reexecuted manager has to send the change of the unit before JobRemoved.
jq -se --arg unit "$unit" '
    (map(.member == "JobRemoved" and .payload.data[2] == $unit) | index(true)) as $removed |
    .[$removed].sender as $manager |
    .[:$removed] | any(
        .sender == $manager and .member == "PropertiesChanged" and
        .payload.data[1].ActiveState.data == "inactive")' "$monitor_log"
