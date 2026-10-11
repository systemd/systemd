#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that the manager broadcasts the Reloading signal on the API bus,
# both for daemon-reload and, as a one-shot Reloading(false), after a
# daemon-reexec.
#
# The reexec case is a regression test: API bus subscribers from the
# pre-reexec instance are coldplugged only once the asynchronous GetId
# reply is processed (see bus_init_api()). The D-Bus queue dispatch must
# not consume send_reloading_done before that happened, otherwise the
# Reloading(false) signal is lost and clients waiting for it to detect the
# end of the reexec time out.

MONITOR_LOG=/run/TEST-07-PID1-reloading-signal.log
MONITOR_UNIT=

at_exit() {
    [[ -n "$MONITOR_UNIT" ]] && systemctl stop "$MONITOR_UNIT" 2>/dev/null || :
    rm -f "$MONITOR_LOG"
}

trap at_exit EXIT

start_monitor() {
    # Use a fresh unit name every time, a previous instance might not have
    # been garbage-collected yet. busctl monitor sends READY=1 once the
    # monitor is installed, so with Type=notify the monitor is guaranteed
    # to be running when systemd-run returns.
    MONITOR_UNIT="busctl-monitor-$RANDOM.service"
    systemd-run --unit="$MONITOR_UNIT" --service-type=notify --quiet \
        --property=StandardOutput=file:"$MONITOR_LOG" \
        busctl monitor \
            --match="type=signal,path=/org/freedesktop/systemd1,interface=org.freedesktop.systemd1.Manager,member=Reloading"
}

stop_monitor() {
    systemctl stop "$MONITOR_UNIT"
    MONITOR_UNIT=
    rm -f "$MONITOR_LOG"
}

wait_for_reloading() {
    local value=${1:?}

    timeout 30 bash -ec "until grep -F 'BOOLEAN ${value};' $MONITOR_LOG >/dev/null; do sleep .5; done"
}

# The manager sends the Reloading signal on the API bus only if it has at
# least one subscriber. logind subscribes, and its subscription is carried
# over a daemon-reexec via serialization, so make sure it is running.
systemctl start systemd-logind.service

# logind's Subscribe call is asynchronous, so it may not have been processed
# by the manager yet when logind announces readiness. Keep reloading until
# the signal shows up in the monitor output.
start_monitor
timeout 30 bash -ec "until grep -F 'BOOLEAN true;' $MONITOR_LOG >/dev/null; do systemctl daemon-reload; sleep 1; done"

# A daemon-reload sends Reloading(true) followed by Reloading(false).
wait_for_reloading true
wait_for_reloading false
stop_monitor

# A daemon-reexec must send the one-shot Reloading(false) once the new
# manager instance is up, even though the subscribers of the old instance
# are re-added only after the asynchronous API bus setup finished.
start_monitor
systemctl daemon-reexec
wait_for_reloading false
stop_monitor
