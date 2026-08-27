#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Verify that PID 1 emits a PropertiesChanged signal when SystemState changes,
# but not when another property changes while SystemState remains unchanged.

MONITOR_LOG=/run/TEST-95-SYSTEM-STATE.log
MONITOR_UNIT=
FAILED_UNITS=()

at_exit() {
    if [[ -n "$MONITOR_UNIT" ]]; then
        systemctl stop "$MONITOR_UNIT" 2>/dev/null || :
    fi
    for unit in "${FAILED_UNITS[@]}"; do
        systemctl reset-failed "$unit" 2>/dev/null || :
    done
    rm -f "$MONITOR_LOG"
}

trap at_exit EXIT

start_monitor() {
    local interface=${1:?}
    local member=${2:?}
    local match="type=signal,path=/org/freedesktop/systemd1,"

    # Use a fresh unit name every time, as a previous instance might not have
    # been garbage-collected yet. busctl monitor sends READY=1 once the monitor
    # is installed, so Type=notify guarantees that it is ready before
    # systemd-run returns.
    match+="interface=$interface,member=$member"
    MONITOR_UNIT="busctl-monitor-$RANDOM.service"
    rm -f "$MONITOR_LOG"
    systemd-run --unit="$MONITOR_UNIT" --service-type=notify --quiet \
        --property=StandardOutput=file:"$MONITOR_LOG" \
        busctl monitor --match="$match"
}

stop_monitor() {
    systemctl stop "$MONITOR_UNIT"
    MONITOR_UNIT=
}

start_failing_service() {
    local unit="false-$RANDOM.service"

    FAILED_UNITS+=("$unit")
    assert_rc 1 systemd-run --unit="$unit" --quiet --wait /bin/false
}

# Complete this test unit's start job so PID 1 can finish booting and enter the
# running state while the test process continues.
systemd-notify --ready
timeout 30 systemctl is-system-running --wait --quiet

# PID 1 sends manager signals on the API bus only when a client has called
# Manager.Subscribe(). Start logind to keep such a subscription active. Since
# logind subscribes asynchronously, wait until PID 1 sends a Reloading signal.
systemctl start systemd-logind.service
start_monitor org.freedesktop.systemd1.Manager Reloading
timeout 30 bash -ec \
    "until grep -F 'BOOLEAN true;' \"$MONITOR_LOG\" >/dev/null; do systemctl daemon-reload; sleep 1; done"
stop_monitor

start_monitor org.freedesktop.DBus.Properties PropertiesChanged
start_failing_service

timeout 30 bash -ec "until grep -F 'STRING \"NFailedUnits\";' \"$MONITOR_LOG\" >/dev/null; do sleep .5; done"
timeout 30 bash -ec "until grep -F 'STRING \"SystemState\";' \"$MONITOR_LOG\" >/dev/null; do sleep .5; done"
grep -F 'STRING "degraded";' "$MONITOR_LOG" >/dev/null

# NFailedUnits changes again, but SystemState remains degraded and must not be emitted again.
start_failing_service
timeout 30 bash -ec \
    "until [[ \$(grep -Fc 'STRING \"NFailedUnits\";' \"$MONITOR_LOG\") -ge 2 ]]; do sleep .5; done"

# Allow any incorrect follow-up SystemState signal to reach the monitor.
sleep 1
stop_monitor

assert_eq "$(grep -Fc 'STRING "SystemState";' "$MONITOR_LOG")" 1
assert_eq "$(grep -Fc 'STRING "degraded";' "$MONITOR_LOG")" 1

touch /testok
