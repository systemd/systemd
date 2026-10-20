#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that Reload() calls are answered, and do not crash the manager, while the API bus is still
# being set up.
#
# After a daemon-reexec, the manager sets up the API bus only once the asynchronous GetId reply has
# been processed (see bus_init_api()). Stopping the bus daemon keeps that reply from arriving. The
# reload replies go to the caller's own connection and must not be held back meanwhile: they used to
# be, and a second Reload() arriving while the first reply was still pending tripped an assertion in
# method_reload()/vl_method_reload_manager() and froze PID 1. This happened at boot when several
# units ran "systemctl daemon-reload" while the bus daemon was still starting.

MONITOR_LOG=/run/TEST-07-PID1-reload-api-bus-setup.log
MONITOR_UNIT=
DBUS_CGROUP=

# Stop and continue the bus daemon with signals rather than "systemctl freeze/thaw": those talk to
# the manager through the bus daemon itself, so they cannot be used on it.
bus_signal() {
    local sig=${1:?}

    [[ -n "$DBUS_CGROUP" ]] || return 0
    # shellcheck disable=SC2046
    kill "-$sig" $(cat "$DBUS_CGROUP/cgroup.procs") || :
}

at_exit() {
    bus_signal CONT
    if [[ -n "$MONITOR_UNIT" ]]; then
        systemctl stop "$MONITOR_UNIT" 2>/dev/null || :
    fi
    rm -f "$MONITOR_LOG"
}

trap at_exit EXIT

start_monitor() {
    if [[ -n "$MONITOR_UNIT" ]]; then
        systemctl stop "$MONITOR_UNIT"
    fi
    rm -f "$MONITOR_LOG"
    MONITOR_UNIT="busctl-monitor-$RANDOM.service"
    systemd-run --unit="$MONITOR_UNIT" --service-type=notify --quiet \
        --property=StandardOutput=file:"$MONITOR_LOG" \
        busctl monitor \
            --match="type=signal,path=/org/freedesktop/systemd1,interface=org.freedesktop.systemd1.Manager,member=Reloading"
}

reload_dbus() {
    timeout "${1:-30}" systemctl daemon-reload
}

reload_varlink() {
    timeout "${1:-30}" varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reload '{}'
}

systemctl start dbus.service
busctl status org.freedesktop.systemd1 >/dev/null

# The manager sends the Reloading signal on the API bus only if it has at least one subscriber (see
# TEST-07-PID1.reloading-signal.sh). logind subscribes asynchronously, so reload until it shows up.
systemctl start systemd-logind.service
start_monitor
timeout 30 bash -ec "until grep -F 'BOOLEAN true;' $MONITOR_LOG >/dev/null; do systemctl daemon-reload; sleep 1; done"

# Start over with an empty log, so that a Reloading(false) seen below was sent after the bus daemon
# continued.
start_monitor
DBUS_CGROUP="/sys/fs/cgroup$(systemctl show -P ControlGroup dbus.service)"
bus_signal STOP

# The reexecuted manager connects to the frozen bus and waits for the GetId reply.
systemctl daemon-reexec

# Reloads over the private socket and Varlink must complete while the API bus is not set up.
reload_dbus
reload_dbus
reload_varlink
reload_varlink
reload_dbus
reload_varlink

# And concurrent ones from both transports. The manager handles them one after another, so give
# the last one enough time to wait for all of them.
pids=()
for _ in {1..4}; do
    reload_dbus 120 &
    pids+=("$!")
    reload_varlink 120 &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid"
done

bus_signal CONT
DBUS_CGROUP=

# The manager finishes setting up the API bus, sends the Reloading(false) signal it held back, and is
# still fully functional.
timeout 30 bash -c 'until busctl status org.freedesktop.systemd1 >/dev/null 2>&1; do sleep .5; done'
timeout 30 bash -ec "until grep -F 'BOOLEAN false;' $MONITOR_LOG >/dev/null; do sleep .5; done"
systemctl daemon-reload
(! journalctl -b -q --no-pager _PID=1 --grep 'Caught <ABRT>|Freezing execution')
