#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that Reload() calls are answered, and do not crash the manager, while the API bus is still
# being set up.
#
# After a daemon-reexec, the manager sets up the API bus only once the asynchronous GetId reply has
# been processed (see bus_init_api()). Freezing the bus daemon keeps that reply from arriving. The
# reload replies go to the caller's own connection and must not be held back meanwhile: they used to
# be, and a second Reload() arriving while the first reply was still pending tripped an assertion in
# method_reload()/vl_method_reload() and froze PID 1. This happened at boot when several units ran
# "systemctl daemon-reload" while the bus daemon was still starting.

DBUS_CGROUP=

bus_signal() {
    local sig=${1:?}

    [[ -n "$DBUS_CGROUP" ]] || return 0
    # shellcheck disable=SC2046
    kill "-$sig" $(cat "$DBUS_CGROUP/cgroup.procs") || :
}

at_exit() {
    bus_signal CONT
}

trap at_exit EXIT

reload_dbus() {
    timeout 30 systemctl daemon-reload
}

reload_varlink() {
    timeout 30 varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reload '{}'
}

systemctl start dbus.service
busctl status org.freedesktop.systemd1 >/dev/null

DBUS_CGROUP="/sys/fs/cgroup$(systemctl show -P ControlGroup dbus.service)"
grep -q . "$DBUS_CGROUP/cgroup.procs"

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

# And concurrent ones from both transports.
pids=()
for _ in {1..4}; do
    reload_dbus &
    pids+=("$!")
    reload_varlink &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid"
done

bus_signal CONT
DBUS_CGROUP=

# The manager finishes setting up the API bus and is still fully functional.
timeout 30 bash -c 'until busctl status org.freedesktop.systemd1 >/dev/null 2>&1; do sleep .5; done'
systemctl daemon-reload
(! journalctl -b -q --no-pager _PID=1 --grep 'Caught <ABRT>|Freezing execution')
