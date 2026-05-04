#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that the manager exposes a ReloadCount property that increments on
# every daemon-reload, resets to zero across daemon-reexec (since the count
# is not serialized), and is reachable over D-Bus, Varlink Describe, and the
# io.systemd.Metrics interface (queried via systemd-report).

# systemd-report silently returns empty if the metrics source is missing,
# which would falsely pass the cross-checks below. Assert the socket exists
# so any failure points at the real problem.
test -S /run/systemd/report/io.systemd.Manager

read_count_dbus() {
    busctl -j get-property org.freedesktop.systemd1 \
                           /org/freedesktop/systemd1 \
                           org.freedesktop.systemd1.Manager \
                           ReloadCount | jq -r '.data'
}

read_count_varlink() {
    varlinkctl call /run/systemd/io.systemd.Manager \
                    io.systemd.Manager.Describe '{}' | jq -r '.runtime.ReloadCount'
}

read_count_report() {
    local out
    # Strip the RS separator that jq --seq re-emits on output.
    out=$(/usr/lib/systemd/systemd-report metrics --json=short \
              io.systemd.Manager.ReloadCount \
          | jq --seq -r 'select(.name == "io.systemd.Manager.ReloadCount") | .value' \
          | tr -d '\036')
    [[ -n "$out" ]] || { echo "ReloadCount metric missing from systemd-report output" >&2; return 1; }
    echo "$out"
}

# Sanity: all three transports must agree.
dbus_count=$(read_count_dbus)
varlink_count=$(read_count_varlink)
report_count=$(read_count_report)
(( dbus_count == varlink_count ))
(( dbus_count == report_count ))

# A single reload bumps the counter by one.
before=$(read_count_dbus)
systemctl daemon-reload
(( $(read_count_dbus) == before + 1 ))

# Multiple reloads accumulate.
systemctl daemon-reload
systemctl daemon-reload
(( $(read_count_dbus) == before + 3 ))

# And all three transports still agree after the reload.
dbus_count=$(read_count_dbus)
varlink_count=$(read_count_varlink)
report_count=$(read_count_report)
(( dbus_count == varlink_count ))
(( dbus_count == report_count ))

# A daemon-reexec resets the counter back to zero on both transports, since
# reload_count lives only in memory and is not carried across the reexec.
# `systemctl daemon-reexec` returns as soon as the old PID 1 closes its bus
# connection, which is before the new PID 1 has rebound /run/systemd/private.
# Use --watch-bind=yes to block on inotify until the new socket is live.
systemctl daemon-reexec
busctl --watch-bind=yes call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
                           org.freedesktop.DBus.Peer Ping >/dev/null

(( $(read_count_dbus) == 0 ))
(( $(read_count_varlink) == 0 ))
(( $(read_count_report) == 0 ))
