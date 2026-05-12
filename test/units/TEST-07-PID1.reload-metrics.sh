#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that the manager exposes ReloadCount and LastReloadUSec on D-Bus,
# Varlink Describe, and io.systemd.Metrics (queried via systemd-report).
# LastReloadUSec is unset before any reload: UINT64_MAX over D-Bus, absent
# over Varlink, no entry over io.systemd.Metrics.

readonly LAST_RELOAD_USEC_UNSET=18446744073709551615

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

read_duration_dbus() {
    busctl -j get-property org.freedesktop.systemd1 \
                           /org/freedesktop/systemd1 \
                           org.freedesktop.systemd1.Manager \
                           LastReloadUSec | jq -r '.data'
}

read_duration_varlink() {
    # Returns the literal "null" when the field is absent (pre-reload).
    varlinkctl call /run/systemd/io.systemd.Manager \
                    io.systemd.Manager.Describe '{}' | jq -r '.runtime.LastReloadUSec'
}

# Returns the metric value, or empty string when no entry is emitted (pre-reload).
read_duration_report() {
    /usr/lib/systemd/systemd-report metrics --json=short \
              io.systemd.Manager.LastReloadUSec \
          | jq --seq -r 'select(.name == "io.systemd.Manager.LastReloadUSec") | .value' \
          | tr -d '\036'
}

# Sanity: all three transports must agree on the count.
dbus_count=$(read_count_dbus)
varlink_count=$(read_count_varlink)
report_count=$(read_count_report)
(( dbus_count == varlink_count ))
(( dbus_count == report_count ))

# Pre-reload assertions only run if no other test has already triggered a reload.
if [[ "$(read_duration_dbus)" == "$LAST_RELOAD_USEC_UNSET" ]]; then
    [[ "$(read_duration_varlink)" == "null" ]]
    [[ -z "$(read_duration_report)" ]]
fi

# A single reload bumps the counter by one and records a finite duration on
# all three transports. The duration may be 0 if the reload was sub-microsecond.
before=$(read_count_dbus)
systemctl daemon-reload
(( $(read_count_dbus) == before + 1 ))

dbus_duration=$(read_duration_dbus)
varlink_duration=$(read_duration_varlink)
report_duration=$(read_duration_report)
[[ "$dbus_duration" != "$LAST_RELOAD_USEC_UNSET" ]]
[[ "$varlink_duration" != "null" ]]
[[ -n "$report_duration" ]]
(( dbus_duration == varlink_duration ))
(( dbus_duration == report_duration ))

# Multiple reloads accumulate the counter; each reload overwrites the duration.
# We only cross-check that the three transports agree after the final reload.
systemctl daemon-reload
systemctl daemon-reload
(( $(read_count_dbus) == before + 3 ))

dbus_duration=$(read_duration_dbus)
varlink_duration=$(read_duration_varlink)
report_duration=$(read_duration_report)
[[ "$dbus_duration" != "$LAST_RELOAD_USEC_UNSET" ]]
[[ "$varlink_duration" != "null" ]]
[[ -n "$report_duration" ]]
(( dbus_duration == varlink_duration ))
(( dbus_duration == report_duration ))

# `systemctl daemon-reexec` returns as soon as the old PID 1 closes its bus
# connection, which is before the new PID 1 has rebound /run/systemd/private.
# Use --watch-bind=yes to block on inotify until the new socket is live.
systemctl daemon-reexec
busctl --watch-bind=yes call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
                           org.freedesktop.DBus.Peer Ping >/dev/null

(( $(read_count_dbus) == 0 ))
(( $(read_count_varlink) == 0 ))
(( $(read_count_report) == 0 ))

[[ "$(read_duration_dbus)" == "$LAST_RELOAD_USEC_UNSET" ]]
[[ "$(read_duration_varlink)" == "null" ]]
[[ -z "$(read_duration_report)" ]]
