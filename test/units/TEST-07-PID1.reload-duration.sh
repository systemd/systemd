#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that the manager exposes LastReloadUSec on D-Bus, Varlink Describe,
# and io.systemd.Metrics. Before the first reload-cycle the value is
# UINT64_MAX over D-Bus, absent over Varlink, and emits no metrics entry.
# After a daemon-reload OR daemon-reexec the duration is finite and consistent
# across all three transports, since both go through manager_reloading_start()
# and manager_ready() which capture the start and finish timestamps.

readonly LAST_RELOAD_USEC_UNSET=18446744073709551615

# systemd-report silently returns empty if the metrics source is missing,
# which would falsely pass the cross-checks below. Assert the socket exists
# so any failure points at the real problem.
test -S /run/systemd/report/io.systemd.Manager

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

read_units_reload_start_monotonic() {
    busctl -j get-property org.freedesktop.systemd1 \
                           /org/freedesktop/systemd1 \
                           org.freedesktop.systemd1.Manager \
                           UnitsReloadStartTimestampMonotonic | jq -r '.data'
}

read_units_reload_finish_monotonic() {
    busctl -j get-property org.freedesktop.systemd1 \
                           /org/freedesktop/systemd1 \
                           org.freedesktop.systemd1.Manager \
                           UnitsReloadFinishTimestampMonotonic | jq -r '.data'
}

assert_finite_and_agree() {
    local d v r start finish
    d=$(read_duration_dbus)
    v=$(read_duration_varlink)
    r=$(read_duration_report)
    [[ -n "$d" ]] || { echo "LastReloadUSec missing from D-Bus" >&2; return 1; }
    [[ -n "$v" ]] || { echo "LastReloadUSec missing from Varlink Describe" >&2; return 1; }
    [[ -n "$r" ]] || { echo "LastReloadUSec metric missing from systemd-report output" >&2; return 1; }
    [[ "$d" != "$LAST_RELOAD_USEC_UNSET" ]]
    [[ "$v" != "null" ]]
    (( d == v ))
    (( d == r ))

    # The duration must equal finish - start of the underlying timestamp pair.
    start=$(read_units_reload_start_monotonic)
    finish=$(read_units_reload_finish_monotonic)
    (( start > 0 ))
    (( finish >= start ))
    (( d == finish - start ))
}

# Pre-reload assertions only run if no other test has already triggered a
# reload or reexec in this boot. Also assert the underlying timestamp pair
# is unset, since both endpoints stay at 0 until the first reload-cycle.
if [[ "$(read_duration_dbus)" == "$LAST_RELOAD_USEC_UNSET" ]]; then
    [[ "$(read_duration_varlink)" == "null" ]]
    [[ -z "$(read_duration_report)" ]]
    (( $(read_units_reload_start_monotonic) == 0 ))
    (( $(read_units_reload_finish_monotonic) == 0 ))
fi

# A single daemon-reload records a finite duration on all three transports.
systemctl daemon-reload
assert_finite_and_agree

# Multiple reloads each overwrite the duration; check that the three
# transports still agree after the final reload.
systemctl daemon-reload
systemctl daemon-reload
assert_finite_and_agree

# A daemon-reexec also goes through manager_reloading_start() and
# manager_ready(), so LastReloadUSec stays finite afterwards (it now
# reports the duration of the reexec). `systemctl daemon-reexec` returns
# as soon as the old PID 1 closes its bus connection, which is before
# the new PID 1 has rebound /run/systemd/private. Use --watch-bind=yes
# to block on inotify until the new socket is live.
systemctl daemon-reexec
busctl --watch-bind=yes call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
                           org.freedesktop.DBus.Peer Ping >/dev/null

assert_finite_and_agree
