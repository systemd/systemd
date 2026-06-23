#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Operate multiple units in a single transaction.
# Issue: https://github.com/systemd/systemd/issues/8102
#
# When 'systemctl start <a> <b>' is executed, both units must be enqueued in a
# single transaction so that After= ordering is honoured regardless of the order
# of the arguments. Previously each unit was sent to PID1 in its own D-Bus
# request and thus its own transaction, which meant the ordering dependency was
# only effective when the dependee was queued before the dependent.

MARKER_DIR="$(mktemp -d /tmp/issue8102.marker.XXXXXX)"
MARKER="$MARKER_DIR/done"
SOCK_DIR="$(mktemp -d /tmp/issue8102.sock.XXXXXX)"
SOCK_PATH="$SOCK_DIR/sock"

at_exit() {
    set +e

    systemctl stop issue8102-second.service issue8102-first.service
    systemctl stop issue8102-sock-foo.service issue8102-sock-foo.socket
    systemctl stop 'issue8102-many@*.service'
    systemctl stop issue8102-conflict-a.service issue8102-conflict-b.service
    systemctl stop issue8102-nop-main.service issue8102-nop-dep.service
    systemctl reset-failed issue8102-second.service issue8102-first.service
    systemctl reset-failed issue8102-sock-foo.service issue8102-sock-foo.socket
    systemctl reset-failed 'issue8102-many@*.service'
    systemctl reset-failed issue8102-conflict-a.service issue8102-conflict-b.service
    systemctl reset-failed issue8102-nop-main.service issue8102-nop-dep.service
    rm -f /run/systemd/system/issue8102-{first,second}.service
    rm -f /run/systemd/system/issue8102-sock-foo.{service,socket}
    rm -f /run/systemd/system/issue8102-many@.service
    rm -f /run/systemd/system/issue8102-conflict-{a,b}.service
    rm -f /run/systemd/system/issue8102-nop-{main,dep}.service
    rm -rf "$MARKER_DIR" "$SOCK_DIR"
    systemctl daemon-reload
}

trap at_exit EXIT

mkdir -p /run/systemd/system

cat >/run/systemd/system/issue8102-first.service <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'sleep 1 && echo done > "$MARKER"'
EOF

cat >/run/systemd/system/issue8102-second.service <<EOF
[Unit]
After=issue8102-first.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'test -e "$MARKER"'
EOF

systemctl daemon-reload
rm -f "$MARKER"

# Pass the units in reverse dependency order. Without the single-transaction
# fix, second.service is enqueued first, dispatched immediately (because
# first.service has no pending job at that point) and fails because the marker
# does not yet exist. With the fix the units are submitted to PID1 in a single
# request and After= ordering is honoured.
systemctl start issue8102-second.service issue8102-first.service

test -e "$MARKER"
[[ "$(systemctl show -P ActiveState issue8102-first.service)" == active ]]
[[ "$(systemctl show -P ActiveState issue8102-second.service)" == active ]]

# Same exercise via the new D-Bus method, calling it directly via busctl. This
# verifies the EnqueueUnitJobMany() method is implemented and behaves as expected.
systemctl stop issue8102-second.service issue8102-first.service
rm -f "$MARKER"

busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    2 issue8102-second.service issue8102-first.service \
    start replace \
    0

# Wait for both units to settle.
# shellcheck disable=SC2016
timeout 30s bash -c '
    while [[ "$(systemctl show -P ActiveState issue8102-first.service)" != active ]] ||
          [[ "$(systemctl show -P ActiveState issue8102-second.service)" != active ]]; do
        sleep 0.5
    done
'

test -e "$MARKER"

# Second scenario: a service unit ordered after its socket unit, passed to
# 'systemctl start' with the service first and the socket second. With per-unit
# transactions the service is enqueued alone: After= alone does not pull in the
# socket, so the service runs before the socket has been listening and its
# ExecStart fails. With a single transaction the After= ordering between the
# two anchors is honored, the socket is brought up first and the service
# succeeds.

cat >/run/systemd/system/issue8102-sock-foo.socket <<EOF
[Socket]
ListenStream=$SOCK_PATH
EOF

cat >/run/systemd/system/issue8102-sock-foo.service <<EOF
[Unit]
After=issue8102-sock-foo.socket

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'test -S "$SOCK_PATH"'
EOF

systemctl daemon-reload

systemctl start issue8102-sock-foo.service issue8102-sock-foo.socket

[[ "$(systemctl show -P ActiveState issue8102-sock-foo.service)" == active ]]
[[ "$(systemctl show -P ActiveState issue8102-sock-foo.socket)" == active ]]
test -S "$SOCK_PATH"

# Third scenario: verify that EnqueueUnitJobMany supports the "reload-or-restart"
# magic job type. The socket unit cannot reload, so it should get a restart job,
# while the service unit (with Type=oneshot) also gets a restart. After the
# call both units must be active again.
busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    2 issue8102-sock-foo.service issue8102-sock-foo.socket \
    reload-or-restart replace \
    0 >/dev/null
# Wait for the units to come back up after the restart.
# shellcheck disable=SC2016
timeout 30s bash -c '
    while [[ "$(systemctl show -P ActiveState issue8102-sock-foo.service)" != active ]] ||
          [[ "$(systemctl show -P ActiveState issue8102-sock-foo.socket)" != active ]]; do
        sleep 0.5
    done
'
test -S "$SOCK_PATH"

# ---------------------------------------------------------------------------
# Argument validation corner cases for EnqueueUnitJobMany().
# ---------------------------------------------------------------------------

# Empty units array → the handler must reject the call with an INVALID_ARGS
# error before doing anything.
out=$(busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    0 \
    start replace \
    0 2>&1) && { echo 'busctl unexpectedly succeeded'; exit 1; }
echo "$out" | grep -F "No units specified" >/dev/null

# Non-zero flags parameter is reserved and must be rejected.
out=$(busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    1 issue8102-first.service \
    start replace \
    1 2>&1) && { echo 'busctl unexpectedly succeeded'; exit 1; }
echo "$out" | grep -F "Invalid flags parameter" >/dev/null

# Bogus job type → rejected before any job is constructed.
out=$(busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    1 issue8102-first.service \
    not-a-real-job-type replace \
    0 2>&1) && { echo 'busctl unexpectedly succeeded'; exit 1; }
echo "$out" | grep -F "Job type not-a-real-job-type invalid" >/dev/null

# Bogus job mode → rejected before any job is constructed.
out=$(busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    1 issue8102-first.service \
    start not-a-real-mode \
    0 2>&1) && { echo 'busctl unexpectedly succeeded'; exit 1; }
echo "$out" | grep -F "Job mode not-a-real-mode invalid" >/dev/null

# Unknown unit must be reported as an error and no partial state should remain
# in the job queue: list one valid + one bogus unit, ensure the call fails and
# that the valid unit has no pending start job afterwards.
systemctl stop issue8102-first.service
[[ "$(systemctl show -P ActiveState issue8102-first.service)" == inactive ]]

(! busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    2 issue8102-first.service issue8102-does-not-exist.service \
    start replace \
    0 2>/dev/null)

# busctl is synchronous: by the time the call returns with an error, PID1 has
# already rejected the transaction. Verify the valid unit was not started
# behind our back (the transaction must be all-or-nothing).
[[ "$(systemctl show -P ActiveState issue8102-first.service)" == inactive ]]

# ---------------------------------------------------------------------------
# Many units in a single transaction.
# ---------------------------------------------------------------------------
# Build a template unit and instantiate a fair number of instances, all
# enqueued via a single EnqueueUnitJobMany() call to exercise the strv path with
# a transaction that anchors many units at once.

cat >/run/systemd/system/issue8102-many@.service <<'EOF'
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
EOF
systemctl daemon-reload

MANY_COUNT=20
mapfile -t MANY_UNITS < <(for i in $(seq 1 "$MANY_COUNT"); do printf 'issue8102-many@%d.service\n' "$i"; done)
MANY_BUSCTL_ARGS=("$MANY_COUNT" "${MANY_UNITS[@]}")

busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    "${MANY_BUSCTL_ARGS[@]}" \
    start replace \
    0 >/dev/null

# Wait for every instance to become active.
# shellcheck disable=SC2016
timeout 30s bash -c '
    for u in "$@"; do
        while [[ "$(systemctl show -P ActiveState "$u")" != active ]]; do
            sleep 0.2
        done
    done
' bash "${MANY_UNITS[@]}"

# Stop them all in one transaction too, verifying the stop path scales as well.
busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    "${MANY_BUSCTL_ARGS[@]}" \
    stop replace \
    0 >/dev/null

# shellcheck disable=SC2016
timeout 30s bash -c '
    for u in "$@"; do
        while [[ "$(systemctl show -P ActiveState "$u")" != inactive ]]; do
            sleep 0.2
        done
    done
' bash "${MANY_UNITS[@]}"

# ---------------------------------------------------------------------------
# Incompatible transaction: two units that Conflict= with each other cannot be
# started together. Both start anchors would force the other unit to stop, so
# the transaction is unsatisfiable regardless of the chosen job mode. The
# handler must report an error and roll back, so that neither unit ends up
# active.
# ---------------------------------------------------------------------------

cat >/run/systemd/system/issue8102-conflict-a.service <<EOF
[Unit]
Conflicts=issue8102-conflict-b.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
EOF

cat >/run/systemd/system/issue8102-conflict-b.service <<EOF
[Unit]
Conflicts=issue8102-conflict-a.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
EOF
systemctl daemon-reload

(! busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    2 issue8102-conflict-a.service issue8102-conflict-b.service \
    start fail \
    0 2>/dev/null)

# Atomicity: neither unit must end up activated by the failed call. busctl is
# synchronous so by the time it returns PID1 has already rolled back.
[[ "$(systemctl show -P ActiveState issue8102-conflict-a.service)" == inactive ]]
[[ "$(systemctl show -P ActiveState issue8102-conflict-b.service)" == inactive ]]

# ---------------------------------------------------------------------------
# reload-or-try-restart with a mix of reloadable and non-reloadable units.
# The socket cannot reload so it must be restarted, while a unit that does
# implement reload would be reloaded. Both must be active afterwards.
# ---------------------------------------------------------------------------

systemctl start issue8102-sock-foo.service issue8102-sock-foo.socket
[[ "$(systemctl show -P ActiveState issue8102-sock-foo.service)" == active ]]
[[ "$(systemctl show -P ActiveState issue8102-sock-foo.socket)" == active ]]

busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    2 issue8102-sock-foo.service issue8102-sock-foo.socket \
    reload-or-try-restart replace \
    0 >/dev/null

# shellcheck disable=SC2016
timeout 30s bash -c '
    while [[ "$(systemctl show -P ActiveState issue8102-sock-foo.service)" != active ]] ||
          [[ "$(systemctl show -P ActiveState issue8102-sock-foo.socket)" != active ]]; do
        sleep 0.5
    done
'
test -S "$SOCK_PATH"

# try-restart on a unit that is not currently running must be a no-op (no error)
# and must not start it.
systemctl stop issue8102-first.service
[[ "$(systemctl show -P ActiveState issue8102-first.service)" == inactive ]]

busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    1 issue8102-first.service \
    try-restart replace \
    0 >/dev/null

[[ "$(systemctl show -P ActiveState issue8102-first.service)" == inactive ]]

# ---------------------------------------------------------------------------
# Regression test: a try-restart anchor that collapses to a NOP job (because
# the unit is inactive) must not crash PID1 when the very same unit is also
# pulled into the transaction as a regular start job by another anchor.
#
# ---------------------------------------------------------------------------

cat >/run/systemd/system/issue8102-nop-dep.service <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
EOF

cat >/run/systemd/system/issue8102-nop-main.service <<EOF
[Unit]
Wants=issue8102-nop-dep.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
EOF
systemctl daemon-reload

systemctl start issue8102-nop-main.service
[[ "$(systemctl show -P ActiveState issue8102-nop-main.service)" == active ]]

# Stop just the dependency. Wants= is a weak dependency, so the main unit stays
# active while the dependency goes inactive.
systemctl stop issue8102-nop-dep.service
[[ "$(systemctl show -P ActiveState issue8102-nop-dep.service)" == inactive ]]
[[ "$(systemctl show -P ActiveState issue8102-nop-main.service)" == active ]]

# try-restart both in a single transaction: the inactive dependency collapses to
# a NOP anchor, while restarting the active main unit pulls the dependency back
# in as a regular start job.
busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitJobMany \
    assst \
    2 issue8102-nop-dep.service issue8102-nop-main.service \
    try-restart replace \
    0 >/dev/null

# shellcheck disable=SC2016
timeout 30s bash -c '
    while [[ "$(systemctl show -P ActiveState issue8102-nop-dep.service)" != active ]] ||
          [[ "$(systemctl show -P ActiveState issue8102-nop-main.service)" != active ]]; do
        sleep 0.5
    done
'

# Ensure we are still running
systemctl daemon-reload
