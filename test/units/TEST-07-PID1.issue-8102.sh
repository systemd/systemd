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

MARKER="$(mktemp -u /tmp/issue8102.marker.XXXXXX)"
SOCK_DIR="$(mktemp -d /tmp/issue8102.sock.XXXXXX)"
SOCK_PATH="$SOCK_DIR/sock"

at_exit() {
    set +e

    systemctl stop issue8102-second.service issue8102-first.service
    systemctl stop issue8102-sock-foo.service issue8102-sock-foo.socket
    systemctl reset-failed issue8102-second.service issue8102-first.service
    systemctl reset-failed issue8102-sock-foo.service issue8102-sock-foo.socket
    rm -f /run/systemd/system/issue8102-{first,second}.service "$MARKER"
    rm -f /run/systemd/system/issue8102-sock-foo.{service,socket}
    rm -rf "$SOCK_DIR"
    systemctl daemon-reload
}

trap at_exit EXIT

mkdir -p /run/systemd/system

cat >/run/systemd/system/issue8102-first.service <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'sleep 3 && echo done > "$MARKER"'
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
# verifies the EnqueueUnitsJobs() method is implemented and behaves as expected.
systemctl stop issue8102-second.service issue8102-first.service
rm -f "$MARKER"

busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitsJobs \
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

# Third scenario: verify that EnqueueUnitsJobs supports the "reload-or-restart"
# magic job type. The socket unit cannot reload, so it should get a restart job,
# while the service unit (with Type=oneshot) also gets a restart. After the
# call both units must be active again.
busctl call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager \
    EnqueueUnitsJobs \
    assst \
    2 issue8102-sock-foo.service issue8102-sock-foo.socket \
    reload-or-restart replace \
    0

# Wait for the units to come back up after the restart.
# shellcheck disable=SC2016
timeout 30s bash -c '
    while [[ "$(systemctl show -P ActiveState issue8102-sock-foo.service)" != active ]] ||
          [[ "$(systemctl show -P ActiveState issue8102-sock-foo.socket)" != active ]]; do
        sleep 0.5
    done
'
test -S "$SOCK_PATH"
