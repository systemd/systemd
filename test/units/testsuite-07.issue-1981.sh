#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Segmentation fault in timer_enter_waiting while masking a unit
# Issue: https://github.com/systemd/systemd/issues/1981

at_exit() {
    set +e

    systemctl stop my.timer my.service
    rm -f /run/systemd/system/my.{service,timer}
    systemctl daemon-reload
}

trap at_exit EXIT

mkdir -p /run/systemd/system

cat >/run/systemd/system/my.service <<\EOF
[Service]
Type=oneshot
ExecStartPre=sh -c 'test "$TRIGGER_UNIT" = my.timer'
ExecStartPre=sh -c 'test -n "$TRIGGER_TIMER_REALTIME_USEC"'
ExecStartPre=sh -c 'test -n "$TRIGGER_TIMER_MONOTONIC_USEC"'
ExecStart=echo Timer runs me
EOF

cat >/run/systemd/system/my.timer <<EOF
[Timer]
OnBootSec=10s
OnUnitInactiveSec=1h
EOF

systemctl unmask my.timer
systemctl start my.timer

mkdir -p /run/systemd/system/my.timer.d/
cat >/run/systemd/system/my.timer.d/override.conf <<EOF
[Timer]
OnBootSec=10s
OnUnitInactiveSec=1h
EOF

systemctl daemon-reload
systemctl mask my.timer
