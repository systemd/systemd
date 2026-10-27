#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="TEST-07-PID1-socket-final-sigterm-$RANDOM"
SOCKET_PATH="/tmp/$UNIT_NAME.sock"

at_exit() {
    set +e
    systemctl stop --no-block "$UNIT_NAME.socket"
    systemctl reset-failed "$UNIT_NAME.socket"
    rm -f /run/systemd/system/"$UNIT_NAME.socket" \
        /run/systemd/system/"$UNIT_NAME.service" "$SOCKET_PATH"
    systemctl daemon-reload
}

trap at_exit EXIT

cat >/run/systemd/system/"$UNIT_NAME.socket" <<EOF
[Socket]
ListenStream=$SOCKET_PATH
ExecStartPost=/bin/sh -c 'sleep 30 &'
TimeoutSec=15s
EOF

cat >/run/systemd/system/"$UNIT_NAME.service" <<EOF
[Service]
ExecStart=true
EOF

systemctl daemon-reload
systemctl start "$UNIT_NAME.socket"

systemctl stop --no-block "$UNIT_NAME.socket"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == final-sigterm ]]; do sleep .1; done"

systemctl daemon-reload

timeout 30 bash -c "until systemctl -q is-failed '$UNIT_NAME.socket'; do sleep .1; done"
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P Result)" "timeout"
