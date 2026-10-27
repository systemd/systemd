#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="TEST-07-PID1-socket-final-sigterm-$RANDOM"

at_exit() {
    set +e
    systemctl stop --no-block "$UNIT_NAME.socket"
    rm -f /run/systemd/system/"$UNIT_NAME.socket" "/run/$UNIT_NAME.sock"
    systemctl daemon-reload
}

trap at_exit EXIT

cat >/run/systemd/system/"$UNIT_NAME.socket" <<EOF
[Socket]
ListenStream=/run/$UNIT_NAME.sock
ExecStartPost=/bin/sh -c 'sleep 30 &'
TimeoutSec=2s
EOF

systemctl daemon-reload
systemctl start "$UNIT_NAME.socket"

systemctl stop --no-block "$UNIT_NAME.socket"
timeout 10 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == final-sigterm ]]; do sleep .1; done"

systemctl daemon-reload

timeout 10 bash -c "until systemctl is-failed '$UNIT_NAME.socket'; do sleep .1; done"
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P Result)" "timeout"
