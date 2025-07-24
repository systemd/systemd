#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="TEST-07-PID1-issue-38320-$RANDOM"

at_exit() {
    systemctl stop "$UNIT_NAME".{socket,service}
    rm -f /run/systemd/system/"$UNIT_NAME".{socket,service}
}

trap at_exit EXIT

cat >/run/systemd/system/"$UNIT_NAME.socket" <<EOF
[Socket]
ListenStream=/tmp/$UNIT_NAME
EOF

cat >/run/systemd/system/"$UNIT_NAME.service" <<EOF
[Service]
ExecStart=true
EOF

(! systemd-analyze fdstore "$UNIT_NAME.socket")

systemctl restart "$UNIT_NAME.socket"
(! systemd-analyze fdstore "$UNIT_NAME.socket")

systemctl daemon-reload
(! systemd-analyze fdstore "$UNIT_NAME.socket")

systemctl is-active "$UNIT_NAME.socket"
