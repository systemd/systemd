#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="TEST-07-PID1-socket-$RANDOM"

at_exit() {
    systemctl stop "$UNIT_NAME.socket"
    rm -f /run/systemd/system/"$UNIT_NAME".{socket,service} \
        /run/systemd/system/TEST-07-PID1-socket-OnFailure.service
}

trap at_exit EXIT

# Test triggering OnFailure= when fails to listen on socket (#35635)

mkdir -p "/tmp/$UNIT_NAME"

cat >/run/systemd/system/"$UNIT_NAME.socket" <<EOF
[Unit]
OnFailure=TEST-07-PID1-socket-OnFailure.service

[Socket]
ListenStream=/tmp/$UNIT_NAME/test
EOF

cat >/run/systemd/system/"$UNIT_NAME.service" <<EOF
[Service]
ExecStart=true
EOF

cat >/run/systemd/system/TEST-07-PID1-socket-OnFailure.service <<EOF
[Service]
Type=oneshot
ExecStart=rmdir /tmp/$UNIT_NAME/test
RemainAfterExit=yes
EOF

systemctl start "$UNIT_NAME.socket"
systemctl is-active "$UNIT_NAME.socket"
[[ -S "/tmp/$UNIT_NAME/test" ]]

systemctl stop "$UNIT_NAME.socket"
rm "/tmp/$UNIT_NAME/test"

chattr +i "/tmp/$UNIT_NAME"

(! systemctl start "$UNIT_NAME.socket")
systemctl is-failed "$UNIT_NAME.socket"
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "failed"

[[ ! -e "/tmp/$UNIT_NAME/test" ]]
timeout 10 bash -c "until systemctl is-failed TEST-07-PID1-socket-OnFailure.service; do sleep .5; done"

chattr -i "/tmp/$UNIT_NAME"

mkdir "/tmp/$UNIT_NAME/test"

(! systemctl start "$UNIT_NAME.socket")
systemctl is-failed "$UNIT_NAME.socket"
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "failed"

timeout 10 bash -c "while [[ -d '/tmp/$UNIT_NAME/test' ]]; do sleep .5; done"
[[ ! -e "/tmp/$UNIT_NAME/test" ]]
systemctl is-active TEST-07-PID1-socket-OnFailure.service

systemctl start "$UNIT_NAME.socket"
systemctl is-active "$UNIT_NAME.socket"
