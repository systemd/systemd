#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="TEST-07-PID1-socket-defer-$RANDOM"

at_exit() {
    systemctl stop "$UNIT_NAME*"
    rm -f /run/systemd/system/"$UNIT_NAME".socket \
        /run/systemd/system/"$UNIT_NAME"{,-conflict1,-conflict2,-forever}.service
}

trap at_exit EXIT

mkdir -p "/tmp/$UNIT_NAME"

cat >/run/systemd/system/"$UNIT_NAME-conflict1.service" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStop=bash -c 'while [[ -f /tmp/$UNIT_NAME/flag ]]; do sleep 1; done'
TimeoutStopSec=infinity
EOF

cat >/run/systemd/system/"$UNIT_NAME-conflict2.service" <<EOF
[Service]
ExecStart=bash -c 'while [[ -f /tmp/$UNIT_NAME/flag ]]; do sleep 1; done'
EOF

cat >/run/systemd/system/"$UNIT_NAME-forever.service" <<EOF
[Service]
Type=oneshot
ExecStart=sleep infinity
TimeoutSec=infinity
EOF

cat >/run/systemd/system/"$UNIT_NAME.socket" <<EOF
[Socket]
ListenStream=/tmp/$UNIT_NAME/test
FlushPending=yes
EOF

cat >/run/systemd/system/"$UNIT_NAME.service" <<EOF
[Unit]
Conflicts=$UNIT_NAME-conflict1.service
Conflicts=$UNIT_NAME-conflict2.service

[Service]
ExecStart=sleep infinity
EOF

# DeferTrigger=no: job mode replace

systemctl start "$UNIT_NAME.socket"
[[ -S "/tmp/$UNIT_NAME/test" ]]
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"
(! systemctl is-active "$UNIT_NAME.service")

echo 1 >"/tmp/$UNIT_NAME/test"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'running' ]]; do sleep .5; done"
systemctl is-active "$UNIT_NAME.service"

touch "/tmp/$UNIT_NAME/flag"
systemctl start "$UNIT_NAME-conflict2.service"
(! systemctl is-active "$UNIT_NAME.service")
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"
echo 1 >"/tmp/$UNIT_NAME/test"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'running' ]]; do sleep .5; done"
systemctl is-active "$UNIT_NAME.service"
(! systemctl is-active "$UNIT_NAME-conflict2.service")

# DeferTrigger=yes

echo "DeferTrigger=yes" >>/run/systemd/system/"$UNIT_NAME.socket"
systemctl daemon-reload

assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "running"
systemctl start "$UNIT_NAME-conflict1.service"
(! systemctl is-active "$UNIT_NAME.service")
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"

# Wait for running stop job in "deferred" state

systemctl stop --no-block "$UNIT_NAME-conflict1.service"
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "stop"
echo 1 >"/tmp/$UNIT_NAME/test"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .5; done"
(! systemctl is-active "$UNIT_NAME.service")

# Return to "listening" on daemon-reload

systemctl daemon-reload
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"
echo 1 >"/tmp/$UNIT_NAME/test"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .5; done"
(! systemctl is-active "$UNIT_NAME.service")

# Activate after conflicting unit exits

rm "/tmp/$UNIT_NAME/flag"
timeout 30 bash -c "while systemctl -q is-active '$UNIT_NAME-conflict1.service'; do sleep .2; done"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'running' ]]; do sleep .5; done"
systemctl is-active "$UNIT_NAME.service"

# An irrelevant job running, during which one of the conflicting units exits

touch "/tmp/$UNIT_NAME/flag"
systemctl start "$UNIT_NAME-forever.service" "$UNIT_NAME-conflict2.service"
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"
echo 1 >"/tmp/$UNIT_NAME/test"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .5; done"
(! systemctl is-active "$UNIT_NAME.service")
rm "/tmp/$UNIT_NAME/flag"
timeout 30 bash -c "while systemctl -q is-active '$UNIT_NAME-conflict2.service'; do sleep .2; done"
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'running' ]]; do sleep .5; done"
systemctl is-active "$UNIT_NAME.service"
assert_eq "$(systemctl show "$UNIT_NAME-forever.service" -P SubState)" "start"
