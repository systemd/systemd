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
ExecStart=bash -c 'until [[ -f /tmp/$UNIT_NAME/flag ]]; do sleep 1; done'
TimeoutStartSec=infinity
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

wait_for_start() {
    timeout 30 bash -c "until systemctl -q is-active '$UNIT_NAME.service'; do sleep .5; done"
    assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "running"
}

wait_for_stop() {
    timeout 30 bash -c "while systemctl -q is-active '$UNIT_NAME.service'; do sleep .5; done"
    assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"
}

# DeferTrigger=no: job mode replace

systemctl start "$UNIT_NAME.socket"
[[ -S "/tmp/$UNIT_NAME/test" ]]
assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "listening"
(! systemctl -q is-active "$UNIT_NAME.service")

socat -u - UNIX-CONNECT:"/tmp/$UNIT_NAME/test" &
wait_for_start
wait %%

touch "/tmp/$UNIT_NAME/flag"
systemctl start "$UNIT_NAME-conflict2.service"
wait_for_stop

socat -u - UNIX-CONNECT:"/tmp/$UNIT_NAME/test" &
wait_for_start
wait %%
(! systemctl -q is-active "$UNIT_NAME-conflict2.service")

# DeferTrigger=yes

echo "DeferTrigger=yes" >>/run/systemd/system/"$UNIT_NAME.socket"
systemctl daemon-reload

assert_eq "$(systemctl show "$UNIT_NAME.socket" -P SubState)" "running"
rm "/tmp/$UNIT_NAME/flag"
systemctl start --no-block "$UNIT_NAME-conflict1.service"
wait_for_stop
assert_eq "$(systemctl show "$UNIT_NAME-conflict1.service" -P SubState)" "start"

# Wait in "deferred" state

socat -u - UNIX-CONNECT:"/tmp/$UNIT_NAME/test" &
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .5; done"
(! systemctl -q is-active "$UNIT_NAME.service")
wait %%
assert_eq "$(systemctl show "$UNIT_NAME-conflict1.service" -P SubState)" "start"

systemctl daemon-reload
timeout 10 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .2; done"
(! systemctl -q is-active "$UNIT_NAME.service")
assert_eq "$(systemctl show "$UNIT_NAME-conflict1.service" -P SubState)" "start"

# Activate after conflicting unit exits

touch "/tmp/$UNIT_NAME/flag"
timeout 30 bash -c "while systemctl -q is-active '$UNIT_NAME-conflict1.service'; do sleep .2; done"
wait_for_start

# An irrelevant job running, during which one of the conflicting units exits

systemctl start --no-block "$UNIT_NAME-forever.service"
systemctl start "$UNIT_NAME-conflict2.service"
wait_for_stop

socat -u - UNIX-CONNECT:"/tmp/$UNIT_NAME/test" &
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .5; done"
(! systemctl -q is-active "$UNIT_NAME.service")
wait %%

rm "/tmp/$UNIT_NAME/flag"
timeout 30 bash -c "while systemctl -q is-active '$UNIT_NAME-conflict2.service'; do sleep .2; done"
wait_for_start
assert_eq "$(systemctl show "$UNIT_NAME-forever.service" -P SubState)" "start"

# Fail if DeferTriggerMaxSec= is reached

systemctl start --no-block "$UNIT_NAME-conflict1.service"
wait_for_stop
assert_eq "$(systemctl show "$UNIT_NAME-conflict1.service" -P SubState)" "start"

socat -u - UNIX-CONNECT:"/tmp/$UNIT_NAME/test" &
timeout 30 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .5; done"
(! systemctl -q is-active "$UNIT_NAME.service")
wait %%

echo "DeferTriggerMaxSec=20s" >>/run/systemd/system/"$UNIT_NAME.socket"
systemctl daemon-reload

timeout 10 bash -c "until [[ \$(systemctl show '$UNIT_NAME.socket' -P SubState) == 'deferred' ]]; do sleep .2; done"
(! systemctl -q is-active "$UNIT_NAME.service")

sleep 10
timeout 30 bash -c "until systemctl -q is-failed '$UNIT_NAME.socket'; do sleep .5; done"
assert_eq "$(systemctl show "$UNIT_NAME-conflict1.service" -P SubState)" "start"
