#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Simple test for that daemon-reexec works in container.
# See: https://github.com/systemd/systemd/pull/23883
systemctl daemon-reexec

# Test merging of a --job-mode=ignore-dependencies job into a previously
# installed job.

systemctl start --no-block hello-after-sleep.target

systemctl list-jobs >/root/list-jobs.txt
until grep 'sleep\.service.*running' /root/list-jobs.txt; do
    systemctl list-jobs >/root/list-jobs.txt
done

grep 'hello\.service.*waiting' /root/list-jobs.txt

# This is supposed to finish quickly, not wait for sleep to finish.
START_SEC=$(date -u '+%s')
systemctl start --job-mode=ignore-dependencies hello
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))

test "$ELAPSED" -lt 3

# sleep should still be running, hello not.
systemctl list-jobs >/root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt
grep 'hello\.service' /root/list-jobs.txt && exit 1
systemctl stop sleep.service hello-after-sleep.target

# Some basic testing that --show-transaction does something useful
(! systemctl is-active systemd-importd)
systemctl -T start systemd-importd
systemctl is-active systemd-importd
systemctl --show-transaction stop systemd-importd
(! systemctl is-active systemd-importd)

# Test for a crash when enqueuing a JOB_NOP when other job already exists
systemctl start --no-block hello-after-sleep.target
# hello.service should still be waiting, so these try-restarts will collapse
# into NOPs.
systemctl try-restart --job-mode=fail hello.service
systemctl try-restart hello.service
systemctl stop hello.service sleep.service hello-after-sleep.target

# TODO: add more job queueing/merging tests here.

# Test that restart propagates to activating units
systemctl -T --no-block start always-activating.service
systemctl list-jobs | grep 'always-activating.service'
ACTIVATING_ID_PRE=$(systemctl show -P InvocationID always-activating.service)
systemctl -T start always-activating.socket # Wait for the socket to come up
systemctl -T restart always-activating.socket
ACTIVATING_ID_POST=$(systemctl show -P InvocationID always-activating.service)
[ "$ACTIVATING_ID_PRE" != "$ACTIVATING_ID_POST" ] || exit 1

# Test for irreversible jobs
systemctl start unstoppable.service

# This is expected to fail with 'job cancelled'
systemctl stop unstoppable.service && exit 1
# But this should succeed
systemctl stop --job-mode=replace-irreversibly unstoppable.service

# We're going to shutdown soon. Let's see if it succeeds when
# there's an active service that tries to be unstoppable.
# Shutdown of the container/VM will hang if not.
systemctl start unstoppable.service

# Test waiting for a started units to terminate again
cat <<EOF >/run/systemd/system/wait2.service
[Unit]
Description=Wait for 2 seconds
[Service]
ExecStart=sh -ec 'sleep 2'
EOF
cat <<EOF >/run/systemd/system/wait5fail.service
[Unit]
Description=Wait for 5 seconds and fail
[Service]
ExecStart=sh -ec 'sleep 5; false'
EOF

# wait2 succeeds
START_SEC=$(date -u '+%s')
systemctl start --wait wait2.service
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 2 ]] && [[ "$ELAPSED" -le 4 ]] || exit 1

# wait5fail fails, so systemctl should fail
START_SEC=$(date -u '+%s')
(! systemctl start --wait wait2.service wait5fail.service)
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 5 ]] && [[ "$ELAPSED" -le 7 ]] || exit 1

# Test time-limited scopes
START_SEC=$(date -u '+%s')
set +e
systemd-run --scope --property=RuntimeMaxSec=3s sleep 10
RESULT=$?
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 3 ]] && [[ "$ELAPSED" -le 5 ]] || exit 1
[[ "$RESULT" -ne 0 ]] || exit 1

# Test transactions with cycles
# Provides coverage for issues like https://github.com/systemd/systemd/issues/26872
for i in {0..19}; do
    cat >"/run/systemd/system/transaction-cycle$i.service" <<EOF
[Unit]
After=transaction-cycle$(((i + 1) % 20)).service
Requires=transaction-cycle$(((i + 1) % 20)).service

[Service]
ExecStart=true
EOF
done
systemctl daemon-reload
for i in {0..19}; do
    systemctl start "transaction-cycle$i.service"
done

# Test PropagatesStopTo= when restart (issue #26839)
systemctl start propagatestopto-and-pullin.target
systemctl --quiet is-active propagatestopto-and-pullin.target

systemctl restart propagatestopto-and-pullin.target
systemctl --quiet is-active propagatestopto-and-pullin.target
systemctl --quiet is-active sleep-infinity-simple.service

systemctl start propagatestopto-only.target
systemctl --quiet is-active propagatestopto-only.target
systemctl --quiet is-active sleep-infinity-simple.service

systemctl restart propagatestopto-only.target
assert_rc 3 systemctl --quiet is-active sleep-infinity-simple.service

systemctl start propagatesstopto-indirect.target propagatestopto-and-pullin.target
systemctl --quiet is-active propagatestopto-indirect.target
systemctl --quiet is-active propagatestopto-and-pullin.target

systemctl restart propagatestopto-indirect.target
assert_rc 3 systemctl --quiet is-active propagatestopto-and-pullin.target
assert_rc 3 systemctl --quiet is-active sleep-infinity-simple.service

# Test restart mode direct

systemctl start succeeds-on-restart-restartdirect.target
assert_rc 0 systemctl --quiet is-active succeeds-on-restart-restartdirect.target

systemctl start fails-on-restart-restartdirect.target || :
assert_rc 3 systemctl --quiet is-active fails-on-restart-restartdirect.target

systemctl start succeeds-on-restart.target || :
assert_rc 3 systemctl --quiet is-active succeeds-on-restart.target

systemctl start fails-on-restart.target || :
assert_rc 3 systemctl --quiet is-active fails-on-restart.target

COUNTER_FILE=/tmp/test-03-restart-counter
export FAILURE_FLAG_FILE=/tmp/test-03-restart-failure-flag

assert_rc 3 systemctl --quiet is-active sleep-infinity-restart-normal.service
assert_rc 3 systemctl --quiet is-active sleep-infinity-restart-direct.service
assert_rc 3 systemctl --quiet is-active counter.service
echo 0 >"$COUNTER_FILE"

systemctl start counter.service
assert_eq "$(cat "$COUNTER_FILE")" "1"
systemctl --quiet is-active sleep-infinity-restart-normal.service
systemctl --quiet is-active sleep-infinity-restart-direct.service
systemctl --quiet is-active counter.service

systemctl kill --signal=KILL sleep-infinity-restart-direct.service
systemctl --quiet is-active counter.service
assert_eq "$(cat "$COUNTER_FILE")" "1"
[[ ! -f "$FAILURE_FLAG_FILE" ]]

systemctl kill --signal=KILL sleep-infinity-restart-normal.service
timeout 10 bash -c 'while [[ ! -f $FAILURE_FLAG_FILE ]]; do sleep .5; done'
timeout 10 bash -c 'while ! systemctl --quiet is-active counter.service; do sleep .5; done'
assert_eq "$(cat "$COUNTER_FILE")" "2"

# Test shortcutting auto restart

export UNIT_NAME="TEST-03-JOBS-shortcut-restart.service"
TMP_FILE="/tmp/test-03-shortcut-restart-test$RANDOM"

cat >"/run/systemd/system/$UNIT_NAME" <<EOF
[Service]
Type=oneshot
ExecStart=rm -v "$TMP_FILE"
Restart=on-failure
RestartSec=1d
RemainAfterExit=yes
EOF

(! systemctl start "$UNIT_NAME")
timeout 10 bash -c 'while [[ "$(systemctl show "$UNIT_NAME" -P SubState)" != "auto-restart" ]]; do sleep .5; done'
touch "$TMP_FILE"
assert_eq "$(systemctl show "$UNIT_NAME" -P SubState)" "auto-restart"

timeout 30 systemctl start "$UNIT_NAME"
systemctl --quiet is-active "$UNIT_NAME"
assert_eq "$(systemctl show "$UNIT_NAME" -P NRestarts)" "1"
[[ ! -f "$TMP_FILE" ]]

rm /run/systemd/system/"$UNIT_NAME"

touch /testok
