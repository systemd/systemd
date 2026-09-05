#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Two subtests below change the log level (the transactions-with-cycles one to info, the
# RestartRandomizedDelaySec= one to debug) and restore it inline when they pass. On abort,
# the EXIT handler restores the boot-time level and cleans up the transient unit the
# aborting subtest had in flight, as in TEST-26-SYSTEMCTL.sh.
ORIG_LOG_LEVEL="$(systemctl log-level)"

at_exit() {
    set +e

    systemctl log-level "$ORIG_LOG_LEVEL"

    # The "systemctl wait" subtest leaves units in failed state behind (wait-sigkill.service may even still
    # be running its "sleep 60" if the subtest aborted midway), which would leak into the remaining subtests
    # of this file, hence clean up unconditionally here.
    systemctl stop wait2.service wait5fail.service wait-exit7.service wait-sigkill.service wait-log.service wait-gc.service wait-watcher.service
    systemctl reset-failed wait2.service wait5fail.service wait-exit7.service wait-sigkill.service wait-log.service wait-gc.service wait-watcher.service
    rm -f /tmp/wait-log.fifo

    if [[ -e /etc/dbus-1/system.d/systemd-test-deny-ref.conf ]]; then
        rm -f /etc/dbus-1/system.d/systemd-test-deny-ref.conf
        systemctl reload dbus.service
    fi

    if [[ -v UNIT_NAME && -e /run/systemd/system/"$UNIT_NAME" ]]; then
        systemctl stop "$UNIT_NAME"
        rm -f /run/systemd/system/"$UNIT_NAME"
        systemctl daemon-reload
    fi
}

trap at_exit EXIT

# Simple test for that daemon-reexec works in container.
# See: https://github.com/systemd/systemd/pull/23883
systemctl daemon-reexec

# Test merging of a --job-mode=ignore-dependencies job into a previously
# installed job.

systemctl start --no-block hello-after-sleep.target

timeout 10 bash -c "until systemctl list-jobs | tee /root/list-jobs.txt | grep 'sleep\.service.*running'; do sleep .1; done"
grep 'hello\.service.*waiting' /root/list-jobs.txt

# This is supposed to finish quickly, not wait for sleep to finish.
timeout 10 systemctl start --job-mode=ignore-dependencies hello

# sleep should still be running, hello not.
systemctl list-jobs >/root/list-jobs.txt
grep 'sleep\.service.*running' /root/list-jobs.txt
(! grep 'hello\.service' /root/list-jobs.txt)
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
[[ "$ACTIVATING_ID_PRE" != "$ACTIVATING_ID_POST" ]]

# Test for irreversible jobs
systemctl start unstoppable.service

# This is expected to fail with 'job cancelled'
(! systemctl stop unstoppable.service)
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
ExecStart=bash -ec 'sleep 2'
EOF
cat <<EOF >/run/systemd/system/wait5fail.service
[Unit]
Description=Wait for 5 seconds and fail
[Service]
ExecStart=bash -ec 'sleep 5; false'
EOF

# wait2 succeeds
START_SEC=$(date -u '+%s')
timeout 10 systemctl start --wait wait2.service
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 2 ]]

# wait5fail fails, so systemctl should fail
START_SEC=$(date -u '+%s')
(! systemctl start --wait wait2.service wait5fail.service)
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 5 ]]

# Test "systemctl wait"
# An already inactive unit terminates the wait immediately, successfully
timeout 5 systemctl wait wait2.service

# A running unit is waited for until it terminates
systemctl --no-block start wait2.service
START_SEC=$(date -u '+%s')
timeout 10 systemctl wait wait2.service
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 1 ]]

# The exit status of the unit's main process is propagated
systemctl --no-block start wait5fail.service
assert_rc 1 timeout 10 systemctl wait wait5fail.service
systemd-run --no-block --unit=wait-exit7.service bash -c 'sleep 2; exit 7'
assert_rc 7 systemctl wait wait-exit7.service
# ... with termination by signal reported as 255
systemd-run --unit=wait-sigkill.service sleep 60
systemctl kill --signal=SIGKILL wait-sigkill.service
assert_rc 255 timeout 10 systemctl wait wait-sigkill.service

# A summary is shown on stdout, unless --quiet is given
systemctl --no-block start wait2.service
systemctl wait wait2.service | grep "Finished with result" >/dev/null
systemctl --no-block start wait2.service
OUT="$(timeout 10 systemctl --quiet wait wait2.service)"
[[ -z "$OUT" ]]

# --verbose forwards the unit's log output. To make this race-free, run "systemctl wait" as a Type=notify
# service: it sends READY=1 once it is fully set up, including the journal follow logic, hence any log output
# of the unit generated after systemd-run returned is guaranteed to be caught. Block the unit on a FIFO until
# then, so that it doesn't log too early.
mkfifo /tmp/wait-log.fifo
systemd-run --unit=wait-log.service bash -c 'read -r </tmp/wait-log.fifo; echo hello-from-wait'
systemd-run --unit=wait-watcher.service --service-type=notify systemctl --verbose wait wait-log.service
INVOCATION_ID="$(systemctl show --property=InvocationID --value wait-watcher.service)"
echo go >/tmp/wait-log.fifo
timeout 10 systemctl wait wait-watcher.service
journalctl --sync
journalctl -b _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" | grep hello-from-wait >/dev/null
rm /tmp/wait-log.fifo

# A non-existent unit is treated as terminated successfully, with a message in place of the summary
systemctl wait nonexistent.service | grep "does not exist" >/dev/null
OUT="$(systemctl --quiet wait nonexistent.service)"
[[ -z "$OUT" ]]

# A unit type without a Result property (e.g. a target) exits successfully once inactive
timeout 5 systemctl wait hello-after-sleep.target

# Template unit names are refused
(! systemctl wait 'foo@.service')

# Test that "systemctl wait" notices if the unit it waits for is removed from the service manager while
# waiting. Normally "systemctl wait" pins the unit via Ref(), so that it is not garbage collected before its
# final state was collected. Hence deny Ref() via D-Bus policy, and make the unit be garbage collected
# aggressively via CollectMode=inactive-or-failed. "systemctl wait" itself runs as a Type=notify service: it
# sends READY=1 once it is fully subscribed to the unit's state changes, so that we can synchronize on that.
mkdir -p /etc/dbus-1/system.d/
cat >/etc/dbus-1/system.d/systemd-test-deny-ref.conf <<EOF
<?xml version="1.0"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
        "https://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
        <policy context="mandatory">
                <deny send_destination="org.freedesktop.systemd1" send_interface="org.freedesktop.systemd1.Unit" send_member="Ref"/>
        </policy>
</busconfig>
EOF
systemctl reload dbus.service

systemd-run --unit=wait-gc.service --property=CollectMode=inactive-or-failed sleep infinity
systemd-run --unit=wait-watcher.service --service-type=notify systemctl wait wait-gc.service
systemctl is-active wait-watcher.service
INVOCATION_ID="$(systemctl show --property=InvocationID --value wait-watcher.service)"
# Stopping the unit makes it disappear right-away, which "systemctl wait" must notice and report as failure
systemctl stop wait-gc.service
assert_rc 1 timeout 10 systemctl wait wait-watcher.service
journalctl --sync
journalctl -b _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" | grep "has been removed while waiting for it" >/dev/null
systemctl reset-failed wait-watcher.service

# A daemon-reload while waiting removes and re-adds the unit, which must not confuse "systemctl wait"
systemd-run --unit=wait-gc.service --property=CollectMode=inactive-or-failed sleep infinity
systemd-run --unit=wait-watcher.service --service-type=notify systemctl wait wait-gc.service
INVOCATION_ID="$(systemctl show --property=InvocationID --value wait-watcher.service)"
systemctl daemon-reload
systemctl is-active wait-watcher.service
systemctl is-active wait-gc.service
# ... but once the unit is stopped and garbage collected, "systemctl wait" must notice again
systemctl stop wait-gc.service
assert_rc 1 timeout 10 systemctl wait wait-watcher.service
journalctl --sync
journalctl -b _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" | grep "has been removed while waiting for it" >/dev/null
(! journalctl -b _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" | grep "removed during service manager reload" >/dev/null)
systemctl reset-failed wait-watcher.service

# With Ref() allowed again the unit is pinned, and hence not garbage collected before its final state was
# collected, even with an aggressive CollectMode= and a daemon-reload while waiting
rm /etc/dbus-1/system.d/systemd-test-deny-ref.conf
systemctl reload dbus.service

systemd-run --unit=wait-gc.service --property=CollectMode=inactive-or-failed sleep infinity
systemd-run --unit=wait-watcher.service --service-type=notify systemctl wait wait-gc.service
INVOCATION_ID="$(systemctl show --property=InvocationID --value wait-watcher.service)"
systemctl daemon-reload
systemctl is-active wait-watcher.service
systemctl stop wait-gc.service
timeout 10 systemctl wait wait-watcher.service
journalctl --sync
journalctl -b _SYSTEMD_INVOCATION_ID="$INVOCATION_ID" | grep "Finished with result: success" >/dev/null

# Test time-limited scopes
START_SEC=$(date -u '+%s')
(! systemd-run --scope --property=RuntimeMaxSec=3s sleep 30)
END_SEC=$(date -u '+%s')
ELAPSED=$((END_SEC-START_SEC))
[[ "$ELAPSED" -ge 3 ]]
[[ "$ELAPSED" -le 10 ]]

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

# The image boots with systemd.log_level=debug, so the daemon-reload and the 20 cyclic starts
# below make PID1 emit thousands of debug messages per second. Under that burst journald falls
# behind and PID1's journal socket sends time out after 10ms (src/basic/log.c). A timed-out
# message is either dropped outright, since log_struct() ignores the send result, or falls back
# to kmsg, where the structured TRANSACTION_ID= field is lost, so the TRANSACTION_ID= matches
# below cannot find it. Run this section at log level info instead: the asserted messages are
# emitted at err and warning (src/core/transaction.c) and are unaffected.
systemctl log-level info

systemctl daemon-reload

# Let journald drain anything the preceding subtests already queued at debug level, so no
# earlier backlog is still competing with the messages asserted on below.
journalctl --sync

for i in {0..19}; do
    # This intentionally fails with:
    #   Failed to start transaction-cycle0.service: Transaction order is cyclic. See system logs for details.
    systemctl start "transaction-cycle$i.service" || :
done

IDS_FILE="/tmp/TEST-03-JOBS-CYCLE-IDS-$RANDOM"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}' | jq '.runtime.TransactionsWithOrderingCycle' >"$IDS_FILE"

systemctl log-level "$ORIG_LOG_LEVEL"

[[ "$(jq length "$IDS_FILE")" -ge 20 ]]
journalctl --sync
for i in {0..19}; do
    journalctl -b TRANSACTION_ID="$(jq -r ".[$i]" "$IDS_FILE")" --grep "cycle starting with"
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

systemctl start propagatestopto-indirect.target propagatestopto-and-pullin.target
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

systemctl stop fails-on-restart.service

COUNTER_FILE=/tmp/test-03-restart-counter
export FAILURE_FLAG_FILE=/tmp/test-03-restart-failure-flag

assert_rc 3 systemctl --quiet is-active sleep-infinity-restart-normal.service
assert_rc 3 systemctl --quiet is-active sleep-infinity-restart-direct.service
assert_rc 3 systemctl --quiet is-active counter.service
echo 0 >"$COUNTER_FILE"
rm -f "$FAILURE_FLAG_FILE"

systemctl start counter.service
assert_eq "$(cat "$COUNTER_FILE")" "1"
systemctl --quiet is-active sleep-infinity-restart-normal.service
systemctl --quiet is-active sleep-infinity-restart-direct.service
systemctl --quiet is-active counter.service

# RestartMode=direct + restart: explicit restart should get propagated as TRY_RESTART to the still active
# counter.service
systemctl restart sleep-infinity-restart-direct.service
timeout 10 bash -c 'while ! systemctl --quiet is-active counter.service; do sleep .5; done'
assert_eq "$(cat "$COUNTER_FILE")" "2"
[[ ! -f "$FAILURE_FLAG_FILE" ]]

# RestartMode=direct + kill: the fail/inactive state shouldn't get propagated to the counter.service
systemctl kill --signal=KILL sleep-infinity-restart-direct.service
systemctl --quiet is-active counter.service
assert_eq "$(cat "$COUNTER_FILE")" "2"
[[ ! -f "$FAILURE_FLAG_FILE" ]]

# RestartMode=normal + restart: explicit restart should get propagated as TRY_RESTART to the still active
# counter.service
systemctl restart sleep-infinity-restart-normal.service
timeout 10 bash -c 'while ! systemctl --quiet is-active counter.service; do sleep .5; done'
assert_eq "$(cat "$COUNTER_FILE")" "3"
[[ ! -f "$FAILURE_FLAG_FILE" ]]

# RestartMode=normal + kill: the fail/inactive state should get propagated to the counter.service, which in
# turn should be stopped
systemctl kill --signal=KILL sleep-infinity-restart-normal.service
timeout 10 bash -c 'while [[ ! -f $FAILURE_FLAG_FILE ]]; do sleep .5; done'
timeout 10 bash -c 'while systemctl --quiet is-active counter.service; do sleep .5; done'
assert_eq "$(cat "$COUNTER_FILE")" "3"

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

# Test RestartRandomizedDelaySec=

export UNIT_NAME="TEST-03-JOBS-restart-randomized-delay.service"

cat >"/run/systemd/system/$UNIT_NAME" <<EOF
[Service]
Type=simple
ExecStart=false
Restart=on-failure
RestartSec=1
RestartRandomizedDelaySec=1
StartLimitIntervalSec=0
EOF

systemctl daemon-reload

# The option should be parsed and exposed on the bus in usec.
assert_eq "$(systemctl show "$UNIT_NAME" -P RestartRandomizedDelayUSec)" "1s"

# The chosen delay is logged at debug level when the unit enters auto-restart, so we can read it without
# waiting for the delay to elapse.
systemctl log-level debug

get_restart_interval() {
    # Enter auto-restart once, read the logged "<total>|<delay>", then stop again so it never has to elapse.
    systemctl start --no-block "$UNIT_NAME"
    timeout 10 bash -c 'while [[ "$(systemctl show "'"$UNIT_NAME"'" -P SubState)" != "auto-restart" ]]; do sleep .2; done'
    systemctl stop "$UNIT_NAME"
    journalctl --sync
    # needed because of -o pipefail
    { journalctl -q --no-pager -o cat -b -u "$UNIT_NAME" --grep="Next restart interval calculated as" || true; } |
        sed -n 's/.*calculated as: \(.*\) (randomized delay: \(.*\))$/\1|\2/p' | tail -n1
}

# Several samples + "not all equal": two draws could rarely render identically (~1e-6) and falsely fail.
DELAYS=()
TOTALS=()
for _ in {1..4}; do
    IFS='|' read -r total delay <<<"$(get_restart_interval)"
    TOTALS+=("$total")
    DELAYS+=("$delay")
done

systemctl log-level "$ORIG_LOG_LEVEL"

: "Chosen randomized restart delays: ${DELAYS[*]} (totals: ${TOTALS[*]})"
for delay in "${DELAYS[@]}"; do
    assert_neq "$delay" ""
    # Within bound: a value below 1s never renders a bare "<digit>s" token (only ms/us).
    if [[ "$delay" =~ [0-9]s ]]; then
        echo "FAIL: randomized restart delay '$delay' exceeds the configured 1s bound" >&2
        exit 1
    fi
done
# Total must vary, proving the jitter is folded into the armed timer (not merely logged).
all_equal=1
for total in "${TOTALS[@]}"; do
    [[ "$total" == "${TOTALS[0]}" ]] || all_equal=0
done
assert_eq "$all_equal" "0"

touch /testok
