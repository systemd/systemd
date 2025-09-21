#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

TMPDIR=
TEST_RULE="/run/udev/rules.d/49-test.rules"
TEST_CONF="/run/udev/udev.conf.d/test-17.conf"
KILL_PID=

setup() {
    mkdir -p "${TEST_RULE%/*}"
    mkdir -p /run/udev/udev.conf.d

    cat >"${TEST_RULE}" <<EOF
ACTION!="add", GOTO="test_end"
SUBSYSTEM!="mem", GOTO="test_end"
KERNEL!="null", GOTO="test_end"

OPTIONS="log_level=debug"
PROGRAM=="/usr/bin/touch /tmp/test-udev-marker"
PROGRAM!="/usr/bin/sleep 60", ENV{PROGRAM_RESULT}="KILLED"

LABEL="test_end"
EOF
    cat >"$TEST_CONF" <<EOF
event_timeout=10
timeout_signal=SIGABRT
EOF

    systemctl reload systemd-udevd.service
}

# shellcheck disable=SC2317
teardown() {
    set +e

    if [[ -n "$KILL_PID" ]]; then
        kill "$KILL_PID"
    fi

    rm -rf "$TMPDIR"
    rm -f "$TEST_RULE" "$TEST_CONF"
    systemctl reload systemd-udevd.service
}

run_test_timeout() {
    TMPDIR=$(mktemp -d -p /tmp udev-tests.XXXXXX)
    udevadm monitor --udev --property --subsystem-match=mem >"$TMPDIR"/monitor.txt &
    KILL_PID="$!"

    SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --action add /dev/null

    for _ in {1..40}; do
        if grep -q 'PROGRAM_RESULT=KILLED' "$TMPDIR"/monitor.txt; then
            sleep .5
            kill "$KILL_PID"
            KILL_PID=

            cat "$TMPDIR"/monitor.txt
            (! grep -q 'UDEV_WORKER_FAILED=1' "$TMPDIR"/monitor.txt)
            (! grep -q 'UDEV_WORKER_SIGNAL=6' "$TMPDIR"/monitor.txt)
            (! grep -q 'UDEV_WORKER_SIGNAL_NAME=ABRT' "$TMPDIR"/monitor.txt)
            grep -q 'PROGRAM_RESULT=KILLED' "$TMPDIR"/monitor.txt
            rm -rf "$TMPDIR"
            return 0
        fi
        sleep .5
    done

    return 1
}

run_test_killed() {
    local killed=

    TMPDIR=$(mktemp -d -p /tmp udev-tests.XXXXXX)
    udevadm monitor --udev --property --subsystem-match=mem >"$TMPDIR"/monitor.txt &
    KILL_PID="$!"

    rm -f /tmp/test-udev-marker
    SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --action add /dev/null

    for _ in {1..40}; do
        if [[ -z "$killed" ]]; then
            if [[ -e /tmp/test-udev-marker ]]; then
                killall --signal ABRT --regexp udev-worker
                killed=1
            fi
        elif grep -q 'UDEV_WORKER_FAILED=1' "$TMPDIR"/monitor.txt; then
            sleep .5
            kill "$KILL_PID"
            KILL_PID=

            cat "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_FAILED=1' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_SIGNAL=6' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_SIGNAL_NAME=ABRT' "$TMPDIR"/monitor.txt
            (! grep -q 'PROGRAM_RESULT=KILLED' "$TMPDIR"/monitor.txt)
            rm -rf "$TMPDIR"
            return 0
        fi
        sleep .5
    done

    return 1
}

trap teardown EXIT

setup
run_test_timeout
run_test_killed

exit 0
