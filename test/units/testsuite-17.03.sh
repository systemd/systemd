#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

test_rule="/run/udev/rules.d/49-test.rules"
KILL_PID=

setup() {
    mkdir -p "${test_rule%/*}"
    cp -f /etc/udev/udev.conf /etc/udev/udev.conf.bckp
    cat >"${test_rule}" <<EOF
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", PROGRAM=="/bin/sleep 60"
EOF
    cat >>/etc/udev/udev.conf <<EOF
event_timeout=10
timeout_signal=SIGABRT
EOF

    systemctl restart systemd-udevd.service
}

teardown() {
    set +e

    if [[ -n "$KILL_PID" ]]; then
        kill "$KILL_PID"
    fi

    rm -rf "$TMPDIR"

    mv -f /etc/udev/udev.conf.bckp /etc/udev/udev.conf
    rm -f "$test_rule"
    systemctl restart systemd-udevd.service
}

run_test() {
    local since

    since="$(date '+%F %T')"

    TMPDIR=$(mktemp -d -p /tmp udev-tests.XXXXXX)
    udevadm monitor --udev --property --subsystem-match=mem >"$TMPDIR"/monitor.txt &
    KILL_PID="$!"

    SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --action add /dev/null

    for _ in {1..40}; do
        if coredumpctl --since "$since" --no-legend --no-pager | grep /bin/udevadm ; then
            kill "$KILL_PID"
            KILL_PID=

            cat "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_FAILED=1' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_SIGNAL=6' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_SIGNAL_NAME=ABRT' "$TMPDIR"/monitor.txt
            return 0
        fi
        sleep .5
    done

    return 1
}

trap teardown EXIT

setup
run_test

exit 0
