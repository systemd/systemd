#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

test_rule="/run/udev/rules.d/49-test.rules"

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

    mv -f /etc/udev/udev.conf.bckp /etc/udev/udev.conf
    rm -f "$test_rule"
    systemctl restart systemd-udevd.service
}

run_test() {
    since="$(date '+%F %T')"

    SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --settle --action add /dev/null

    for _ in {1..20}; do
        if coredumpctl --since "$since" --no-legend --no-pager | grep /bin/udevadm ; then
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
