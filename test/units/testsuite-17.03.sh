#!/usr/bin/env bash

set -ex

test_rule="/run/udev/rules.d/49-test.rules"

setup() {
    mkdir -p "${test_rule%/*}"
    cp -f /etc/udev/udev.conf /etc/udev/udev.conf.bckp
    echo 'KERNEL=="lo", SUBSYSTEM=="net", PROGRAM=="/bin/sleep 60"' > "${test_rule}"
    echo "event_timeout=30" >> /etc/udev/udev.conf
    echo "timeout_signal=SIGABRT" >> /etc/udev/udev.conf

    systemctl restart systemd-udevd.service
}

teardown() {
    set +e

    mv -f /etc/udev/udev.conf.bckp /etc/udev/udev.conf
    rm -f "$test_rule"
    systemctl restart systemd-udevd.service
}

run_test() {
    since="$(date +%T)"

    echo add > /sys/class/net/lo/uevent

    for n in {1..20}; do
        sleep 5
        if coredumpctl --since "$since" --no-legend --no-pager | grep /bin/udevadm ; then
            return 0
        fi
    done

    return 1
}

trap teardown EXIT

setup
run_test

exit 0
