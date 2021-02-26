#!/usr/bin/env bash

set -ex
set -o pipefail

setup() {
    systemd-analyze log-level debug
    systemd-analyze log-target console

    for i in `seq 0 3`;
    do
        ip netns del ns${i} || true
        ip link del veth${i} || true
        ip netns add ns${i}
        ip link add veth${i} type veth peer name veth${i}_
        ip link set veth${i}_ netns ns${i}
        ip -n ns${i} link set dev veth${i}_ up
        ip -n ns${i} link set dev lo up
        ip -n ns${i} addr add "192.168.113."$((4*i+1))/30 dev veth${i}_
        ip link set dev veth${i} up
        ip addr add "192.168.113."$((4*i+2))/30 dev veth${i}
    done
}

teardown() {
    set +e

    for i in `seq 0 3`;
    do
        ip netns del ns${i}
        ip link del veth${i}
    done

    systemd-analyze log-level info
}

trap teardown EXIT
setup

systemctl start --wait testsuite-60-1.service
systemctl start --wait testsuite-60-2.service
systemctl start --wait testsuite-60-3.service
systemctl start --wait testsuite-60-4.service
systemctl start --wait testsuite-60-5.service

echo OK > /testok

exit 0