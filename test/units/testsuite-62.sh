#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

setup() {
    systemd-analyze log-level debug

    for i in {0..3};
    do
        ip netns del "ns${i}" || true
        ip link del "veth${i}" || true
        ip netns add "ns${i}"
        ip link add "veth${i}" type veth peer name "veth${i}_"
        ip link set "veth${i}_" netns "ns${i}"
        ip -n "ns${i}" link set dev "veth${i}_" up
        ip -n "ns${i}" link set dev lo up
        ip -n "ns${i}" addr add "192.168.113."$((4*i+1))/30 dev "veth${i}_"
        ip link set dev "veth${i}" up
        ip link property add dev "veth${i}" altname "veth${i}-altname-with-more-than-15-chars"
        ip addr add "192.168.113."$((4*i+2))/30 dev "veth${i}"
    done
}

# shellcheck disable=SC2317
teardown() {
    set +e

    for i in {0..3}; do
        ip netns del "ns${i}"
        ip link del "veth${i}"
    done

    systemd-analyze log-level info
}

KERNEL_VERSION="$(uname -r)"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
KERNEL_MINOR="${KERNEL_VERSION#"$KERNEL_MAJOR".}"
KERNEL_MINOR="${KERNEL_MINOR%%.*}"

MAJOR_REQUIRED=5
MINOR_REQUIRED=7

if [[ "$KERNEL_MAJOR" -lt $MAJOR_REQUIRED || ("$KERNEL_MAJOR" -eq $MAJOR_REQUIRED && "$KERNEL_MINOR" -lt $MINOR_REQUIRED) ]]; then
    echo "kernel is not 5.7+" >>/skipped
    exit 0
fi

if systemctl --version | grep -q -F -- "-BPF_FRAMEWORK"; then
    echo "bpf-framework is disabled" >>/skipped
    exit 0
fi

trap teardown EXIT
setup

systemctl start --wait testsuite-62-1.service
systemctl start --wait testsuite-62-2.service
systemctl start --wait testsuite-62-3.service
systemctl start --wait testsuite-62-4.service
systemctl start --wait testsuite-62-5.service

touch /testok
