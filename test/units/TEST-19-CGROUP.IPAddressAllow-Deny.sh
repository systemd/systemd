#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "Skipping $0 as we're not running with the unified cgroup hierarchy."
    exit 0
fi

if systemd-detect-virt --container --quiet; then
    echo "Skipping $0 as we're running on container."
    exit 0
fi

ip netns add test-ns
ip link add test-veth-1 type veth peer test-veth-2
ip link set test-veth-2 netns test-ns
ip link set test-veth-1 up
ip address add 192.0.2.1/24 dev test-veth-1
ip address add 2001:db8::1/64 dev test-veth-1 nodad
ip netns exec test-ns ip link set test-veth-2 up
ip netns exec test-ns ip address add 192.0.2.2/24 dev test-veth-2
ip netns exec test-ns ip address add 2001:db8::2/64 dev test-veth-2 nodad

ping_ok_one() {
    local interface="${1?}"
    local target="${2?}"
    shift 2

    assert_ok systemd-run --wait --pipe "$@" ping -c 1 -W 1 -I "$interface" "$target"
}

ping_fail_one() {
    local interface="${1?}"
    local target="${2?}"
    shift 2

    assert_fail systemd-run --wait --pipe "$@" ping -c 1 -W 1 -I "$interface" "$target"
}

ping_ok() {
    ping_ok_one lo 127.0.0.1 "$@"
    ping_ok_one lo ::1 "$@"
    ping_ok_one test-veth-1 192.0.2.2 "$@"
    ping_ok_one test-veth-1 2001:db8::2 "$@"
}

ping_fail() {
    ping_fail_one lo 127.0.0.1 "$@"
    ping_fail_one lo ::1 "$@"
    ping_fail_one test-veth-1 192.0.2.2 "$@"
    ping_fail_one test-veth-1 2001:db8::2 "$@"
}

ping_ok
ping_ok -p IPAddressDeny=any -p IPAddressDeny=
ping_ok -p IPAddressDeny=any -p IPAddressDeny= -p IPAddressDeny=link-local
ping_ok -p IPAddressDeny=any -p IPAddressAllow=localhost -p IPAddressAllow=192.0.2.0/24 -p IPAddressAllow=2001:db8::/64
ping_ok -p IPAddressDeny=any -p IPAddressAllow=localhost -p IPAddressAllow=192.0.2.0/24 -p IPAddressAllow=2001:db8::/64 \
        -p IPAddressAllow= -p IPAddressAllow=localhost -p IPAddressAllow=192.0.2.0/24 -p IPAddressAllow=2001:db8::/64

ping_fail -p IPAddressDeny=any
ping_fail -p IPAddressDeny=any -p IPAddressDeny= -p IPAddressDeny=localhost -p IPAddressDeny=192.0.2.0/24 -p IPAddressDeny=2001:db8::/64
ping_fail -p IPAddressDeny=any -p IPAddressAllow=localhost -p IPAddressAllow=192.0.2.0/24 -p IPAddressAllow=2001:db8::/64 -p IPAddressAllow=
ping_fail -p IPAddressDeny=any -p IPAddressAllow=localhost -p IPAddressAllow=192.0.2.0/24 -p IPAddressAllow=2001:db8::/64 -p IPAddressAllow= -p IPAddressAllow=link-local

ip link del test-veth-1
ip netns exec test-ns ip link del test-veth-2 || :
ip netns del test-ns
