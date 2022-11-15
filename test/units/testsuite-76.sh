#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug

echo "foo.bar=42" > /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl /tmp/foo.conf
assert_rc 1 /usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf

echo "-foo.foo=42" > /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf

if ! systemd-detect-virt --quiet --container; then
    ip link add hoge type dummy
    udevadm wait /sys/class/net/hoge

    cat >/tmp/foo.conf <<EOF
net.ipv4.conf.*.drop_gratuitous_arp=1
net.ipv4.*.*.bootp_relay=1
net.ipv4.aaa.*.disable_policy=1
EOF

    echo 0 > /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
    echo 0 > /proc/sys/net/ipv4/conf/hoge/bootp_relay
    echo 0 > /proc/sys/net/ipv4/conf/hoge/disable_policy

    assert_rc 0 /usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge /tmp/foo.conf
    assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
    assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
    assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"
fi

touch /testok
