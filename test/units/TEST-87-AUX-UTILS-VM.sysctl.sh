#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

echo "foo.bar=42" >/tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl /tmp/foo.conf
assert_rc 1 /usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf

echo "-foo.foo=42" >/tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl /tmp/foo.conf
assert_rc 0 /usr/lib/systemd/systemd-sysctl --strict /tmp/foo.conf

assert_rc 0 /usr/lib/systemd/systemd-sysctl --inline "foo.bar=42"
assert_rc 1 /usr/lib/systemd/systemd-sysctl --inline --strict "foo.bar=42"
assert_rc 0 /usr/lib/systemd/systemd-sysctl --inline -- "-foo.bar=42"
assert_rc 0 /usr/lib/systemd/systemd-sysctl --inline --strict -- "-foo.bar=42"

/usr/lib/systemd/systemd-sysctl - <<EOF
foo.bar=42
EOF
(! /usr/lib/systemd/systemd-sysctl --strict - <<EOF
foo.bar=42
EOF
)
/usr/lib/systemd/systemd-sysctl - <<EOF
-foo.bar=42
EOF
/usr/lib/systemd/systemd-sysctl --strict - <<EOF
-foo.bar=42
EOF

ip link add hoge type dummy
trap 'ip link del hoge' EXIT
udevadm wait --timeout=30 /sys/class/net/hoge

cat >/tmp/foo.conf <<EOF
net.ipv4.conf.*.drop_gratuitous_arp=1
net.ipv4.*.*.bootp_relay=1
net.ipv4.aaa.*.disable_policy=1
EOF

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

assert_rc 0 /usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge /tmp/foo.conf
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

assert_rc 0 /usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge --inline \
          'net.ipv4.conf.*.drop_gratuitous_arp=1' \
          'net.ipv4.*.*.bootp_relay=1' \
          'net.ipv4.aaa.*.disable_policy=1'
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge - <<EOF
net.ipv4.conf.*.drop_gratuitous_arp=1
net.ipv4.*.*.bootp_relay=1
net.ipv4.aaa.*.disable_policy=1
EOF
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"
