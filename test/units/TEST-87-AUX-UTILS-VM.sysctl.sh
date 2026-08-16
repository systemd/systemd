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

assert_rc 1 /usr/lib/systemd/systemd-sysctl --inline
assert_rc 0 /usr/lib/systemd/systemd-sysctl --inline "   foo.bar=42" "#comment" "   "
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

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge --verify - <<EOF
net.ipv4.conf.*.drop_gratuitous_arp=1
net.ipv4.*.*.bootp_relay=1
net.ipv4.aaa.*.disable_policy=1
EOF
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

##########################
# --install= and --revert=
##########################
(! /usr/lib/systemd/systemd-sysctl --install=)
(! /usr/lib/systemd/systemd-sysctl --install=.)
(! /usr/lib/systemd/systemd-sysctl --install=.conf)
(! /usr/lib/systemd/systemd-sysctl --install=aaa/hoge.conf)
(! /usr/lib/systemd/systemd-sysctl --install=../hoge.conf)
(! /usr/lib/systemd/systemd-sysctl --revert=)
(! /usr/lib/systemd/systemd-sysctl --revert=.)
(! /usr/lib/systemd/systemd-sysctl --revert=.conf)
(! /usr/lib/systemd/systemd-sysctl --revert=aaa/hoge.conf)
(! /usr/lib/systemd/systemd-sysctl --revert=../hoge.conf)

# --install requires positional arguments
(! /usr/lib/systemd/systemd-sysctl --install=foo)

# Do not create an empty conf file.
/usr/lib/systemd/systemd-sysctl \
    --prefix=/net/ipv4/conf/hoge --install=foo --inline "# comment only"
[[ ! -e /run/sysctl.d/foo.conf ]]

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

/usr/lib/systemd/systemd-sysctl \
    --prefix=/net/ipv4/conf/hoge --install=foo --inline -- \
    '# This argument should be ignored' \
    'net.ipv4.conf.*.drop_gratuitous_arp=1' \
    'net.ipv4.*.*.bootp_relay=1' \
    '-net.ipv4.conf.all.bootp_relay' \
    '-net.ipv4.aaa.*.disable_policy=1' \
    '# Arguments with unsafe characters should be ignored' \
    $'foo\nbar.hoge=1' \
    $'foo.bar=4\n2'

assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

diff /run/sysctl.d/foo.conf - <<EOF
# This is generated by systemd-sysctl.
net/ipv4/conf/*/drop_gratuitous_arp = 1
net/ipv4/*/*/bootp_relay = 1
-net/ipv4/conf/all/bootp_relay
-net/ipv4/aaa/*/disable_policy = 1
EOF

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge --install=foo - <<EOF
# This line should be ignored
net.ipv4.conf.*.drop_gratuitous_arp=1
net.ipv4.*.*.bootp_relay=1
-net.ipv4.conf.all.bootp_relay
-net.ipv4.aaa.*.disable_policy=1
foo.bar=42
EOF

assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

diff /run/sysctl.d/foo.conf - <<EOF
# This is generated by systemd-sysctl.
net/ipv4/conf/*/drop_gratuitous_arp = 1
net/ipv4/*/*/bootp_relay = 1
-net/ipv4/conf/all/bootp_relay
-net/ipv4/aaa/*/disable_policy = 1
foo/bar = 42
EOF

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

# Verify that the installed .conf file is loaded.
/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

# Check that the installed .conf file can be overridden.
/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/hoge --install=foo /run/sysctl.d/foo.conf - <<EOF
net.ipv4.conf.*.drop_gratuitous_arp=0
net.ipv4.conf.hoge.disable_policy=1
EOF
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "0"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "1"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "1"

diff /run/sysctl.d/foo.conf - <<EOF
# This is generated by systemd-sysctl.
net/ipv4/*/*/bootp_relay = 1
-net/ipv4/conf/all/bootp_relay
-net/ipv4/aaa/*/disable_policy = 1
foo/bar = 42
net/ipv4/conf/*/drop_gratuitous_arp = 0
net/ipv4/conf/hoge/disable_policy = 1
EOF

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

/usr/lib/systemd/systemd-sysctl --revert=foo --prefix=/net/ipv4/conf/hoge
[[ ! -e /run/sysctl.d/foo.conf ]]

# Assume that no installed sysctl .conf files modify these variables.
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "0"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "0"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"

echo 0 >/proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp
echo 0 >/proc/sys/net/ipv4/conf/hoge/bootp_relay
echo 0 >/proc/sys/net/ipv4/conf/hoge/disable_policy

# Try again to test when foo.conf does not exist
/usr/lib/systemd/systemd-sysctl --revert=foo --prefix=/net/ipv4/conf/hoge

assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/drop_gratuitous_arp)" "0"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/bootp_relay)" "0"
assert_eq "$(cat /proc/sys/net/ipv4/conf/hoge/disable_policy)" "0"
