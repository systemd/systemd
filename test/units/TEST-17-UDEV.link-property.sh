#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

udevadm control --log-level=debug

mkdir -p /run/systemd/network/
cat >/run/systemd/network/10-test.link <<EOF
[Match]
Kind=dummy
MACAddress=00:50:56:c0:00:19

[Link]
Name=test1
EOF

mkdir /run/systemd/network/10-test.link.d
cat >/run/systemd/network/10-test.link.d/10-override.conf <<EOF
[Link]
Property=HOGE=foo BAR=baz SHOULD_BE_UNSET=unset
UnsetProperty=SHOULD_BE_UNSET
EOF

udevadm control --reload

ip link add address 00:50:56:c0:00:19 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/test1
output=$(udevadm info --query property /sys/class/net/test1)
assert_in "HOGE=foo" "$output"
assert_in "BAR=baz" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

cat >/run/systemd/network/10-test.link.d/11-override.conf <<EOF
[Link]
Property=
Property=HOGE2=foo2 BAR2=baz2 SHOULD_BE_UNSET=unset
ImportProperty=HOGE
EOF

udevadm control --reload

udevadm trigger --settle --action add /sys/class/net/test1
output=$(udevadm info --query property /sys/class/net/test1)
assert_in "HOGE=foo" "$output"
assert_in "HOGE2=foo2" "$output"
assert_not_in "BAR=" "$output"
assert_in "BAR2=baz2" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

# On change event, .link file will not be applied.
udevadm trigger --settle --action change /sys/class/net/test1
output=$(udevadm info --query property /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

### testing with udevadm test-builtin
output=$(udevadm test-builtin --action add net_setup_link /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_in "HOGE2=foo2" "$output"
assert_not_in "BAR=" "$output"
assert_in "BAR2=baz2" "$output"
assert_in "SHOULD_BE_UNSET=" "$output"  # this is expected, as an empty assignment is also logged.
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

# check that test-builtin command does not update udev database.
output=$(udevadm info --query property /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

output=$(udevadm test-builtin --action change net_setup_link /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

output=$(udevadm info --query property /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

### testing with udevadm test
output=$(udevadm test --action add /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_in "HOGE2=foo2" "$output"
assert_not_in "BAR=" "$output"
assert_in "BAR2=baz2" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

# check that test command does not update udev database.
output=$(udevadm info --query property /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

output=$(udevadm test --action change /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

output=$(udevadm info --query property /sys/class/net/test1)
assert_not_in "HOGE=" "$output"
assert_not_in "HOGE2=" "$output"
assert_not_in "BAR=" "$output"
assert_not_in "BAR2=" "$output"
assert_not_in "SHOULD_BE_UNSET=" "$output"
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test.link" "$output"
assert_in "ID_NET_LINK_FILE_DROPINS=/run/systemd/network/10-test.link.d/10-override.conf:/run/systemd/network/10-test.link.d/11-override.conf" "$output"
assert_in "ID_NET_NAME=test1" "$output"

# test for specifiers
cat >/run/systemd/network/10-test.link.d/12-override.conf <<EOF
[Link]
Property=
Property=LINK_VERSION=%v
EOF

udevadm control --reload

output=$(udevadm test --action add /sys/class/net/test1)
assert_in "LINK_VERSION=$(uname -r | sed 's/\+/\\+/g')" "$output"

udevadm trigger --settle --action add /sys/class/net/test1
output=$(udevadm info --query property /sys/class/net/test1)
assert_in "LINK_VERSION=$(uname -r | sed 's/\+/\\+/g')" "$output"

# test for constant properties
cat >/run/systemd/network/10-test.link.d/13-override.conf <<EOF
[Link]
Property=
Property=ACTION=foo IFINDEX=bar
UnsetProperty=DEVPATH
EOF

udevadm control --reload

output=$(udevadm test --action add /sys/class/net/test1)
assert_in "ACTION=add" "$output"
assert_not_in "ACTION=foo" "$output"
assert_in "IFINDEX=" "$output"
assert_not_in "IFINDEX=bar" "$output"
assert_in "DEVPATH=" "$output"

udevadm trigger --settle --action add /sys/class/net/test1
output=$(udevadm info --query property /sys/class/net/test1)
assert_not_in "ACTION=foo" "$output"
assert_in "IFINDEX=" "$output"
assert_not_in "IFINDEX=bar" "$output"
assert_in "DEVPATH=" "$output"

# cleanup
ip link del dev test1

rm -f /run/systemd/network/10-test.link
rm -rf /run/systemd/network/10-test.link.d
udevadm control --reload --log-level=info

exit 0
