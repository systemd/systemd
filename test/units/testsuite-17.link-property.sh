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

# cleanup
ip link del dev test1

rm -f /run/systemd/network/10-test.link
rm -rf /run/systemd/network/10-test.link.d
udevadm control --reload --log-level=info

exit 0
