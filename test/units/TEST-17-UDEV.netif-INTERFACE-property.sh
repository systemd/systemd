#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

mkdir -p /run/systemd/network/
cat >/run/systemd/network/10-rename-test.link <<EOF
[Match]
OriginalName=testif

[Link]
Name=te!st!if
EOF

udevadm control --reload

# Check if any interfaces originally named with '!' in their name have been renamed unexpectedly.
ip link add 'hoge!foo' type dummy
udevadm wait --settle --timeout=30 '/sys/class/net/hoge!foo'
output=$(udevadm info --query property '/sys/class/net/hoge!foo')
assert_in 'INTERFACE=hoge!foo' "$output"
assert_in 'ID_NET_DRIVER=dummy' "$output"
assert_in 'ID_NET_NAME=hoge!foo' "$output"
assert_not_in 'ID_RENAMING=' "$output"
ip link show dev 'hoge!foo'
ip link del dev 'hoge!foo'

# Check if the interface renamed to include '!' as expected.
ip link add 'testif' type dummy
udevadm wait --settle --timeout=30 '/sys/class/net/te!st!if'
output=$(udevadm info --query property '/sys/class/net/te!st!if')
assert_in 'INTERFACE=te!st!if' "$output"
assert_in 'ID_NET_DRIVER=dummy' "$output"
assert_in 'ID_NET_NAME=te!st!if' "$output"
assert_not_in 'ID_RENAMING=' "$output"
ip link show dev 'te!st!if'
ip link del dev 'te!st!if'

# cleanup
rm -f /run/systemd/network/10-rename-test.link
udevadm control --reload

exit 0
