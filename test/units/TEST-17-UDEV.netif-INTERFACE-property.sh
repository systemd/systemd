#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

udevadm control --log-level=debug

ip link add 'hoge!foo' type dummy
udevadm wait --settle --timeout=30 '/sys/class/net/hoge!foo'
output=$(udevadm info --query property /sys/class/net/hoge!foo)
assert_in "INTERFACE=hoge!foo" "$output"
assert_in "ID_NET_DRIVER=dummy" "$output"
assert_in "ID_NET_NAME=hoge!foo" "$output"
assert_not_in "ID_RENAMING=" "$output"
ip link show dev 'hoge!foo'

# cleanup
ip link del dev 'hoge!foo'
udevadm control --log-level=info

exit 0
