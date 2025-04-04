#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

create_link_file() {
    name=${1?}

    mkdir -p /run/systemd/network/
    cat >/run/systemd/network/10-test.link <<EOF
[Match]
Kind=dummy
MACAddress=00:50:56:c0:00:18

[Link]
Name=$name
AlternativeName=test1 test2 test3 test4
EOF
    udevadm control --reload
}

udevadm control --log-level=debug

create_link_file test1
ip link add address 00:50:56:c0:00:18 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/test1
output=$(ip link show dev test1)
if ! [[ "$output" =~ altname ]]; then
    echo "alternative name for network interface not supported, skipping test."
    exit 0
fi
assert_not_in "altname test1" "$output"
assert_in "altname test2" "$output"
assert_in "altname test3" "$output"
assert_in "altname test4" "$output"

# By triggering add event, Name= and AlternativeNames= are re-applied
create_link_file test2
udevadm trigger --action add --settle /sys/class/net/test1
udevadm wait --settle --timeout=30 /sys/class/net/test2
output=$(ip link show dev test2)
assert_in "altname test1" "$output"
assert_not_in "altname test2" "$output"
assert_in "altname test3" "$output"
assert_in "altname test4" "$output"

# Name= and AlternativeNames= are not applied on move event
create_link_file test3
udevadm trigger --action move --settle /sys/class/net/test2
udevadm wait --settle --timeout=30 /sys/class/net/test2
output=$(ip link show dev test2)
assert_in "altname test1" "$output"
assert_not_in "altname test2" "$output"
assert_in "altname test3" "$output"
assert_in "altname test4" "$output"

# Test move event triggered by manual renaming
ip link set dev test2 name hoge
udevadm wait --settle --timeout=30 /sys/class/net/hoge
output=$(ip link show dev hoge)
assert_in "altname test1" "$output"
assert_not_in "altname test2" "$output"
assert_in "altname test3" "$output"
assert_in "altname test4" "$output"
assert_not_in "altname hoge" "$output"

# Re-test add event
udevadm trigger --action add --settle /sys/class/net/hoge
udevadm wait --settle --timeout=30 /sys/class/net/test3
output=$(ip link show dev test3)
assert_in "altname test1" "$output"
assert_in "altname test2" "$output"
assert_not_in "altname test3" "$output"
assert_in "altname test4" "$output"
assert_not_in "altname hoge" "$output"

# cleanup
ip link del dev test3

rm -f /run/systemd/network/10-test.link
udevadm control --reload --log-level=info

exit 0
