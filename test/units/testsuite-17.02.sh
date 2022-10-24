#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# disable shellcheck warning about '"aaa"' type quotation
# shellcheck disable=SC2016

set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

mkdir -p /run/udev/rules.d/

# test for ID_RENAMING= udev property and device unit state

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="remove", GOTO="hoge_end"
SUBSYSTEM!="net", GOTO="hoge_end"
KERNEL!="hoge", GOTO="hoge_end"

OPTIONS="log_level=debug"

# emulate renaming
ACTION=="online", ENV{ID_RENAMING}="1"

LABEL="hoge_end"
EOF

udevadm control --log-priority=debug --reload --timeout=30

ip link add hoge type dummy
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'

udevadm trigger --action=online --settle /sys/devices/virtual/net/hoge
assert_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "inactive" ]]; do sleep .5; done'

udevadm trigger --action=move --settle /sys/devices/virtual/net/hoge
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'

# test for renaming interface with NAME= (issue #25106)

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="add", GOTO="hoge_end"
SUBSYSTEM!="net", GOTO="hoge_end"

OPTIONS="log_level=debug"

KERNEL=="hoge",  NAME="foobar"
KERNEL=="foobar", NAME="hoge"

LABEL="hoge_end"
EOF

udevadm control --log-priority=debug --reload --timeout=30

# FIXME(?): the 'add' uevent is broadcast as for 'foobar', instead of 'hoge'. Hence, we cannot use --settle here.
# See issue #25115.
udevadm trigger --action=add /sys/devices/virtual/net/hoge
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/foobar
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/foobar)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "active" ]]; do sleep .5; done'

udevadm trigger --action=add /sys/devices/virtual/net/foobar
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "inactive" ]]; do sleep .5; done'

# cleanup
rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload --timeout=30

# test for renaming interface with an external tool (issue #16967)

ip link set hoge name foobar
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/foobar
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "active" ]]; do sleep .5; done'

ip link set foobar name hoge
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "inactive" ]]; do sleep .5; done'

# cleanup
ip link del hoge

exit 0
