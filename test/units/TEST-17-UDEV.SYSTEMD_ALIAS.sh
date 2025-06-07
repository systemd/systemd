#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# This is a test for issue #24518.

mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="mem", KERNEL=="null", OPTIONS="log_level=debug", TAG+="systemd"
SUBSYSTEM=="mem", KERNEL=="null", ACTION=="add",    SYMLINK+="test/symlink-to-null-on-add",    ENV{SYSTEMD_ALIAS}+="/sys/test/alias-to-null-on-add"
SUBSYSTEM=="mem", KERNEL=="null", ACTION=="change", SYMLINK+="test/symlink-to-null-on-change", ENV{SYSTEMD_ALIAS}+="/sys/test/alias-to-null-on-change"
EOF

udevadm control --reload

udevadm trigger --settle --action add /dev/null
for i in {1..20}; do
    ((i > 1)) && sleep .5

    (
        systemctl -q is-active /dev/test/symlink-to-null-on-add
        ! systemctl -q is-active /dev/test/symlink-to-null-on-change
        systemctl -q is-active /sys/test/alias-to-null-on-add
        ! systemctl -q is-active /sys/test/alias-to-null-on-change
    ) && break
done
assert_rc 0 systemctl -q is-active /dev/test/symlink-to-null-on-add
assert_rc 3 systemctl -q is-active /dev/test/symlink-to-null-on-change
assert_rc 0 systemctl -q is-active /sys/test/alias-to-null-on-add
assert_rc 3 systemctl -q is-active /sys/test/alias-to-null-on-change

udevadm trigger --settle --action change /dev/null
for i in {1..20}; do
    ((i > 1)) && sleep .5

    (
        ! systemctl -q is-active /dev/test/symlink-to-null-on-add
        systemctl -q is-active /dev/test/symlink-to-null-on-change
        ! systemctl -q is-active /sys/test/alias-to-null-on-add
        systemctl -q is-active /sys/test/alias-to-null-on-change
    ) && break
done
assert_rc 3 systemctl -q is-active /dev/test/symlink-to-null-on-add
assert_rc 0 systemctl -q is-active /dev/test/symlink-to-null-on-change
assert_rc 3 systemctl -q is-active /sys/test/alias-to-null-on-add
assert_rc 0 systemctl -q is-active /sys/test/alias-to-null-on-change

udevadm trigger --settle --action add /dev/null
for i in {1..20}; do
    ((i > 1)) && sleep .5

    (
        systemctl -q is-active /dev/test/symlink-to-null-on-add
        ! systemctl -q is-active /dev/test/symlink-to-null-on-change
        systemctl -q is-active /sys/test/alias-to-null-on-add
        ! systemctl -q is-active /sys/test/alias-to-null-on-change
    ) && break
done
assert_rc 0 systemctl -q is-active /dev/test/symlink-to-null-on-add
assert_rc 3 systemctl -q is-active /dev/test/symlink-to-null-on-change
assert_rc 0 systemctl -q is-active /sys/test/alias-to-null-on-add
assert_rc 3 systemctl -q is-active /sys/test/alias-to-null-on-change

# cleanup
rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload

exit 0
