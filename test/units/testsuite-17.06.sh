#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# tests for udev watch

function check_validity() {
    local f ID_OR_HANDLE

    for f in /run/udev/watch/*; do
        ID_OR_HANDLE="$(readlink "$f")"
        test -L "/run/udev/watch/${ID_OR_HANDLE}"
        test "$(readlink "/run/udev/watch/${ID_OR_HANDLE}")" = "$(basename "$f")"
    done
}

function check() {
    for _ in {1..2}; do
        systemctl restart systemd-udevd.service
        udevadm control --ping
        udevadm settle
        check_validity

        for _ in {1..2}; do
            udevadm trigger -w --action add --subsystem-match=block
            check_validity
        done

        for _ in {1..2}; do
            udevadm trigger -w --action change --subsystem-match=block
            check_validity
        done
    done
}

mkdir -p /run/udev/rules.d/

cat >/run/udev/rules.d/00-debug.rules <<EOF
SUBSYSTEM=="block", KERNEL=="sda*", OPTIONS="log_level=debug"
EOF

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="watch"
EOF

check

MAJOR=$(udevadm info /dev/sda | grep -e '^E: MAJOR=' | sed -e 's/^E: MAJOR=//')
MINOR=$(udevadm info /dev/sda | grep -e '^E: MINOR=' | sed -e 's/^E: MINOR=//')
test -L "/run/udev/watch/b${MAJOR}:${MINOR}"

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="nowatch"
EOF

check

MAJOR=$(udevadm info /dev/sda | grep -e '^E: MAJOR=' | sed -e 's/^E: MAJOR=//')
MINOR=$(udevadm info /dev/sda | grep -e '^E: MINOR=' | sed -e 's/^E: MINOR=//')
test ! -e "/run/udev/watch/b${MAJOR}:${MINOR}"

rm /run/udev/rules.d/00-debug.rules
rm /run/udev/rules.d/50-testsuite.rules

udevadm control --reload
systemctl reset-failed systemd-udevd.service

exit 0
