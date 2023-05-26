#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

get_unit() {
    busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnit s -- "$1" \
    | awk '{ print $2; }' | tr -d \"
}

assert_property() {
    assert_eq "$(busctl get-property org.freedesktop.systemd1 "$1" org.freedesktop.systemd1.Slice $2)" "u $3"
}

cleanup() {
    systemctl stop testsuite-23.MaxUnits.slice
}

trap cleanup EXIT

: >/failed

systemctl start testsuite-23.MaxUnits.slice

: Check that DBus property is exported properly

assert_property "$(get_unit -.slice)" MaxUnits $[2**32 - 1]
assert_property "$(get_unit testsuite-23.MaxUnits.slice)" MaxUnits 4

: Check that unit count capping works

systemd-run --unit testsuite-23.MaxUnits-1.service --slice testsuite-23.MaxUnits.slice sleep infinity
systemd-run --unit testsuite-23.MaxUnits-2.service --slice testsuite-23.MaxUnits.slice sleep infinity
systemd-run --unit testsuite-23.MaxUnits-3.service --slice testsuite-23.MaxUnits.slice sleep infinity
systemd-run --unit testsuite-23.MaxUnits-4.service --slice testsuite-23.MaxUnits.slice sleep infinity
(! systemd-run --unit testsuite-23.MaxUnits-5.service --slice testsuite-23.MaxUnits.slice sleep infinity)
systemctl stop testsuite-23.MaxUnits-1.service
systemd-run --unit testsuite-23.MaxUnits-5.service --slice testsuite-23.MaxUnits.slice sleep infinity
(! systemd-run --unit testsuite-23.MaxUnits-6.service --slice testsuite-23.MaxUnits.slice sleep infinity)

: Check that the capping is recursive

systemctl stop testsuite-23.MaxUnits-2.service
systemctl start testsuite-23.MaxUnits-child.slice

# testsuite-23.MaxUnits-child.slice is not capped itself
assert_property "$(get_unit testsuite-23.MaxUnits-child.slice)" MaxUnits $[2**32 - 1]

(! systemd-run --slice testsuite-23.MaxUnits-child.slice sleep infinity)
systemctl stop testsuite-23.MaxUnits-3.service
systemd-run --slice testsuite-23.MaxUnits-child.slice sleep infinity
(! systemd-run --slice testsuite-23.MaxUnits-child.slice sleep infinity)

: Check that the capping works for templates too # the original use case

systemctl stop testsuite-23.MaxUnits-*

systemctl start testsuite-23.MaxUnits@1.service
systemctl start testsuite-23.MaxUnits@2.service
systemctl start testsuite-23.MaxUnits@3.service
systemctl start testsuite-23.MaxUnits@4.service
(! systemctl start testsuite-23.MaxUnits@5.service)
systemctl stop testsuite-23.MaxUnits@1.service
systemctl start testsuite-23.MaxUnits@5.service
(! systemctl start testsuite-23.MaxUnits@6.service)

touch /testok
rm /failed
