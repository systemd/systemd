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
    assert_eq "$(busctl get-property org.freedesktop.systemd1 "$1" org.freedesktop.systemd1.Slice "$2")" "u $3"
}

cleanup() {
    systemctl stop testsuite-23.MaxUnits.slice
    rm -f /etc/systemd/system/testsuite-23.MaxUnits.slice.d/maxunits.conf
}

trap cleanup EXIT

: >/failed

systemctl start testsuite-23.MaxUnits.slice

: "Check that DBus property is exported properly"

assert_property "$(get_unit -.slice)" MaxUnits $((2**32 - 1))
slice="$(get_unit testsuite-23.MaxUnits.slice)"
assert_property "$slice" MaxUnits 4
assert_property "$slice" Units 0

: "Check that unit count capping works"

systemd-run --unit testsuite-23.MaxUnits-1.service --slice testsuite-23.MaxUnits.slice sleep infinity
assert_property "$slice" Units 1
systemd-run --unit testsuite-23.MaxUnits-2.service --slice testsuite-23.MaxUnits.slice sleep infinity
assert_property "$slice" Units 2
systemd-run --unit testsuite-23.MaxUnits-3.service --slice testsuite-23.MaxUnits.slice sleep infinity
assert_property "$slice" Units 3
systemd-run --unit testsuite-23.MaxUnits-4.service --slice testsuite-23.MaxUnits.slice sleep infinity
assert_property "$slice" Units 4
(! systemd-run --unit testsuite-23.MaxUnits-5.service --slice testsuite-23.MaxUnits.slice sleep infinity)
systemctl stop testsuite-23.MaxUnits-1.service
assert_property "$slice" Units 3
systemd-run --unit testsuite-23.MaxUnits-5.service --slice testsuite-23.MaxUnits.slice sleep infinity
assert_property "$slice" Units 4
(! systemd-run --unit testsuite-23.MaxUnits-6.service --slice testsuite-23.MaxUnits.slice sleep infinity)

: "Check that the capping is recursive"

systemctl stop testsuite-23.MaxUnits-2.service
assert_property "$slice" Units 3

systemctl start testsuite-23.MaxUnits-child.slice
child_slice="$(get_unit testsuite-23.MaxUnits-child.slice)"
assert_property "$slice" Units 4
assert_property "$child_slice" Units 0
# testsuite-23.MaxUnits-child.slice is not capped itself
assert_property "$child_slice" MaxUnits $((2**32 - 1))

(! systemd-run --slice testsuite-23.MaxUnits-child.slice sleep infinity)
systemctl stop testsuite-23.MaxUnits-3.service
assert_property "$slice" Units 3
systemd-run --slice testsuite-23.MaxUnits-child.slice sleep infinity
assert_property "$slice" Units 4
assert_property "$child_slice" Units 1
(! systemd-run --slice testsuite-23.MaxUnits-child.slice sleep infinity)

: "Check that capping continues to work correctly after daemon-reload"

systemctl daemon-reload

assert_property "$slice" Units 4
(! systemd-run --unit testsuite-23.MaxUnits-6.service --slice testsuite-23.MaxUnits.slice sleep infinity)

: "Check that increasing MaxUnits works"

mkdir -p /etc/systemd/system/testsuite-23.MaxUnits.slice.d
cat > /etc/systemd/system/testsuite-23.MaxUnits.slice.d/maxunits.conf <<EOF
[Slice]
MaxUnits=5
EOF

systemctl daemon-reload

# We can start one more unit now
assert_property "$slice" MaxUnits 5
assert_property "$slice" Units 4
systemd-run --unit testsuite-23.MaxUnits-6.service --slice testsuite-23.MaxUnits.slice sleep infinity
assert_property "$slice" Units 5
(! systemd-run --unit testsuite-23.MaxUnits-7.service --slice testsuite-23.MaxUnits.slice sleep infinity)

: "Check that decreasing MaxUnits works"

rm /etc/systemd/system/testsuite-23.MaxUnits.slice.d/maxunits.conf
systemctl daemon-reload

# Nope, too many units running already
assert_property "$slice" MaxUnits 4
assert_property "$slice" Units 5
(! systemd-run --unit testsuite-23.MaxUnits-7.service --slice testsuite-23.MaxUnits.slice sleep infinity)
systemctl stop testsuite-23.MaxUnits-4.service
# Still not...
assert_property "$slice" Units 4
(! systemd-run --unit testsuite-23.MaxUnits-7.service --slice testsuite-23.MaxUnits.slice sleep infinity)
systemctl stop testsuite-23.MaxUnits-5.service
# Now!
assert_property "$slice" Units 3
systemd-run --unit testsuite-23.MaxUnits-7.service --slice testsuite-23.MaxUnits.slice sleep infinity

: "Check that the capping works for templates too (the original use case)"

systemctl stop testsuite-23.MaxUnits-*

assert_property "$slice" Units 0
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
