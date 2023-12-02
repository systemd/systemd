#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test for `udevadm control -p`

test_not_property() {
    assert_eq "$(udevadm info --query property --property "$2" --value "$1")" ""
}

test_property() {
    assert_eq "$(udevadm info --query property --property "$2" --value "$1")" "$3"
}

# shellcheck disable=SC2317
cleanup() {
    set +e

    udevadm control -p FOO= -p BAR=

    rm -f "$rules"
}

# Set up a test device
trap cleanup EXIT

rules="/run/udev/rules.d/99-test-17.13.rules"

mkdir -p "${rules%/*}"
cat > "$rules" <<'EOF'
ENV{FOO}=="?*", ENV{PROP_FOO}="$env{FOO}"
ENV{BAR}=="?*", ENV{PROP_BAR}="$env{BAR}"
EOF

udevadm control --reload

test_not_property /dev/null PROP_FOO
test_not_property /dev/null PROP_BAR

: Setting of a property works

udevadm control --property FOO=foo
udevadm trigger --action change --settle /dev/null
test_property /dev/null PROP_FOO foo
test_not_property /dev/null PROP_BAR

: Change of a property works

udevadm control --property FOO=goo
udevadm trigger --action change --settle /dev/null
test_property /dev/null PROP_FOO goo

: Removal of a property works

udevadm control --property FOO=
udevadm trigger --action change --settle /dev/null
test_not_property /dev/null PROP_FOO

: Repeated removal of a property does nothing

udevadm control --property FOO=
udevadm trigger --action change --settle /dev/null
test_not_property /dev/null PROP_FOO

: Multiple properties can be set at once

udevadm control --property FOO=foo --property BAR=bar
udevadm trigger --action change --settle /dev/null
test_property /dev/null PROP_FOO foo
test_property /dev/null PROP_BAR bar

: Multiple setting of the same property is handled correctly

udevadm control --property FOO=foo --property FOO=42
udevadm trigger --action change --settle /dev/null
test_property /dev/null PROP_FOO 42

: Mix of settings and removals of the same property is handled correctly

udevadm control -p FOO= -p FOO=foo -p BAR=car -p BAR=
udevadm trigger --action change --settle /dev/null
test_property /dev/null PROP_FOO foo
test_not_property /dev/null PROP_BAR

exit 0
