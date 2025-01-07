#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2317
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

if [[ -n "${COVERAGE_BUILD_DIR:-}" ]]; then
    echo "TEST-38-FREEZER freezes when systemd is built with coverage enabled" >/skipped
    exit 77
fi

systemd-analyze log-level debug

unit=TEST-38-FREEZER-sleep.service

start_test_service() {
    systemctl daemon-reload
    systemctl start "${unit}"
}

dbus_freeze() {
    local name object_path suffix

    suffix="${1##*.}"
    name="${1%".$suffix"}"
    object_path="/org/freedesktop/systemd1/unit/${name//-/_2d}_2e${suffix}"

    busctl call \
           org.freedesktop.systemd1 \
           "${object_path}" \
           org.freedesktop.systemd1.Unit \
           Freeze
}

dbus_thaw() {
    local name object_path suffix

    suffix="${1##*.}"
    name="${1%".$suffix"}"
    object_path="/org/freedesktop/systemd1/unit/${name//-/_2d}_2e${suffix}"

    busctl call \
           org.freedesktop.systemd1 \
           "${object_path}" \
           org.freedesktop.systemd1.Unit \
           Thaw
}

dbus_freeze_unit() {
    busctl call \
           org.freedesktop.systemd1 \
           /org/freedesktop/systemd1 \
           org.freedesktop.systemd1.Manager \
           FreezeUnit \
           s \
           "$1"
}

dbus_thaw_unit() {
    busctl call \
           org.freedesktop.systemd1 \
           /org/freedesktop/systemd1 \
           org.freedesktop.systemd1.Manager \
           ThawUnit \
           s \
           "$1"
}

dbus_can_freeze() {
    local name object_path suffix

    suffix="${1##*.}"
    name="${1%".$suffix"}"
    object_path="/org/freedesktop/systemd1/unit/${name//-/_2d}_2e${suffix}"

    busctl get-property \
           org.freedesktop.systemd1 \
           "${object_path}" \
           org.freedesktop.systemd1.Unit \
           CanFreeze
}

check_freezer_state() {
    local name object_path suffix

    suffix="${1##*.}"
    name="${1%".$suffix"}"
    object_path="/org/freedesktop/systemd1/unit/${name//-/_2d}_2e${suffix}"

    for _ in {0..10}; do
        state=$(busctl get-property \
                       org.freedesktop.systemd1 \
                       "${object_path}" \
                       org.freedesktop.systemd1.Unit \
                       FreezerState | cut -d " " -f2 | tr -d '"')

        # Ignore the intermediate freezing & thawing states in case we check
        # the unit state too quickly
        [[ "$state" =~ ^(freezing|thawing) ]] || break
        sleep .5
    done

    [ "$state" = "$2" ] || {
        echo "error: unexpected freezer state, expected: $2, actual: $state" >&2
        exit 1
    }
}

check_cgroup_state() {
    # foo.unit -> /system.slice/foo.unit/
    # foo.slice/ -> /foo.slice/./
    # foo.slice/foo.unit -> /foo.slice/foo.unit/
    local slice unit
    unit="${1##*/}"
    slice="${1%"$unit"}"
    slice="${slice%/}"
    grep -q "frozen $2" /sys/fs/cgroup/"${slice:-system.slice}"/"${unit:-.}"/cgroup.events
}

testcase_dbus_api() {
    echo "Test that DBus API works:"
    echo -n "  - Freeze(): "
    dbus_freeze "${unit}"
    check_freezer_state "${unit}" "frozen"
    check_cgroup_state "$unit" 1
    echo "[ OK ]"

    echo -n "  - Thaw(): "
    dbus_thaw "${unit}"
    check_freezer_state "${unit}" "running"
    check_cgroup_state "$unit" 0
    echo "[ OK ]"

    echo -n "  - FreezeUnit(): "
    dbus_freeze_unit "${unit}"
    check_freezer_state "${unit}" "frozen"
    check_cgroup_state "$unit" 1
    echo "[ OK ]"

    echo -n "  - ThawUnit(): "
    dbus_thaw_unit "${unit}"
    check_freezer_state "${unit}" "running"
    check_cgroup_state "$unit" 0
    echo "[ OK ]"

    echo -n "  - CanFreeze(): "
    output=$(dbus_can_freeze "${unit}")
    [ "$output" = "b true" ]
    echo "[ OK ]"

    echo
}

testcase_systemctl() {
    echo "Test that systemctl freeze/thaw verbs:"

    systemctl start "$unit"

    echo -n "  - freeze: "
    systemctl freeze "$unit"
    check_freezer_state "${unit}" "frozen"
    check_cgroup_state "$unit" 1
    # Freezing already frozen unit should be NOP and return quickly
    timeout 3s systemctl freeze "$unit"
    echo "[ OK ]"

    echo -n "  - thaw: "
    systemctl thaw "$unit"
    check_freezer_state "${unit}" "running"
    check_cgroup_state "$unit" 0
    # Likewise thawing already running unit shouldn't block
    timeout 3s systemctl thaw "$unit"
    echo "[ OK ]"

    systemctl stop "$unit"

    echo
}

testcase_systemctl_show() {
    echo "Test systemctl show integration:"

    systemctl start "$unit"

    echo -n "  - FreezerState property: "
    state=$(systemctl show -p FreezerState --value "$unit")
    [ "$state" = "running" ]
    systemctl freeze "$unit"
    state=$(systemctl show -p FreezerState --value "$unit")
    [ "$state" = "frozen" ]
    systemctl thaw "$unit"
    echo "[ OK ]"

    echo -n "  - CanFreeze property: "
    state=$(systemctl show -p CanFreeze --value "$unit")
    [ "$state" = "yes" ]
    echo "[ OK ]"

    systemctl stop "$unit"
    echo
}

testcase_recursive() {
    local slice="bar.slice"
    local unit="baz.service"

    systemd-run --unit "$unit" --slice "$slice" sleep 3600 >/dev/null 2>&1

    echo "Test recursive freezing:"

    echo -n "  - freeze/thaw parent: "
    systemctl freeze "$slice"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen-by-parent"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$slice"
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "running"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 0
    echo "[ OK ]"

    echo -n "  - child freeze/thaw during frozen parent: "
    systemctl freeze "$slice"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen-by-parent"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl freeze "$unit"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$unit"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen-by-parent"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$slice"
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "running"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 0
    echo "[ OK ]"

    echo -n "  - pre-frozen child not thawed by parent: "
    systemctl freeze "$unit"
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 1
    systemctl freeze "$slice"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$slice"
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 1
    echo "[ OK ]"

    echo -n "  - pre-frozen child demoted and thawed by parent: "
    systemctl freeze "$slice"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$unit"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen-by-parent"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$slice"
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "running"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 0
    echo "[ OK ]"

    echo -n "  - child promoted and not thawed by parent: "
    systemctl freeze "$slice"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen-by-parent"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl freeze "$unit"
    check_freezer_state "$slice" "frozen"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    systemctl thaw "$slice"
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "frozen"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 1
    echo "[ OK ]"

    echo -n "  - can't stop a frozen unit: "
    (! systemctl -q stop "$unit" )
    echo "[ OK ]"
    systemctl thaw "$unit"

    systemctl stop "$unit"
    systemctl stop "$slice"

    echo
}

testcase_preserve_state() {
    local slice="bar.slice"
    local unit="baz.service"

    systemd-run --unit "$unit" --slice "$slice" sleep 3600 >/dev/null 2>&1

    echo "Test that freezer state is preserved when recursive freezing is initiated from outside (e.g. by manager up the tree):"

    echo -n "  - freeze from outside: "
    echo 1 >/sys/fs/cgroup/"$slice"/cgroup.freeze
    # Give kernel some time to freeze the slice
    sleep 1

    # Our state should not be affected
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "running"

    # However actual kernel state should be frozen
    check_cgroup_state "$slice/" 1
    check_cgroup_state "$slice/$unit" 1
    echo "[ OK ]"

    echo -n "  - thaw from outside: "
    echo 0 >/sys/fs/cgroup/"$slice"/cgroup.freeze
    sleep 1

    check_freezer_state "$unit" "running"
    check_freezer_state "$slice" "running"
    check_cgroup_state "$slice/" 0
    check_cgroup_state "$slice/$unit" 0
    echo "[ OK ]"

    echo -n "  - thaw from outside while inner service is frozen: "
    systemctl freeze "$unit"
    check_freezer_state "$unit" "frozen"
    echo 1 >/sys/fs/cgroup/"$slice"/cgroup.freeze
    echo 0 >/sys/fs/cgroup/"$slice"/cgroup.freeze
    check_freezer_state "$slice" "running"
    check_freezer_state "$unit" "frozen"
    echo "[ OK ]"

    systemctl thaw "$unit"
    systemctl stop "$unit"
    systemctl stop "$slice"

    echo
}

if [[ -e /sys/fs/cgroup/system.slice/cgroup.freeze ]]; then
    start_test_service
    run_testcases
fi

touch /testok
