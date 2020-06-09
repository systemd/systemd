#!/usr/bin/env bash

set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

unit=testsuite-38-sleep.service

start_test_service() {
    systemctl daemon-reload
    systemctl start "${unit}"
}

dbus_freeze() {
    local suffix=
    suffix="${1##*.}"

    local name="$(echo ${1%.$suffix} | sed s/-/_2d/g)"
    local object_path="/org/freedesktop/systemd1/unit/${name}_2e${suffix}"

    busctl call \
           org.freedesktop.systemd1 \
           "${object_path}" \
           org.freedesktop.systemd1.Unit \
           Freeze
}

dbus_thaw() {
    local suffix=
    suffix="${1##*.}"

    local name="$(echo ${1%.$suffix} | sed s/-/_2d/g)"
    local object_path="/org/freedesktop/systemd1/unit/${name}_2e${suffix}"

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
    local suffix=
    suffix="${1##*.}"

    local name="$(echo ${1%.$suffix} | sed s/-/_2d/g)"
    local object_path="/org/freedesktop/systemd1/unit/${name}_2e${suffix}"

    busctl get-property \
           org.freedesktop.systemd1 \
           "${object_path}" \
           org.freedesktop.systemd1.Unit \
           CanFreeze
}

check_freezer_state() {
    local suffix=
    suffix="${1##*.}"

    local name="$(echo ${1%.$suffix} | sed s/-/_2d/g)"
    local object_path="/org/freedesktop/systemd1/unit/${name}_2e${suffix}"

    state=$(busctl get-property \
                   org.freedesktop.systemd1 \
                   "${object_path}" \
                   org.freedesktop.systemd1.Unit \
                   FreezerState | cut -d " " -f2 | tr -d '"')

    [ "$state" = "$2" ] || {
        echo "error: unexpected freezer state, expected: $2, actual: $state" >&2
        exit 1
    }
}

check_cgroup_state() {
    grep -q "frozen $2" /sys/fs/cgroup/system.slice/"$1"/cgroup.events
}

test_dbus_api() {
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

test_jobs() {
    local pid_before=
    local pid_after=
    echo "Test that it is possible to apply jobs on frozen units:"

    systemctl start "${unit}"
    dbus_freeze "${unit}"
    check_freezer_state "${unit}" "frozen"

    echo -n "  - restart: "
    pid_before=$(systemctl show -p MainPID "${unit}" --value)
    systemctl restart "${unit}"
    pid_after=$(systemctl show -p MainPID "${unit}" --value)
    [ "$pid_before" != "$pid_after" ] && echo "[ OK ]"

    dbus_freeze "${unit}"
    check_freezer_state "${unit}" "frozen"

    echo -n "  - stop: "
    timeout 5s systemctl stop "${unit}"
    echo "[ OK ]"

    echo
}

test_systemctl() {
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

test_systemctl_show() {
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

test_recursive() {
    local slice="bar.slice"
    local unit="baz.service"

    systemd-run --unit "$unit" --slice "$slice" sleep 3600 >/dev/null 2>&1

    echo "Test recursive freezing:"

    echo -n "  - freeze: "
    systemctl freeze "$slice"
    check_freezer_state "${slice}" "frozen"
    check_freezer_state "${unit}" "frozen"
    grep -q "frozen 1" /sys/fs/cgroup/"${slice}"/cgroup.events
    grep -q "frozen 1" /sys/fs/cgroup/"${slice}"/"${unit}"/cgroup.events
    echo "[ OK ]"

    echo -n "  - thaw: "
    systemctl thaw "$slice"
    check_freezer_state "${unit}" "running"
    check_freezer_state "${slice}" "running"
    grep -q "frozen 0" /sys/fs/cgroup/"${slice}"/cgroup.events
    grep -q "frozen 0" /sys/fs/cgroup/"${slice}"/"${unit}"/cgroup.events
    echo "[ OK ]"

    systemctl stop "$unit"
    systemctl stop "$slice"

    echo
}

test_preserve_state() {
    local slice="bar.slice"
    local unit="baz.service"

    systemd-run --unit "$unit" --slice "$slice" sleep 3600 >/dev/null 2>&1

    echo "Test that freezer state is preserved when recursive freezing is initiated from outside (e.g. by manager up the tree):"

    echo -n "  - freeze from outside: "
    echo 1 > /sys/fs/cgroup/"${slice}"/cgroup.freeze
    # Give kernel some time to freeze the slice
    sleep 1

    # Our state should not be affected
    check_freezer_state "${slice}" "running"
    check_freezer_state "${unit}" "running"

    # However actual kernel state should be frozen
    grep -q "frozen 1" /sys/fs/cgroup/"${slice}"/cgroup.events
    grep -q "frozen 1" /sys/fs/cgroup/"${slice}"/"${unit}"/cgroup.events
    echo "[ OK ]"

    echo -n "  - thaw from outside: "
    echo 0 > /sys/fs/cgroup/"${slice}"/cgroup.freeze
    sleep 1

    check_freezer_state "${unit}" "running"
    check_freezer_state "${slice}" "running"
    grep -q "frozen 0" /sys/fs/cgroup/"${slice}"/cgroup.events
    grep -q "frozen 0" /sys/fs/cgroup/"${slice}"/"${unit}"/cgroup.events
    echo "[ OK ]"

    echo -n "  - thaw from outside while inner service is frozen: "
    systemctl freeze "$unit"
    check_freezer_state "${unit}" "frozen"
    echo 1 > /sys/fs/cgroup/"${slice}"/cgroup.freeze
    echo 0 > /sys/fs/cgroup/"${slice}"/cgroup.freeze
    check_freezer_state "${slice}" "running"
    check_freezer_state "${unit}" "frozen"
    echo "[ OK ]"

    systemctl stop "$unit"
    systemctl stop "$slice"

    echo
}

test -e /sys/fs/cgroup/system.slice/cgroup.freeze && {
    start_test_service
    test_dbus_api
    test_systemctl
    test_systemctl_show
    test_jobs
    test_recursive
    test_preserve_state
}

echo OK > /testok
exit 0
