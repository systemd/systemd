#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

RULE=/run/udev/rules.d/99-udevtest-device-state.rules

check_state() {
    local unit=${1:?}
    local activestate=${2:?}
    local substate=${3:?}
    local syspath=${4:-}

    assert_eq "$(systemctl show -q --property=ActiveState --value "$unit")" "$activestate"
    assert_eq "$(systemctl show -q --property=SubState --value "$unit")" "$substate"

    if [[ -n "$syspath" ]]; then
        assert_eq "$(systemctl show -q --property=SysFSPath --value "$unit")" "$syspath"
    fi
}

wait_for_inactive() {
    local unit=${1:?}

    # Do not use 'systemctl stop foo.device' to wait for the device unit to become inactive.
    # Unlike 'systemctl start foo.device', which waits for the device unit to become active,
    # 'systemctl stop foo.device' also kills device units with the same sysfs path and
    # the units that depend on these device units.

    # shellcheck disable=SC2016
    timeout 30 bash -c 'until [[ "$(systemctl show -q --property=ActiveState --value '"$unit"')" == inactive ]]; do sleep .5; done'
}

start_bound_service() {
    local path=${1:?}
    local name=${path##*/}
    local escaped

    escaped=$(systemd-escape --path "$path")
    escaped=${escaped//\\/\\\\} # escape backslash, as systemd-run unescapes it.

    systemd-run \
        -p After="${escaped}.device" \
        -p BindsTo="${escaped}.device" \
        -u "testsleep-${name}.service" \
        sleep 1h

    check_state "testsleep-${name}.service" active running
}

loopdev_setup() {
    local dev name=udevtest-${1:?}
    local -n ret=${2:?}

    if [[ -f "$RULE" ]]; then
        rm "$RULE"
        udevadm control --reload
    fi

    truncate -s 30m "/tmp/${name}.img"
    mkfs.ext4 -L "${name}-fs1" "/tmp/${name}.img"
    sfdisk --wipe=always "/tmp/${name}.img" <<EOF
label:gpt

name="${name}-part1"
EOF
    dev=$(losetup -P --show -f "/tmp/${name}.img")
    udevadm settle --timeout=30

    # shellcheck disable=SC2034
    ret="$dev"
}

# shellcheck disable=SC2034
loopdev_init_vars() {
    local dev=${1:?}
    local -n ret_part_devname=${2:?} ret_part_syspath=${3:?} ret_part_name=${4:?}

    ret_part_devname="${dev}"p1
    ret_part_syspath=/sys/devices/virtual/block/"${dev##*/}"/"${dev##*/}"p1
    ret_part_name="${dev##*/}"p1
}

loopdev_prepare() {
    local dev_a=${1:?}
    local dev_b=${2:?}
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_a}", \
  OPTIONS="link_priority=10", \
  SYMLINK+="udevtest/a1", SYMLINK+="udevtest/a2", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_b}", \
  SYMLINK+="udevtest/b1", SYMLINK+="udevtest/b2", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle "$part_devname_a" "$part_devname_b"
    systemctl start /dev/udevtest/a1
    systemctl start /dev/udevtest/b1

    # By syspath
    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    # By device node
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"
    # By devlink
    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 active plugged "$part_syspath_a"
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_a"

    start_bound_service /dev/udevtest/a1
    start_bound_service /dev/udevtest/a2
    start_bound_service /dev/udevtest/b1
    start_bound_service /dev/udevtest/b2
    start_bound_service /dev/udevtest/x1
    start_bound_service /dev/udevtest/x2
}

loopdev_remove() {
    local dev=${1:?}
    local alias_name=${2:?}
    local part_devname part_syspath
    # shellcheck disable=SC2034
    local part_name

    loopdev_init_vars "$dev" part_devname part_syspath part_name

    losetup -d "$dev"
    udevadm settle --timeout=30
    wait_for_inactive "$part_syspath"

    check_state "$part_syspath" inactive dead
    check_state "$part_devname" inactive dead

    check_state /dev/udevtest/"$alias_name"1 inactive dead
    check_state /dev/udevtest/"$alias_name"2 inactive dead
    check_state /dev/udevtest/"$alias_name"3 inactive dead

    check_state testsleep-"$alias_name"1.service inactive dead
    check_state testsleep-"$alias_name"2.service inactive dead
}

loopdev_remove_all() {
    local dev_a=${1:?}
    local dev_b=${2:?}

    loopdev_remove "$dev_a" a
    loopdev_remove "$dev_b" b

    check_state /dev/udevtest/x1 inactive dead
    check_state /dev/udevtest/x2 inactive dead
    check_state /dev/udevtest/x3 inactive dead

    check_state testsleep-x1.service inactive dead
    check_state testsleep-x2.service inactive dead
}

loopdev_get_udev_db() {
    local dev=${1:?}
    local devnum

    devnum=$(stat -c '%Hr:%Lr' "$dev")
    echo /run/udev/data/b"$devnum"
}

loopdev_emulate_switching_root() {
    local dev_a=${1:?}
    local dev_b=${2:?}
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_prepare "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # Emulate switching-root from initrd to host system by removing the udev database,
    # which is typically done by udevadm info --cleanup-db. If the database is removed,
    # the active device units enter the activating (tentative) state.
    rm -f "$(loopdev_get_udev_db "$part_devname_a")"
    rm -f "$(loopdev_get_udev_db "$part_devname_b")"
    rm -rf /run/udev/links/udevtest*

    # Also remove devlinks here. Otherwise, the device units for the devlinks left over from
    # before switching-root will not be removed.
    rm -rf /dev/udevtest

    systemctl daemon-reload

    check_state "$part_syspath_a" activating tentative "$part_syspath_a"
    check_state "$part_syspath_b" activating tentative "$part_syspath_b"
    check_state "$part_devname_a" activating tentative "$part_syspath_a"
    check_state "$part_devname_b" activating tentative "$part_syspath_b"

    check_state /dev/udevtest/a1 activating tentative "$part_syspath_a"
    check_state /dev/udevtest/a2 activating tentative "$part_syspath_a"
    check_state /dev/udevtest/b1 activating tentative "$part_syspath_b"
    check_state /dev/udevtest/b2 activating tentative "$part_syspath_b"
    check_state /dev/udevtest/x1 activating tentative "$part_syspath_a"
    check_state /dev/udevtest/x2 activating tentative "$part_syspath_a"

    check_state testsleep-a1.service active running
    check_state testsleep-a2.service active running
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service active running
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running
}

kill_sleep_by_udevd() {
    local pid comm
    local -a pids

    # Collect PIDs first, then kill: killing while reading cgroup.procs would
    # mutate the set we are iterating over.

    while read -r pid; do
        read -r comm <"/proc/$pid/comm" 2>/dev/null || continue
        [[ "${comm##*/}" == sleep ]] && pids+=("$pid")
    done <"/sys/fs/cgroup$(systemctl show -P ControlGroup systemd-udevd.service)/workers/cgroup.procs"

    for pid in "${pids[@]}"; do
        kill "$pid" || :
    done
}

testcase_loopdev_basic() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    for action in daemon-reload daemon-reexec; do
        systemctl "$action"

        check_state "$part_syspath_a" active plugged "$part_syspath_a"
        check_state "$part_syspath_b" active plugged "$part_syspath_b"
        check_state "$part_devname_a" active plugged "$part_syspath_a"
        check_state "$part_devname_b" active plugged "$part_syspath_b"

        check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
        check_state /dev/udevtest/a2 active plugged "$part_syspath_a"
        check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
        check_state /dev/udevtest/b2 active plugged "$part_syspath_b"
        check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
        check_state /dev/udevtest/x2 active plugged "$part_syspath_a"

        check_state testsleep-a1.service active running
        check_state testsleep-a2.service active running
        check_state testsleep-b1.service active running
        check_state testsleep-b2.service active running
        check_state testsleep-x1.service active running
        check_state testsleep-x2.service active running
    done

    loopdev_remove "$dev_a" a

    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"

    check_state testsleep-b1.service active running
    check_state testsleep-b2.service active running
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    loopdev_remove "$dev_b" b

    check_state /dev/udevtest/x1 inactive dead
    check_state /dev/udevtest/x2 inactive dead

    check_state testsleep-x1.service inactive dead
    check_state testsleep-x2.service inactive dead
}

testcase_loopdev_change_devlink() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # Here, x2 for part_b is intentional.
    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_a}", \
  OPTIONS="link_priority=10", \
  SYMLINK+="udevtest/a1", SYMLINK+="udevtest/a3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x3"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_b}", \
  SYMLINK+="udevtest/b1", SYMLINK+="udevtest/b3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle "$part_devname_a"
    systemctl start /dev/udevtest/a3
    udevadm trigger --action change --settle "$part_devname_b"
    systemctl start /dev/udevtest/b3

    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 inactive dead
    check_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    check_state testsleep-a1.service active running
    check_state testsleep-a2.service inactive dead
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_change_devlink_priority() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_b}", \
  OPTIONS="link_priority=20", \
  SYMLINK+="udevtest/b1", SYMLINK+="udevtest/b3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle "$part_devname_b"
    systemctl start /dev/udevtest/b3

    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 active plugged "$part_syspath_a"
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"

    check_state testsleep-a1.service active running
    check_state testsleep-a2.service active running
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_systemd_ready() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # Change event: SYSTEMD_READY=0 -> all device units will be inactive.
    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_a}|${part_name_b}", \
  ENV{SYSTEMD_READY}="0"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle "$part_devname_a" "$part_devname_b"
    wait_for_inactive "$part_syspath_a"
    wait_for_inactive "$part_syspath_b"

    check_state "$part_syspath_a" inactive dead
    check_state "$part_syspath_b" inactive dead
    check_state "$part_devname_a" inactive dead
    check_state "$part_devname_b" inactive dead

    check_state /dev/udevtest/a1 inactive dead
    check_state /dev/udevtest/a2 inactive dead
    check_state /dev/udevtest/b1 inactive dead
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/x1 inactive dead
    check_state /dev/udevtest/x2 inactive dead

    check_state testsleep-a1.service inactive dead
    check_state testsleep-a2.service inactive dead
    check_state testsleep-b1.service inactive dead
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service inactive dead
    check_state testsleep-x2.service inactive dead

    # Change event: SYSTEMD_READY=1 -> devices will be ready.
    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_a}", \
  OPTIONS="link_priority=10", \
  SYMLINK+="udevtest/a1", SYMLINK+="udevtest/a3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x3"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_b}", \
  SYMLINK+="udevtest/b1", SYMLINK+="udevtest/b3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle "$part_devname_a" "$part_devname_b"
    systemctl start "$part_syspath_a" "$part_syspath_b"

    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 inactive dead
    check_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    check_state testsleep-a1.service inactive dead
    check_state testsleep-a2.service inactive dead
    check_state testsleep-b1.service inactive dead
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service inactive dead
    check_state testsleep-x2.service inactive dead

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_id_processing() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # Change event: with long RUN, hence ID_PROCESSING=1 can be seen.
    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_a}", \
  OPTIONS="link_priority=10", \
  SYMLINK+="udevtest/a1", SYMLINK+="udevtest/a3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x3", \
  RUN+="/usr/bin/sleep 1000"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_b}", \
  SYMLINK+="udevtest/b1", SYMLINK+="udevtest/b3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
EOF
    udevadm control --reload
    udevadm trigger --action change "$part_devname_a" "$part_devname_b"
    timeout 30 bash -c "until grep -q -F 'ID_PROCESSING=1' '$(loopdev_get_udev_db "$part_devname_a")'; do sleep .5; done"
    systemctl start /dev/udevtest/b3

    # The states of the device units corresponding to part_a are not changed yet.
    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a3 inactive dead
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x3 inactive dead

    # Also the states of the service units bound to part_a are not changed.
    check_state testsleep-a1.service active running
    check_state testsleep-a2.service active running
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    # With daemon-reload/reexec, the active device units with ID_PROCESSING=1
    # enter the activating (tentative) state.
    local action
    for action in daemon-reload daemon-reexec daemon-reload; do
        systemctl "$action"

        check_state "$part_syspath_a" activating tentative "$part_syspath_a"
        check_state "$part_syspath_b" active plugged "$part_syspath_b"
        check_state "$part_devname_a" activating tentative "$part_syspath_a"
        check_state "$part_devname_b" active plugged "$part_syspath_b"

        check_state /dev/udevtest/a1 activating tentative "$part_syspath_a"
        check_state /dev/udevtest/a2 activating tentative "$part_syspath_a"
        check_state /dev/udevtest/a3 inactive dead
        check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
        check_state /dev/udevtest/b2 inactive dead
        check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
        check_state /dev/udevtest/x1 activating tentative "$part_syspath_a"
        check_state /dev/udevtest/x2 active plugged "$part_syspath_b"
        check_state /dev/udevtest/x3 inactive dead

        check_state testsleep-a1.service active running
        check_state testsleep-a2.service active running
        check_state testsleep-b1.service active running
        check_state testsleep-b2.service inactive dead
        check_state testsleep-x1.service active running
        check_state testsleep-x2.service active running
    done

    # Check if the daemon-reload/reexec finished while the event was being processed.
    grep -q -F 'ID_PROCESSING=1' "$(loopdev_get_udev_db "$part_devname_a")"

    # Kill the sleep command in RUN, and wait for the event to finish.
    kill_sleep_by_udevd
    udevadm settle --timeout=30
    (! grep -q -F 'ID_PROCESSING=1' "$(loopdev_get_udev_db "$part_devname_a")")
    systemctl start /dev/udevtest/a3

    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 inactive dead
    check_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    check_state testsleep-a1.service active running
    check_state testsleep-a2.service inactive dead
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_switching_root() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_emulate_switching_root "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # When a uevent for the device is received, then the device units enter the
    # active or inactive state.
    cat >"$RULE" <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_a}", \
  OPTIONS="link_priority=10", \
  SYMLINK+="udevtest/a1", SYMLINK+="udevtest/a3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x3"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${part_name_b}", \
  SYMLINK+="udevtest/b1", SYMLINK+="udevtest/b3", \
  SYMLINK+="udevtest/x1", SYMLINK+="udevtest/x2"
EOF
    udevadm control --reload
    udevadm trigger --action change "$part_devname_b"
    systemctl start /dev/udevtest/b3
    udevadm trigger --action change "$part_devname_a"
    systemctl start /dev/udevtest/a3

    check_state "$part_syspath_a" active plugged "$part_syspath_a"
    check_state "$part_syspath_b" active plugged "$part_syspath_b"
    check_state "$part_devname_a" active plugged "$part_syspath_a"
    check_state "$part_devname_b" active plugged "$part_syspath_b"

    check_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/a2 inactive dead
    check_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    check_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    check_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    check_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    check_state testsleep-a1.service active running
    check_state testsleep-a2.service inactive dead
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_remove_on_switching_root() {
    local dev_a dev_b
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_emulate_switching_root "$dev_a" "$dev_b"
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # Remove device before the first uevent after the switching-root.
    losetup -d "$dev_a"
    losetup -d "$dev_b"
    udevadm settle --timeout=30

    # If a device is removed without its udev DB file, then the corresponding device units DO NOT enter the
    # dead state, as the broadcast uevent message does not have 'systemd' tag, thus the message is filtered
    # by BPF and PID1 does not process the message. The stale unit states will be resolved after
    # the next daemon-reload and friends.
    check_state "$part_syspath_a" activating tentative "$part_syspath_a"
    check_state "$part_syspath_b" activating tentative "$part_syspath_b"
    check_state "$part_devname_a" activating tentative "$part_syspath_a"
    check_state "$part_devname_b" activating tentative "$part_syspath_b"

    check_state /dev/udevtest/a1 activating tentative "$part_syspath_a"
    check_state /dev/udevtest/a2 activating tentative "$part_syspath_a"
    check_state /dev/udevtest/b1 activating tentative "$part_syspath_b"
    check_state /dev/udevtest/b2 activating tentative "$part_syspath_b"
    check_state /dev/udevtest/x1 activating tentative "$part_syspath_a"
    check_state /dev/udevtest/x2 activating tentative "$part_syspath_a"

    check_state testsleep-a1.service active running
    check_state testsleep-a2.service active running
    check_state testsleep-b1.service active running
    check_state testsleep-b2.service active running
    check_state testsleep-x1.service active running
    check_state testsleep-x2.service active running

    systemctl daemon-reload
    wait_for_inactive "$part_syspath_a"
    wait_for_inactive "$part_syspath_b"

    check_state "$part_syspath_a" inactive dead
    check_state "$part_syspath_b" inactive dead
    check_state "$part_devname_a" inactive dead
    check_state "$part_devname_b" inactive dead

    check_state /dev/udevtest/a1 inactive dead
    check_state /dev/udevtest/a2 inactive dead
    check_state /dev/udevtest/b1 inactive dead
    check_state /dev/udevtest/b2 inactive dead
    check_state /dev/udevtest/x1 inactive dead
    check_state /dev/udevtest/x2 inactive dead

    check_state testsleep-a1.service inactive dead
    check_state testsleep-a2.service inactive dead
    check_state testsleep-b1.service inactive dead
    check_state testsleep-b2.service inactive dead
    check_state testsleep-x1.service inactive dead
    check_state testsleep-x2.service inactive dead
}

at_exit() (
    set +e

    systemctl stop testsleep-a1.service
    systemctl stop testsleep-a2.service
    systemctl stop testsleep-b1.service
    systemctl stop testsleep-b2.service
    systemctl stop testsleep-x1.service
    systemctl stop testsleep-x2.service

    kill_sleep_by_udevd

    rm -f /run/udev/udev.conf.d/timeout.conf
    rm -f "$RULE"
    udevadm control --reload
    return 0
)

trap at_exit EXIT

udevadm settle --timeout=30

mkdir -p /run/udev/udev.conf.d/
cat >/run/udev/udev.conf.d/timeout.conf <<EOF
event_timeout=1h
EOF

mkdir -p "${RULE%/*}"

run_testcases
