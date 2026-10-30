#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

RULE=/run/udev/rules.d/99-udevtest-device-state.rules

loopdev_setup() {
    local dev name=udevtest-${1:?}
    local -n ret=${2:?}

    if [[ -f "$RULE" ]]; then
        rm "$RULE"
        udevadm control --reload
    fi

    truncate -s 30m "/tmp/${name}.img"
    sfdisk --wipe=always "/tmp/${name}.img" <<EOF
label:gpt

name="${name}-part1"
EOF
    dev=$(losetup -P --show -f "/tmp/${name}.img")
    udevadm wait --settle --timeout=30 "$dev" "${dev}p1"
    udevadm lock --timeout=30 --device="$dev" mkfs.ext4 -L "${name}-fs1" "${dev}p1"
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

# shellcheck disable=SC2034
loopdev_prepare() {
    local dev_a=${1:?}
    local dev_b=${2:?}
    local -n ret_invocation_ids=${3:?}
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
    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    # By device node
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"
    # By devlink
    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_a"

    start_bound_service /dev/udevtest/a1 a1
    start_bound_service /dev/udevtest/a2 a2
    start_bound_service /dev/udevtest/b1 b1
    start_bound_service /dev/udevtest/b2 b2
    start_bound_service /dev/udevtest/x1 x1
    start_bound_service /dev/udevtest/x2 x2

    ret_invocation_ids=(
        ["$part_syspath_a"]="$(get_invocation_id "$part_syspath_a")"
        ["$part_syspath_b"]="$(get_invocation_id "$part_syspath_b")"
        ["$part_devname_a"]="$(get_invocation_id "$part_devname_a")"
        ["$part_devname_b"]="$(get_invocation_id "$part_devname_b")"

        ["/dev/udevtest/a1"]="$(get_invocation_id /dev/udevtest/a1)"
        ["/dev/udevtest/a2"]="$(get_invocation_id /dev/udevtest/a2)"
        ["/dev/udevtest/b1"]="$(get_invocation_id /dev/udevtest/b1)"
        ["/dev/udevtest/b2"]="$(get_invocation_id /dev/udevtest/b2)"
        ["/dev/udevtest/x1"]="$(get_invocation_id /dev/udevtest/x1)"
        ["/dev/udevtest/x2"]="$(get_invocation_id /dev/udevtest/x2)"

        ["testsleep-a1.service"]="$(get_invocation_id testsleep-a1.service)"
        ["testsleep-a2.service"]="$(get_invocation_id testsleep-a2.service)"
        ["testsleep-b1.service"]="$(get_invocation_id testsleep-b1.service)"
        ["testsleep-b2.service"]="$(get_invocation_id testsleep-b2.service)"
        ["testsleep-x1.service"]="$(get_invocation_id testsleep-x1.service)"
        ["testsleep-x2.service"]="$(get_invocation_id testsleep-x2.service)"
    )
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

    assert_unit_state "$part_syspath" inactive dead
    assert_unit_state "$part_devname" inactive dead

    assert_unit_state /dev/udevtest/"$alias_name"1 inactive dead
    assert_unit_state /dev/udevtest/"$alias_name"2 inactive dead
    assert_unit_state /dev/udevtest/"$alias_name"3 inactive dead

    assert_unit_state testsleep-"$alias_name"1.service inactive dead
    assert_unit_state testsleep-"$alias_name"2.service inactive dead
}

loopdev_remove_all() {
    local dev_a=${1:?}
    local dev_b=${2:?}

    loopdev_remove "$dev_a" a
    loopdev_remove "$dev_b" b

    assert_unit_state /dev/udevtest/x1 inactive dead
    assert_unit_state /dev/udevtest/x2 inactive dead
    assert_unit_state /dev/udevtest/x3 inactive dead

    assert_unit_state testsleep-x1.service inactive dead
    assert_unit_state testsleep-x2.service inactive dead
}

loopdev_emulate_switching_root() {
    local dev_a=${1:?}
    local dev_b=${2:?}
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b

    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    # Emulate switching-root from initrd to host system by removing the udev database,
    # which is typically done by udevadm info --cleanup-db. If the database is removed,
    # the active device units enter the activating (tentative) state.
    rm -f "$(device_get_udev_db "$part_devname_a")"
    rm -f "$(device_get_udev_db "$part_devname_b")"
    rm -rf /run/udev/links/udevtest*

    # Also remove devlinks here. Otherwise, the device units for the devlinks left over from
    # before switching-root will not be removed.
    rm -rf /dev/udevtest

    systemctl daemon-reload

    assert_unit_state "$part_syspath_a" activating tentative "$part_syspath_a"
    assert_unit_state "$part_syspath_b" activating tentative "$part_syspath_b"
    assert_unit_state "$part_devname_a" activating tentative "$part_syspath_a"
    assert_unit_state "$part_devname_b" activating tentative "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 activating tentative "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 activating tentative "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 activating tentative "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 activating tentative "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 activating tentative "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 activating tentative "$part_syspath_a"

    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service active running
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service active running
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 0
    assert_wc_l /tmp/testsleep-reload-x2.txt 0
}

testcase_loopdev_basic() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i action

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids
    loopdev_init_vars "$dev_a" part_devname_a part_syspath_a part_name_a
    loopdev_init_vars "$dev_b" part_devname_b part_syspath_b part_name_b

    for action in daemon-reload daemon-reexec; do
        systemctl "$action"

        assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
        assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
        assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
        assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

        assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
        assert_unit_state /dev/udevtest/a2 active plugged "$part_syspath_a"
        assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
        assert_unit_state /dev/udevtest/b2 active plugged "$part_syspath_b"
        assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
        assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_a"

        assert_unit_state testsleep-a1.service active running
        assert_unit_state testsleep-a2.service active running
        assert_unit_state testsleep-b1.service active running
        assert_unit_state testsleep-b2.service active running
        assert_unit_state testsleep-x1.service active running
        assert_unit_state testsleep-x2.service active running

        assert_wc_l /tmp/testsleep-reload-a1.txt 0
        assert_wc_l /tmp/testsleep-reload-a2.txt 0
        assert_wc_l /tmp/testsleep-reload-b1.txt 0
        assert_wc_l /tmp/testsleep-reload-b2.txt 0
        assert_wc_l /tmp/testsleep-reload-x1.txt 0
        assert_wc_l /tmp/testsleep-reload-x2.txt 0

        for i in "${!invocation_ids[@]}"; do
            assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
        done
    done

    loopdev_remove "$dev_a" a

    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"

    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service active running
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 1
    assert_wc_l /tmp/testsleep-reload-x2.txt 1

    unset "invocation_ids[$part_syspath_a]"
    unset "invocation_ids[$part_devname_a]"
    unset "invocation_ids[/dev/udevtest/a1]"
    unset "invocation_ids[/dev/udevtest/a2]"
    unset "invocation_ids[testsleep-a1.service]"
    unset "invocation_ids[testsleep-a2.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    loopdev_remove "$dev_b" b

    assert_unit_state /dev/udevtest/x1 inactive dead
    assert_unit_state /dev/udevtest/x2 inactive dead

    assert_unit_state testsleep-x1.service inactive dead
    assert_unit_state testsleep-x2.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 1
    assert_wc_l /tmp/testsleep-reload-x2.txt 1
}

testcase_loopdev_change_devlink() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids
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

    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 inactive dead
    assert_unit_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service inactive dead
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 1
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 1
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 1
    assert_wc_l /tmp/testsleep-reload-x2.txt 2

    unset "invocation_ids[/dev/udevtest/a2]"
    unset "invocation_ids[/dev/udevtest/b2]"
    unset "invocation_ids[testsleep-a2.service]"
    unset "invocation_ids[testsleep-b2.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_change_devlink_priority() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids
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

    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"

    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service active running
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 1
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 1
    assert_wc_l /tmp/testsleep-reload-x2.txt 1

    unset "invocation_ids[/dev/udevtest/b2]"
    unset "invocation_ids[testsleep-b2.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_systemd_ready() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids
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

    assert_unit_state "$part_syspath_a" inactive dead
    assert_unit_state "$part_syspath_b" inactive dead
    assert_unit_state "$part_devname_a" inactive dead
    assert_unit_state "$part_devname_b" inactive dead

    assert_unit_state /dev/udevtest/a1 inactive dead
    assert_unit_state /dev/udevtest/a2 inactive dead
    assert_unit_state /dev/udevtest/b1 inactive dead
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/x1 inactive dead
    assert_unit_state /dev/udevtest/x2 inactive dead

    assert_unit_state testsleep-a1.service inactive dead
    assert_unit_state testsleep-a2.service inactive dead
    assert_unit_state testsleep-b1.service inactive dead
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service inactive dead
    assert_unit_state testsleep-x2.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 0
    assert_wc_l /tmp/testsleep-reload-x2.txt 0

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

    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 inactive dead
    assert_unit_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    assert_unit_state testsleep-a1.service inactive dead
    assert_unit_state testsleep-a2.service inactive dead
    assert_unit_state testsleep-b1.service inactive dead
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service inactive dead
    assert_unit_state testsleep-x2.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 0
    assert_wc_l /tmp/testsleep-reload-x2.txt 0

    for i in "${!invocation_ids[@]}"; do
        assert_neq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_id_processing() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids
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
    udevadm trigger --action change "$part_devname_a"
    timeout 30 bash -c "until grep -q -F 'ID_PROCESSING=1' '$(device_get_udev_db "$part_devname_a")'; do sleep .5; done"
    udevadm trigger --action change --settle "$part_devname_b"
    systemctl start /dev/udevtest/b3

    # The states of the device units corresponding to part_a are not changed yet.
    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a3 inactive dead
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x3 inactive dead

    # Also the states of the service units bound to part_a are not changed.
    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service active running
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 1
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 0
    assert_wc_l /tmp/testsleep-reload-x2.txt 1

    unset "invocation_ids[/dev/udevtest/b2]"
    unset "invocation_ids[testsleep-b2.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    # With daemon-reload/reexec, the active device units with ID_PROCESSING=1
    # enter the activating (tentative) state.
    local action
    for action in daemon-reload daemon-reexec daemon-reload; do
        systemctl "$action"

        assert_unit_state "$part_syspath_a" activating tentative "$part_syspath_a"
        assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
        assert_unit_state "$part_devname_a" activating tentative "$part_syspath_a"
        assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

        assert_unit_state /dev/udevtest/a1 activating tentative "$part_syspath_a"
        assert_unit_state /dev/udevtest/a2 activating tentative "$part_syspath_a"
        assert_unit_state /dev/udevtest/a3 inactive dead
        assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
        assert_unit_state /dev/udevtest/b2 inactive dead
        assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
        assert_unit_state /dev/udevtest/x1 activating tentative "$part_syspath_a"
        assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"
        assert_unit_state /dev/udevtest/x3 inactive dead

        assert_unit_state testsleep-a1.service active running
        assert_unit_state testsleep-a2.service active running
        assert_unit_state testsleep-b1.service active running
        assert_unit_state testsleep-b2.service inactive dead
        assert_unit_state testsleep-x1.service active running
        assert_unit_state testsleep-x2.service active running

        assert_wc_l /tmp/testsleep-reload-a1.txt 0
        assert_wc_l /tmp/testsleep-reload-a2.txt 0
        assert_wc_l /tmp/testsleep-reload-b1.txt 1
        assert_wc_l /tmp/testsleep-reload-b2.txt 0
        assert_wc_l /tmp/testsleep-reload-x1.txt 0
        assert_wc_l /tmp/testsleep-reload-x2.txt 1

        for i in "${!invocation_ids[@]}"; do
            assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
        done
    done

    # Check if the daemon-reload/reexec finished while the event was being processed.
    grep -q -F 'ID_PROCESSING=1' "$(device_get_udev_db "$part_devname_a")"

    # Kill the sleep command in RUN, and wait for the event to finish.
    kill_sleep_by_udevd
    udevadm settle --timeout=30
    (! grep -q -F 'ID_PROCESSING=1' "$(device_get_udev_db "$part_devname_a")")
    systemctl start /dev/udevtest/a3

    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 inactive dead
    assert_unit_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service inactive dead
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 1
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 1
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 1
    assert_wc_l /tmp/testsleep-reload-x2.txt 1

    unset "invocation_ids[/dev/udevtest/a2]"
    unset "invocation_ids[testsleep-a2.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_switching_root() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids

    loopdev_emulate_switching_root "$dev_a" "$dev_b"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

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
    udevadm trigger --action change --settle "$part_devname_b"
    systemctl start /dev/udevtest/b3
    udevadm trigger --action change --settle "$part_devname_a"
    systemctl start /dev/udevtest/a3

    assert_unit_state "$part_syspath_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_syspath_b" active plugged "$part_syspath_b"
    assert_unit_state "$part_devname_a" active plugged "$part_syspath_a"
    assert_unit_state "$part_devname_b" active plugged "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 inactive dead
    assert_unit_state /dev/udevtest/a3 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/b3 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 active plugged "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 active plugged "$part_syspath_b"
    assert_unit_state /dev/udevtest/x3 active plugged "$part_syspath_a"

    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service inactive dead
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 1
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 1
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 2
    assert_wc_l /tmp/testsleep-reload-x2.txt 1

    unset "invocation_ids[/dev/udevtest/a2]"
    unset "invocation_ids[/dev/udevtest/b2]"
    unset "invocation_ids[testsleep-a2.service]"
    unset "invocation_ids[testsleep-b2.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    loopdev_remove_all "$dev_a" "$dev_b"
}

testcase_loopdev_remove_on_switching_root() {
    local dev_a dev_b
    local -A invocation_ids
    local part_devname_a part_devname_b part_syspath_a part_syspath_b part_name_a part_name_b
    local i

    loopdev_setup a dev_a
    loopdev_setup b dev_b
    loopdev_prepare "$dev_a" "$dev_b" invocation_ids

    loopdev_emulate_switching_root "$dev_a" "$dev_b"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

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
    assert_unit_state "$part_syspath_a" activating tentative "$part_syspath_a"
    assert_unit_state "$part_syspath_b" activating tentative "$part_syspath_b"
    assert_unit_state "$part_devname_a" activating tentative "$part_syspath_a"
    assert_unit_state "$part_devname_b" activating tentative "$part_syspath_b"

    assert_unit_state /dev/udevtest/a1 activating tentative "$part_syspath_a"
    assert_unit_state /dev/udevtest/a2 activating tentative "$part_syspath_a"
    assert_unit_state /dev/udevtest/b1 activating tentative "$part_syspath_b"
    assert_unit_state /dev/udevtest/b2 activating tentative "$part_syspath_b"
    assert_unit_state /dev/udevtest/x1 activating tentative "$part_syspath_a"
    assert_unit_state /dev/udevtest/x2 activating tentative "$part_syspath_a"

    assert_unit_state testsleep-a1.service active running
    assert_unit_state testsleep-a2.service active running
    assert_unit_state testsleep-b1.service active running
    assert_unit_state testsleep-b2.service active running
    assert_unit_state testsleep-x1.service active running
    assert_unit_state testsleep-x2.service active running

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 0
    assert_wc_l /tmp/testsleep-reload-x2.txt 0

    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    systemctl daemon-reload
    wait_for_inactive "$part_syspath_a"
    wait_for_inactive "$part_syspath_b"

    assert_unit_state "$part_syspath_a" inactive dead
    assert_unit_state "$part_syspath_b" inactive dead
    assert_unit_state "$part_devname_a" inactive dead
    assert_unit_state "$part_devname_b" inactive dead

    assert_unit_state /dev/udevtest/a1 inactive dead
    assert_unit_state /dev/udevtest/a2 inactive dead
    assert_unit_state /dev/udevtest/b1 inactive dead
    assert_unit_state /dev/udevtest/b2 inactive dead
    assert_unit_state /dev/udevtest/x1 inactive dead
    assert_unit_state /dev/udevtest/x2 inactive dead

    assert_unit_state testsleep-a1.service inactive dead
    assert_unit_state testsleep-a2.service inactive dead
    assert_unit_state testsleep-b1.service inactive dead
    assert_unit_state testsleep-b2.service inactive dead
    assert_unit_state testsleep-x1.service inactive dead
    assert_unit_state testsleep-x2.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a1.txt 0
    assert_wc_l /tmp/testsleep-reload-a2.txt 0
    assert_wc_l /tmp/testsleep-reload-b1.txt 0
    assert_wc_l /tmp/testsleep-reload-b2.txt 0
    assert_wc_l /tmp/testsleep-reload-x1.txt 0
    assert_wc_l /tmp/testsleep-reload-x2.txt 0
}

at_exit() (
    set +e

    systemctl stop testsleep-a1.service
    systemctl stop testsleep-a2.service
    systemctl stop testsleep-b1.service
    systemctl stop testsleep-b2.service
    systemctl stop testsleep-x1.service
    systemctl stop testsleep-x2.service

    rm -f /tmp/testsleep-reload-*.txt

    kill_sleep_by_udevd

    rm -f /run/udev/udev.conf.d/timeout.conf
    rm -f "$RULE"
    udevadm control --reload

    local i j
    for i in /tmp/udevtest-*.img; do
        [[ -e "$i" ]] || continue
        for j in $(losetup -j "$i" | awk -F: '{print $1}'); do
            losetup -d "$j"
        done
        rm "$i"
    done

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
