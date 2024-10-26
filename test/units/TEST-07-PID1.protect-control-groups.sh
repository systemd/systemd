#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

SLICE="system.slice"
UNIT_PREFIX="test-07-protect-control-groups"

READ_ONLY_MOUNT_FLAG="ro"
READ_WRITE_MOUNT_FLAG="rw"

at_exit() {
    set +e

    systemctl stop "$UNIT_PREFIX*.service"
    systemctl reset-failed
}

trap at_exit EXIT

ROOT_CGROUP_NS=$(readlink /proc/self/ns/cgroup)

ENABLE_MEM_PRESSURE_TEST=true

# We do not just test if the file exists, but try to read from it, since if
# CONFIG_PSI_DEFAULT_DISABLED is set in the kernel the file will exist and can
# be opened, but any read()s will fail with EOPNOTSUPP, which we want to
# detect.
if ! cat /proc/pressure/memory >/dev/null ; then
    echo "Kernel too old, has no PSI, not running ProtectControlGroups= with MemoryPressureWatch= test." >&2
    ENABLE_MEM_PRESSURE_TEST=false
fi

if ! test -f "/sys/fs/cgroup/$(systemctl show TEST-07-PID1.service -P ControlGroup)/memory.pressure" ; then
    echo "No memory accounting/PSI delegated via cgroup, not running ProtectControlGroups= with MemoryPressureWatch= test." >&2
    ENABLE_MEM_PRESSURE_TEST=false
fi

test_basic() {
    local protect_control_groups_ex="$1"
    local protect_control_groups="$2"
    local in_cgroup_ns="$3"
    local mount_flag="$4"

    if [[ $in_cgroup_ns == true ]]; then
      local ns_cmp_op="!="
      local unit_cgroup="0::/"
      local memory_pressure_watch="/sys/fs/cgroup/memory.pressure"
    else
      local ns_cmp_op="=="
      local unit_cgroup="0::/$SLICE/$UNIT_PREFIX-$protect_control_groups_ex-1.service"
      local memory_pressure_watch="/sys/fs/cgroup/$SLICE/$UNIT_PREFIX-$protect_control_groups_ex-2.service/memory.pressure"
    fi

    # Compare cgroup namespace to root namespace
    systemd-run -p "ProtectControlGroupsEx=$protect_control_groups_ex" --slice "$SLICE" --wait \
            bash -xec "test \"\$(readlink /proc/self/ns/cgroup)\" $ns_cmp_op \"$ROOT_CGROUP_NS\""
    # Verify unit cgroup
    systemd-run -p "ProtectControlGroupsEx=$protect_control_groups_ex" --slice "$SLICE" --wait \
            --unit "$UNIT_PREFIX-$protect_control_groups_ex-1" \
            bash -xec "test \"\$(cat /proc/self/cgroup)\" == \"$unit_cgroup\""
    # Verify memory pressure watch points to correct file
    if [[ $ENABLE_MEM_PRESSURE_TEST == true ]]; then
        systemd-run -p "ProtectControlGroupsEx=$protect_control_groups_ex" -p MemoryPressureWatch=yes --slice "$SLICE" --wait \
                --unit "$UNIT_PREFIX-$protect_control_groups_ex-2" \
                bash -xec "test \"\$MEMORY_PRESSURE_WATCH\" == \"$memory_pressure_watch\""
    fi
    # Verify /sys/fs/cgroup mount is read-only or read-write
    systemd-run -p "ProtectControlGroupsEx=$protect_control_groups_ex" --slice "$SLICE" --wait \
            bash -xec "[[ \"\$\$(findmnt --mountpoint /sys/fs/cgroup --noheadings -o FSTYPE)\" == cgroup2 ]];
                       [[ \"\$\$(findmnt --mountpoint /sys/fs/cgroup --noheadings -o FS-OPTIONS)\" =~ nsdelegate ]];
                       [[ \"\$\$(findmnt --mountpoint /sys/fs/cgroup --noheadings -o VFS-OPTIONS)\" =~ noexec ]];
                       [[ \"\$\$(findmnt --mountpoint /sys/fs/cgroup --noheadings -o VFS-OPTIONS)\" =~ nosuid ]];
                       [[ \"\$\$(findmnt --mountpoint /sys/fs/cgroup --noheadings -o VFS-OPTIONS)\" =~ nodev ]];
                       [[ \"\$\$(findmnt --mountpoint /sys/fs/cgroup --noheadings -o VFS-OPTIONS)\" =~ \"$mount_flag\" ]];"

    # Verify dbus properties
    systemd-run -p "ProtectControlGroupsEx=$protect_control_groups_ex" --slice "$SLICE" --remain-after-exit \
            --unit "$UNIT_PREFIX-$protect_control_groups_ex-3" true
    assert_eq "$(systemctl show -P ProtectControlGroupsEx "$UNIT_PREFIX-$protect_control_groups_ex-3")" "$protect_control_groups_ex"
    assert_eq "$(systemctl show -P ProtectControlGroups "$UNIT_PREFIX-$protect_control_groups_ex-3")" "$protect_control_groups"
    systemctl stop "$UNIT_PREFIX-$protect_control_groups_ex-3"
}

testcase_basic_no() {
    test_basic "no" "no" false "$READ_WRITE_MOUNT_FLAG"
}

testcase_basic_yes() {
    test_basic "yes" "yes" false "$READ_ONLY_MOUNT_FLAG"
}

testcase_basic_private() {
    test_basic "private" "yes" true "$READ_WRITE_MOUNT_FLAG"
}

testcase_basic_strict() {
    test_basic "strict" "yes" true "$READ_ONLY_MOUNT_FLAG"
}

run_testcases
