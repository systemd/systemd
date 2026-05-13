#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

testcase_tasks_max_scale_serialize() {
    # Regression test for https://github.com/systemd/systemd/issues/41009
    # TasksMaxScale was serialized as 4.0% instead of 40.00%, causing 10x reduction on daemon-reload

    local unit="test-tasks-max.slice"
    local unit_file="/run/systemd/system/${unit}"
    local dropin_dir="/run/systemd/system.control/${unit}.d"

    # shellcheck disable=SC2329
    cleanup() (
        set +e
        rm -rf "${dropin_dir}"
        rm -f "${unit_file}"
        systemctl daemon-reload
    )
    trap cleanup RETURN

    printf '[Slice]\n' >"${unit_file}"

    systemctl daemon-reload

    # Set TasksMax=40% via D-Bus — exercises bus_cgroup_set_tasks_max_scale()
    systemctl set-property --runtime "${unit}" TasksMax=40%

    # Verify drop-in file contains correct percentage (40.00%, not 4.0%)
    grep -q '^TasksMax=40\.00%$' "${dropin_dir}/50-TasksMaxScale.conf"

    # Capture value before daemon-reload
    local tasks_max_before
    tasks_max_before=$(systemctl show -P TasksMax "${unit}")

    # Reload and verify value is preserved (the actual bug: value dropped 10x here)
    systemctl daemon-reload

    local tasks_max_after
    tasks_max_after=$(systemctl show -P TasksMax "${unit}")
    assert_eq "${tasks_max_before}" "${tasks_max_after}"
}

run_testcases
