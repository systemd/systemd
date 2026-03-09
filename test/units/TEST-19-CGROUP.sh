#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

testcase_tasks_max_scale_serialize() {
    # Regression test for https://github.com/systemd/systemd/issues/41009
    # TasksMaxScale was serialized as 4.0% instead of 40.00%, causing 10x reduction on daemon-reload

    local slice="test-tasks-max-scale-$$.slice"
    local dropin_dir="/run/systemd/system.control/${slice}.d"
    local dropin_file="${dropin_dir}/50-TasksMaxScale.conf"

    # Set TasksMax=40% via D-Bus property
    systemctl set-property --runtime "$slice" TasksMax=40%

    # Verify drop-in contains correct percentage (40.00%, not 4.0%)
    grep -q "TasksMax=40.00%" "$dropin_file"

    # Capture value before daemon-reload
    local tasks_max_before
    tasks_max_before=$(systemctl show -P TasksMax "$slice")

    # Reload and verify value is preserved
    systemctl daemon-reload
    local tasks_max_after
    tasks_max_after=$(systemctl show -P TasksMax "$slice")
    [[ "$tasks_max_before" == "$tasks_max_after" ]] || {
        echo "TasksMax changed after daemon-reload: $tasks_max_before -> $tasks_max_after" >&2
        exit 1
    }
    
    # Cleanup
    systemctl stop "$slice" 2>/dev/null || :
    rm -rf "$dropin_dir"
}
run_subtests
touch /testok
