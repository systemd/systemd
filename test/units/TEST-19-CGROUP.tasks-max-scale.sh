#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "Skipping $0 as we're not running with the unified cgroup hierarchy"
    exit 0
fi

testcase_tasks_max_scale_serialize() {
    # Regression test for https://github.com/systemd/systemd/issues/41009
    # TasksMaxScale was serialized as 4.0% instead of 40.00%, causing 10x reduction on daemon-reload
    systemd-run --unit=test-tasks-max.service \
                sleep inf

    systemctl set-property test-tasks-max.service TasksMax=40%

    # Verify drop-in contains correct percentage (40.00%, not 4.0%)
    grep -q "TasksMax=40.00%" /run/systemd/system.control/test-tasks-max.service.d/50-TasksMaxScale.conf

    # Capture value before daemon-reload
    local tasks_max_before
    tasks_max_before=$(systemctl show -P TasksMax test-tasks-max.service)

    # Reload and verify value is preserved
    systemctl daemon-reload

    local tasks_max_after
    tasks_max_after=$(systemctl show -P TasksMax test-tasks-max.service)
    [[ "$tasks_max_before" == "$tasks_max_after" ]] || {
        echo "TasksMax changed after daemon-reload: $tasks_max_before -> $tasks_max_after" >&2
        exit 1
    }

    systemctl stop test-tasks-max.service
}

run_testcases
