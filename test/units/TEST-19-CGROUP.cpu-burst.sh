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

testcase_burst_transient() {
    systemd-run --unit=test-burst.service \
                -p CPUQuota=50% \
                -p CPUBurst=20% \
                sleep inf

    CGROUP_PATH=$(systemctl show -P ControlGroup test-burst.service)

    # Verify cpu.max has the expected quota
    read -r quota period < /sys/fs/cgroup"$CGROUP_PATH"/cpu.max
    [[ "$quota" -gt 0 ]]
    [[ "$period" -gt 0 ]]

    # Verify cpu.max.burst is written
    burst=$(cat /sys/fs/cgroup"$CGROUP_PATH"/cpu.max.burst)
    [[ "$burst" -gt 0 ]]

    systemctl stop test-burst.service
}

testcase_burst_set_property() {
    systemd-run --unit=test-burst-setprop.service \
                -p CPUQuota=50% \
                sleep inf

    CGROUP_PATH=$(systemctl show -P ControlGroup test-burst-setprop.service)

    # Initially burst should be 0
    burst=$(cat /sys/fs/cgroup"$CGROUP_PATH"/cpu.max.burst)
    [[ "$burst" -eq 0 ]]

    # Set burst at runtime
    systemctl set-property --runtime test-burst-setprop.service CPUBurst=40%
    burst=$(cat /sys/fs/cgroup"$CGROUP_PATH"/cpu.max.burst)
    [[ "$burst" -gt 0 ]]

    # Verify the dropin was written
    grep -r "CPUBurst=40.00%" /run/systemd/system.control/test-burst-setprop.service.d/

    # Reset burst
    systemctl set-property --runtime test-burst-setprop.service CPUBurst=
    burst=$(cat /sys/fs/cgroup"$CGROUP_PATH"/cpu.max.burst)
    [[ "$burst" -eq 0 ]]

    systemctl stop test-burst-setprop.service
}

testcase_burst_show() {
    systemd-run --unit=test-burst-show.service \
                -p CPUQuota=50% \
                -p CPUBurst=20% \
                sleep inf

    # Verify show reports the property
    val=$(systemctl show -P CPUBurstPerSecUSec test-burst-show.service)
    [[ "$val" != "" ]]
    [[ "$val" != "infinity" ]]

    systemctl stop test-burst-show.service
}

testcase_burst_unitfile() {
    cat > /run/systemd/system/test-burst-unit.service <<EOF
[Service]
ExecStart=sleep inf
CPUQuota=50%
CPUBurst=25%
EOF
    systemctl daemon-reload
    systemctl start test-burst-unit.service

    CGROUP_PATH=$(systemctl show -P ControlGroup test-burst-unit.service)
    burst=$(cat /sys/fs/cgroup"$CGROUP_PATH"/cpu.max.burst)
    [[ "$burst" -gt 0 ]]

    systemctl stop test-burst-unit.service
    rm -f /run/systemd/system/test-burst-unit.service
    systemctl daemon-reload
}

run_testcases
