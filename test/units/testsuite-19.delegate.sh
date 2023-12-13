#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test cgroup delegation in the unified hierarchy

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "Skipping $0 as we're not running with the unified cgroup hierarchy"
    exit 0
fi

at_exit() {
    set +e
    userdel -r test
}

systemd-run --wait \
            --unit=test-0.service \
            --property="DynamicUser=1" \
            --property="Delegate=" \
            test -w /sys/fs/cgroup/system.slice/test-0.service/ -a \
                 -w /sys/fs/cgroup/system.slice/test-0.service/cgroup.procs -a \
                 -w /sys/fs/cgroup/system.slice/test-0.service/cgroup.subtree_control

# Test if this also works for some of the more recent attrs the kernel might or might not support
for attr in cgroup.threads memory.oom.group memory.reclaim ; do

    if grep -q "$attr" /sys/kernel/cgroup/delegate ; then
        systemd-run --wait \
                    --unit=test-0.service \
                    --property="DynamicUser=1" \
                    --property="Delegate=" \
                    test -w /sys/fs/cgroup/system.slice/test-0.service/ -a \
                    -w /sys/fs/cgroup/system.slice/test-0.service/"$attr"
    fi
done

systemd-run --wait \
            --unit=test-1.service \
            --property="DynamicUser=1" \
            --property="Delegate=memory pids" \
            grep -q memory /sys/fs/cgroup/system.slice/test-1.service/cgroup.controllers

systemd-run --wait \
            --unit=test-2.service \
            --property="DynamicUser=1" \
            --property="Delegate=memory pids" \
            grep -q pids /sys/fs/cgroup/system.slice/test-2.service/cgroup.controllers

# "io" is not among the controllers enabled by default for all units, verify that
grep -qv io /sys/fs/cgroup/system.slice/cgroup.controllers

# Run a service with "io" enabled, and verify it works
systemd-run --wait \
            --unit=test-3.service \
            --property="IOAccounting=yes" \
            --property="Slice=system-foo-bar-baz.slice"  \
            grep -q io /sys/fs/cgroup/system.slice/system-foo.slice/system-foo-bar.slice/system-foo-bar-baz.slice/test-3.service/cgroup.controllers

# We want to check if "io" is removed again from the controllers
# list. However, PID 1 (rightfully) does this asynchronously. In order
# to force synchronization on this, let's start a short-lived service
# which requires PID 1 to refresh the cgroup tree, so that we can
# verify that this all works.
systemd-run --wait --unit=test-4.service true

# And now check again, "io" should have vanished
grep -qv io /sys/fs/cgroup/system.slice/cgroup.controllers

# Check that unprivileged delegation works for scopes
useradd test ||:
systemd-run --uid=test \
            --property="User=test" \
            --property="Delegate=yes" \
            --slice workload.slice \
            --unit test-workload0.scope\
            --scope \
            test -w /sys/fs/cgroup/workload.slice/test-workload0.scope -a \
                 -w /sys/fs/cgroup/workload.slice/test-workload0.scope/cgroup.procs -a \
                 -w /sys/fs/cgroup/workload.slice/test-workload0.scope/cgroup.subtree_control

# Verify that DelegateSubgroup= affects ownership correctly
unit="test-subgroup-$RANDOM.service"
systemd-run --wait \
            --unit="$unit" \
            --property="DynamicUser=1" \
            --property="Delegate=pids" \
            --property="DelegateSubgroup=foo" \
            test -w "/sys/fs/cgroup/system.slice/$unit" -a \
                 -w "/sys/fs/cgroup/system.slice/$unit/foo"

# Check that for the subgroup also attributes that aren't covered by
# regular (i.e. main cgroup) delegation ownership rules are delegated properly
if test -f /sys/fs/cgroup/cgroup.max.depth; then
    unit="test-subgroup-$RANDOM.service"
    systemd-run --wait \
                --unit="$unit" \
                --property="DynamicUser=1" \
                --property="Delegate=pids" \
                --property="DelegateSubgroup=zzz" \
                test -w "/sys/fs/cgroup/system.slice/$unit/zzz/cgroup.max.depth"
fi

# Check that the invoked process itself is also in the subgroup
unit="test-subgroup-$RANDOM.service"
systemd-run --wait \
            --unit="$unit" \
            --property="DynamicUser=1" \
            --property="Delegate=pids" \
            --property="DelegateSubgroup=bar" \
            grep -q -x -F "0::/system.slice/$unit/bar" /proc/self/cgroup
