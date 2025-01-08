#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux
set -o pipefail

# Test cgroup delegation in the unified hierarchy

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "Skipping $0 as we're not running with the unified cgroup hierarchy"
    exit 0
fi

testcase_controllers() {
    systemd-run --wait \
                --unit=test-0.service \
                --property="DynamicUser=1" \
                --property="Delegate=" \
                test -w /sys/fs/cgroup/system.slice/test-0.service/ -a \
                     -w /sys/fs/cgroup/system.slice/test-0.service/cgroup.procs -a \
                     -w /sys/fs/cgroup/system.slice/test-0.service/cgroup.subtree_control

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
}

testcase_attributes() {
    # Test if delegation also works for some of the more recent attrs the kernel might or might not support
    for attr in cgroup.threads memory.oom.group memory.reclaim ; do
        if grep -q "$attr" /sys/kernel/cgroup/delegate ; then
            systemd-run --wait \
                        --unit=test-0.service \
                        --property="MemoryAccounting=1" \
                        --property="DynamicUser=1" \
                        --property="Delegate=" \
                        test -w /sys/fs/cgroup/system.slice/test-0.service/ -a \
                        -w /sys/fs/cgroup/system.slice/test-0.service/"$attr"
        fi
    done
}

testcase_scope_unpriv_delegation() {
    # Check that unprivileged delegation works for scopes
    useradd test
    trap "userdel -r test" RETURN
    systemd-run --uid=test \
                --property="User=test" \
                --property="Delegate=yes" \
                --slice workload.slice \
                --unit test-workload0.scope\
                --scope \
                test -w /sys/fs/cgroup/workload.slice/test-workload0.scope -a \
                     -w /sys/fs/cgroup/workload.slice/test-workload0.scope/cgroup.procs -a \
                     -w /sys/fs/cgroup/workload.slice/test-workload0.scope/cgroup.subtree_control
}

testcase_user_unpriv_delegation() {
    # Check that delegation works for unpriv users, and that we can insert a
    # subcgroup owned by a different user (which can happen in case unpriv
    # userns where a UID range was delegated), which is still cleaned up
    # correctly when it goes down.

    run0 -u testuser systemd-run --user \
                --property="Delegate=yes" \
                --unit=test-chown-subcgroup \
                --service-type=exec \
                sleep infinity

    TESTUID=$(id -u testuser)
    CGROUP="/sys/fs/cgroup/user.slice/user-$TESTUID.slice/user@$TESTUID.service/app.slice/test-chown-subcgroup.service"
    test -d "$CGROUP"

    # Create a subcgroup, and make it owned by some unrelated user
    SUBCGROUP="$CGROUP/subcgroup"
    mkdir "$SUBCGROUP"
    chown 1:1 "$SUBCGROUP"

    # Make sure the subcgroup is not empty (empty dirs owned by other users can
    # be removed if one owns the dir they are contained in, after all)
    mkdir "$SUBCGROUP"/filler

    run0 -u testuser systemctl stop --user test-chown-subcgroup.service

    # Verify that the subcgroup got correctly removed
    (! test -e "$CGROUP")

    systemctl stop user@testuser.service
}

testcase_subgroup() {
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
}

run_testcases
