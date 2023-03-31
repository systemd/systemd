#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

test_scope_unpriv_delegation() {
    useradd test ||:
    trap "userdel -r test" RETURN

    systemd-run --uid=test -p User=test -p Delegate=yes --slice workload.slice --unit test-workload0.scope --scope \
            test -w /sys/fs/cgroup/workload.slice/test-workload0.scope -a \
            -w /sys/fs/cgroup/workload.slice/test-workload0.scope/cgroup.procs -a \
            -w /sys/fs/cgroup/workload.slice/test-workload0.scope/cgroup.subtree_control
}

if grep -q cgroup2 /proc/filesystems ; then
    systemd-run --wait --unit=test-0.service -p "DynamicUser=1" -p "Delegate=" \
                test -w /sys/fs/cgroup/system.slice/test-0.service/ -a \
                -w /sys/fs/cgroup/system.slice/test-0.service/cgroup.procs -a \
                -w /sys/fs/cgroup/system.slice/test-0.service/cgroup.subtree_control

    systemd-run --wait --unit=test-1.service -p "DynamicUser=1" -p "Delegate=memory pids" \
                grep -q memory /sys/fs/cgroup/system.slice/test-1.service/cgroup.controllers

    systemd-run --wait --unit=test-2.service -p "DynamicUser=1" -p "Delegate=memory pids" \
                grep -q pids /sys/fs/cgroup/system.slice/test-2.service/cgroup.controllers

    # "io" is not among the controllers enabled by default for all units, verify that
    grep -qv io /sys/fs/cgroup/system.slice/cgroup.controllers

    # Run a service with "io" enabled, and verify it works
    systemd-run --wait --unit=test-3.service -p "IOAccounting=yes" -p "Slice=system-foo-bar-baz.slice"  \
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
    test_scope_unpriv_delegation

else
    echo "Skipping TEST-19-DELEGATE, as the kernel doesn't actually support cgroup v2" >&2
fi

echo OK >/testok

exit 0
