#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

function test_controllers() {
    systemd-run --wait --unit=test0.service -p "DynamicUser=1" -p "Delegate=" \
                test -w /sys/fs/cgroup/system.slice/test0.service/ -a \
                -w /sys/fs/cgroup/system.slice/test0.service/cgroup.procs -a \
                -w /sys/fs/cgroup/system.slice/test0.service/cgroup.subtree_control

    systemd-run --wait --unit=test1.service -p "DynamicUser=1" -p "Delegate=memory pids" \
                grep -q memory /sys/fs/cgroup/system.slice/test1.service/cgroup.controllers

    systemd-run --wait --unit=test2.service -p "DynamicUser=1" -p "Delegate=memory pids" \
                grep -q pids /sys/fs/cgroup/system.slice/test2.service/cgroup.controllers

    # "io" is not among the controllers enabled by default for all units, verify that
    grep -qv io /sys/fs/cgroup/system.slice/cgroup.controllers

    # Run a service with "io" enabled, and verify it works
    systemd-run --wait --unit=test3.service -p "IOAccounting=yes" -p "Slice=system-foo-bar-baz.slice"  \
                grep -q io /sys/fs/cgroup/system.slice/system-foo.slice/system-foo-bar.slice/system-foo-bar-baz.slice/test3.service/cgroup.controllers

    # We want to check if "io" is removed again from the controllers
    # list. However, PID 1 (rightfully) does this asynchronously. In order
    # to force synchronization on this, let's start a short-lived service
    # which requires PID 1 to refresh the cgroup tree, so that we can
    # verify that this all works.
    systemd-run --wait --unit=test4.service true

    # And now check again, "io" should have vanished
    grep -qv io /sys/fs/cgroup/system.slice/cgroup.controllers
}

test_scope_unpriv_delegation() {
    useradd test ||:
    trap "userdel -r test" RETURN

    systemd-run --uid=test -p User=test -p Delegate=yes --slice workload.slice --unit workload0.scope --scope \
            test -w /sys/fs/cgroup/workload.slice/workload0.scope -a \
            -w /sys/fs/cgroup/workload.slice/workload0.scope/cgroup.procs -a \
            -w /sys/fs/cgroup/workload.slice/workload0.scope/cgroup.subtree_control
}

function test_threaded() {
    if [ ! -f /sys/fs/cgroup/init.scope/cgroup.type ] ; then
        echo "Skippint TEST-19-DELEGATE threads test, cgroup v2 doesn't support cgroup.type" >&2
        return
    fi

    local SERVICE_PATH SERVICE_NAME
    SERVICE_PATH="$(mktemp /etc/systemd/system/test-delegate-XXX.service)"
    SERVICE_NAME="${SERVICE_PATH##*/}"

    cat >"$SERVICE_PATH" <<EOF
[Service]
Delegate=true
ExecStartPre=/bin/mkdir /sys/fs/cgroup/system.slice/$SERVICE_NAME/subtree
ExecStartPre=/bin/bash -c "echo threaded >/sys/fs/cgroup/system.slice/$SERVICE_NAME/subtree/cgroup.type"
ExecStart=/bin/sleep 86400
ExecReload=/bin/echo pretending to reload
EOF

    systemctl daemon-reload
    systemctl start "$SERVICE_NAME"
    systemctl status "$SERVICE_NAME"
    # The reload SHOULD succeed
    systemctl reload "$SERVICE_NAME" || { echo 'unexpected reload failure'; exit 1; }
    systemctl stop "$SERVICE_NAME"

    rm -f "$SERVICE_PATH"
}

function test_suffix() {
    local SERVICE_PATH SERVICE_NAME pid directive
    local config="$1"
    local exp_payload="${2:+/}$2"
    local exp_control="${3:+/}$3"
    SERVICE_PATH="$(mktemp /run/systemd/system/test-delegate-wrap-XXX.service)"
    SERVICE_NAME="${SERVICE_PATH##*/}"

    cat >"$SERVICE_PATH" <<EOF
[Service]
Slice=system.slice
Delegate=true
DelegateControlGroupSuffix=$config
DynamicUser=1
ExecStart=/bin/sleep inf
ExecStartPost=/bin/mkdir /sys/fs/cgroup/system.slice/$SERVICE_NAME/subcgroup
ExecStartPost=/bin/bash -c "echo 0>/sys/fs/cgroup/system.slice/$SERVICE_NAME/subcgroup/cgroup.procs"
ExecReload=/bin/sh -c "grep 0:: /proc/self/cgroup"
EOF

    systemctl daemon-reload
    systemctl start "$SERVICE_NAME"
    trap 'systemctl stop "$SERVICE_NAME"' RETURN
    pid="$(systemctl show -P MainPID "$SERVICE_NAME")"
    if ! grep -q "0::/system.slice/$SERVICE_NAME$exp_payload\\>" "/proc/$pid/cgroup" ; then
        echo "Wrong payload cgroup: $(cat "/proc/$pid/cgroup")"
        return 1
    fi

    systemctl reload "$SERVICE_NAME"
    if ! journalctl -b -u "$SERVICE_NAME" | grep -q "0::/system.slice/$SERVICE_NAME$exp_control\\>" ; then
        echo "Wrong control cgroup: $(journalctl -b -u "$SERVICE_NAME" | grep 0::)"
        return 1
    fi
}

if ! grep -q cgroup2 /proc/filesystems ; then
    echo "Skipping TEST-19-DELEGATE, as the kernel doesn't actually support cgroup v2" >&2
    exit 0
fi

test_controllers
test_scope_unpriv_delegation
test_threaded
test_suffix "."       ""        ""
test_suffix "my/path" "my/path" "my/path"
test_suffix ""        ""        ".control"

echo OK >/testok

exit 0
