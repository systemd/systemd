#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e

    # Remove any test files
    rm -rf /tmp/TEST-07-PID1-private-pids
    # Stop any test services
    systemctl kill --signal=KILL TEST-07-PID1-private-pid.service
    # Remove any failed transient units
    systemctl reset-failed
}

trap at_exit EXIT

testcase_basic() {
    # Verify current process is PID1 in new namespace
    assert_eq "$(systemd-run -p PrivatePIDs=yes --wait --pipe readlink /proc/self)" "1"
    # Verify we are only processes in new namespace
    assert_eq "$(systemd-run -p PrivatePIDs=yes --wait --pipe ps aux --no-heading | wc -l)" "1"
    # Verify procfs mount
    systemd-run -p PrivatePIDs=yes --wait --pipe \
            bash -xec '[[ "$$(findmnt --mountpoint /proc --noheadings -o VFS-OPTIONS)" =~ rw ]];
                       [[ "$$(findmnt --mountpoint /proc --noheadings -o VFS-OPTIONS)" =~ nosuid ]];
                       [[ "$$(findmnt --mountpoint /proc --noheadings -o VFS-OPTIONS)" =~ nodev ]];
                       [[ "$$(findmnt --mountpoint /proc --noheadings -o VFS-OPTIONS)" =~ noexec ]];'

    # Verify main PID is correct
    systemd-run -p PrivatePIDs=yes  --remain-after-exit --unit TEST-07-PID1-private-pid sleep infinity
    # Wait for ExecMainPID to be correctly populated as there might be a race between spawning service
    # and actual exec child process
    sleep 2
    pid=$(systemctl show TEST-07-PID1-private-pid.service -p ExecMainPID --value)
    kill -9 "$pid"
    timeout 10s bash -xec 'while [[ "$(systemctl show -P SubState TEST-07-PID1-private-pid.service)" != "failed" ]]; do sleep .5; done'
    assert_eq "$(systemctl show -P Result TEST-07-PID1-private-pid.service)" "signal"
    assert_eq "$(systemctl show -P ExecMainStatus TEST-07-PID1-private-pid.service)" "9"
    systemctl reset-failed
}

testcase_analyze() {
    mkdir -p /tmp/TEST-07-PID1-private-pids

    # Verify other services are compatible with PrivatePIDs=yes
    cat <<EOF >/tmp/TEST-07-PID1-private-pids/oneshot-valid.service
[Service]
ExecStart=echo hello
PrivatePIDs=yes
Type=oneshot
EOF

    # Verify Type=forking services are not compatible with PrivatePIDs=yes
    cat <<EOF >/tmp/TEST-07-PID1-private-pids/forking-invalid.service
[Service]
ExecStart=echo hello
PrivatePIDs=yes
Type=forking
EOF

    systemd-analyze --recursive-errors=no verify /tmp/TEST-07-PID1-private-pids/oneshot-valid.service
    (! systemd-analyze --recursive-errors=no verify /tmp/TEST-07-PID1-private-pids/forking-invalid.service)


    rm -rf /tmp/TEST-07-PID1-private-pids
}

testcase_multiple_features() {
    systemd-run \
        -p PrivatePIDs=yes \
        -p RootDirectory=/usr/share/TEST-13-NSPAWN-container-template \
        -p ProcSubset=pid \
        -p BindReadOnlyPaths=/usr/share \
        -p NoNewPrivileges=yes \
        -p ProtectSystem=strict \
        -p User=testuser\
        -p Group=testuser \
        -p RuntimeDirectory=abc \
        -p StateDirectory=qed \
        -p InaccessiblePaths=/usr/include \
        -p TemporaryFileSystem=/home \
        -p PrivateTmp=yes \
        -p PrivateDevices=yes \
        -p PrivateNetwork=yes \
        -p PrivateUsersEx=self \
        -p PrivateIPC=yes \
        -p ProtectHostname=yes \
        -p ProtectClock=yes \
        -p ProtectKernelTunables=yes \
        -p ProtectKernelModules=yes \
        -p ProtectKernelLogs=yes \
        -p ProtectControlGroupsEx=private \
        -p LockPersonality=yes \
        -p Environment=ABC=QED \
        --wait \
        --pipe \
        true
}

testcase_unpriv() {
    if [ ! -f /usr/lib/systemd/user/dbus.socket ] && [ ! -f /etc/systemd/user/dbus.socket ]; then
        echo "Per-user instances are not supported, skipping unprivileged PrivatePIDs=yes test"
        return 77
    fi

    if [[ "$(sysctl -ne kernel.apparmor_restrict_unprivileged_userns)" -eq 1 ]]; then
        echo "Cannot create unprivileged user namespaces, skipping unprivileged PrivatePIDs=yes test"
        return 77
    fi

    # For debugging - remove later
    mount

    # Verify running as unprivileged user can unshare PID namespace and mounts /proc properly
    assert_eq "$(runas testuser systemd-run --wait --user --pipe -p PrivatePIDs=yes readlink /proc/self)" "1"
    assert_eq "$(runas testuser systemd-run --wait --user --pipe -p PrivatePIDs=yes ps aux --no-heading | wc -l)" "1"
}

run_testcases
