#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug

# Ensure that the init.scope.d drop-in is applied on boot
test "$(cat /sys/fs/cgroup/init.scope/memory.high)" != "max"

# Loose checks to ensure the environment has the necessary features for systemd-oomd
[[ -e /proc/pressure ]] || echo "no PSI" >>/skipped
cgroup_type="$(stat -fc %T /sys/fs/cgroup/)"
if [[ "$cgroup_type" != *"cgroup2"* ]] && [[ "$cgroup_type" != *"0x63677270"* ]]; then
    echo "no cgroup2" >>/skipped
fi
if [ ! -f /usr/lib/systemd/systemd-oomd ] && [ ! -f /lib/systemd/systemd-oomd ]; then
    echo "no oomd" >>/skipped
fi

if [[ -e /skipped ]]; then
    exit 0
fi

rm -rf /run/systemd/system/testsuite-55-testbloat.service.d

# Configure oomd explicitly to avoid conflicts with distro dropins
mkdir -p /run/systemd/oomd.conf.d/
cat >/run/systemd/oomd.conf.d/99-oomd-test.conf <<EOF
[OOM]
DefaultMemoryPressureDurationSec=2s
EOF

mkdir -p /run/systemd/system/-.slice.d/
cat >/run/systemd/system/-.slice.d/99-oomd-test.conf <<EOF
[Slice]
ManagedOOMSwap=auto
EOF

mkdir -p /run/systemd/system/user@.service.d/
cat >/run/systemd/system/user@.service.d/99-oomd-test.conf <<EOF
[Service]
ManagedOOMMemoryPressure=auto
ManagedOOMMemoryPressureLimit=0%
EOF

mkdir -p /run/systemd/system/systemd-oomd.service.d/
cat >/run/systemd/system/systemd-oomd.service.d/debug.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

systemctl daemon-reload

# enable the service to ensure dbus-org.freedesktop.oom1.service exists
# and D-Bus activation works
systemctl enable systemd-oomd.service

# if oomd is already running for some reasons, then restart it to make sure the above settings to be applied
if systemctl is-active systemd-oomd.service; then
    systemctl restart systemd-oomd.service
fi

systemctl start testsuite-55-testchill.service
systemctl start testsuite-55-testbloat.service

# Verify systemd-oomd is monitoring the expected units
# Try to avoid racing the oomctl output check by checking in a loop with a timeout
oomctl_output=$(oomctl)
timeout="$(date -ud "1 minutes" +%s)"
while [[ $(date -u +%s) -le $timeout ]]; do
    if grep "/testsuite-55-workload.slice" <<< "$oomctl_output"; then
        break
    fi
    oomctl_output=$(oomctl)
    sleep 1
done

grep "/testsuite-55-workload.slice" <<< "$oomctl_output"
grep "20.00%" <<< "$oomctl_output"
grep "Default Memory Pressure Duration: 2s" <<< "$oomctl_output"

systemctl status testsuite-55-testchill.service

# systemd-oomd watches for elevated pressure for 2 seconds before acting.
# It can take time to build up pressure so either wait 2 minutes or for the service to fail.
timeout="$(date -ud "2 minutes" +%s)"
while [[ $(date -u +%s) -le $timeout ]]; do
    if ! systemctl status testsuite-55-testbloat.service; then
        break
    fi
    sleep 2
done

# testbloat should be killed and testchill should be fine
if systemctl status testsuite-55-testbloat.service; then exit 42; fi
if ! systemctl status testsuite-55-testchill.service; then exit 24; fi

# Make sure we also work correctly on user units.

systemctl start --machine "testuser@.host" --user testsuite-55-testchill.service
systemctl start --machine "testuser@.host" --user testsuite-55-testbloat.service

# Verify systemd-oomd is monitoring the expected units
# Try to avoid racing the oomctl output check by checking in a loop with a timeout
oomctl_output=$(oomctl)
timeout="$(date -ud "1 minutes" +%s)"
while [[ $(date -u +%s) -le $timeout ]]; do
    if grep -E "/user.slice.*/testsuite-55-workload.slice" <<< "$oomctl_output"; then
        break
    fi
    oomctl_output=$(oomctl)
    sleep 1
done

grep -E "/user.slice.*/testsuite-55-workload.slice" <<< "$oomctl_output"
grep "20.00%" <<< "$oomctl_output"
grep "Default Memory Pressure Duration: 2s" <<< "$oomctl_output"

systemctl --machine "testuser@.host" --user status testsuite-55-testchill.service

# systemd-oomd watches for elevated pressure for 2 seconds before acting.
# It can take time to build up pressure so either wait 2 minutes or for the service to fail.
timeout="$(date -ud "2 minutes" +%s)"
while [[ $(date -u +%s) -le $timeout ]]; do
    if ! systemctl --machine "testuser@.host" --user status testsuite-55-testbloat.service; then
        break
    fi
    sleep 2
done

# testbloat should be killed and testchill should be fine
if systemctl --machine "testuser@.host" --user status testsuite-55-testbloat.service; then exit 42; fi
if ! systemctl --machine "testuser@.host" --user status testsuite-55-testchill.service; then exit 24; fi

# only run this portion of the test if we can set xattrs
if setfattr -n user.xattr_test -v 1 /sys/fs/cgroup/; then
    sleep 120 # wait for systemd-oomd kill cool down and elevated memory pressure to come down

    mkdir -p /run/systemd/system/testsuite-55-testbloat.service.d/
    cat >/run/systemd/system/testsuite-55-testbloat.service.d/override.conf <<EOF
[Service]
ManagedOOMPreference=avoid
EOF

    systemctl daemon-reload
    systemctl start testsuite-55-testchill.service
    systemctl start testsuite-55-testmunch.service
    systemctl start testsuite-55-testbloat.service

    timeout="$(date -ud "2 minutes" +%s)"
    while [[ "$(date -u +%s)" -le "$timeout" ]]; do
        if ! systemctl status testsuite-55-testmunch.service; then
            break
        fi
        sleep 2
    done

    # testmunch should be killed since testbloat had the avoid xattr on it
    if ! systemctl status testsuite-55-testbloat.service; then exit 25; fi
    if systemctl status testsuite-55-testmunch.service; then exit 43; fi
    if ! systemctl status testsuite-55-testchill.service; then exit 24; fi
fi

systemd-analyze log-level info

echo OK >/testok

exit 0
