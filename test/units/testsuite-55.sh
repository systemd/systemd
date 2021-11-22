#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

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

rm -rf /etc/systemd/system/testsuite-55-testbloat.service.d

echo "DefaultMemoryPressureDurationSec=2s" >>/etc/systemd/oomd.conf

mkdir -p /etc/systemd/system/systemd-oomd.service.d/
echo -e "[Service]\nEnvironment=SYSTEMD_LOG_LEVEL=debug" >/etc/systemd/system/systemd-oomd.service.d/debug.conf

systemctl daemon-reload

# if oomd is already running for some reasons, then restart it to make sure the above settings to be applied
if systemctl is-active systemd-oomd.service; then
    systemctl restart systemd-oomd.service
fi

systemctl start testsuite-55-testchill.service
systemctl start testsuite-55-testbloat.service

# Verify systemd-oomd is monitoring the expected units
oomctl | grep "/testsuite-55-workload.slice"
oomctl | grep "20.00%"
oomctl | grep "Default Memory Pressure Duration: 2s"

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
oomctl | grep -E "/user.slice.*/testsuite-55-workload.slice"
oomctl | grep "20.00%"
oomctl | grep "Default Memory Pressure Duration: 2s"

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

    mkdir -p /etc/systemd/system/testsuite-55-testbloat.service.d/
    echo "[Service]" >/etc/systemd/system/testsuite-55-testbloat.service.d/override.conf
    echo "ManagedOOMPreference=avoid" >>/etc/systemd/system/testsuite-55-testbloat.service.d/override.conf

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
