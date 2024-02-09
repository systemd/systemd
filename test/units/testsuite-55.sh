#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
 . "$(dirname "$0")"/util.sh

systemd-analyze log-level debug

# Ensure that the init.scope.d drop-in is applied on boot
test "$(cat /sys/fs/cgroup/init.scope/memory.high)" != "max"

# Loose checks to ensure the environment has the necessary features for systemd-oomd
[[ -e /proc/pressure ]] || echo "no PSI" >>/skipped
[[ "$(get_cgroup_hierarchy)" == "unified" ]] || echo "no cgroupsv2" >>/skipped
[[ -x /usr/lib/systemd/systemd-oomd ]] || echo "no oomd" >>/skipped
if [[ -s /skipped ]]; then
    exit 0
fi

rm -rf /run/systemd/system/testsuite-55-testbloat.service.d

# Activate swap file if we are in a VM
if systemd-detect-virt --vm --quiet; then
    mkswap /swapfile
    swapon /swapfile
    swapon --show
fi

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

if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running with sanitizers, sd-executor might pull in quite a significant chunk of shared
    # libraries, which in turn causes a lot of pressure that can put us in the front when sd-oomd decides to
    # go on a killing spree. This fact is exacerbated further on Arch Linux which ships unstripped gcc-libs,
    # so sd-executor pulls in over 30M of libs on startup. Let's make the MemoryHigh= limit a bit more
    # generous when running with sanitizers to make the test happy.
    systemctl edit --runtime --stdin --drop-in=99-MemoryHigh.conf testsuite-55-testchill.service <<EOF
[Service]
MemoryHigh=60M
EOF
    # Do the same for the user instance as well
    mkdir -p /run/systemd/user/
    cp -rfv /run/systemd/system/testsuite-55-testchill.service.d/ /run/systemd/user/
else
    # Ensure that we can start services even with a very low hard memory cap without oom-kills, but skip
    # under sanitizers as they balloon memory usage.
    systemd-run -t -p MemoryMax=10M -p MemorySwapMax=0 -p MemoryZSwapMax=0 /bin/true
fi

systemctl start testsuite-55-testchill.service
systemctl start testsuite-55-testbloat.service

# Verify systemd-oomd is monitoring the expected units
timeout 1m bash -xec 'until oomctl | grep "/testsuite-55-workload.slice"; do sleep 1; done'
oomctl | grep "/testsuite-55-workload.slice"
oomctl | grep "20.00%"
oomctl | grep "Default Memory Pressure Duration: 2s"

systemctl status testsuite-55-testchill.service

# systemd-oomd watches for elevated pressure for 2 seconds before acting.
# It can take time to build up pressure so either wait 2 minutes or for the service to fail.
for _ in {0..59}; do
    if ! systemctl status testsuite-55-testbloat.service; then
        break
    fi
    oomctl
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
timeout 1m bash -xec 'until oomctl | grep "/testsuite-55-workload.slice"; do sleep 1; done'
oomctl | grep -E "/user.slice.*/testsuite-55-workload.slice"
oomctl | grep "20.00%"
oomctl | grep "Default Memory Pressure Duration: 2s"

systemctl --machine "testuser@.host" --user status testsuite-55-testchill.service

# systemd-oomd watches for elevated pressure for 2 seconds before acting.
# It can take time to build up pressure so either wait 2 minutes or for the service to fail.
for _ in {0..59}; do
    if ! systemctl --machine "testuser@.host" --user status testsuite-55-testbloat.service; then
        break
    fi
    oomctl
    sleep 2
done

# testbloat should be killed and testchill should be fine
if systemctl --machine "testuser@.host" --user status testsuite-55-testbloat.service; then exit 42; fi
if ! systemctl --machine "testuser@.host" --user status testsuite-55-testchill.service; then exit 24; fi

# only run this portion of the test if we can set xattrs
if cgroupfs_supports_user_xattrs; then
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

    for _ in {0..59}; do
        if ! systemctl status testsuite-55-testmunch.service; then
            break
        fi
        oomctl
        sleep 2
    done

    # testmunch should be killed since testbloat had the avoid xattr on it
    if ! systemctl status testsuite-55-testbloat.service; then exit 25; fi
    if systemctl status testsuite-55-testmunch.service; then exit 43; fi
    if ! systemctl status testsuite-55-testchill.service; then exit 24; fi
fi

systemd-analyze log-level info

touch /testok
