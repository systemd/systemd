#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
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
    exit 77
fi

# Activate swap file if we are in a VM
if systemd-detect-virt --vm --quiet; then
    swapoff --all
    rm -f /swapfile
    if [[ "$(findmnt -n -o FSTYPE /)" == btrfs ]]; then
        btrfs filesystem mkswapfile -s 64M /swapfile
    else
        dd if=/dev/zero of=/swapfile bs=1M count=64
        chmod 0600 /swapfile
        mkswap /swapfile
    fi

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

# Check if the oomd.conf drop-in config is loaded.
assert_in 'Default Memory Pressure Duration: 2s' "$(oomctl)"

if [[ -v ASAN_OPTIONS || -v UBSAN_OPTIONS ]]; then
    # If we're running with sanitizers, sd-executor might pull in quite a significant chunk of shared
    # libraries, which in turn causes a lot of pressure that can put us in the front when sd-oomd decides to
    # go on a killing spree. This fact is exacerbated further on Arch Linux which ships unstripped gcc-libs,
    # so sd-executor pulls in over 30M of libs on startup. Let's make the MemoryHigh= limit a bit more
    # generous when running with sanitizers to make the test happy.
    systemctl edit --runtime --stdin --drop-in=99-MemoryHigh.conf TEST-55-OOMD-testchill.service <<EOF
[Service]
MemoryHigh=60M
EOF
    # Do the same for the user instance as well
    mkdir -p /run/systemd/user/
    cp -rfv /run/systemd/system/TEST-55-OOMD-testchill.service.d/ /run/systemd/user/
else
    # Ensure that we can start services even with a very low hard memory cap without oom-kills, but skip
    # under sanitizers as they balloon memory usage.
    systemd-run -t -p MemoryMax=10M -p MemorySwapMax=0 -p MemoryZSwapMax=0 /bin/true
fi

test_basic() {
    local cgroup_path="${1:?}"
    shift

    systemctl "$@" start TEST-55-OOMD-testchill.service
    systemctl "$@" status TEST-55-OOMD-testchill.service
    systemctl "$@" status TEST-55-OOMD-workload.slice

    # Verify systemd-oomd is monitoring the expected units.
    timeout 1m bash -xec "until oomctl | grep -q -F 'Path: $cgroup_path'; do sleep 1; done"
    assert_in 'Memory Pressure Limit: 20.00%' \
              "$(oomctl | tac | sed -e '/Memory Pressure Monitored CGroups:/q' | tac | grep -A8 "Path: $cgroup_path")"

    systemctl "$@" start TEST-55-OOMD-testbloat.service

    # systemd-oomd watches for elevated pressure for 2 seconds before acting.
    # It can take time to build up pressure so either wait 2 minutes or for the service to fail.
    for _ in {0..59}; do
        if ! systemctl "$@" status TEST-55-OOMD-testbloat.service; then
            break
        fi
        oomctl
        sleep 2
    done

    # testbloat should be killed and testchill should be fine
    if systemctl "$@" status TEST-55-OOMD-testbloat.service; then exit 42; fi
    if ! systemctl "$@" status TEST-55-OOMD-testchill.service; then exit 24; fi

    systemctl "$@" kill --signal=KILL TEST-55-OOMD-testbloat.service || :
    systemctl "$@" stop TEST-55-OOMD-testbloat.service
    systemctl "$@" stop TEST-55-OOMD-testchill.service
    systemctl "$@" stop TEST-55-OOMD-workload.slice
}

testcase_basic_system() {
    test_basic /TEST.slice/TEST-55.slice/TEST-55-OOMD.slice/TEST-55-OOMD-workload.slice
}

testcase_basic_user() {
    # Make sure we also work correctly on user units.
    loginctl enable-linger testuser

    test_basic "/user.slice/user-$(id -u testuser).slice/user@$(id -u testuser).service/TEST.slice/TEST-55.slice/TEST-55-OOMD.slice/TEST-55-OOMD-workload.slice" \
               --machine "testuser@.host" --user

    loginctl disable-linger testuser
}

testcase_preference_avoid() {
    # only run this portion of the test if we can set xattrs
    if ! cgroupfs_supports_user_xattrs; then
        echo "cgroup does not support user xattrs, skipping test for ManagedOOMPreference=avoid"
        return 0
    fi

    mkdir -p /run/systemd/system/TEST-55-OOMD-testbloat.service.d/
    cat >/run/systemd/system/TEST-55-OOMD-testbloat.service.d/99-managed-oom-preference.conf <<EOF
[Service]
ManagedOOMPreference=avoid
EOF

    systemctl daemon-reload
    systemctl start TEST-55-OOMD-testchill.service
    systemctl start TEST-55-OOMD-testmunch.service
    systemctl start TEST-55-OOMD-testbloat.service

    for _ in {0..59}; do
        if ! systemctl status TEST-55-OOMD-testmunch.service; then
            break
        fi
        oomctl
        sleep 2
    done

    # testmunch should be killed since testbloat had the avoid xattr on it
    if ! systemctl status TEST-55-OOMD-testbloat.service; then exit 25; fi
    if systemctl status TEST-55-OOMD-testmunch.service; then exit 43; fi
    if ! systemctl status TEST-55-OOMD-testchill.service; then exit 24; fi

    systemctl kill --signal=KILL TEST-55-OOMD-testbloat.service || :
    systemctl kill --signal=KILL TEST-55-OOMD-testmunch.service || :
    systemctl stop TEST-55-OOMD-testbloat.service
    systemctl stop TEST-55-OOMD-testmunch.service
    systemctl stop TEST-55-OOMD-testchill.service
    systemctl stop TEST-55-OOMD-workload.slice

    # clean up overrides since test cases can be run in any order
    # and overrides shouldn't affect other tests
    rm -rf /run/systemd/system/TEST-55-OOMD-testbloat.service.d
    systemctl daemon-reload
}

testcase_duration_analyze() {
    # Verify memory pressure duration is valid if >= 1 second
    cat <<EOF >/tmp/TEST-55-OOMD-valid-duration.service
[Service]
ExecStart=echo hello
ManagedOOMMemoryPressureDurationSec=1s
EOF

    # Verify memory pressure duration is invalid if < 1 second
    cat <<EOF >/tmp/TEST-55-OOMD-invalid-duration.service
[Service]
ExecStart=echo hello
ManagedOOMMemoryPressureDurationSec=0
EOF

    systemd-analyze --recursive-errors=no verify /tmp/TEST-55-OOMD-valid-duration.service
    (! systemd-analyze --recursive-errors=no verify /tmp/TEST-55-OOMD-invalid-duration.service)

    rm -f /tmp/TEST-55-OOMD-valid-duration.service
    rm -f /tmp/TEST-55-OOMD-invalid-duration.service
}

testcase_duration_override() {
    # Verify memory pressure duration can be overridden to non-zero values
    mkdir -p /run/systemd/system/TEST-55-OOMD-testmunch.service.d/
    cat >/run/systemd/system/TEST-55-OOMD-testmunch.service.d/99-duration-test.conf <<EOF
[Service]
ManagedOOMMemoryPressureDurationSec=3s
ManagedOOMMemoryPressure=kill
EOF

    # Verify memory pressure duration will use default if set to empty
    mkdir -p /run/systemd/system/TEST-55-OOMD-testchill.service.d/
    cat >/run/systemd/system/TEST-55-OOMD-testchill.service.d/99-duration-test.conf <<EOF
[Service]
ManagedOOMMemoryPressureDurationSec=
ManagedOOMMemoryPressure=kill
EOF

    systemctl daemon-reload
    systemctl start TEST-55-OOMD-testmunch.service
    systemctl start TEST-55-OOMD-testchill.service

    timeout 1m bash -xec 'until oomctl | grep "/TEST-55-OOMD-testmunch.service"; do sleep 1; done'
    oomctl | grep -A 2 "/TEST-55-OOMD-testmunch.service" | grep "Memory Pressure Duration: 3s"

    timeout 1m bash -xec 'until oomctl | grep "/TEST-55-OOMD-testchill.service"; do sleep 1; done'
    oomctl | grep -A 2 "/TEST-55-OOMD-testchill.service" | grep "Memory Pressure Duration: 2s"

    [[ "$(systemctl show -P ManagedOOMMemoryPressureDurationUSec TEST-55-OOMD-testmunch.service)" == "3s" ]]
    [[ "$(systemctl show -P ManagedOOMMemoryPressureDurationUSec TEST-55-OOMD-testchill.service)" == "[not set]" ]]

    for _ in {0..59}; do
        if ! systemctl status TEST-55-OOMD-testmunch.service; then
            break
        fi
        oomctl
        sleep 2
    done

    if systemctl status TEST-55-OOMD-testmunch.service; then exit 44; fi
    if ! systemctl status TEST-55-OOMD-testchill.service; then exit 23; fi

    systemctl kill --signal=KILL TEST-55-OOMD-testmunch.service || :
    systemctl stop TEST-55-OOMD-testmunch.service
    systemctl stop TEST-55-OOMD-testchill.service
    systemctl stop TEST-55-OOMD-workload.slice

    # clean up overrides since test cases can be run in any order
    # and overrides shouldn't affect other tests
    rm -rf /run/systemd/system/TEST-55-OOMD-testmunch.service.d
    rm -rf /run/systemd/system/TEST-55-OOMD-testchill.service.d
    systemctl daemon-reload
}

testcase_reload() {
    # Check if the oomd.conf drop-in config is loaded.
    assert_in 'Swap Used Limit: 90.00%' "$(oomctl)"
    assert_in 'Default Memory Pressure Limit: 60.00%' "$(oomctl)"
    assert_in 'Default Memory Pressure Duration: 2s' "$(oomctl)"

    # Test oomd reload
    mkdir -p /run/systemd/oomd.conf.d/
    {
        echo "[OOM]"
        echo "SwapUsedLimit=80%"
        echo "DefaultMemoryPressureLimit=55%"
        echo "DefaultMemoryPressureDurationSec=5s"
    } >/run/systemd/oomd.conf.d/99-oomd-test.conf

    systemctl reload systemd-oomd.service
    assert_in 'Swap Used Limit: 80.00%' "$(oomctl)"
    assert_in 'Default Memory Pressure Limit: 55.00%' "$(oomctl)"
    assert_in 'Default Memory Pressure Duration: 5s' "$(oomctl)"

    # Set back to default via reload
    mkdir -p /run/systemd/oomd.conf.d/
    {
        echo "[OOM]"
        echo "DefaultMemoryPressureDurationSec=2s"
    } >/run/systemd/oomd.conf.d/99-oomd-test.conf

    systemctl reload systemd-oomd.service

    assert_in 'Swap Used Limit: 90.00%' "$(oomctl)"
    assert_in 'Default Memory Pressure Limit: 60.00%' "$(oomctl)"
    assert_in 'Default Memory Pressure Duration: 2s' "$(oomctl)"
}

run_testcases

systemd-analyze log-level info

touch /testok
