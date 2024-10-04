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

testcase_iodevice_dbus () {
    # Test that per-device properties are applied in configured order even for different devices (because
    # they may resolve to same underlying device in the end
    # Note: if device does not exist cgroup attribute write fails but systemd should still track the
    # configured properties
    systemd-run --unit=test0.service \
                --property="IOAccounting=yes" \
                sleep inf

    systemctl set-property test0.service \
              IOReadBandwidthMax="/dev/sda1 1M" \
              IOReadBandwidthMax="/dev/sda2 2M" \
              IOReadBandwidthMax="/dev/sda3 4M"

    local output
    output=$(mktemp)
    trap 'rm -f "$output"' RETURN
    systemctl show -P IOReadBandwidthMax test0.service >"$output"
    diff -u "$output" - <<EOF
/dev/sda1 1000000
/dev/sda2 2000000
/dev/sda3 4000000
EOF

    systemctl stop test0.service
}

testcase_iodevice_unitfile () {
    cat >/run/systemd/system/test1.service <<EOF
[Service]
ExecStart=/usr/bin/sleep inf
IOReadBandwidthMax=/dev/sda1 1M
IOReadBandwidthMax=/dev/sda2 2M
IOReadBandwidthMax=/dev/sda3 4M
EOF
    systemctl daemon-reload

    local output
    output=$(mktemp)
    trap 'rm -f "$output"' RETURN
    systemctl show -P IOReadBandwidthMax test1.service >"$output"
    diff -u "$output" - <<EOF
/dev/sda1 1000000
/dev/sda2 2000000
/dev/sda3 4000000
EOF
    rm -f /run/systemd/system/test1.service
}

run_testcases
