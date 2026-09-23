#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

IFNAME=udevtestnetif
RULE=/run/udev/rules.d/99-udevtest-device-state.rules

netif_start_bound_service() {
    local path=${1:?}
    local name=${path##*-}
    local escaped

    escaped=$(systemd-escape --path "$path")
    escaped=${escaped//\\/\\\\} # escape backslash, as systemd-run unescapes it.

    systemd-run \
        -p After="${escaped}.device" \
        -p BindsTo="${escaped}.device" \
        -u "testsleep-${name}.service" \
        sleep 1h

    check_state "testsleep-${name}.service" active running
}

netif_prepare() {
    mkdir -p "${RULE%/*}"

    cat >"$RULE" <<EOF
ACTION=="add", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-b /dev/alias/%k-x /dev/alias/%k-y"
EOF
    udevadm control --reload

    ip link add "$IFNAME" type dummy
    ip link set "$IFNAME" down

    udevadm wait --timeout=30 --settle /sys/class/net/"$IFNAME"
    systemctl start /sys/devices/virtual/net/"$IFNAME"

    # The main device
    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    # The default alias
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    # The custom aliases
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b active plugged
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y active plugged
    check_state /dev/alias/"$IFNAME"-z inactive dead

    netif_start_bound_service /sys/alias/"$IFNAME"-a
    netif_start_bound_service /sys/alias/"$IFNAME"-b
    netif_start_bound_service /dev/alias/"$IFNAME"-x
    netif_start_bound_service /dev/alias/"$IFNAME"-y
}

netif_remove() {
    local ifname=${1:-$IFNAME}

    ip link del "$ifname"
    wait_for_inactive /sys/devices/virtual/net/"$ifname"

    check_state /sys/devices/virtual/net/"$ifname" inactive dead
    check_state /sys/subsystem/net/devices/"$ifname" inactive dead

    # Note that we always use $IFNAME for aliases.
    check_state /sys/alias/"$IFNAME"-a inactive dead
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x inactive dead
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service inactive dead
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service inactive dead
    check_state testsleep-y.service inactive dead
}

netif_get_udev_db() {
    local ifindex

    ifindex="$(cat /sys/class/net/"$IFNAME"/ifindex)"
    echo /run/udev/data/n"$ifindex"
}

netif_emulate_switching_root() {
    netif_prepare

    # Emulate switching-root from initrd to host system by removing the udev database,
    # which is typically done by udevadm info --cleanup-db. If the database is removed,
    # the active device units enter the activating (tentative) state.
    rm -f "$(netif_get_udev_db)"
    systemctl daemon-reload

    check_state /sys/devices/virtual/net/"$IFNAME" activating tentative
    check_state /sys/subsystem/net/devices/"$IFNAME" activating tentative
    check_state /sys/alias/"$IFNAME"-a activating tentative
    check_state /sys/alias/"$IFNAME"-b activating tentative
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x activating tentative
    check_state /dev/alias/"$IFNAME"-y activating tentative
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service active running
    check_state testsleep-b.service active running
    check_state testsleep-x.service active running
    check_state testsleep-y.service active running
}

testcase_netif_basic() {
    netif_prepare

    systemctl daemon-reload

    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b active plugged
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y active plugged
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service active running
    check_state testsleep-b.service active running
    check_state testsleep-x.service active running
    check_state testsleep-y.service active running

    systemctl daemon-reexec

    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b active plugged
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y active plugged
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service active running
    check_state testsleep-b.service active running
    check_state testsleep-x.service active running
    check_state testsleep-y.service active running

    netif_remove
}

testcase_netif_change_alias() {
    netif_prepare

    # Change event: update SYSTEMD_ALIAS.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    wait_for_inactive /sys/alias/"$IFNAME"-b
    systemctl start /sys/alias/"$IFNAME"-c

    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c active plugged
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z active plugged

    check_state testsleep-a.service active running
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service active running
    check_state testsleep-y.service inactive dead

    netif_remove
}

testcase_netif_systemd_ready() {
    netif_prepare

    # Change event: SYSTEMD_READY=0 -> all device units will be inactive.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_READY}="0"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    wait_for_inactive /sys/devices/virtual/net/"$IFNAME"

    check_state /sys/devices/virtual/net/"$IFNAME" inactive dead
    check_state /sys/subsystem/net/devices/"$IFNAME" inactive dead
    check_state /sys/alias/"$IFNAME"-a inactive dead
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x inactive dead
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service inactive dead
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service inactive dead
    check_state testsleep-y.service inactive dead

    # Change event: SYSTEMD_READY=1 -> devices will be ready.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z", \
  ENV{SYSTEMD_READY}="1"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    systemctl start /sys/devices/virtual/net/"$IFNAME"

    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c active plugged
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z active plugged

    check_state testsleep-a.service inactive dead
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service inactive dead
    check_state testsleep-y.service inactive dead

    netif_remove
}

testcase_netif_id_processing() {
    netif_prepare

    # Change event: with long RUN, hence ID_PROCESSING=1 can be seen.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z", \
  RUN+="/usr/bin/sleep 1000"
EOF
    udevadm control --reload
    udevadm trigger --action change /sys/devices/virtual/net/"$IFNAME"
    timeout 30 bash -c "until grep -q -F 'ID_PROCESSING=1' '$(netif_get_udev_db)'; do sleep .5; done"

    # The states of the device units are not changed yet.
    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b active plugged
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y active plugged
    check_state /dev/alias/"$IFNAME"-z inactive dead

    # Also the states of the service units are not changed.
    check_state testsleep-a.service active running
    check_state testsleep-b.service active running
    check_state testsleep-x.service active running
    check_state testsleep-y.service active running

    # With daemon-reload/reexec, the active device units with ID_PROCESSING=1
    # enter the activating (tentative) state.
    local action
    for action in daemon-reload daemon-reexec daemon-reload; do
        systemctl "$action"

        check_state /sys/devices/virtual/net/"$IFNAME" activating tentative
        check_state /sys/subsystem/net/devices/"$IFNAME" activating tentative
        check_state /sys/alias/"$IFNAME"-a activating tentative
        check_state /sys/alias/"$IFNAME"-b activating tentative
        check_state /sys/alias/"$IFNAME"-c inactive dead
        check_state /dev/alias/"$IFNAME"-x activating tentative
        check_state /dev/alias/"$IFNAME"-y activating tentative
        check_state /dev/alias/"$IFNAME"-z inactive dead

        check_state testsleep-a.service active running
        check_state testsleep-b.service active running
        check_state testsleep-x.service active running
        check_state testsleep-y.service active running
    done

    # Check if the daemon-reload/reexec finished while the event was being processed.
    grep -q -F 'ID_PROCESSING=1' "$(netif_get_udev_db)"

    # Kill the sleep command in RUN, and wait for the event to finish.
    kill_sleep_by_udevd
    udevadm settle --timeout=30
    (! grep -q -F 'ID_PROCESSING=1' "$(netif_get_udev_db)")
    wait_for_inactive /sys/alias/"$IFNAME"-b
    systemctl start /sys/alias/"$IFNAME"-c

    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c active plugged
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z active plugged

    check_state testsleep-a.service active running
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service active running
    check_state testsleep-y.service inactive dead

    netif_remove
}

testcase_netif_switching_root() {
    netif_emulate_switching_root

    # When a uevent for the device is received, then the device units enter the
    # active or inactive state.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    systemctl start /sys/devices/virtual/net/"$IFNAME"

    check_state /sys/devices/virtual/net/"$IFNAME" active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c active plugged
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z active plugged

    check_state testsleep-a.service active running
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service active running
    check_state testsleep-y.service inactive dead

    netif_remove
}

testcase_netif_remove_on_switching_root() {
    netif_emulate_switching_root

    # Remove device before the first uevent after the switching-root.
    ip link del "$IFNAME"
    udevadm settle --timeout=30

    # If a device is removed without its udev DB file, then the corresponding device units DO NOT enter the
    # dead state, as the broadcast uevent message does not have 'systemd' tag, thus the message is filtered
    # by BPF and PID1 does not process the message. The stale unit states will be resolved after
    # the next daemon-reload and friends.
    check_state /sys/devices/virtual/net/"$IFNAME" activating tentative
    check_state /sys/subsystem/net/devices/"$IFNAME" activating tentative
    check_state /sys/alias/"$IFNAME"-a activating tentative
    check_state /sys/alias/"$IFNAME"-b activating tentative
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x activating tentative
    check_state /dev/alias/"$IFNAME"-y activating tentative
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service active running
    check_state testsleep-b.service active running
    check_state testsleep-x.service active running
    check_state testsleep-y.service active running

    systemctl daemon-reload
    wait_for_inactive /sys/devices/virtual/net/"$IFNAME"

    check_state /sys/devices/virtual/net/"$IFNAME" inactive dead
    check_state /sys/subsystem/net/devices/"$IFNAME" inactive dead
    check_state /sys/alias/"$IFNAME"-a inactive dead
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c inactive dead
    check_state /dev/alias/"$IFNAME"-x inactive dead
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z inactive dead

    check_state testsleep-a.service inactive dead
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service inactive dead
    check_state testsleep-y.service inactive dead
}

test_netif_rename() {
    local by_udev=${1:?}
    local switching_root=${2:?}

    if "$switching_root"; then
        netif_emulate_switching_root
    else
        netif_prepare
    fi

    cat >"$RULE" <<EOF
ACTION=="add", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/${IFNAME}-a /sys/alias/${IFNAME}-c /dev/alias/${IFNAME}-x /dev/alias/${IFNAME}-z", \
  NAME="${IFNAME}2"
ACTION=="move", SUBSYSTEM=="net", KERNEL=="${IFNAME}2", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/${IFNAME}-a /sys/alias/${IFNAME}-c /dev/alias/${IFNAME}-x /dev/alias/${IFNAME}-z"
EOF
    udevadm control --reload

    if "$by_udev"; then
        udevadm trigger --action add --settle /sys/devices/virtual/net/"$IFNAME"
    else
        ip link set "$IFNAME" name "$IFNAME"2
    fi

    wait_for_inactive /sys/devices/virtual/net/"$IFNAME"
    systemctl start /sys/devices/virtual/net/"$IFNAME"2

    check_state /sys/devices/virtual/net/"$IFNAME" inactive dead
    check_state /sys/subsystem/net/devices/"$IFNAME" inactive dead
    check_state /sys/devices/virtual/net/"$IFNAME"2 active plugged
    check_state /sys/subsystem/net/devices/"$IFNAME"2 active plugged
    check_state /sys/alias/"$IFNAME"-a active plugged
    check_state /sys/alias/"$IFNAME"-b inactive dead
    check_state /sys/alias/"$IFNAME"-c active plugged
    check_state /dev/alias/"$IFNAME"-x active plugged
    check_state /dev/alias/"$IFNAME"-y inactive dead
    check_state /dev/alias/"$IFNAME"-z active plugged

    check_state testsleep-a.service active running
    check_state testsleep-b.service inactive dead
    check_state testsleep-x.service active running
    check_state testsleep-y.service inactive dead

    netif_remove "$IFNAME"2
}

testcase_netif_rename_by_ip() {
    test_netif_rename false false
}

testcase_netif_rename_by_ip_on_switching_root() {
    test_netif_rename false true
}

testcase_netif_rename_by_udev() {
    test_netif_rename true false
}

testcase_netif_rename_by_udev_on_switching_root() {
    test_netif_rename true true
}

at_exit() (
    set +e

    systemctl stop testsleep-a.service
    systemctl stop testsleep-b.service
    systemctl stop testsleep-x.service
    systemctl stop testsleep-y.service

    kill_sleep_by_udevd

    rm -f /run/udev/udev.conf.d/timeout.conf
    rm -f "$RULE"
    udevadm control --reload

    ip link del "$IFNAME"
    ip link del "$IFNAME"2
    return 0
)

trap at_exit EXIT

udevadm settle --timeout=30

mkdir -p /run/udev/udev.conf.d/
cat >/run/udev/udev.conf.d/timeout.conf <<EOF
event_timeout=1h
EOF

run_testcases
