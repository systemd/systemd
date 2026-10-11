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

# shellcheck disable=SC2034
netif_prepare() {
    local -n ret_invocation_ids=${1:?}

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
    assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
    # The default alias
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    # The custom aliases
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b active plugged
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y active plugged
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    start_bound_service /sys/alias/"$IFNAME"-a a
    start_bound_service /sys/alias/"$IFNAME"-b b
    start_bound_service /dev/alias/"$IFNAME"-x x
    start_bound_service /dev/alias/"$IFNAME"-y y

    ret_invocation_ids=(
        ["/sys/devices/virtual/net/${IFNAME}"]="$(get_invocation_id "/sys/devices/virtual/net/${IFNAME}")"
        ["/sys/subsystem/net/devices/${IFNAME}"]="$(get_invocation_id "/sys/subsystem/net/devices/${IFNAME}")"

        ["/sys/alias/${IFNAME}-a"]="$(get_invocation_id "/sys/alias/${IFNAME}-a")"
        ["/sys/alias/${IFNAME}-b"]="$(get_invocation_id "/sys/alias/${IFNAME}-b")"
        ["/dev/alias/${IFNAME}-x"]="$(get_invocation_id "/dev/alias/${IFNAME}-x")"
        ["/dev/alias/${IFNAME}-y"]="$(get_invocation_id "/dev/alias/${IFNAME}-y")"

        ["testsleep-a.service"]="$(get_invocation_id testsleep-a.service)"
        ["testsleep-b.service"]="$(get_invocation_id testsleep-b.service)"
        ["testsleep-x.service"]="$(get_invocation_id testsleep-x.service)"
        ["testsleep-y.service"]="$(get_invocation_id testsleep-y.service)"
    )
}

netif_remove() {
    local ifname=${1:-$IFNAME}

    ip link del "$ifname"
    wait_for_inactive /sys/devices/virtual/net/"$ifname"

    assert_unit_state /sys/devices/virtual/net/"$ifname" inactive dead
    assert_unit_state /sys/subsystem/net/devices/"$ifname" inactive dead

    # Note that we always use $IFNAME for aliases.
    assert_unit_state /sys/alias/"$IFNAME"-a inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    assert_unit_state testsleep-a.service inactive dead
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service inactive dead
    assert_unit_state testsleep-y.service inactive dead
}

netif_get_udev_db() {
    device_get_udev_db /sys/class/net/"$IFNAME"
}

netif_emulate_switching_root() {
    # Emulate switching-root from initrd to host system by removing the udev database,
    # which is typically done by udevadm info --cleanup-db. If the database is removed,
    # the active device units enter the activating (tentative) state.
    rm -f "$(netif_get_udev_db)"
    systemctl daemon-reload

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" activating tentative
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" activating tentative
    assert_unit_state /sys/alias/"$IFNAME"-a activating tentative
    assert_unit_state /sys/alias/"$IFNAME"-b activating tentative
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x activating tentative
    assert_unit_state /dev/alias/"$IFNAME"-y activating tentative
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service active running
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service active running

    assert_wc_l /tmp/testsleep-reload-a.txt 0
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 0
    assert_wc_l /tmp/testsleep-reload-y.txt 0
}

testcase_netif_basic() {
    local -A invocation_ids
    local i action

    netif_prepare invocation_ids

    for action in daemon-reload daemon-reexec; do
        systemctl "$action"

        assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
        assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
        assert_unit_state /sys/alias/"$IFNAME"-a active plugged
        assert_unit_state /sys/alias/"$IFNAME"-b active plugged
        assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
        assert_unit_state /dev/alias/"$IFNAME"-x active plugged
        assert_unit_state /dev/alias/"$IFNAME"-y active plugged
        assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

        assert_unit_state testsleep-a.service active running
        assert_unit_state testsleep-b.service active running
        assert_unit_state testsleep-x.service active running
        assert_unit_state testsleep-y.service active running

        assert_wc_l /tmp/testsleep-reload-a.txt 0
        assert_wc_l /tmp/testsleep-reload-b.txt 0
        assert_wc_l /tmp/testsleep-reload-x.txt 0
        assert_wc_l /tmp/testsleep-reload-y.txt 0

        for i in "${!invocation_ids[@]}"; do
            assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
        done
    done

    netif_remove
}

testcase_netif_change_alias() {
    local -A invocation_ids
    local i

    netif_prepare invocation_ids

    # Change event: update SYSTEMD_ALIAS.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    wait_for_inactive /sys/alias/"$IFNAME"-b
    systemctl start /sys/alias/"$IFNAME"-c

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c active plugged
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z active plugged

    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 1
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 1
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    unset "invocation_ids[/sys/alias/${IFNAME}-b]"
    unset "invocation_ids[/dev/alias/${IFNAME}-y]"
    unset "invocation_ids[testsleep-b.service]"
    unset "invocation_ids[testsleep-y.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    netif_remove
}

testcase_netif_systemd_ready() {
    local -A invocation_ids
    local i

    netif_prepare invocation_ids

    # Change event: SYSTEMD_READY=0 -> all device units will be inactive.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_READY}="0"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    wait_for_inactive /sys/devices/virtual/net/"$IFNAME"

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" inactive dead
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-a inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    assert_unit_state testsleep-a.service inactive dead
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service inactive dead
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 0
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 0
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    # Change event: SYSTEMD_READY=1 -> devices will be ready.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z", \
  ENV{SYSTEMD_READY}="1"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    systemctl start /sys/devices/virtual/net/"$IFNAME"

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c active plugged
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z active plugged

    assert_unit_state testsleep-a.service inactive dead
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service inactive dead
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 0
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 0
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    for i in "${!invocation_ids[@]}"; do
        assert_neq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    netif_remove
}

testcase_netif_id_processing() {
    local -A invocation_ids
    local i action

    netif_prepare invocation_ids

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
    assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b active plugged
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y active plugged
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    # Also the states of the service units are not changed.
    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service active running
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service active running

    assert_wc_l /tmp/testsleep-reload-a.txt 0
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 0
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    # With daemon-reload/reexec, the active device units with ID_PROCESSING=1
    # enter the activating (tentative) state.
    for action in daemon-reload daemon-reexec daemon-reload; do
        systemctl "$action"

        assert_unit_state /sys/devices/virtual/net/"$IFNAME" activating tentative
        assert_unit_state /sys/subsystem/net/devices/"$IFNAME" activating tentative
        assert_unit_state /sys/alias/"$IFNAME"-a activating tentative
        assert_unit_state /sys/alias/"$IFNAME"-b activating tentative
        assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
        assert_unit_state /dev/alias/"$IFNAME"-x activating tentative
        assert_unit_state /dev/alias/"$IFNAME"-y activating tentative
        assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

        assert_unit_state testsleep-a.service active running
        assert_unit_state testsleep-b.service active running
        assert_unit_state testsleep-x.service active running
        assert_unit_state testsleep-y.service active running

        assert_wc_l /tmp/testsleep-reload-a.txt 0
        assert_wc_l /tmp/testsleep-reload-b.txt 0
        assert_wc_l /tmp/testsleep-reload-x.txt 0
        assert_wc_l /tmp/testsleep-reload-y.txt 0

        for i in "${!invocation_ids[@]}"; do
            assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
        done
    done

    # Check if the daemon-reload/reexec finished while the event was being processed.
    grep -q -F 'ID_PROCESSING=1' "$(netif_get_udev_db)"

    # Kill the sleep command in RUN, and wait for the event to finish.
    kill_sleep_by_udevd
    udevadm settle --timeout=30
    (! grep -q -F 'ID_PROCESSING=1' "$(netif_get_udev_db)")
    wait_for_inactive /sys/alias/"$IFNAME"-b
    systemctl start /sys/alias/"$IFNAME"-c

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c active plugged
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z active plugged

    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 1
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 1
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    unset "invocation_ids[/sys/alias/${IFNAME}-b]"
    unset "invocation_ids[/dev/alias/${IFNAME}-y]"
    unset "invocation_ids[testsleep-b.service]"
    unset "invocation_ids[testsleep-y.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    netif_remove
}

testcase_netif_switching_root() {
    local -A invocation_ids
    local i

    netif_prepare invocation_ids

    netif_emulate_switching_root

    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    # When a uevent for the device is received, then the device units enter the
    # active or inactive state.
    cat >"$RULE" <<EOF
ACTION=="change", SUBSYSTEM=="net", KERNEL=="${IFNAME}", \
  ENV{SYSTEMD_ALIAS}+="/sys/alias/%k-a /sys/alias/%k-c /dev/alias/%k-x /dev/alias/%k-z"
EOF
    udevadm control --reload
    udevadm trigger --action change --settle /sys/devices/virtual/net/"$IFNAME"
    systemctl start /sys/devices/virtual/net/"$IFNAME"

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" active plugged
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" active plugged
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c active plugged
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z active plugged

    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 1
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 1
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    unset "invocation_ids[/sys/alias/${IFNAME}-b]"
    unset "invocation_ids[/dev/alias/${IFNAME}-y]"
    unset "invocation_ids[testsleep-b.service]"
    unset "invocation_ids[testsleep-y.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    netif_remove
}

testcase_netif_remove_on_switching_root() {
    local -A invocation_ids
    local i

    netif_prepare invocation_ids

    netif_emulate_switching_root

    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    # Remove device before the first uevent after the switching-root.
    ip link del "$IFNAME"
    udevadm settle --timeout=30

    # If a device is removed without its udev DB file, then the corresponding device units DO NOT enter the
    # dead state, as the broadcast uevent message does not have 'systemd' tag, thus the message is filtered
    # by BPF and PID1 does not process the message. The stale unit states will be resolved after
    # the next daemon-reload and friends.
    assert_unit_state /sys/devices/virtual/net/"$IFNAME" activating tentative
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" activating tentative
    assert_unit_state /sys/alias/"$IFNAME"-a activating tentative
    assert_unit_state /sys/alias/"$IFNAME"-b activating tentative
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x activating tentative
    assert_unit_state /dev/alias/"$IFNAME"-y activating tentative
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service active running
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service active running

    assert_wc_l /tmp/testsleep-reload-a.txt 0
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 0
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

    systemctl daemon-reload
    wait_for_inactive /sys/devices/virtual/net/"$IFNAME"

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" inactive dead
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-a inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-x inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z inactive dead

    assert_unit_state testsleep-a.service inactive dead
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service inactive dead
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 0
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 0
    assert_wc_l /tmp/testsleep-reload-y.txt 0
}

test_netif_rename() {
    local by_udev=${1:?}
    local switching_root=${2:?}
    local -A invocation_ids
    local i

    netif_prepare invocation_ids

    if "$switching_root"; then
        netif_emulate_switching_root

        for i in "${!invocation_ids[@]}"; do
            assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
        done
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

    assert_unit_state /sys/devices/virtual/net/"$IFNAME" inactive dead
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME" inactive dead
    assert_unit_state /sys/devices/virtual/net/"$IFNAME"2 active plugged
    assert_unit_state /sys/subsystem/net/devices/"$IFNAME"2 active plugged
    assert_unit_state /sys/alias/"$IFNAME"-a active plugged
    assert_unit_state /sys/alias/"$IFNAME"-b inactive dead
    assert_unit_state /sys/alias/"$IFNAME"-c active plugged
    assert_unit_state /dev/alias/"$IFNAME"-x active plugged
    assert_unit_state /dev/alias/"$IFNAME"-y inactive dead
    assert_unit_state /dev/alias/"$IFNAME"-z active plugged

    assert_unit_state testsleep-a.service active running
    assert_unit_state testsleep-b.service inactive dead
    assert_unit_state testsleep-x.service active running
    assert_unit_state testsleep-y.service inactive dead

    assert_wc_l /tmp/testsleep-reload-a.txt 1
    assert_wc_l /tmp/testsleep-reload-b.txt 0
    assert_wc_l /tmp/testsleep-reload-x.txt 1
    assert_wc_l /tmp/testsleep-reload-y.txt 0

    unset "invocation_ids[/sys/devices/virtual/net/${IFNAME}]"
    unset "invocation_ids[/sys/subsystem/net/devices/${IFNAME}]"
    unset "invocation_ids[/sys/alias/${IFNAME}-b]"
    unset "invocation_ids[/dev/alias/${IFNAME}-y]"
    unset "invocation_ids[testsleep-b.service]"
    unset "invocation_ids[testsleep-y.service]"
    for i in "${!invocation_ids[@]}"; do
        assert_eq "$(get_invocation_id "$i")" "${invocation_ids[$i]}"
    done

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

    rm -f /tmp/testsleep-reload-*.txt

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
