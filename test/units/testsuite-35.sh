#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

test_enable_debug() {
    mkdir -p /run/systemd/system/systemd-logind.service.d
    cat >/run/systemd/system/systemd-logind.service.d/debug.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF
    systemctl daemon-reload
}

test_properties() {
    mkdir -p /run/systemd/logind.conf.d

    cat >/run/systemd/logind.conf.d/kill-user-processes.conf <<EOF
[Login]
KillUserProcesses=no
EOF

    systemctl restart systemd-logind.service
    r=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses)
    if [[ "$r" != "b false" ]]; then
        echo "Unexpected KillUserProcesses property '$r', expected='b false'" >&2
        exit 1
    fi

    cat >/run/systemd/logind.conf.d/kill-user-processes.conf <<EOF
[Login]
KillUserProcesses=yes
EOF

    systemctl restart systemd-logind.service
    r=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses)
    if [[ "$r" != "b true" ]]; then
        echo "Unexpected KillUserProcesses property '$r', expected='b true'" >&2
        exit 1
    fi

    rm -rf /run/systemd/logind.conf.d
}

test_started() {
    systemctl restart systemd-logind.service

    # should start at boot, not with D-BUS activation
    LOGINDPID=$(systemctl show systemd-logind.service -p ExecMainPID --value)

    # loginctl should succeed
    loginctl --no-pager
}

# args: <timeout>
wait_suspend() {
    timeout="$1"
    while [[ $timeout -gt 0 && ! -e /run/suspend.flag ]]; do
        sleep 1
        timeout=$((timeout - 1))
    done
    if [[ ! -e /run/suspend.flag ]]; then
        echo "closing lid did not cause suspend" >&2
        exit 1
    fi
    rm /run/suspend.flag
}

test_suspend_tear_down() {
    set +e

    kill "$KILL_PID"
}

test_suspend_on_lid() {
    if systemd-detect-virt --quiet --container; then
        echo "Skipping suspend test in container"
        return
    fi
    if ! grep -s -q mem /sys/power/state; then
        echo "suspend not supported on this testbed, skipping"
        return
    fi
    if ! command -v evemu-device &>/dev/null; then
        echo "command evemu-device not found, skipping"
        return
    fi
    if ! command -v evemu-event &>/dev/null; then
        echo "command evemu-event not found, skipping"
        return
    fi

    KILL_PID=
    trap test_suspend_tear_down EXIT

    # create fake suspend
    mkdir -p /run/systemd/system/systemd-suspend.service.d
    cat >/run/systemd/system/systemd-suspend.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=touch /run/suspend.flag
EOF
    systemctl daemon-reload

    # create fake lid switch
    mkdir -p /run/udev/rules.d
    cat >/run/udev/rules.d/70-logindtest-lid.rules <<EOF
SUBSYSTEM=="input", KERNEL=="event*", ATTRS{name}=="Fake Lid Switch", TAG+="power-switch"
EOF
    udevadm control --reload

    cat >/run/lidswitch.evemu <<EOF
# EVEMU 1.2
# Input device name: "Lid Switch"
# Input device ID: bus 0x19 vendor 0000 product 0x05 version 0000
# Supported events:
#   Event type 0 (EV_SYN)
#     Event code 0 (SYN_REPORT)
#     Event code 5 (FF_STATUS_MAX)
#   Event type 5 (EV_SW)
#     Event code 0 (SW_LID)
# Properties:
N: Fake Lid Switch
I: 0019 0000 0005 0000
P: 00 00 00 00 00 00 00 00
B: 00 21 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 01 00 00 00 00 00 00 00 00
B: 02 00 00 00 00 00 00 00 00
B: 03 00 00 00 00 00 00 00 00
B: 04 00 00 00 00 00 00 00 00
B: 05 01 00 00 00 00 00 00 00
B: 11 00 00 00 00 00 00 00 00
B: 12 00 00 00 00 00 00 00 00
B: 15 00 00 00 00 00 00 00 00
B: 15 00 00 00 00 00 00 00 00
EOF

    evemu-device /run/lidswitch.evemu &
    KILL_PID="$!"

    for ((i=0;i<20;i++)); do
        if (( i != 0 )); then sleep .5; fi

        INPUT_NAME=$(grep -l '^Fake Lid Switch' /sys/class/input/*/device/name || :)
        if [[ -n "$INPUT_NAME" ]]; then break; fi
    done
    if [[ -z "$INPUT_NAME" ]]; then
        echo "cannot find fake lid switch." >&2
        exit 1
    fi
    INPUT_NAME=${INPUT_NAME%/device/name}
    LID_DEV=/dev/${INPUT_NAME#/sys/class/}
    udevadm info --wait-for-initialization=10s "$LID_DEV"
    udevadm settle

    # close lid
    evemu-event "$LID_DEV" --sync --type 5 --code 0 --value 1
    # need to wait for 30s suspend inhibition after boot
    wait_suspend 31
    # open lid again
    evemu-event "$LID_DEV" --sync --type 5 --code 0 --value 0

    # waiting for 30s inhibition time between suspends
    sleep 30

    # now closing lid should cause instant suspend
    evemu-event "$LID_DEV" --sync --type 5 --code 0 --value 1
    wait_suspend 2
    evemu-event "$LID_DEV" --sync --type 5 --code 0 --value 0

    P=$(systemctl show systemd-logind.service -p ExecMainPID --value)
    if [[ "$P" != "$LOGINDPID" ]]; then
        echo "logind crashed" >&2
        exit 1
    fi

    test_suspend_tear_down
    trap - EXIT
}

test_shutdown() {
    # scheduled shutdown with wall message
    shutdown 2>&1
    sleep 5
    shutdown -c || :
    # logind should still be running
    P=$(systemctl show systemd-logind.service -p ExecMainPID --value)
    if [[ "$P" != "$LOGINDPID" ]]; then
        echo "logind crashed" >&2
        exit 1
    fi

    # scheduled shutdown without wall message
    shutdown --no-wall 2>&1
    sleep 5
    shutdown -c --no-wall || true
    P=$(systemctl show systemd-logind.service -p ExecMainPID --value)
    if [[ "$P" != "$LOGINDPID" ]]; then
        echo "logind crashed" >&2
        exit 1
    fi
}

test_session_tear_down() {
    set +e

    rm -f /run/udev/rules.d/70-logindtest-scsi_debug-user.rules
    udevadm control --reload

    systemctl stop getty@tty2.service
    rm -rf /run/systemd/system/getty@tty2.service.d
    systemctl daemon-reload

    pkill -u logind-test-user
    userdel logind-test-user

    rmmod scsi_debug
}

check_session() {
    loginctl
    if [[ $(loginctl --no-legend | grep -c "logind-test-user") != 1 ]]; then
        echo "no session or multile sessions for logind-test-user." >&2
        return 1
    fi

    SEAT=$(loginctl --no-legend | grep 'logind-test-user *seat' | awk '{ print $4 }')
    if [[ -z "$SEAT" ]]; then
        echo "no seat found for user logind-test-user" >&2
        return 1
    fi

    SESSION=$(loginctl --no-legend | grep "logind-test-user" | awk '{ print $1 }')
    if [[ -z "$SESSION" ]]; then
        echo "no session found for user logind-test-user" >&2
        return 1
    fi

    loginctl session-status "$SESSION"
    loginctl session-status "$SESSION" | grep -q "Unit: session-${SESSION}\.scope"
    LEADER_PID=$(loginctl session-status "$SESSION" | grep "Leader:" | awk '{ print $2 }')
    if [[ -z "$LEADER_PID" ]]; then
        echo "cannot found leader process for session $SESSION" >&2
        return 1
    fi

    # cgroup v1: "1:name=systemd:/user.slice/..."; unified hierarchy: "0::/user.slice"
    if ! grep -q -E '(name=systemd|^0:):.*session.*scope' /proc/"$LEADER_PID"/cgroup; then
        echo "FAIL: process $LEADER_PID is not in the session cgroup" >&2
        cat /proc/self/cgroup
        return 1
    fi
}

test_session() {
    if systemd-detect-virt --quiet --container; then
        echo " * Skipping ACL tests in container"
        return
    fi

    trap test_session_tear_down EXIT

    # add user
    useradd -s /bin/bash logind-test-user

    # login with the test user to start a session
    mkdir -p /run/systemd/system/getty@tty2.service.d
    cat >/run/systemd/system/getty@tty2.service.d/override.conf <<EOF
[Service]
Type=simple
ExecStart=
ExecStart=-/sbin/agetty --autologin logind-test-user --noclear %I $TERM
EOF
    systemctl daemon-reload
    systemctl start getty@tty2.service

    # check session
    ret=1
    for ((i=0;i<30;i++)); do
        if (( i != 0)); then sleep 1; fi
        if check_session; then
            ret=0
            break
        fi
    done
    if [[ "$ret" == "1" ]]; then
        exit 1
    fi

    # scsi_debug should not be loaded yet
    if [[ -d /sys/bus/pseudo/drivers/scsi_debug ]]; then
        echo "scsi_debug module is already loaded." >&2
        exit 1
    fi

    # we use scsi_debug to create new devices which we can put ACLs on
    # tell udev about the tagging, so that logind can pick it up
    mkdir -p /run/udev/rules.d
    cat >/run/udev/rules.d/70-logindtest-scsi_debug-user.rules <<EOF
SUBSYSTEM=="block", ATTRS{model}=="scsi_debug*", TAG+="uaccess"
EOF
    udevadm control --reload

    # coldplug: logind started with existing device
    systemctl stop systemd-logind.service
    modprobe scsi_debug
    for ((i=0;i<30;i++)); do
        if (( i != 0)); then sleep 1; fi
        if dev=/dev/$(ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null); then
            break
        fi
    done
    if [[ ! -b "$dev" ]]; then
        echo "cannot find suitable scsi block device" >&2
        exit 1
    fi
    udevadm settle
    udevadm info "$dev"

    # trigger logind and activate session
    loginctl activate "$SESSION"

    # check ACL
    sleep 1
    if ! getfacl -p "$dev" | grep -q "user:logind-test-user:rw-"; then
        echo "$dev has no ACL for user logind-test-user" >&2
        getfacl -p "$dev" >&2
        exit 1
    fi

    # hotplug: new device appears while logind is running
    rmmod scsi_debug
    modprobe scsi_debug
    for ((i=0;i<30;i++)); do
        if (( i != 0)); then sleep 1; fi
        if dev=/dev/$(ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null); then
            break
        fi
    done
    if [[ ! -b "$dev" ]]; then
        echo "cannot find suitable scsi block device" >&2
        exit 1
    fi
    udevadm settle

    # check ACL
    sleep 1
    if ! getfacl -p "$dev" | grep -q "user:logind-test-user:rw-"; then
        echo "$dev has no ACL for user logind-test-user" >&2
        getfacl -p "$dev" >&2
        exit 1
    fi

    test_session_tear_down
    trap - EXIT
}

: >/failed

test_enable_debug
test_properties
test_started
test_suspend_on_lid
test_shutdown
test_session

touch /testok
rm /failed
