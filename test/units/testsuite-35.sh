#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

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
    [ "$r" = "b false" ]

    cat >/run/systemd/logind.conf.d/kill-user-processes.conf <<EOF
[Login]
KillUserProcesses=yes
EOF

    systemctl restart systemd-logind.service
    r=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses)
    [ "$r" = "b true" ]

    rm -rf /run/systemd/logind.conf.d
}

test_started() {
    systemctl restart systemd-logind.service

    echo " * daemon is started"
    # should start at boot, not with D-BUS activation
    LOGINDPID=$(systemctl show systemd-logind.service -p ExecMainPID --value)

    # loginctl should succeed
    echo " * loginctl succeeds"
    LOGINCTL_OUT=$(loginctl --no-pager --no-legend)
}

# args: <timeout>
wait_suspend() {
    timeout="$1"
    while [ $timeout -gt 0 ] && [ ! -e /run/suspend.flag ]; do
        sleep 1
        timeout=$((timeout - 1))
        [ $(($timeout % 5)) -ne 0 ] || echo "   waiting for suspend, ${timeout}s remaining..."
    done
    if [ ! -e /run/suspend.flag ]; then
        echo "closing lid did not cause suspend" >&2
        exit 1
    fi
    rm /run/suspend.flag
    echo " * closing lid caused suspend"
}

test_suspend_on_lid() {
    if systemd-detect-virt --quiet --container; then
        echo " * Skipping suspend test in container"
        return
    fi
    if ! grep -s -q mem /sys/power/state; then
        echo " * suspend not supported on this testbed, skipping"
        return
    fi
    if ! command -v evemu-device &>/dev/null; then
        echo " * command evemu-device not found, skipping"
        return
    fi

    # cleanup handler
    trap 'rm -f /run/udev/rules.d/70-logindtest-*.rules; udevadm control --reload;
          kill $KILL_PID;
          rm /run/systemd/system/systemd-suspend.service.d/override.conf;
          if [ -d /sys/module/scsi_debug ]; then rmmod scsi_debug 2>/dev/null || (sleep 2; rmmod scsi_debug ) || true; fi' \
                  EXIT INT QUIT TERM PIPE

    # watch what's going on
    journalctl -f -u systemd-logind.service -u systemd-suspend.service &
    KILL_PID="$KILL_PID $!"

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
    evemu-device $(dirname $0)/lidswitch.evemu &
    KILL_PID="$KILL_PID $!"
    while [ -z "$O" ]; do
        sleep 0.1
        O=$(grep -l '^Fake Lid Switch' /sys/class/input/*/device/name)
    done
    O=${O%/device/name}
    LID_DEV=/dev/${O#/sys/class/}
    udevadm info --wait-for-initialization=10s $LID_DEV
    udevadm settle

    # close lid
    evemu-event $LID_DEV --sync --type 5 --code 0 --value 1
    # need to wait for 30s suspend inhibition after boot
    wait_suspend 31
    # open lid again
    evemu-event $LID_DEV --sync --type 5 --code 0 --value 0

    echo " * waiting for 30s inhibition time between suspends"
    sleep 30

    # now closing lid should cause instant suspend
    evemu-event $LID_DEV --sync --type 5 --code 0 --value 1
    wait_suspend 2
    evemu-event $LID_DEV --sync --type 5 --code 0 --value 0

    P=$(systemctl show systemd-logind.service -p ExecMainPID --value)
    [ "$P" = "$LOGINDPID" ] || { echo "logind crashed" >&2; exit 1; }
}

test_shutdown() {
    echo " * scheduled shutdown with wall message"
    shutdown 2>&1
    sleep 5
    shutdown -c || true
    # logind should still be running
    P=$(systemctl show systemd-logind.service -p ExecMainPID --value)
    [ "$P" = "$LOGINDPID" ] || { echo "logind crashed" >&2; exit 1; }

    echo " * scheduled shutdown without wall message"
    shutdown --no-wall 2>&1
    sleep 5
    shutdown -c --no-wall || true
    P=$(systemctl show systemd-logind.service -p ExecMainPID --value)
    [ "$P" = "$LOGINDPID" ] || { echo "logind crashed" >&2; exit 1; }
}

test_acl() {
    # ACL tests
    if ! echo "$LOGINCTL_OUT" | grep -q "seat0"; then
        echo " * Skipping ACL tests, as there is no seat"
        return
    fi
    if systemd-detect-virt --quiet --container; then
        echo " * Skipping ACL tests in container"
        return
    fi

    # determine user
    USER=$(echo "$OUT" | grep "seat0" | awk '{print $3}')
    echo "seat user: $USER"

    # scsi_debug should not be loaded yet
    if test -d /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block; then
        echo "scsi_debug module is already loaded." >&2
        exit 1
    fi

    # we use scsi_debug to create new devices which we can put ACLs on
    # tell udev about the tagging, so that logind can pick it up
    cat >/run/udev/rules.d/70-logindtest-scsi_debug-user.rules <<EOF
SUBSYSTEM=="block", ATTRS{model}=="scsi_debug*", TAG+="uaccess"
EOF
    udevadm control --reload

    echo " * coldplug: logind started with existing device"
    killall systemd-logind
    modprobe scsi_debug
    while ! dev=/dev/`ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null`; do
        sleep 0.1
    done
    test -b $dev
    echo "got block device $dev"
    udevadm settle

    # trigger logind
    loginctl >/dev/null
    sleep 1
    if getfacl -p $dev | grep -q "user:$USER:rw-"; then
        echo "$dev has ACL for user $USER"
    else
        echo "$dev has no ACL for user $USER:" >&2
        getfacl -p $dev >&2
        exit 1
    fi

    rmmod scsi_debug

    echo " * hotplug: new device appears while logind is running"
    modprobe scsi_debug
    while ! dev=/dev/`ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block`; do sleep 0.1; done
    test -b $dev
    echo "got block device $dev"
    udevadm settle
    sleep 1
    if getfacl -p $dev | grep -q "user:$USER:rw-"; then
        echo "$dev has ACL for user $USER"
    else
        echo "$dev has no ACL for user $USER:" >&2
        getfacl -p $dev >&2
        exit 1
    fi
}

test_enable_debug
test_properties
test_started
test_suspend_on_lid
test_shutdown
test_acl

touch /testok
rm /failed
