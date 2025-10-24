#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

cleanup_test_user() (
    set +ex

    pkill -u "$(id -u logind-test-user)"
    sleep 1
    pkill -KILL -u "$(id -u logind-test-user)"
    userdel -r logind-test-user

    return 0
)

setup_test_user() {
    mkdir -p /var/spool/cron /var/spool/mail
    useradd -m -s /usr/bin/bash logind-test-user
    trap cleanup_test_user EXIT
}

test_write_dropin() {
    systemctl edit --runtime --stdin systemd-logind.service --drop-in=debug.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

    # We test "coldplug" (completely stop and start logind) here. So we need to preserve
    # the fdstore, which might contain session leader pidfds, but only if pidfd id isn't
    # a thing. This is extremely rare use case and shall not be considered fully supported.
    # See also: https://github.com/systemd/systemd/pull/30610#discussion_r1440507850
    if systemd-analyze compare-versions "$(uname -r)" lt 6.9; then
        systemctl edit --runtime --stdin systemd-logind.service --drop-in=fdstore-preserve.conf <<EOF
[Service]
FileDescriptorStorePreserve=yes
EOF
    fi

    systemctl restart systemd-logind.service
}

testcase_properties() {
    mkdir -p /run/systemd/logind.conf.d

    cat >/run/systemd/logind.conf.d/kill-user-processes.conf <<EOF
[Login]
KillUserProcesses=no
EOF

    systemctl restart systemd-logind.service
    assert_eq "$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses)" "b false"

    cat >/run/systemd/logind.conf.d/kill-user-processes.conf <<EOF
[Login]
KillUserProcesses=yes
EOF

    systemctl restart systemd-logind.service
    assert_eq "$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses)" "b true"

    rm -rf /run/systemd/logind.conf.d
}

testcase_sleep_automated() {
    assert_eq "$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SleepOperation)" 'as 3 "suspend-then-hibernate" "suspend" "hibernate"'

    mkdir -p /run/systemd/logind.conf.d

    cat >/run/systemd/logind.conf.d/sleep-operations.conf <<EOF
[Login]
SleepOperation=suspend hybrid-sleep
EOF

    systemctl restart systemd-logind.service

    assert_eq "$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SleepOperation)" 'as 2 "hybrid-sleep" "suspend"'

    busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanSleep

    rm -rf /run/systemd/logind.conf.d
}

testcase_started() {
    local pid

    systemctl restart systemd-logind.service

    # should start at boot, not with D-BUS activation
    pid=$(systemctl show systemd-logind.service -p ExecMainPID --value)

    # loginctl should succeed
    loginctl

    # logind should still be running
    assert_eq "$(systemctl show systemd-logind.service -p ExecMainPID --value)" "$pid"
}

wait_suspend() {
    timeout "${1?}" bash -c "while [[ ! -e /run/suspend.flag ]]; do sleep 1; done"
    rm /run/suspend.flag
}

teardown_suspend() (
    set +eux

    pkill evemu-device

    rm -rf /run/systemd/system/systemd-suspend.service.d
    systemctl daemon-reload

    rm -f /run/udev/rules.d/70-logindtest-lid.rules
    udevadm control --reload

    return 0
)

testcase_suspend_on_lid() {
    local pid input_name lid_dev

    if systemd-detect-virt --quiet --container; then
        echo "Skipping suspend test in container"
        return
    fi
    if ! grep -s -q mem /sys/power/state; then
        echo "suspend not supported on this testbed, skipping"
        return
    fi
    if ! command -v evemu-device >/dev/null; then
        echo "command evemu-device not found, skipping"
        return
    fi
    if ! command -v evemu-event >/dev/null; then
        echo "command evemu-event not found, skipping"
        return
    fi

    trap teardown_suspend RETURN

    # save pid
    pid=$(systemctl show systemd-logind.service -p ExecMainPID --value)

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

    timeout 20 bash -c 'until grep "^Fake Lid Switch" /sys/class/input/*/device/name; do sleep .5; done'
    input_name=$(grep -l '^Fake Lid Switch' /sys/class/input/*/device/name || :)
    if [[ -z "$input_name" ]]; then
        echo "cannot find fake lid switch." >&2
        exit 1
    fi
    input_name=${input_name%/device/name}
    lid_dev=/dev/${input_name#/sys/class/}
    udevadm info --wait-for-initialization=10s "$lid_dev"
    udevadm settle --timeout=30

    # close lid
    evemu-event "$lid_dev" --sync --type 5 --code 0 --value 1
    # need to wait for 30s suspend inhibition after boot
    wait_suspend 31
    # open lid again
    evemu-event "$lid_dev" --sync --type 5 --code 0 --value 0

    # waiting for 30s inhibition time between suspends
    sleep 30

    # now closing lid should cause instant suspend
    evemu-event "$lid_dev" --sync --type 5 --code 0 --value 1
    wait_suspend 2
    evemu-event "$lid_dev" --sync --type 5 --code 0 --value 0

    assert_eq "$(systemctl show systemd-logind.service -p ExecMainPID --value)" "$pid"
}

testcase_shutdown() {
    local pid

    # save pid
    pid=$(systemctl show systemd-logind.service -p ExecMainPID --value)

    # scheduled shutdown with wall message
    shutdown 2>&1
    sleep 5
    shutdown -c || :
    # logind should still be running
    assert_eq "$(systemctl show systemd-logind.service -p ExecMainPID --value)" "$pid"

    # scheduled shutdown without wall message
    shutdown --no-wall 2>&1
    sleep 5
    shutdown -c --no-wall || true
    assert_eq "$(systemctl show systemd-logind.service -p ExecMainPID --value)" "$pid"
}

cleanup_session() (
    set +ex

    local uid s

    uid=$(id -u logind-test-user)

    loginctl disable-linger logind-test-user

    systemctl stop getty@tty2.service

    for s in $(loginctl --no-legend list-sessions | grep -v manager | awk '$3 == "logind-test-user" { print $1 }'); do
        echo "INFO: stopping session $s"
        loginctl terminate-session "$s"
    done

    loginctl terminate-user logind-test-user

    if ! timeout 30 bash -c "while loginctl --no-legend | grep -q logind-test-user; do sleep 1; done"; then
        echo "WARNING: session for logind-test-user still active, ignoring."
    fi

    pkill -u "$uid"
    sleep 1
    pkill -KILL -u "$uid"

    if ! timeout 30 bash -c "while systemctl is-active --quiet user@${uid}.service; do sleep 1; done"; then
        echo "WARNING: user@${uid}.service is still active, ignoring."
    fi

    if ! timeout 30 bash -c "while systemctl is-active --quiet user-runtime-dir@${uid}.service; do sleep 1; done"; then
        echo "WARNING: user-runtime-dir@${uid}.service is still active, ignoring."
    fi

    if ! timeout 30 bash -c "while systemctl is-active --quiet user-${uid}.slice; do sleep 1; done"; then
        echo "WARNING: user-${uid}.slice is still active, ignoring."
    fi

    rm -rf /run/systemd/system/getty@tty2.service.d
    systemctl daemon-reload

    return 0
)

teardown_session() (
    set +ex

    cleanup_session

    rm -f /run/udev/rules.d/70-logindtest-scsi_debug-user.rules
    udevadm control --reload
    rmmod scsi_debug || true

    return 0
)

check_session() (
    set +ex

    local seat session leader_pid

    if [[ $(loginctl --no-legend | grep -v manager | grep -c "logind-test-user") != 1 ]]; then
        echo "no session or multiple sessions for logind-test-user." >&2
        return 1
    fi

    seat=$(loginctl --no-legend | grep -v manager | grep 'logind-test-user *seat' | awk '{ print $4 }')
    if [[ -z "$seat" ]]; then
        echo "no seat found for user logind-test-user" >&2
        return 1
    fi

    session=$(loginctl --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $1 }')
    if [[ -z "$session" ]]; then
        echo "no session found for user logind-test-user" >&2
        return 1
    fi

    if ! loginctl session-status "$session" | grep -q "Unit: session-${session}\.scope"; then
        echo "cannot find scope unit for session $session" >&2
        return 1
    fi

    leader_pid=$(loginctl session-status "$session" | awk '$1 == "Leader:" { print $2 }')
    if [[ -z "$leader_pid" ]]; then
        echo "cannot found leader process for session $session" >&2
        return 1
    fi

    # cgroup v1: "1:name=systemd:/user.slice/..."; unified hierarchy: "0::/user.slice"
    if ! grep -q -E '(name=systemd|^0:):.*session.*scope' /proc/"$leader_pid"/cgroup; then
        echo "FAIL: process $leader_pid is not in the session cgroup" >&2
        cat /proc/self/cgroup
        return 1
    fi
)

create_session() {
    # login with the test user to start a session
    mkdir -p /run/systemd/system/getty@tty2.service.d
    cat >/run/systemd/system/getty@tty2.service.d/override.conf <<EOF
[Service]
Type=simple
ExecStart=
ExecStart=-agetty --autologin logind-test-user --noclear %I $TERM
Restart=no
EOF
    systemctl daemon-reload

    systemctl restart getty@tty2.service

    # check session
    for i in {1..30}; do
        (( i > 1 )) && sleep 1
        check_session && break
    done
    check_session
    assert_eq "$(loginctl --no-legend | grep -v manager | awk '$3=="logind-test-user" { print $7 }')" "tty2"
}

testcase_sanity_check() {
    # Exercise basic loginctl options

    if [[ ! -c /dev/tty2 ]]; then
        echo "/dev/tty2 does not exist, skipping test ${FUNCNAME[0]}."
        return
    fi

    trap cleanup_session RETURN
    create_session

    # Run most of the loginctl commands from a user session to make
    # the seat/session autodetection work-ish
    systemd-run --user --pipe --wait -M "logind-test-user@.host" bash -eux <<\EOF
    loginctl list-sessions
    loginctl list-sessions -j
    loginctl list-sessions --json=short
    loginctl session-status
    loginctl show-session
    loginctl show-session -P DelayInhibited

    # We're not in the same session scope, so in this case we need to specify
    # the session ID explicitly
    session=$(loginctl --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $1; exit; }')
    loginctl kill-session --signal=SIGCONT "$session"
    # FIXME(?)
    #loginctl kill-session --signal=SIGCONT --kill-whom=leader "$session"

    loginctl list-users
    loginctl user-status
    loginctl show-user -a
    loginctl show-user -P IdleAction
    loginctl kill-user --signal=SIGCONT ""

    loginctl list-seats
    loginctl seat-status
    loginctl show-seat
    loginctl show-seat -P IdleActionUSec
EOF

    # Requires root privileges
    loginctl lock-sessions
    loginctl unlock-sessions
    loginctl flush-devices
}

testcase_session() {
    local dev

    if systemd-detect-virt --quiet --container; then
        echo "Skipping ACL tests in container"
        return
    fi

    if [[ ! -c /dev/tty2 ]]; then
        echo "/dev/tty2 does not exist, skipping test ${FUNCNAME[0]}."
        return
    fi

    trap teardown_session RETURN

    create_session

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
    if ! modprobe scsi_debug; then
        echo "scsi_debug module not available, skipping test ${FUNCNAME[0]}."
        systemctl start systemd-logind.service
        return
    fi
    timeout 30 bash -c 'until ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null; do sleep 1; done'
    dev=/dev/$(ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null)
    if [[ ! -b "$dev" ]]; then
        echo "cannot find suitable scsi block device" >&2
        exit 1
    fi
    udevadm settle --timeout=30
    udevadm info "$dev"

    # trigger logind and activate session
    loginctl activate "$(loginctl --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $1 }')"

    # check ACL
    sleep 1
    assert_in "user:logind-test-user:rw-" "$(getfacl -p "$dev")"

    # hotplug: new device appears while logind is running
    rmmod scsi_debug
    modprobe scsi_debug
    timeout 30 bash -c 'until ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null; do sleep 1; done'
    dev=/dev/$(ls /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*:*/block 2>/dev/null)
    if [[ ! -b "$dev" ]]; then
        echo "cannot find suitable scsi block device" >&2
        exit 1
    fi
    udevadm settle --timeout=30

    # check ACL
    sleep 1
    assert_in "user:logind-test-user:rw-" "$(getfacl -p "$dev")"
}

teardown_lock_idle_action() (
    set +eux

    rm -f /run/systemd/logind.conf.d/idle-action-lock.conf
    systemctl restart systemd-logind.service

    cleanup_session

    return 0
)

testcase_lock_idle_action() {
    local ts

    if [[ ! -c /dev/tty2 ]]; then
        echo "/dev/tty2 does not exist, skipping test ${FUNCNAME[0]}."
        return
    fi

    if loginctl --no-legend | grep -v manager | grep -q logind-test-user; then
        echo >&2 "Session of the 'logind-test-user' is already present."
        exit 1
    fi

    trap teardown_lock_idle_action RETURN

    create_session

    journalctl --sync
    ts="$(date '+%H:%M:%S')"

    mkdir -p /run/systemd/logind.conf.d
    cat >/run/systemd/logind.conf.d/idle-action-lock.conf <<EOF
[Login]
IdleAction=lock
IdleActionSec=1s
EOF
    systemctl restart systemd-logind.service

    # Wait for 35s, in that interval all sessions should have become idle
    # and "Lock" signal should have been sent out. Then we wrote to tty to make
    # session active again and next we slept for another 35s so sessions have
    # become idle again. 'Lock' signal is sent out for each session, we have at
    # least one session, so minimum of 2 "Lock" signals must have been sent.
    journalctl --sync
    timeout -v 35 journalctl -b -u systemd-logind.service --since="$ts" -n all --follow | grep -m 1 -q 'Sent message type=signal .* member=Lock'

    # We need to know that a new message was sent after waking up,
    # so we must track how many happened before sleeping to check we have extra.
    locks="$(journalctl -b -u systemd-logind.service --since="$ts" | grep -c 'Sent message type=signal .* member=Lock')"

    # Wakeup
    touch /dev/tty2

    # Wait again
    journalctl --sync
    timeout -v 35 journalctl -b -u systemd-logind.service --since="$ts" -n all --follow | grep -m "$((locks + 1))" -q 'Sent message type=signal .* member=Lock'
    timeout -v 35 journalctl -b -u systemd-logind.service --since="$ts" -n all --follow | grep -m 2 -q -F 'System idle. Will be locked now.'
}

testcase_session_properties() {
    local s

    if [[ ! -c /dev/tty2 ]]; then
        echo "/dev/tty2 does not exist, skipping test ${FUNCNAME[0]}."
        return
    fi

    trap cleanup_session RETURN
    create_session

    s=$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $1 }')
    /usr/lib/systemd/tests/unit-tests/manual/test-session-properties "/org/freedesktop/login1/session/_3${s?}" /dev/tty2
}

testcase_list_users_sessions_seats() {
    local session seat

    if [[ ! -c /dev/tty2 ]]; then
        echo "/dev/tty2 does not exist, skipping test ${FUNCNAME[0]}."
        return
    fi

    trap cleanup_session RETURN
    create_session

    # Activate the session
    loginctl activate "$(loginctl --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $1 }')"

    session=$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $1 }')
    : check that we got a valid session id
    busctl get-property org.freedesktop.login1 "/org/freedesktop/login1/session/_3${session?}" org.freedesktop.login1.Session Id
    busctl get-property org.freedesktop.login1 "/org/freedesktop/login1/session/_3${session?}" org.freedesktop.login1.Session CanIdle
    busctl get-property org.freedesktop.login1 "/org/freedesktop/login1/session/_3${session?}" org.freedesktop.login1.Session CanLock
    assert_eq "$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $2 }')" "$(id -ru logind-test-user)"
    seat=$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $4 }')
    assert_eq "$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $6 }')" user
    assert_eq "$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $7 }')" tty2
    assert_eq "$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $8 }')" no
    assert_eq "$(loginctl list-sessions --no-legend | grep -v manager | awk '$3 == "logind-test-user" { print $9 }')" '-'

    loginctl list-seats --no-legend | grep -Fwq "${seat?}"

    assert_eq "$(loginctl list-users --no-legend | awk '$2 == "logind-test-user" { print $1 }')" "$(id -ru logind-test-user)"
    assert_eq "$(loginctl list-users --no-legend | awk '$2 == "logind-test-user" { print $3 }')" no
    assert_eq "$(loginctl list-users --no-legend | awk '$2 == "logind-test-user" { print $4 }')" active

    systemd-run --quiet --service-type=notify --unit=test-linger-signal-wait --pty \
                -p Environment=SYSTEMD_LOG_LEVEL=debug \
                -p ExecStartPost="loginctl enable-linger logind-test-user" \
		busctl --timeout=30 wait "/org/freedesktop/login1/user/_$(id -ru logind-test-user)" org.freedesktop.DBus.Properties PropertiesChanged | grep -qF '"Linger" b true'
    assert_eq "$(loginctl list-users --no-legend | awk '$2 == "logind-test-user" { print $3 }')" yes

    for s in $(loginctl list-sessions --no-legend | grep tty | awk '$3 == "logind-test-user" { print $1 }'); do
        loginctl terminate-session "$s"
    done
    if ! timeout 30 bash -c "while loginctl --no-legend | grep tty | grep -q logind-test-user; do sleep 1; done"; then
        echo "WARNING: session for logind-test-user still active, ignoring."
        return
    fi

    timeout 30 bash -c "until [[ \"\$(loginctl list-users --no-legend | awk '\$2 == \"logind-test-user\" { print \$4 }')\" == lingering ]]; do sleep 1; done"
}

teardown_stop_idle_session() (
    set +eux

    rm -f /run/systemd/logind.conf.d/stop-idle-session.conf
    systemctl restart systemd-logind.service

    cleanup_session
)

testcase_stop_idle_session() {
    local id ts

    if [[ ! -c /dev/tty2 ]]; then
        echo "/dev/tty2 does not exist, skipping test ${FUNCNAME[0]}."
        return
    fi

    create_session
    trap teardown_stop_idle_session RETURN

    id="$(loginctl --no-legend | grep tty | awk '$3 == "logind-test-user" { print $1; }')"

    journalctl --sync
    ts="$(date '+%H:%M:%S')"

    mkdir -p /run/systemd/logind.conf.d
    cat >/run/systemd/logind.conf.d/stop-idle-session.conf <<EOF
[Login]
StopIdleSessionSec=2s
EOF
    systemctl restart systemd-logind.service
    sleep 5

    journalctl --sync
    assert_eq "$(journalctl -b -u systemd-logind.service --since="$ts" --grep "Session \"$id\" of user \"logind-test-user\" is idle, stopping." | wc -l)" 1
    assert_eq "$(loginctl --no-legend | grep -v manager | grep tty | grep -c "logind-test-user")" 0
}

testcase_ambient_caps() {
    local PAMSERVICE TRANSIENTUNIT SCRIPT

    # Verify that pam_systemd works and assigns ambient caps as it should

    if ! grep -q 'CapAmb:' /proc/self/status ; then
        echo "ambient caps not available, skipping test." >&2
        return
    fi

    typeset -i BND MASK

    # Get PID 1's bounding set
    BND="0x$(grep 'CapBnd:' /proc/1/status | cut -d: -f2 | tr -d '[:space:]')"

    # CAP_CHOWN | CAP_KILL
    MASK=$(((1 << 0) | (1 << 5)))

    if [ $((BND & MASK)) -ne "$MASK" ] ; then
        echo "CAP_CHOWN or CAP_KILL not available in bounding set, skipping test." >&2
        return
    fi

    PAMSERVICE="pamserv$RANDOM"
    TRANSIENTUNIT="capwakealarm$RANDOM.service"
    SCRIPT="/tmp/capwakealarm$RANDOM.sh"

    cat > /etc/pam.d/"$PAMSERVICE" <<EOF
auth sufficient    pam_unix.so
auth required      pam_deny.so
account sufficient pam_unix.so
account required   pam_permit.so
session optional   pam_systemd.so default-capability-ambient-set=CAP_CHOWN,CAP_KILL debug
session required   pam_unix.so
EOF

    cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -ex
typeset -i AMB MASK
AMB="0x$(grep 'CapAmb:' /proc/self/status | cut -d: -f2 | tr -d '[:space:]')"
MASK=$(((1 << 0) | (1 << 5)))
test "$AMB" -eq "$MASK"
EOF

    chmod +x "$SCRIPT"

    systemd-run -u "$TRANSIENTUNIT" -p PAMName="$PAMSERVICE" -p Type=oneshot -p User=logind-test-user -p StandardError=tty "$SCRIPT"

    rm -f "$SCRIPT" "$PAMSERVICE"
}

background_at_return() {
    rm -f /etc/pam.d/"$PAMSERVICE"
    unset PAMSERVICE
}

testcase_background() {

    local uid TRANSIENTUNIT0 TRANSIENTUNIT1 TRANSIENTUNIT2

    uid=$(id -u logind-test-user)

    systemctl stop user@"$uid".service

    PAMSERVICE="pamserv$RANDOM"
    TRANSIENTUNIT0="none$RANDOM.service"
    TRANSIENTUNIT1="bg$RANDOM.service"
    TRANSIENTUNIT2="bgg$RANDOM.service"
    TRANSIENTUNIT3="bggg$RANDOM.service"
    TRANSIENTUNIT4="bgggg$RANDOM.service"
    RUN0UNIT0="run0$RANDOM.service"
    RUN0UNIT1="runn0$RANDOM.service"
    RUN0UNIT2="runnn0$RANDOM.service"
    RUN0UNIT3="runnnn0$RANDOM.service"

    trap background_at_return RETURN

    cat > /etc/pam.d/"$PAMSERVICE" <<EOF
auth sufficient    pam_unix.so
auth required      pam_deny.so
account sufficient pam_unix.so
account required   pam_permit.so
session optional   pam_systemd.so debug
session required   pam_unix.so
EOF

    systemd-run -u "$TRANSIENTUNIT0" -p PAMName="$PAMSERVICE" -p "Environment=XDG_SESSION_CLASS=none" -p Type=exec -p User=logind-test-user sleep infinity

    # This was a 'none' service, so logind should take no action
    (! systemctl is-active user@"$uid".service )

    systemctl stop "$TRANSIENTUNIT0"

    systemd-run -u "$TRANSIENTUNIT1" -p PAMName="$PAMSERVICE" -p "Environment=XDG_SESSION_CLASS=background-light" -p Type=exec -p User=logind-test-user sleep infinity

    # This was a 'light' background service, hence the service manager should not be running
    (! systemctl is-active user@"$uid".service )

    systemctl stop "$TRANSIENTUNIT1"

    systemd-run -u "$TRANSIENTUNIT2" -p PAMName="$PAMSERVICE" -p "Environment=XDG_SESSION_CLASS=background" -p Type=exec -p User=logind-test-user sleep infinity

    # This was a regular background service, hence the service manager should be running
    systemctl is-active user@"$uid".service

    systemctl stop "$TRANSIENTUNIT2"

    systemctl stop user@"$uid".service

    # Now check that system users automatically get the light session class assigned
    systemd-sysusers --inline "u lightuser"

    systemd-run -u "$TRANSIENTUNIT3" -p PAMName="$PAMSERVICE" -p "Environment=XDG_SESSION_TYPE=unspecified" -p Type=exec -p User=lightuser sleep infinity
    loginctl | grep lightuser | grep -q background-light
    systemctl stop "$TRANSIENTUNIT3"

    systemd-run -u "$TRANSIENTUNIT4" -p PAMName="$PAMSERVICE" -p "Environment=XDG_SESSION_TYPE=tty" -p Type=exec -p User=lightuser sleep infinity
    loginctl | grep lightuser | grep -q user-light
    systemctl stop "$TRANSIENTUNIT4"

    # Now check that run0's session class control works
    systemd-run --service-type=notify run0 -u lightuser --unit="$RUN0UNIT0" sleep infinity
    loginctl | grep lightuser | grep -qw background-light
    systemctl stop "$RUN0UNIT0"

    systemd-run --service-type=notify run0 -u lightuser --unit="$RUN0UNIT1" --lightweight=yes sleep infinity
    loginctl | grep lightuser | grep -qw background-light
    systemctl stop "$RUN0UNIT1"

    systemd-run --service-type=notify run0 -u lightuser --unit="$RUN0UNIT2" --lightweight=no sleep infinity
    loginctl | grep lightuser | grep -qw background
    systemctl stop "$RUN0UNIT2"

    systemd-run --service-type=notify run0 -u root --unit="$RUN0UNIT3" sleep infinity
    loginctl | grep root | grep -qw background-light
    systemctl stop "$RUN0UNIT3"
}

testcase_varlink() {
    varlinkctl introspect /run/systemd/io.systemd.Login
}

testcase_restart() {
    local classes unit c

    classes='user user-early user-incomplete greeter lock-screen background background-light manager manager-early'

    for c in $classes; do
        unit="user-sleeper-$c.service"
        systemd-run --service-type=notify run0  --setenv XDG_SESSION_CLASS="$c" -u logind-test-user --unit="$unit" sleep infinity
    done

    systemctl restart systemd-logind

    for c in $classes; do
        unit="user-sleeper-$c.service"
        systemctl --quiet is-active "$unit"
        loginctl | grep logind-test-user | grep -qw "$c"
        systemctl kill "$unit"
    done
}

setup_test_user
test_write_dropin
run_testcases

touch /testok
