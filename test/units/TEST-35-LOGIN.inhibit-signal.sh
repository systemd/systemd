#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNITS=()
SUSPEND_DROPIN=/run/systemd/system/systemd-suspend.service.d/99-inhibit-signal.conf
LOGIND_DROPIN=/run/systemd/logind.conf.d/99-inhibit-signal.conf
DROPINS_INSTALLED=0
STATE_DIR=

at_exit() {
    set +e

    for unit in "${UNITS[@]}"; do
        systemctl stop "$unit"
        systemctl reset-failed "$unit"
    done

    systemctl unmask systemd-poweroff.service

    if [[ "$DROPINS_INSTALLED" -eq 1 ]]; then
        rm -f "$SUSPEND_DROPIN"
        rmdir /run/systemd/system/systemd-suspend.service.d
        systemctl daemon-reload

        rm -f "$LOGIND_DROPIN"
        rmdir /run/systemd/logind.conf.d
        systemctl restart systemd-logind.service
    fi

    rm -f /run/suspend.flag
    if [[ -n "$STATE_DIR" ]]; then
        rm -rf "$STATE_DIR"
    fi

    return 0
}

trap at_exit EXIT

: "Signal help and listing do not need a command or a bus connection"
for option in help list; do
    DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/nonexistent-inhibit-bus systemd-inhibit --signal="$option" | grep TERM >/dev/null
done

: "--signal= needs a command to send the signal to"
(! systemd-inhibit --what=sleep --mode=delay --signal=SIGTERM)
(! systemd-inhibit --what=sleep --mode=delay --signal=SIGTERM --list)

: "--signal= is refused unless the lock is a delay lock"
(! systemd-inhibit --what=sleep --mode=block --signal=SIGTERM true)
(! systemd-inhibit --what=sleep --mode=block-weak --signal=SIGTERM true)
(! systemd-inhibit --what=sleep --signal=SIGTERM true)

: "Bogus signal specifications are refused"
(! systemd-inhibit --what=sleep --mode=delay --signal=SIGNOSUCHTHING true)
(! systemd-inhibit --what=sleep --mode=delay --signal=20011130 true)
(! systemd-inhibit --what=sleep --mode=delay --signal=0 true)
(! systemd-inhibit --what=sleep --mode=delay --signal= true)

: "Signals may be given by name, with or without the SIG prefix, or by number"
systemd-inhibit --what=sleep --mode=delay --signal=SIGTERM true
systemd-inhibit --what=sleep --mode=delay --signal=TERM true
systemd-inhibit --what=sleep --mode=delay --signal=15 true

: "The exit status of the command is propagated with and without --signal="
(! systemd-inhibit --what=sleep --mode=delay --signal=SIGTERM false)
assert_rc 3 systemd-inhibit --what=sleep --mode=delay --signal=SIGTERM bash -c 'exit 3'
systemd-inhibit --what=idle true
(! systemd-inhibit --what=idle false)
assert_rc 3 systemd-inhibit --what=idle bash -c 'exit 3'

: "An inherited ignored SIGCHLD must not prevent watching the command"
for status in 0 3; do
    # shellcheck disable=SC2016
    assert_rc "$status" bash -c 'trap "" CHLD; exec systemd-inhibit --what=sleep --mode=delay --signal=SIGTERM bash -c "exit $1"' bash "$status"
done

: "Matching signal death is a failure when no signal has been forwarded"
for signal in SIGTERM SIGABRT; do
    # shellcheck disable=SC2016
    assert_rc 1 systemd-inhibit --what=sleep --mode=delay --signal="$signal" bash -c 'kill -s "$1" "$$"' bash "$signal"
done

if systemd-detect-virt --quiet --container; then
    echo "Running in a container, skipping the suspend part of the test"
    exit 0
fi

if ! grep -s mem /sys/power/state >/dev/null; then
    echo "Suspend is not supported on this testbed, skipping the suspend part of the test"
    exit 0
fi

# Any other delay lock would hold the operation up after ours is gone, and
# everything below is about timing, so make sure there is none. logind can
# still be winding down an earlier operation, so give it a moment rather than
# failing right away.
# shellcheck disable=SC2016
timeout 30 bash -c 'until [[ -z "$(systemd-inhibit --list --no-legend --mode=delay)" ]]; do sleep 0.5; done'

STATE_DIR=$(mktemp -d /run/inhibit-signal.XXXXXX)
cat >"$STATE_DIR/handler.sh" <<'EOF'
#!/usr/bin/env bash
set -eu

trap 'echo signal >>"$1/signals"; if [[ "$2" == exit ]]; then exit 0; fi' "$3"
touch "$1/ready"
while :; do
    sleep 0.1
done
EOF

# Make the delay window long enough that an operation completing quickly can
# only be the result of our lock being released early, and not of the delay
# simply timing out
DROPINS_INSTALLED=1
mkdir -p /run/systemd/logind.conf.d
cat >"$LOGIND_DROPIN" <<EOF
[Login]
InhibitDelayMaxSec=120
EOF

# We don't want the testbed to actually suspend, so
mkdir -p /run/systemd/system/systemd-suspend.service.d
cat >"$SUSPEND_DROPIN" <<EOF
[Service]
ExecStart=
ExecStart=touch /run/suspend.flag
EOF

systemctl restart systemd-logind.service
systemctl daemon-reload

wait_for_property() {
    local property="${1:?}" value="${2:?}"

    timeout 30 bash -c "
        until [[ \"\$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager $property)\" == 'b $value' ]]; do
            sleep 0.5
        done
    "
}

check_forwarding() {
    local what="${1:?}" signal="${2:?}" property="${3:?}" wording="${4:?}"
    local status="${5:?}"
    shift 5

    local unit="test-inhibit-signal-$RANDOM.service"
    local who="inhibit-signal-$RANDOM"
    local substate=failed result=exit-code
    local command=(sleep infinity)

    if [[ "$status" -eq 0 ]]; then
        substate=exited
        result=success
        command=(bash "$STATE_DIR/handler.sh" "$STATE_DIR" exit "$signal")
    fi

    UNITS+=("$unit")
    rm -f /run/suspend.flag "$STATE_DIR/ready" "$STATE_DIR/signals"

    systemd-run --unit="$unit" --service-type=exec -p RemainAfterExit=yes \
        systemd-inhibit --what="$what" --mode=delay --signal="$signal" --who="$who" --why="testing --signal=" \
            "${command[@]}"

    if [[ "$status" -eq 0 ]]; then
        # shellcheck disable=SC2016
        timeout 30 bash -c 'until test -e "$1/ready"; do sleep 0.1; done' bash "$STATE_DIR"
    fi

    timeout 30 bash -c "until systemd-inhibit --list --no-legend | grep -F '$who' >/dev/null; do sleep 0.5; done"
    systemd-inhibit --list --no-legend --mode=delay | grep -F "$who" >/dev/null

    "$@"

    for _ in {1..60}; do
        if [[ "$(systemctl show -p SubState --value "$unit")" == "$substate" ]]; then
            break
        fi
        sleep 0.5
    done
    assert_eq "$(systemctl show -p SubState --value "$unit")" "$substate"
    assert_eq "$(systemctl show -p Result --value "$unit")" "$result"
    assert_eq "$(systemctl show -p ExecMainStatus --value "$unit")" "$status"
    if [[ "$status" -eq 0 ]]; then
        assert_eq "$(cat "$STATE_DIR/signals")" signal
    fi

    wait_for_property "$property" false

    journalctl --sync
    journalctl -b --no-pager -u "$unit" | grep -F "Forwarding $signal to '${command[0]}', because the system is about to $wording." >/dev/null

    # Check it isn't lingering
    (! systemd-inhibit --list --no-legend | grep -F "$who" >/dev/null)

    if [[ "$status" -eq 0 ]]; then
        systemctl stop "$unit"
    else
        systemctl reset-failed "$unit"
    fi
}

# There is no payload to swap out for shutdown the way there is for suspend, so
# mask the service required by poweroff.target instead. The target itself must
# remain loaded so logind sends the notification before trying to start it.
check_shutdown_forwarding() {
    systemctl mask systemd-poweroff.service
    check_forwarding "$@"
    systemctl unmask systemd-poweroff.service
}

# Signal termination remains a failure
for signal in SIGTERM SIGABRT; do
    check_forwarding sleep "$signal" PreparingForSleep sleep 1 systemctl suspend --no-block
    test -e /run/suspend.flag

    check_shutdown_forwarding shutdown "$signal" PreparingForShutdown "shut down" 1 systemctl poweroff --no-block
done

# Only the operation that actually happens gets the signal forwarded for it
check_shutdown_forwarding sleep:shutdown SIGTERM PreparingForShutdown "shut down" 1 systemctl poweroff --no-block

: "A command can handle the notification and exit successfully before the delay expires"
check_forwarding sleep SIGTERM PreparingForSleep sleep 0 systemctl suspend --no-block
test -e /run/suspend.flag
check_shutdown_forwarding shutdown SIGTERM PreparingForShutdown "shut down" 0 systemctl poweroff --no-block

check_repeated_forwarding() {
    local what="${1:?}" expected
    local unit="test-inhibit-signal-$RANDOM.service"
    local who="inhibit-signal-$RANDOM"

    cat >"$LOGIND_DROPIN" <<EOF
[Login]
InhibitDelayMaxSec=2
EOF
    systemctl restart systemd-logind.service

    UNITS+=("$unit")
    rm -f "$STATE_DIR/ready" "$STATE_DIR/signals"
    : >"$STATE_DIR/signals"
    systemd-run --unit="$unit" --service-type=exec \
        systemd-inhibit --what="$what" --mode=delay --signal=SIGUSR1 --who="$who" --why="testing repeated notifications" \
            bash "$STATE_DIR/handler.sh" "$STATE_DIR" stay SIGUSR1

    # shellcheck disable=SC2016
    timeout 30 bash -c 'until test -e "$1/ready"; do sleep 0.1; done' bash "$STATE_DIR"
    timeout 30 bash -c "until systemd-inhibit --list --no-legend | grep -F '$who' >/dev/null; do sleep 0.5; done"

    for count in 1 2; do
        expected=0
        if [[ "$what" == sleep ]]; then
            expected=$count
        fi

        rm -f /run/suspend.flag
        systemctl suspend --no-block
        timeout 30 bash -c 'until test -e /run/suspend.flag; do sleep 0.1; done'
        wait_for_property PreparingForSleep false

        # The operation must complete even though the command and its lock are still alive.
        assert_eq "$(systemctl show -p SubState --value "$unit")" running
        systemd-inhibit --list --no-legend --mode=delay | grep -F "$who" >/dev/null
        # shellcheck disable=SC2016
        timeout 30 bash -c 'until [[ "$(wc -l <"$1/signals")" -ge "$2" ]]; do sleep 0.1; done' bash "$STATE_DIR" "$expected"

        # Observe the count after resuming too, to catch a signal incorrectly forwarded for false.
        for _ in {1..10}; do
            assert_eq "$(wc -l <"$STATE_DIR/signals")" "$expected"
            sleep 0.1
        done
    done

    systemctl stop "$unit"
}

: "A surviving command is notified once per operation, and does not prevent delay expiry"
check_repeated_forwarding sleep

: "A shutdown-only lock must not forward sleep notifications"
check_repeated_forwarding shutdown
