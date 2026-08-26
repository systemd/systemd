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

at_exit() {
    set +e

    for unit in "${UNITS[@]}"; do
        systemctl stop "$unit"
        systemctl reset-failed "$unit"
    done

    systemctl unmask poweroff.target

    if [[ "$DROPINS_INSTALLED" -eq 1 ]]; then
        rm -f "$SUSPEND_DROPIN"
        rmdir /run/systemd/system/systemd-suspend.service.d
        systemctl daemon-reload

        rm -f "$LOGIND_DROPIN"
        rmdir /run/systemd/logind.conf.d
        systemctl restart systemd-logind.service
    fi

    rm -f /run/suspend.flag

    return 0
}

trap at_exit EXIT

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

# Make the delay window long enough that an operation completing quickly can
# only be the result of our lock being released early, and not of the delay
# simply timing out
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

DROPINS_INSTALLED=1
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
    shift 4

    local unit="test-inhibit-signal-$RANDOM.service"
    local who="inhibit-signal-$RANDOM"

    UNITS+=("$unit")
    rm -f /run/suspend.flag

    systemd-run --unit="$unit" --service-type=exec -p RemainAfterExit=yes \
        systemd-inhibit --what="$what" --mode=delay --signal="$signal" --who="$who" --why="testing --signal=" \
            sleep infinity

    timeout 30 bash -c "until systemd-inhibit --list --no-legend | grep -F '$who' >/dev/null; do sleep 0.5; done"
    systemd-inhibit --list --no-legend --mode=delay | grep -F "$who" >/dev/null

    "$@"

    for _ in {1..60}; do
        if [[ "$(systemctl show -p SubState --value "$unit")" == "failed" ]]; then
            break
        fi
        sleep 0.5
    done
    assert_eq "$(systemctl show -p SubState --value "$unit")" "failed"
    assert_eq "$(systemctl show -p Result --value "$unit")" "exit-code"
    assert_eq "$(systemctl show -p ExecMainStatus --value "$unit")" "1"

    wait_for_property "$property" false

    journalctl --sync
    journalctl -b --no-pager -u "$unit" | grep -F "Forwarding $signal to 'sleep', because the system is about to $wording." >/dev/null

    # Check it isn't lingering
    (! systemd-inhibit --list --no-legend | grep -F "$who" >/dev/null)

    systemctl reset-failed "$unit"
}

# There is no payload to swap out for shutdown the way there is for suspend, so
# make the unit logind wants to start unstartable instead, and unscrew it as
# early as possible so we don't end up wedging the VM.
check_shutdown_forwarding() {
    systemctl mask poweroff.target
    check_forwarding "$@"
    systemctl unmask poweroff.target
}

# Signal termination remains a failure
for signal in SIGTERM SIGABRT; do
    check_forwarding sleep "$signal" PreparingForSleep sleep systemctl suspend --no-block
    test -e /run/suspend.flag

    check_shutdown_forwarding shutdown "$signal" PreparingForShutdown "shut down" systemctl poweroff --no-block
done

# Only the operation that actually happens gets the signal forwarded for it
check_shutdown_forwarding sleep:shutdown SIGTERM PreparingForShutdown "shut down" systemctl poweroff --no-block
