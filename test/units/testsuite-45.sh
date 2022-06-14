#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

restore_timezone() {
    if [[ -f /tmp/timezone.bak ]]; then
        mv /tmp/timezone.bak /etc/timezone
    else
        rm -f /etc/timezone
    fi
}

test_timezone() {
    local ORIG_TZ=

    # Debian/Ubuntu specific file
    if [[ -f /etc/timezone ]]; then
        mv /etc/timezone /tmp/timezone.bak
    fi

    trap restore_timezone EXIT

    if [[ -L /etc/localtime ]]; then
        ORIG_TZ=$(readlink /etc/localtime | sed 's#^.*zoneinfo/##')
        echo "original tz: $ORIG_TZ"
    fi

    echo 'timedatectl works'
    assert_in "Local time:" "$(timedatectl --no-pager)"

    echo 'change timezone'
    assert_eq "$(timedatectl --no-pager set-timezone Europe/Kiev 2>&1)" ""
    assert_eq "$(readlink /etc/localtime | sed 's#^.*zoneinfo/##')" "Europe/Kiev"
    if [[ -f /etc/timezone ]]; then
        assert_eq "$(cat /etc/timezone)" "Europe/Kiev"
    fi
    assert_in "Time zone: Europe/Kiev \(EEST, \+0[0-9]00\)" "$(timedatectl)"

    if [[ -n "$ORIG_TZ" ]]; then
        echo 'reset timezone to original'
        assert_eq "$(timedatectl set-timezone "$ORIG_TZ" 2>&1)" ""
        assert_eq "$(readlink /etc/localtime | sed 's#^.*zoneinfo/##')" "$ORIG_TZ"
        if [[ -f /etc/timezone ]]; then
            assert_eq "$(cat /etc/timezone)" "$ORIG_TZ"
        fi
    fi

    restore_timezone
    trap - EXIT
}

restore_adjtime() {
    if [[ -e /etc/adjtime.bak ]]; then
        mv /etc/adjtime.bak /etc/adjtime
    else
        rm /etc/adjtime
    fi
}

check_adjtime_not_exist() {
    if [[ -e /etc/adjtime ]]; then
        echo "/etc/adjtime unexpectedly exists." >&2
        exit 1
    fi
}

test_adjtime() {
    # test setting UTC vs. LOCAL in /etc/adjtime
    if [[ -e /etc/adjtime ]]; then
        mv /etc/adjtime /etc/adjtime.bak
    fi

    trap restore_adjtime EXIT

    echo 'no adjtime file'
    rm -f /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"
    timedatectl set-local-rtc 0
    check_adjtime_not_exist

    echo 'UTC set in adjtime file'
    printf '0.0 0 0\n0\nUTC\n' > /etc/adjtime
    timedatectl set-local-rtc 0
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
UTC"
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'non-zero values in adjtime file'
    printf '0.1 123 0\n0\nLOCAL\n' > /etc/adjtime
    timedatectl set-local-rtc 0
    assert_eq "$(cat /etc/adjtime)" "0.1 123 0
0
UTC"
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.1 123 0
0
LOCAL"

    echo 'fourth line adjtime file'
    printf '0.0 0 0\n0\nLOCAL\nsomethingelse\n' > /etc/adjtime
    timedatectl set-local-rtc 0
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
UTC
somethingelse"
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL
somethingelse"

    echo 'no final newline in adjtime file'
    printf '0.0 0 0\n0\nUTC' > /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0\nUTC' > /etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only one line in adjtime file'
    printf '0.0 0 0\n' > /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n' > /etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only one line in adjtime file, no final newline'
    printf '0.0 0 0' > /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0' > /etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only two lines in adjtime file'
    printf '0.0 0 0\n0\n' > /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0\n' > /etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only two lines in adjtime file, no final newline'
    printf '0.0 0 0\n0' > /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0' > /etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'unknown value in 3rd line of adjtime file'
    printf '0.0 0 0\n0\nFOO\n' > /etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0\nFOO\n' > /etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    restore_adjtime
    trap - EXIT
}

assert_ntp() {
    assert_eq "$(busctl get-property org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 NTP)" "b $1"
}

start_mon() {
    busctl monitor --match="type='signal',sender=org.freedesktop.timedate1,member='PropertiesChanged',path=/org/freedesktop/timedate1" >"$mon" &
    MONPID=$!
}

wait_mon() {
    for ((i = 0; i < 10; i++)); do
        if (( i != 0 )); then sleep 1; fi
        if grep -q "$1" "$mon"; then break; fi
    done
    assert_in "$2" "$(cat "$mon")"
    kill "$MONPID"
    wait "$MONPID" 2>/dev/null || true
}

test_ntp() {
    # timesyncd has ConditionVirtualization=!container by default; drop/mock that for testing
    if systemd-detect-virt --container --quiet; then
        systemctl disable --quiet --now systemd-timesyncd
        mkdir -p /run/systemd/system/systemd-timesyncd.service.d
        cat >/run/systemd/system/systemd-timesyncd.service.d/container.conf <<EOF
[Unit]
ConditionVirtualization=

[Service]
Type=simple
AmbientCapabilities=
ExecStart=
ExecStart=/bin/sleep infinity
EOF
        systemctl daemon-reload
    fi

    mon=$(mktemp -t dbusmon.XXXXXX)

    echo 'disable NTP'
    timedatectl set-ntp false
    for ((i = 0; i < 10; i++)); do
        if (( i != 0 )); then sleep 1; fi
        if [[ "$(systemctl show systemd-timesyncd --property ActiveState)" == "ActiveState=inactive" ]]; then
            break;
        fi
    done
    assert_eq "$(systemctl show systemd-timesyncd --property ActiveState)" "ActiveState=inactive"
    assert_ntp "false"
    assert_rc 3 systemctl is-active --quiet systemd-timesyncd

    echo 'enable NTP'
    start_mon
    timedatectl set-ntp true
    wait_mon "NTP" "BOOLEAN true"
    assert_ntp "true"
    for ((i = 0; i < 10; i++)); do
        if (( i != 0 )); then sleep 1; fi
        if [[ "$(systemctl show systemd-timesyncd --property ActiveState)" == "ActiveState=active" ]]; then
            break;
        fi
    done
    assert_eq "$(systemctl show systemd-timesyncd --property ActiveState)" "ActiveState=active"
    assert_rc 0 systemctl is-active --quiet systemd-timesyncd

    echo 're-disable NTP'
    start_mon
    timedatectl set-ntp false
    wait_mon "NTP" "BOOLEAN false"
    assert_ntp "false"
    assert_rc 3 systemctl is-active --quiet systemd-timesyncd
}

: >/failed

test_timezone
test_adjtime
test_ntp

touch /testok
rm /failed
