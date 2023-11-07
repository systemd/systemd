#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

testcase_timedatectl() {
    timedatectl --no-pager --help
    timedatectl --version

    timedatectl
    timedatectl --no-ask-password
    timedatectl status --machine=testuser@.host
    timedatectl status
    timedatectl show
    timedatectl show --all
    timedatectl show -p NTP
    timedatectl show -p NTP --value
    timedatectl list-timezones

    if ! systemd-detect-virt -qc; then
        systemctl enable --runtime --now systemd-timesyncd
        timedatectl timesync-status
        timedatectl show-timesync
    fi
}

restore_timezone() {
    if [[ -f /tmp/timezone.bak ]]; then
        mv /tmp/timezone.bak /etc/timezone
    else
        rm -f /etc/timezone
    fi
}

testcase_timezone() {
    local ORIG_TZ=

    # Debian/Ubuntu specific file
    if [[ -f /etc/timezone ]]; then
        mv /etc/timezone /tmp/timezone.bak
    fi

    trap restore_timezone RETURN

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
    assert_in "Time zone: Europe/Kiev \(EES*T, \+0[0-9]00\)" "$(timedatectl)"

    if [[ -n "$ORIG_TZ" ]]; then
        echo 'reset timezone to original'
        assert_eq "$(timedatectl set-timezone "$ORIG_TZ" 2>&1)" ""
        assert_eq "$(readlink /etc/localtime | sed 's#^.*zoneinfo/##')" "$ORIG_TZ"
        if [[ -f /etc/timezone ]]; then
            assert_eq "$(cat /etc/timezone)" "$ORIG_TZ"
        fi
    fi
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

testcase_adjtime() {
    # test setting UTC vs. LOCAL in /etc/adjtime
    if [[ -e /etc/adjtime ]]; then
        mv /etc/adjtime /etc/adjtime.bak
    fi

    trap restore_adjtime RETURN

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
    printf '0.0 0 0\n0\nUTC\n' >/etc/adjtime
    timedatectl set-local-rtc 0
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
UTC"
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'non-zero values in adjtime file'
    printf '0.1 123 0\n0\nLOCAL\n' >/etc/adjtime
    timedatectl set-local-rtc 0
    assert_eq "$(cat /etc/adjtime)" "0.1 123 0
0
UTC"
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.1 123 0
0
LOCAL"

    echo 'fourth line adjtime file'
    printf '0.0 0 0\n0\nLOCAL\nsomethingelse\n' >/etc/adjtime
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
    printf '0.0 0 0\n0\nUTC' >/etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0\nUTC' >/etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only one line in adjtime file'
    printf '0.0 0 0\n' >/etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n' >/etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only one line in adjtime file, no final newline'
    printf '0.0 0 0' >/etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0' >/etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only two lines in adjtime file'
    printf '0.0 0 0\n0\n' >/etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0\n' >/etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'only two lines in adjtime file, no final newline'
    printf '0.0 0 0\n0' >/etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0' >/etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"

    echo 'unknown value in 3rd line of adjtime file'
    printf '0.0 0 0\n0\nFOO\n' >/etc/adjtime
    timedatectl set-local-rtc 0
    check_adjtime_not_exist
    printf '0.0 0 0\n0\nFOO\n' >/etc/adjtime
    timedatectl set-local-rtc 1
    assert_eq "$(cat /etc/adjtime)" "0.0 0 0
0
LOCAL"
}

assert_ntp() {
    assert_eq "$(busctl get-property org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 NTP)" "b $1"
}

assert_timedated_signal() {
    local timestamp="${1:?}"
    local value="${2:?}"
    local args=(-q -n 1 --since="$timestamp" -p info _SYSTEMD_UNIT="busctl-monitor.service")

    journalctl --sync

    for _ in {0..9}; do
        if journalctl "${args[@]}" --grep .; then
            [[ "$(journalctl "${args[@]}" -o cat | tr -d '\n' | jq -r '.payload.data[1].NTP.data')" == "$value" ]];
            return 0
        fi

        sleep .5
    done

    return 1
}

assert_timesyncd_state() {
    local state="${1:?}"

    for _ in {0..9}; do
        [[ "$(systemctl show systemd-timesyncd.service -P ActiveState)" == "$state" ]] && return 0
        sleep .5
    done

    return 1
}

testcase_ntp() {
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

    systemd-run --unit busctl-monitor.service --service-type=exec \
        busctl monitor --json=short --match="type='signal',sender=org.freedesktop.timedate1,member='PropertiesChanged',path=/org/freedesktop/timedate1"

    : 'Disable NTP'
    timedatectl set-ntp false
    assert_timesyncd_state "inactive"
    assert_ntp "false"
    assert_rc 3 systemctl is-active --quiet systemd-timesyncd

    : 'Enable NTP'
    ts="$(date +"%F %T.%6N")"
    timedatectl set-ntp true
    assert_timedated_signal "$ts" "true"
    assert_ntp "true"
    assert_timesyncd_state "active"
    assert_rc 0 systemctl is-active --quiet systemd-timesyncd

    : 'Re-disable NTP'
    ts="$(date +"%F %T.%6N")"
    timedatectl set-ntp false
    assert_timedated_signal "$ts" "false"
    assert_ntp "false"
    assert_rc 3 systemctl is-active --quiet systemd-timesyncd

    systemctl stop busctl-monitor.service
}

run_testcases

touch /testok
