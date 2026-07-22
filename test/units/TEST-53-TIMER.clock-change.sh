#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/6036
#   - https://github.com/systemd/systemd/issues/24984

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

WAITING_UNIT="timer-clock-change-waiting-$RANDOM"
MISSED_UNIT="timer-clock-change-missed-$RANDOM"
MISSED_MARKER="/tmp/$MISSED_UNIT.ran"
MISSED_STAMP="/var/lib/systemd/timers/stamp-$MISSED_UNIT.timer"

START_REALTIME="$(date "+%s")"
START_MONOTONIC="$(cut -d . -f 1 /proc/uptime)"

at_exit() {
    set +e

    systemctl stop \
        "$WAITING_UNIT.timer" \
        "$WAITING_UNIT.service" \
        "$MISSED_UNIT.timer" \
        "$MISSED_UNIT.service"
    systemctl clean --what=state "$MISSED_UNIT.timer"
    rm -f \
        "/run/systemd/system/$MISSED_UNIT.timer" \
        "/run/systemd/system/$MISSED_UNIT.service" \
        "$MISSED_MARKER" \
        "$MISSED_STAMP"
    systemctl daemon-reload

    END_MONOTONIC="$(cut -d . -f 1 /proc/uptime)"
    date --set="@$((START_REALTIME + END_MONOTONIC - START_MONOTONIC))"
}

trap at_exit EXIT

timer_delta_s() {
    local next_elapse next_elapse_s now

    next_elapse="$(systemctl show -P NextElapseUSecRealtime "$1")"
    next_elapse_s="$(date --date="$next_elapse" "+%s")"
    now="$(date "+%s")"

    TIMER_NEXT_ELAPSE="$next_elapse"
    TIMER_NOW="$now"
    TIMER_DELTA_S="$((next_elapse_s - now))"
}

assert_timer_due_within() {
    local ok=0 unit="${1:?}" max_delta_s="${2:?}"

    for _ in {1..50}; do
        timer_delta_s "$unit"

        if ((TIMER_DELTA_S >= 0 && TIMER_DELTA_S <= max_delta_s)); then
            ok=1
            break
        fi

        sleep .2
    done

    if ((ok == 0)); then
        echo "Timer elapse outside of the expected window."
        echo "  unit=$unit"
        echo "  next_elapse=$TIMER_NEXT_ELAPSE"
        echo "  now=$TIMER_NOW"
        echo "  time_delta=$TIMER_DELTA_S"
        exit 1
    fi
}

: "A waiting calendar timer is recalculated after the clock is set backwards"

date --set="+3 days"
systemd-run --unit "$WAITING_UNIT" --on-calendar "*:0/15:0" true
systemctl status "$WAITING_UNIT.timer"

date --set="-3 days"
assert_timer_due_within "$WAITING_UNIT.timer" 1200

systemctl stop "$WAITING_UNIT.timer" "$WAITING_UNIT.service"

: "A persistent calendar timer still catches up after time advances past a missed elapse"

date --set="19:00:00"

cat >"/run/systemd/system/$MISSED_UNIT.timer" <<EOF
[Timer]
OnCalendar=*-*-* 20:30:00
Persistent=true
AccuracySec=1ms
EOF

cat >"/run/systemd/system/$MISSED_UNIT.service" <<EOF
[Service]
Type=oneshot
ExecStart=touch $MISSED_MARKER
EOF

systemctl daemon-reload
mkdir -p "$(dirname "$MISSED_STAMP")"
touch -d "yesterday 20:30:00" "$MISSED_STAMP"

systemctl start "$MISSED_UNIT.timer"
systemctl status "$MISSED_UNIT.timer"
test ! -e "$MISSED_MARKER"

date --set="tomorrow 09:00:00"
timeout 30 bash -xec "until [[ -e '$MISSED_MARKER' ]]; do sleep .5; done"
