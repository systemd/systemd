#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# A timer whose unit file is rejected and then repaired must be armed again by
# daemon-reload alone. An already elapsed one-shot must not fire again when
# that reload re-evaluates elapsed timers.
#
# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/44667
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

wait_substate() {
    local unit="$1" want="$2" deadline=$((SECONDS + 30))

    while ((SECONDS < deadline)); do
        if [[ "$(systemctl show -P SubState "$unit")" == "$want" ]]; then
            return 0
        fi
        sleep 0.1
    done

    systemctl status "$unit" || true
    echo "Timed out waiting for $unit to be $want" >&2
    return 1
}

write_calendar_timer() {
    cat >"/run/systemd/system/$CAL_UNIT.timer" <<EOF
[Timer]
OnCalendar=$1
AccuracySec=1s
EOF
}

at_exit() {
    set +e
    systemctl stop "$CAL_UNIT.timer" "$CAL_UNIT.service" "$SHOT_UNIT.timer" "$SHOT_UNIT.service"
    rm -f \
        "/run/systemd/system/$CAL_UNIT.timer" \
        "/run/systemd/system/$CAL_UNIT.service" \
        "/run/systemd/system/$SHOT_UNIT.timer" \
        "/run/systemd/system/$SHOT_UNIT.service" \
        "$SHOT_STAMP"
    systemctl daemon-reload
}
trap at_exit EXIT

CAL_UNIT="timer-bad-setting-$RANDOM"
SHOT_UNIT="timer-elapsed-oneshot-$RANDOM"
SHOT_STAMP="/tmp/$SHOT_UNIT.stamp"
# Keep the calendar event away from the assertions, even when the test starts
# just before a minute boundary.
CALENDAR="$(date --date='+1 day' '+%Y-%m-%d %H:%M:%S')"

cat >"/run/systemd/system/$CAL_UNIT.service" <<EOF
[Service]
Type=oneshot
ExecStart=/usr/bin/true
EOF

write_calendar_timer "$CALENDAR"

systemctl daemon-reload
systemctl start "$CAL_UNIT.timer"
assert_eq "$(systemctl show -P LoadState "$CAL_UNIT.timer")" "loaded"
assert_eq "$(systemctl show -P ActiveState "$CAL_UNIT.timer")" "active"
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "waiting"
next="$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"
assert_neq "$next" ""
assert_neq "$next" "infinity"

# The report's broken file is a single line outside any section. The parser
# ignores it and the timer is then rejected for having no values.
echo test >"/run/systemd/system/$CAL_UNIT.timer"
systemctl daemon-reload
assert_eq "$(systemctl show -P LoadState "$CAL_UNIT.timer")" "bad-setting"
assert_eq "$(systemctl show -P ActiveState "$CAL_UNIT.timer")" "active"
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "waiting"
# Nothing is armed while the file is rejected.
bad_next="$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"
case "$bad_next" in
    ""|infinity) ;;
    *)
        echo "FAIL: expected no realtime elapse while the unit file is bad, got '$bad_next'" >&2
        exit 1
        ;;
esac

write_calendar_timer "$CALENDAR"

systemctl daemon-reload
assert_eq "$(systemctl show -P LoadState "$CAL_UNIT.timer")" "loaded"
assert_eq "$(systemctl show -P ActiveState "$CAL_UNIT.timer")" "active"
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "waiting"
next="$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"
assert_neq "$next" ""
assert_neq "$next" "infinity"

# A second reload of the repaired file must keep the timer armed.
systemctl daemon-reload
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "waiting"
assert_neq "$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")" ""
assert_neq "$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")" "infinity"

# Exercise recovery from an already elapsed state too, as left by an older
# manager after a bad load. A calendar event in the past has no next elapse.
write_calendar_timer "2000-01-01 00:00:00"
systemctl daemon-reload
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "elapsed"
write_calendar_timer "$CALENDAR"
systemctl daemon-reload
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "waiting"
assert_neq "$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")" ""
assert_neq "$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")" "infinity"

# An elapsed one-shot is re-evaluated on reload too. It must stay elapsed and
# must not run the triggered service again.
cat >"/run/systemd/system/$SHOT_UNIT.service" <<EOF
[Service]
Type=oneshot
ExecStart=/usr/bin/touch $SHOT_STAMP
EOF

cat >"/run/systemd/system/$SHOT_UNIT.timer" <<EOF
[Timer]
OnActiveSec=1s
AccuracySec=100ms
RemainAfterElapse=yes
EOF

rm -f "$SHOT_STAMP"
systemctl daemon-reload
systemctl start "$SHOT_UNIT.timer"
wait_substate "$SHOT_UNIT.timer" elapsed
assert_eq "$(systemctl show -P Result "$SHOT_UNIT.timer")" "success"
test -f "$SHOT_STAMP"
stamp_mtime="$(stat -c %y "$SHOT_STAMP")"

systemctl daemon-reload
sleep 3
assert_eq "$(systemctl show -P SubState "$SHOT_UNIT.timer")" "elapsed"
assert_eq "$(stat -c %y "$SHOT_STAMP")" "$stamp_mtime"
shot_next="$(systemctl show -P NextElapseUSecMonotonic "$SHOT_UNIT.timer")"
case "$shot_next" in
    ""|infinity) ;;
    *)
        echo "FAIL: elapsed one-shot was re-armed, next elapse is '$shot_next'" >&2
        exit 1
        ;;
esac
