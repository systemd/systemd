#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# A timer whose unit file is rejected and then repaired must be armed again by
# daemon-reload alone. Healthy elapsed timers must stay elapsed across reloads,
# even if the new configuration supplies a future trigger.
#
# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/44667
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

assert_calendar_waiting() {
    local load_state="$1"

    assert_eq "$(systemctl show -P LoadState "$CAL_UNIT.timer")" "$load_state"
    assert_unit_state "$CAL_UNIT.timer" active waiting
    if [[ "$load_state" == loaded ]]; then
        local next
        next="$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"
        assert_not_empty "$next"
        assert_neq "$next" infinity
    else
        assert_in '^$|^infinity$' "$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"
    fi
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
assert_calendar_waiting loaded

# The report's broken file is a single line outside any section. The parser
# ignores it and the timer is then rejected for having no values.
echo test >"/run/systemd/system/$CAL_UNIT.timer"
systemctl daemon-reload
assert_calendar_waiting bad-setting
write_calendar_timer "$CALENDAR"

systemctl daemon-reload
assert_calendar_waiting loaded

# Masking a waiting timer must also leave it in a state where reload can rearm it.
ln -sf /dev/null "/run/systemd/system/$CAL_UNIT.timer"
systemctl daemon-reload
assert_calendar_waiting masked

rm "/run/systemd/system/$CAL_UNIT.timer"
write_calendar_timer "$CALENDAR"
systemctl daemon-reload
assert_calendar_waiting loaded

# A second reload must keep the timer armed.
systemctl daemon-reload
assert_calendar_waiting loaded

# A calendar event in the past has no next elapse. Once the timer has elapsed,
# a valid configuration change must not start it again on daemon-reload.
write_calendar_timer "2000-01-01 00:00:00"
systemctl daemon-reload
assert_eq "$(systemctl show -P LoadState "$CAL_UNIT.timer")" "loaded"
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "elapsed"
write_calendar_timer "$CALENDAR"
systemctl daemon-reload
assert_eq "$(systemctl show -P LoadState "$CAL_UNIT.timer")" "loaded"
assert_eq "$(systemctl show -P SubState "$CAL_UNIT.timer")" "elapsed"
assert_in '^$|^infinity$' "$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"

# An elapsed one-shot must stay elapsed and must not run its service again.
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
# shellcheck disable=SC2016
timeout 30 bash -c 'until [[ "$(systemctl show -P SubState "$1")" == elapsed ]]; do sleep .5; done' _ "$SHOT_UNIT.timer"
assert_eq "$(systemctl show -P Result "$SHOT_UNIT.timer")" "success"
test -f "$SHOT_STAMP"
stamp_mtime="$(stat -c %y "$SHOT_STAMP")"

systemctl daemon-reload
sleep 3
assert_eq "$(systemctl show -P SubState "$SHOT_UNIT.timer")" "elapsed"
assert_eq "$(stat -c %y "$SHOT_STAMP")" "$stamp_mtime"
assert_in '^$|^infinity$' "$(systemctl show -P NextElapseUSecMonotonic "$SHOT_UNIT.timer")"
