#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# When deserializing a serialized timer unit with RandomizedDelaySec= set, systemd should use the last
# inactive exit timestamp instead of current realtime to calculate the new next elapse, so the timer unit
# actually runs in the given calendar window.
#
# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/18678
#   - https://github.com/systemd/systemd/pull/27752
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="timer-RandomizedDelaySec-$RANDOM"
TARGET_TS="$(date --date="tomorrow 00:10" "+%a %Y-%m-%d %H:%M:%S %Z")"
TARGET_TS_S="$(date --date="$TARGET_TS" "+%s")"
# Maximum possible next elapse timestamp: $TARGET_TS (OnCalendar=) + 22 hours (RandomizedDelaySec=)
MAX_NEXT_ELAPSE_REALTIME_S="$((TARGET_TS_S + 22 * 60 * 60))"
MAX_NEXT_ELAPSE_REALTIME="$(date --date="@$MAX_NEXT_ELAPSE_REALTIME_S" "+%a %Y-%m-%d %H:%M:%S %Z")"

# Let's make sure to return the date & time back to the original state once we're done with our time
# shenigans. One way to do this would be to use hwclock, but the RTC in VMs can be unreliable or slow to
# respond, causing unexpected test fails/timeouts.
#
# Instead, let's save the realtime timestamp before we start with the test together with a current monotonic
# timestamp, after the test ends take the difference between the current monotonic timestamp and the "start"
# one, add it to the originally saved realtime timestamp, and finally use that timestamp to set the system
# time. This should advance the system time by the amount of time the test actually ran, and hence restore it
# to some sane state after the time jumps performed by the test. It won't be perfect, but it should be close
# enough for our needs.
START_REALTIME="$(date "+%s")"
START_MONOTONIC="$(cut -d . -f 1 /proc/uptime)"
at_exit() {
    : "Restore the system date to a sane state"
    END_MONOTONIC="$(cut -d . -f 1 /proc/uptime)"
    date --set="@$((START_REALTIME + END_MONOTONIC - START_MONOTONIC))"
}
trap at_exit EXIT

# Set some predictable time so we can schedule the first timer elapse in a deterministic-ish way
date --set="23:00"

# Setup
cat >"/run/systemd/system/$UNIT_NAME.timer" <<EOF
[Timer]
# Run this timer daily, ten minutes after midnight
OnCalendar=*-*-* 00:10:00
RandomizedDelaySec=22h
AccuracySec=1ms
EOF

cat >"/run/systemd/system/$UNIT_NAME.service" <<EOF
[Service]
ExecStart=echo "Hello world"
EOF

systemctl daemon-reload

check_elapse_timestamp() {
    systemctl status "$UNIT_NAME.timer"
    systemctl show -p InactiveExitTimestamp "$UNIT_NAME.timer"

    NEXT_ELAPSE_REALTIME="$(systemctl show -P NextElapseUSecRealtime "$UNIT_NAME.timer")"
    NEXT_ELAPSE_REALTIME_S="$(date --date="$NEXT_ELAPSE_REALTIME" "+%s")"
    : "Next elapse timestamp should be $TARGET_TS <= $NEXT_ELAPSE_REALTIME <= $MAX_NEXT_ELAPSE_REALTIME"
    assert_ge "$NEXT_ELAPSE_REALTIME_S" "$TARGET_TS_S"
    assert_le "$NEXT_ELAPSE_REALTIME_S" "$MAX_NEXT_ELAPSE_REALTIME_S"
}

# Restart the timer unit and check the initial next elapse timestamp
: "Initial next elapse timestamp"
systemctl restart "$UNIT_NAME.timer"
check_elapse_timestamp

# Bump the system date to exactly the original calendar timer time (without any random delay!) - systemd
# should recalculate the next elapse timestamp with a new randomized delay, but it should use the original
# inactive exit timestamp as a "base", so the final timestamp should not end up beyond the original calendar
# timestamp + randomized delay range.
#
# Similarly, do the same check after doing daemon-reload, as that also forces systemd to recalculate the next
# elapse timestamp (this goes through a slightly different codepath that actually contained the original
# issue).
: "Next elapse timestamp after time jump"
date --set="tomorrow 00:10"
check_elapse_timestamp

: "Next elapse timestamp after daemon-reload"
systemctl daemon-reload
check_elapse_timestamp

# Cleanup
systemctl stop "$UNIT_NAME".{timer,service}
rm -f "/run/systemd/system/$UNIT_NAME".{timer,service}
systemctl daemon-reload
