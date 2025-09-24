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
TARGET_TS="$(date --date="tomorrow 00:10")"
TARGET_TS_S="$(date --date="$TARGET_TS" "+%s")"
MAX_NEXT_ELAPSE_REALTIME_S="$((TARGET_TS_S + 23 * 60 * 60))"
MAX_NEXT_ELAPSE_REALTIME="$(date --date="@$MAX_NEXT_ELAPSE_REALTIME_S")"

# Save the current date & time into RTC, so we can restore it later once we're done with our time shenanigans
hwclock --systohc
trap 'hwclock --hctosys; date' EXIT
# Set some predictable time so we can schedule the first timer elapse in a deterministic-ish way
date --set="23:00"

# Setup
cat >"/run/systemd/system/$UNIT_NAME.timer" <<EOF
[Timer]
# Run this timer daily, ten minutes after midnight
OnCalendar=*-*-* 00:10
RandomizedDelaySec=22h
EOF

cat >"/run/systemd/system/$UNIT_NAME.service" <<EOF
[Service]
ExecStart=echo "Hello world"
EOF

systemctl daemon-reload

# Restart the timer unit and check some currently calculated values
systemctl restart "$UNIT_NAME.timer"
systemctl status "$UNIT_NAME.timer"
systemctl show -p InactiveExitTimestamp "$UNIT_NAME.timer"

# The next elapse timestamp must be in range:
#   $TARGET_TS <= timestamp <= $TARGET_TS + max RandomizedDelaySec (23 hours)
NEXT_ELAPSE_REALTIME="$(systemctl show -P NextElapseUSecRealtime "$UNIT_NAME.timer")"
NEXT_ELAPSE_REALTIME_S="$(date --date="$NEXT_ELAPSE_REALTIME" "+%s")"
: "Next elapse timestamp should be $TARGET_TS <= $NEXT_ELAPSE_REALTIME <= $MAX_NEXT_ELAPSE_REALTIME"
assert_ge "$NEXT_ELAPSE_REALTIME_S" "$TARGET_TS_S"
assert_le "$NEXT_ELAPSE_REALTIME_S" "$MAX_NEXT_ELAPSE_REALTIME_S"

# Bump the system date to 1 minute after the original calendar timer would've expired (without any random
# delay!) - systemd should recalculate the next elapse timestamp with a new randomized delay, but it should
# use the original inactive exit timestamp as a base, so the final timestamp should not end up beyond the
# original calendar timestamp + randomized delay range we checked above. Given we might hit a valid timestamp
# even with a "broken" code, try it a couple of times to at least minimize the chance
date -s "tomorrow 00:11"
for i in {0..9}; do
    : "Try #$i"
    # Note: the time jump above will force the first recalculation for us, so check that as well
    systemctl status "$UNIT_NAME.timer"
    systemctl show -p InactiveExitTimestamp "$UNIT_NAME.timer"
    NEW_NEXT_ELAPSE_REALTIME="$(systemctl show -P NextElapseUSecRealtime "$UNIT_NAME.timer")"
    NEW_NEXT_ELAPSE_REALTIME_S="$(date --date="$NEW_NEXT_ELAPSE_REALTIME" "+%s")"
    : "Next elapse timestamp should be $TARGET_TS <= $NEW_NEXT_ELAPSE_REALTIME <= $MAX_NEXT_ELAPSE_REALTIME"
    assert_ge "$NEW_NEXT_ELAPSE_REALTIME_S" "$TARGET_TS_S"
    assert_le "$NEW_NEXT_ELAPSE_REALTIME_S" "$MAX_NEXT_ELAPSE_REALTIME_S"
    systemctl daemon-reload
done

# Cleanup
systemctl stop "$UNIT_NAME".{timer,service}
rm -f "/run/systemd/system/$UNIT_NAME".{timer,service}
systemctl daemon-reload
