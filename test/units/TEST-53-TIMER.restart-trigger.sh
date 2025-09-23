#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Restarting an already elapsed timer shouldn't immediately trigger the corresponding service unit.
#
# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/31231
#   - https://github.com/systemd/systemd/issues/35805
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="timer-restart-$RANDOM"
TEST_MESSAGE="Hello from timer $RANDOM"

# Setup
cat >"/run/systemd/system/$UNIT_NAME.timer" <<EOF
[Timer]
OnCalendar=$(date --date="+1 hour" "+%Y-%m-%d %H:%M:%S")
AccuracySec=1s
EOF

cat >"/run/systemd/system/$UNIT_NAME.service" <<EOF
[Service]
ExecStart=echo "$TEST_MESSAGE"
EOF

systemctl daemon-reload

JOURNAL_TS="$(date "+%s")"
# Paranoia check that the test message is not already in the logs
(! journalctl -p info --since="@$JOURNAL_TS" --unit="$UNIT_NAME" --grep="$TEST_MESSAGE")

# Restart time timer and move time forward by 2 hours to trigger the timer
systemctl restart "$UNIT_NAME.timer"
systemctl status "$UNIT_NAME.timer"

date -s '+2 hours'
trap 'date -s "-2 hours"' EXIT
sleep 1
systemctl status "$UNIT_NAME.timer"
assert_eq "$(journalctl -q -p info --since="@$JOURNAL_TS" --unit="$UNIT_NAME" --grep="$TEST_MESSAGE" | wc -l)" "1"

# Restarting the timer unit shouldn't trigger neither the timer nor the service, so these
# fields should remain constant through the following tests
SERVICE_INV_ID="$(systemctl show --property=InvocationID "$UNIT_NAME.service")"
TIMER_LAST_TRIGGER="$(systemctl show --property=LastTriggerUSec "$UNIT_NAME.timer")"

# Now restart the timer and check if the timer and the service weren't triggered again
systemctl restart "$UNIT_NAME.timer"
sleep 5
assert_eq "$(journalctl -q -p info --since="@$JOURNAL_TS" --unit="$UNIT_NAME" --grep="$TEST_MESSAGE" | wc -l)" "1"
assert_eq "$SERVICE_INV_ID" "$(systemctl show --property=InvocationID "$UNIT_NAME.service")"
assert_eq "$TIMER_LAST_TRIGGER" "$(systemctl show --property=LastTriggerUSec "$UNIT_NAME.timer")"

# Set the timer into the past, restart it, and again check if it wasn't triggered
TIMER_TS="$(date --date="-1 day" "+%Y-%m-%d %H:%M:%S")"
mkdir "/run/systemd/system/$UNIT_NAME.timer.d/"
cat >"/run/systemd/system/$UNIT_NAME.timer.d/99-override.conf" <<EOF
[Timer]
OnCalendar=$TIMER_TS
EOF
systemctl daemon-reload
systemctl status "$UNIT_NAME.timer"
assert_in "OnCalendar=$TIMER_TS" "$(systemctl show -P TimersCalendar "$UNIT_NAME".timer)"
systemctl restart "$UNIT_NAME.timer"
sleep 5
assert_eq "$(journalctl -q -p info --since="@$JOURNAL_TS" --unit="$UNIT_NAME" --grep="$TEST_MESSAGE" | wc -l)" "1"
assert_eq "$SERVICE_INV_ID" "$(systemctl show --property=InvocationID "$UNIT_NAME.service")"
assert_eq "$TIMER_LAST_TRIGGER" "$(systemctl show --property=LastTriggerUSec "$UNIT_NAME.timer")"

# Cleanup
systemctl stop "$UNIT_NAME".{timer,service}
rm -f "/run/systemd/system/$UNIT_NAME".{timer,service}
systemctl daemon-reload
