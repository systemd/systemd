#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Persistent timers (i.e. timers with Persitent=yes) save their last trigger timestamp to a persistent
# storage (a stamp file), which is loaded during subsequent boots. As mentioned in the man page, such timers
# should be still affected by RandomizedDelaySec= during boot even if they already elapsed and would be then
# triggered immediately.
#
# This behavior was, however, broken by [0], which stopped rebasing the to-be next elapse timestamps
# unconditionally and left that only for timers that have neither last trigger nor inactive exit timestamps
# set, since rebasing is needed only during boot. This holds for regular timers during boot, but not for
# persistent ones, since the last trigger timestamp is loaded from a persistent storage.
#
# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/39739
#
# [0] bdb8e584f4509de0daebbe2357d23156160c3a90
#
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="timer-RandomizedDelaySec-persistent-$RANDOM"
STAMP_FILE="/var/lib/systemd/timers/stamp-$UNIT_NAME.timer"

# Setup
cat >"/run/systemd/system/$UNIT_NAME.timer" <<EOF
[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=12h
EOF

cat >"/run/systemd/system/$UNIT_NAME.service" <<\EOF
[Service]
ExecStart=echo "Service ran at $(date)"
EOF

systemctl daemon-reload

# Create timer's state file with an old-enough timestamp (~2 days ago), so it'd definitely elapse if the next
# elapse timestamp wouldn't get rebased
mkdir -p "$(dirname "$STAMP_FILE")"
touch -d "2 days ago" "$STAMP_FILE"
stat "$STAMP_FILE"
SAVED_LAST_TRIGGER_S="$(stat --format="%Y" "$STAMP_FILE")"

# Start the timer and verify that its last trigger timestamp didn't change
#
# The last trigger timestamp should get rebased before it gets used as a base for the next elapse timestamp
# (since it pre-dates the machine boot time). This should then add a RandomizedDelaySec= to the rebased
# timestamp and the timer unit should not get triggered immediately after starting.
systemctl start "$UNIT_NAME.timer"
systemctl status "$UNIT_NAME.timer"

TIMER_LAST_TRIGGER="$(systemctl show --property=LastTriggerUSec --value "$UNIT_NAME.timer")"
TIMER_LAST_TRIGGER_S="$(date --date="$TIMER_LAST_TRIGGER" "+%s")"
: "The timer should not be triggered immediately, hence the last trigger timestamp should not change"
assert_eq "$SAVED_LAST_TRIGGER_S" "$TIMER_LAST_TRIGGER_S"

# Cleanup
systemctl stop "$UNIT_NAME".{timer,service}
systemctl clean --what=state "$UNIT_NAME.timer"
rm -f "/run/systemd/system/$UNIT_NAME".{timer,service}
systemctl daemon-reload
