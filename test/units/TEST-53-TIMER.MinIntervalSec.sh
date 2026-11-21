#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# MinIntervalSec= skips all calendar events that would elapse earlier than the given time after the last
# trigger. Use a persistent timer, so that the last trigger timestamp can be set via the stamp file.
#
# Provides coverage for:
#   - https://github.com/systemd/systemd/issues/6024
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="timer-MinIntervalSec-$RANDOM"
TRANSIENT_UNIT_NAME="timer-MinIntervalSec-transient-$RANDOM"
STAMP_FILE="/var/lib/systemd/timers/stamp-$UNIT_NAME.timer"
MARKER_FILE="/tmp/$UNIT_NAME.ran"

at_exit() {
    set +e

    systemctl stop "$UNIT_NAME".{timer,service} "$TRANSIENT_UNIT_NAME".{timer,service}
    systemctl clean --what=state "$UNIT_NAME.timer"
    rm -f "/run/systemd/system/$UNIT_NAME".{timer,service} "$MARKER_FILE"
    systemctl daemon-reload
}

trap at_exit EXIT

timer_timestamp_s() {
    local ts

    ts="$(systemctl show --property="${2:?}" --value --timestamp=unix "${1:?}")"
    echo "${ts#@}"
}

# With OnCalendar=hourly and MinIntervalSec=3h, the next elapse must be the first full hour that is at least
# three hours after the last trigger.
assert_next_elapse() {
    local last next

    last="$(timer_timestamp_s "$UNIT_NAME.timer" LastTriggerUSec)"
    next="$(timer_timestamp_s "$UNIT_NAME.timer" NextElapseUSecRealtime)"

    assert_ge "$next" "$((last + 3 * 60 * 60))"
    assert_le "$next" "$((last + 4 * 60 * 60))"
    assert_eq "$(date --date="@$next" "+%M:%S")" "00:00"
}

cat >"/run/systemd/system/$UNIT_NAME.timer" <<EOF
[Timer]
OnCalendar=hourly
MinIntervalSec=3h
Persistent=yes
AccuracySec=1us
EOF

cat >"/run/systemd/system/$UNIT_NAME.service" <<EOF
[Service]
Type=oneshot
ExecStart=touch $MARKER_FILE
EOF

systemctl daemon-reload
assert_eq "$(systemctl show --property=MinIntervalUSec --value "$UNIT_NAME.timer")" "3h"

NOW_S="$(date "+%s")"
mkdir -p "$(dirname "$STAMP_FILE")"

: "Calendar events that are less than MinIntervalSec= after the last trigger are skipped"
# The timer last triggered 90 minutes ago, so it missed an hourly event since then. Without MinIntervalSec=
# it would catch up on it right away.
touch --date="@$((NOW_S - 90 * 60))" "$STAMP_FILE"
systemctl start "$UNIT_NAME.timer"
assert_eq "$(timer_timestamp_s "$UNIT_NAME.timer" LastTriggerUSec)" "$((NOW_S - 90 * 60))"
assert_next_elapse
sleep 1
test ! -e "$MARKER_FILE"
systemctl stop "$UNIT_NAME.timer"

: "A missed calendar event after MinIntervalSec= is still caught up"
touch --date="@$((NOW_S - 5 * 60 * 60))" "$STAMP_FILE"
systemctl start "$UNIT_NAME.timer"
timeout 30 bash -c "until [[ -e '$MARKER_FILE' ]]; do sleep .5; done"
timeout 30 bash -c "until [[ \$(systemctl show --property=SubState --value '$UNIT_NAME.timer') == waiting ]]; do sleep .5; done"
assert_ge "$(timer_timestamp_s "$UNIT_NAME.timer" LastTriggerUSec)" "$NOW_S"
assert_next_elapse

: "The next elapse survives daemon-reload"
NEXT_ELAPSE="$(systemctl show --property=NextElapseUSecRealtime --value "$UNIT_NAME.timer")"
systemctl daemon-reload
assert_eq "$(systemctl show --property=NextElapseUSecRealtime --value "$UNIT_NAME.timer")" "$NEXT_ELAPSE"
systemctl stop "$UNIT_NAME.timer"

: "MinIntervalSec= can be set for transient timers"
systemd-run --unit="$TRANSIENT_UNIT_NAME" --on-calendar=hourly --timer-property=MinIntervalSec=2d true
assert_eq "$(systemctl show --property=MinIntervalUSec --value "$TRANSIENT_UNIT_NAME.timer")" "2d"
