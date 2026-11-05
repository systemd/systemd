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
    local unit="$1" want="$2" i

    for ((i = 0; i < 50; i++)); do
        if [[ "$(systemctl show -P SubState "$unit")" == "$want" ]]; then
            return 0
        fi
        sleep 0.1
    done

    systemctl status "$unit" || true
    echo "Timed out waiting for $unit to be $want" >&2
    return 1
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

cat >"/run/systemd/system/$CAL_UNIT.service" <<EOF
[Service]
Type=oneshot
ExecStart=/usr/bin/true
EOF

cat >"/run/systemd/system/$CAL_UNIT.timer" <<EOF
[Unit]
Description=Calendar timer recovered after a bad setting

[Timer]
OnCalendar=minutely
AccuracySec=1s
EOF

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
# Nothing is armed while the file is rejected. systemctl prints an unset
# realtime elapse as an empty string, and an infinite monotonic elapse as
# "infinity"; accept either.
bad_next="$(systemctl show -P NextElapseUSecRealtime "$CAL_UNIT.timer")"
case "$bad_next" in
    ""|infinity) ;;
    *)
        echo "FAIL: expected no realtime elapse while the unit file is bad, got '$bad_next'" >&2
        exit 1
        ;;
esac

cat >"/run/systemd/system/$CAL_UNIT.timer" <<EOF
[Unit]
Description=Calendar timer recovered after a bad setting

[Timer]
OnCalendar=minutely
AccuracySec=1s
EOF

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
stamp_mtime="$(stat -c %Y "$SHOT_STAMP")"

systemctl daemon-reload
sleep 3
assert_eq "$(systemctl show -P SubState "$SHOT_UNIT.timer")" "elapsed"
assert_eq "$(stat -c %Y "$SHOT_STAMP")" "$stamp_mtime"
shot_next="$(systemctl show -P NextElapseUSecRealtime "$SHOT_UNIT.timer")"
case "$shot_next" in
    ""|infinity) ;;
    *)
        echo "FAIL: elapsed one-shot was re-armed, next elapse is '$shot_next'" >&2
        exit 1
        ;;
esac
