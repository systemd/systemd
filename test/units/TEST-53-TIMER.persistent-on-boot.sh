#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

unit="test53timer$RANDOM"
timer="/run/systemd/system/$unit.timer"
service="/run/systemd/system/$unit.service"
stamp="/var/lib/systemd/timers/stamp-$unit.timer"

at_exit() {
    set +e
    systemctl stop "$unit.timer" "$unit.service"
    rm -f "$timer" "$service" "$stamp"
    systemctl daemon-reload
}
trap at_exit EXIT

cat >"$timer" <<EOF
[Timer]
OnBootSec=1w
OnUnitActiveSec=2h
OnCalendar=$(date -d '+1 week' +%F)
RandomizedDelaySec=1s
AccuracySec=1ms
Persistent=yes
EOF
cat >"$service" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=true
EOF

mkdir -p /var/lib/systemd/timers
touch -d @1 "$stamp"
systemctl daemon-reload
systemctl start "$unit.timer"
assert_eq "$(systemctl show --timestamp=unix -P LastTriggerUSec "$unit.timer")" @1
assert_eq "$(systemctl show -P LastTriggerUSecMonotonic "$unit.timer")" 0

# Put the nominal boot deadline in the past at reload, without racing the randomized first trigger.
# The stamp predates this boot, and the calendar event is a week away: only OnBootSec= can start the service.
sed -i 's/^OnBootSec=1w$/OnBootSec=1us/' "$timer"
systemctl daemon-reload
assert_neq "$(systemctl show -P NextElapseUSecMonotonic "$unit.timer")" 0
deadline=$((SECONDS + 30))
until systemctl is-active --quiet "$unit.service"; do
    (( SECONDS < deadline ))
    sleep .1
done

# After a real activation, reloading must keep the recurrence, not replay the boot trigger.
systemctl stop "$unit.service"
systemctl daemon-reload
start=$(systemctl show -P InactiveExitTimestampMonotonic "$unit.service")
read -r _ next < <(busctl get-property org.freedesktop.systemd1 "/org/freedesktop/systemd1/unit/${unit}_2etimer" \
                   org.freedesktop.systemd1.Timer NextElapseUSecMonotonic)
base=$((start + 2 * 60 * 60 * 1000000))
assert_ge "$next" "$base"
assert_lt "$next" "$((base + 1000000))"
