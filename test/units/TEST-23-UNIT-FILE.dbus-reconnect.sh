#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

HOLDER=/usr/lib/systemd/tests/unit-tests/manual/test-dbus-name-holder
NAME=systemd.test.DBusReconnect
UNIT=dbus-reconnect-victim.service
MARKER=/run/dbus-reconnect-go

at_exit() {
    set +e
    rm -f "$MARKER"
    systemctl stop "$UNIT"
    systemctl log-level info
}
trap at_exit EXIT

systemctl reset-failed "$UNIT" 2>/dev/null || true
systemctl log-level debug
rm -f "$MARKER"

# The holder won't grab the name back until we touch $MARKER, so we can release it at a controlled
# point inside the grace window rather than racing pid1's reconnect.
systemd-run --unit="$UNIT" -p Type=dbus -p BusName="$NAME" -p Restart=no "$HOLDER" "$NAME" "$MARKER"

timeout 30 bash -c "until [[ \"\$(systemctl is-active $UNIT)\" == active ]]; do sleep 0.2; done"
mainpid="$(systemctl show -p MainPID --value "$UNIT")"
assert_neq "$mainpid" "0"

cursor="$(journalctl --show-cursor -n0 2>/dev/null | sed -n 's/^-- cursor: //p')"

systemctl restart dbus.service

# Wait until pid1 has seen the name vanish on reconnect and deferred the stop
timeout 30 bash -c "until journalctl --after-cursor '$cursor' -u $UNIT --no-pager 2>/dev/null | grep 'deferring stop for grace period' >/dev/null; do sleep 0.2; done"

# ...now the holder can grab the name back...
touch "$MARKER"

# ...and the service should recover.
timeout 30 bash -c "until journalctl --after-cursor '$cursor' -u $UNIT --no-pager 2>/dev/null | grep 'now owned by' >/dev/null; do sleep 0.2; done"
assert_eq "$(systemctl is-active "$UNIT")" "active"
assert_eq "$(systemctl show -p MainPID --value "$UNIT")" "$mainpid"
