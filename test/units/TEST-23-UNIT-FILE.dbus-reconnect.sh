#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

HOLDER=/usr/lib/systemd/tests/unit-tests/manual/test-dbus-name-holder
NAME=systemd.test.DBusReconnect
UNIT=dbus-reconnect-victim.service

if [[ ! -x "$HOLDER" ]]; then
    echo "$HOLDER not installed, skipping." >&2
    exit 0
fi

at_exit() {
    set +e
    systemctl stop "$UNIT"
    systemctl log-level info
}
trap at_exit EXIT

systemctl reset-failed "$UNIT" 2>/dev/null || true
systemctl log-level debug

# This will try to grab the name back when the broker returns
systemd-run --unit="$UNIT" -p Type=dbus -p BusName="$NAME" -p Restart=no "$HOLDER" "$NAME"

timeout 30 bash -c "until [[ \"\$(systemctl is-active $UNIT)\" == active ]]; do sleep 0.2; done"
mainpid="$(systemctl show -p MainPID --value "$UNIT")"
assert_neq "$mainpid" "0"

cursor="$(journalctl --show-cursor -n0 2>/dev/null | sed -n 's/^-- cursor: //p')"

systemctl restart dbus.service

# Make sure the grace path was actually taken (pid1 saw the name gone on
# reconnect and deferred), else the test could pass for free if the helper
# happened to win the reconnect race.
timeout 30 bash -c "until journalctl --after-cursor '$cursor' -u $UNIT --no-pager 2>/dev/null | grep 'deferring stop for grace period' >/dev/null; do sleep 0.2; done"

# After the grace period the service should still be up unchanged
sleep 3
assert_eq "$(systemctl is-active "$UNIT")" "active"
assert_eq "$(systemctl show -p MainPID --value "$UNIT")" "$mainpid"
