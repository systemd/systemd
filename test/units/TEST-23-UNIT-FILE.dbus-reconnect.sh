#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

HOLDER=/usr/lib/systemd/tests/unit-tests/manual/test-dbus-name-holder
NAME=systemd.test.ExecStopPost

if [[ ! -x "$HOLDER" ]]; then
    echo "$HOLDER not installed, skipping." >&2
    exit 0
fi

systemctl reset-failed dbus-reconnect-victim.service 2>/dev/null || true

systemd-run --unit=dbus-reconnect-victim.service \
            -p Type=dbus -p BusName="$NAME" -p Restart=no \
            "$HOLDER" "$NAME"

mainpid="$(systemctl show -p MainPID --value dbus-reconnect-victim.service)"
assert_neq "$mainpid" "0"

systemctl restart dbus.service

# Wait out the grace period to check if manager wants to stop the service
sleep 3
assert_eq "$(systemctl is-active dbus-reconnect-victim.service)" "active"
assert_eq "$(systemctl show -p MainPID --value dbus-reconnect-victim.service)" "$mainpid"

systemctl stop dbus-reconnect-victim.service
