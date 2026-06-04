#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

holder=/usr/lib/systemd/tests/unit-tests/manual/test-dbus-name-holder
name=systemd.test.DBusReconnect
marker=/run/dbus-reconnect-go
release=/run/dbus-reconnect-release

at_exit() {
    set +e
    rm -f "$marker" "$release"
    systemctl stop dbus-reconnect-recover.service dbus-reconnect-stop.service dbus-reconnect-exit.service dbus-reconnect-drop.service 2>/dev/null
}
trap at_exit EXIT

# Poll until property $2 of unit $1 reaches value $3
poll() {
    local unit="${1:?}" prop="${2:?}" want="${3:?}" got i
    for ((i = 0; i < 150; i++)); do
        got="$(systemctl show -p "$prop" --value "$unit")"
        if [[ "$got" == "$want" ]]; then
            return 0
        fi
        sleep 0.2
    done
    echo "poll: timed out waiting for $unit $prop=$want (last: $got)" >&2
    return 1
}

reset_failed() {
    local unit="${1:?}"

    set +e
    systemctl reset-failed "$unit" 2>/dev/null
    set -e
}

enter_revalidation() {
    local unit="${1:?}"

    shift
    reset_failed "$unit"
    rm -f "$marker"
    systemd-run --unit="$unit" -p Type=dbus -p BusName="$name" -p Restart=no "$@" "$holder" "$name" "$marker"
    systemctl restart dbus.service
    poll "$unit" SubState running-revalidating
}

# the name comes back within the grace window
unit=dbus-reconnect-recover.service
enter_revalidation "$unit"
main_pid="$(systemctl show -p MainPID --value "$unit")"
assert_neq "$main_pid" "0"
touch "$marker"
poll "$unit" SubState running
assert_eq "$(systemctl show -p MainPID --value "$unit")" "$main_pid"
systemctl stop "$unit"

# the name never comes back
unit=dbus-reconnect-stop.service
enter_revalidation "$unit"
poll "$unit" ActiveState inactive

# ditto with RemainAfterExit=yes
unit=dbus-reconnect-exit.service
enter_revalidation "$unit" -p RemainAfterExit=yes
poll "$unit" SubState exited
systemctl stop "$unit"

# the name is dropped on a live connection and we action it at once
unit=dbus-reconnect-drop.service
reset_failed "$unit"
rm -f "$release"
systemd-run --unit="$unit" -p Type=dbus -p BusName="$name" -p Restart=no "$holder" "$name" "$marker" "$release"
poll "$unit" SubState running
touch "$release"
for ((i = 0; i < 150; i++)); do
    sub_state="$(systemctl show -p SubState --value "$unit")"
    if [[ "$sub_state" == running-revalidating ]]; then
        echo "live drop entered the revalidation window" >&2
        exit 1
    fi

    active_state="$(systemctl show -p ActiveState --value "$unit")"
    if [[ "$active_state" == inactive ]]; then
        break
    fi

    sleep 0.2
done
assert_eq "$(systemctl show -p ActiveState --value "$unit")" inactive
