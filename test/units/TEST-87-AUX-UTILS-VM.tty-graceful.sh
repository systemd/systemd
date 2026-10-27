#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Simulate a kernel without a usable console by overmounting the list of active consoles. This needs a VM: in
# containers, /dev/console is a pty and /sys is read-only, so the active consoles are never looked at.
ACTIVE="$(mktemp)"

at_exit() {
    if findmnt /sys/class/tty/console/active >/dev/null; then
        umount /sys/class/tty/console/active
    fi
    rm -f "$ACTIVE" /run/systemd/system/tty-graceful-deps.service
    systemctl daemon-reload
}

trap at_exit EXIT

# The fallback needs the journal
cat >/run/systemd/system/tty-graceful-deps.service <<EOF
[Service]
StandardInput=tty-graceful
ExecStart=true
EOF
systemctl daemon-reload
assert_in systemd-journald.socket "$(systemctl show -P After tty-graceful-deps.service)"

for console in none ttynull; do
    if [[ "$console" == none ]]; then
        : >"$ACTIVE"
    else
        echo "$console" >"$ACTIVE"
    fi
    mount --bind "$ACTIVE" /sys/class/tty/console/active

    # stdin falls back to /dev/null, stdout and stderr to the journal; both with their default "inherit",
    # and when explicitly set to "tty". TTYReset=yes would write ANSI sequences to a TTY, but must not
    # write them into the journal.
    for output in inherit tty; do
        unit="tty-graceful-$console-$output"
        systemd-run --wait --unit="$unit" -p TTYReset=yes \
                    -p StandardInput=tty-graceful -p StandardOutput="$output" -p StandardError="$output" \
                    bash -exc 'test "$(readlink /proc/self/fd/0)" = /dev/null; echo "stdout-$0"; echo "stderr-$0" >&2' "$unit"
        journalctl --sync
        journalctl -u "$unit" --grep "^stdout-$unit\$"
        journalctl -u "$unit" --grep "^stderr-$unit\$"
        [[ "$(journalctl -u "$unit" -o cat --all)" != *$'\e'* ]]
    done

    # An explicitly configured TTYPath= is expected to exist
    unit="tty-graceful-$console-ttypath"
    (! systemd-run --wait --unit="$unit" -p StandardInput=tty-graceful -p TTYPath=/dev/nonexistent-tty true)
    assert_eq "$(systemctl show -P ExecMainStatus "$unit")" 208
    systemctl reset-failed "$unit"

    umount /sys/class/tty/console/active
done
