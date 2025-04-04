#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# tests for udev watch

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

function check_validity() {
    local f ID_OR_HANDLE

    for f in /run/udev/watch/*; do
        ID_OR_HANDLE="$(readlink "$f")"
        test -L "/run/udev/watch/${ID_OR_HANDLE}"
        test "$(readlink "/run/udev/watch/${ID_OR_HANDLE}")" = "$(basename "$f")"

        if [[ "${1:-}" == "1" ]]; then
            journalctl -n 1 -q -I -u systemd-udevd.service --grep "Found inotify watch .*$ID_OR_HANDLE"
        fi
    done
}

function check() {
    for _ in {1..2}; do
        systemctl reset-failed systemd-udevd.service
        systemctl restart systemd-udevd.service
        udevadm control --ping --log-level=debug --timeout=30
        udevadm settle --timeout=30

        journalctl --sync

        # systemd-udevd checks validity of inotify watch symlinks on start and stop.
        assert_eq "$(journalctl -q --invocation -1 -u systemd-udevd.service --grep 'Found broken inotify watch' || :)" ""
        assert_eq "$(journalctl -q --invocation  0 -u systemd-udevd.service --grep 'Found broken inotify watch' || :)" ""

        # Also check if the inotify watch fd is pushed on stop, and received on start.
        journalctl -n 1 -q --invocation -1 -u systemd-udevd.service --grep "Pushed inotify file descriptor to service manager."
        journalctl -n 1 -q --invocation  0 -u systemd-udevd.service --grep "Received inotify fd \(\d\) from service manager."

        check_validity 1

        for _ in {1..2}; do
            udevadm trigger -w --action add --subsystem-match=block --settle
            check_validity
        done

        for _ in {1..2}; do
            udevadm trigger -w --action change --subsystem-match=block --settle
            check_validity
        done
    done
}

mkdir -p /run/systemd/system/systemd-udevd.service.d/
cat >/run/systemd/system/systemd-udevd.service.d/10-debug.conf <<EOF
[Service]
SYSTEMD_LOG_LEVEL=debug
EOF

systemctl daemon-reload

mkdir -p /run/udev/rules.d/

cat >/run/udev/rules.d/00-debug.rules <<EOF
SUBSYSTEM=="block", KERNEL=="sda*", OPTIONS="log_level=debug"
EOF

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="watch"
EOF

# To make the previous invocation of systemd-udevd generates debugging logs on stop,
# that will be checked by check().
udevadm control --log-level debug

check

ROOTDEV="$(bootctl -RR)"

MAJOR="$(udevadm info "$ROOTDEV" | grep -e '^E: MAJOR=' | sed -e 's/^E: MAJOR=//')"
MINOR="$(udevadm info "$ROOTDEV" | grep -e '^E: MINOR=' | sed -e 's/^E: MINOR=//')"
test -L "/run/udev/watch/b${MAJOR}:${MINOR}"

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="nowatch"
EOF

check

MAJOR="$(udevadm info "$ROOTDEV" | grep -e '^E: MAJOR=' | sed -e 's/^E: MAJOR=//')"
MINOR="$(udevadm info "$ROOTDEV" | grep -e '^E: MINOR=' | sed -e 's/^E: MINOR=//')"
test ! -e "/run/udev/watch/b${MAJOR}:${MINOR}"

rm /run/udev/rules.d/00-debug.rules
rm /run/udev/rules.d/50-testsuite.rules
udevadm control --reload

rm -f /run/systemd/system/systemd-udevd.service.d/10-debug.conf
systemctl daemon-reload

exit 0
