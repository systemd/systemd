#!/usr/bin/env bash
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
            journalctl -n 1 -q -u systemd-udevd.service --invocation=0 --grep "Found inotify watch .*$ID_OR_HANDLE"
        fi
    done
}

function check() {
    for _ in {1..2}; do
        systemctl reset-failed systemd-udevd.service
        systemctl restart systemd-udevd.service
        udevadm settle --timeout=30

        journalctl --sync
        # Also rotate journal to make expected journal entries in an archived journal file.
        journalctl --rotate

        # Check if the inotify watch fd is received from fd store.
        journalctl -n 1 -q -u systemd-udevd.service --invocation=0 --grep 'Received inotify fd \(\d+\) from service manager.'

        # Check if there is no broken symlink chain.
        assert_eq "$(journalctl -n 1 -q -u systemd-udevd.service --invocation=0 --grep 'Found broken inotify watch' || :)" ""

        check_validity 1

        for _ in {1..2}; do
            udevadm trigger -w --action add --subsystem-match=block
            check_validity
        done

        for _ in {1..2}; do
            udevadm trigger -w --action change --subsystem-match=block
            check_validity
        done
    done
}

# Check if the first invocation (should be in initrd) pushed the inotify fd to fdstore,
# and the next invocation gained the fd from service manager.
# TNote the service may be started without generating debugging logs. Let's check failure log.
if ! journalctl -n 1 -q -u systemd-udevd.service --invocation=1 --grep 'Pushed inotify fd to service manager.'; then
    assert_eq "$(journalctl -n 1 -q -u systemd-udevd.service --invocation=1 --grep 'Failed to push inotify fd to service manager.' || :)" ""
fi
if ! journalctl -n 1 -q -u systemd-udevd.service --invocation=2 --grep 'Received inotify fd \(\d+\) from service manager.'; then
    assert_eq "$(journalctl -n 1 -q -u systemd-udevd.service --invocation=2 --grep 'Pushed inotify fd to service manager.' || :)" ""
fi

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

# Unfortunately, journalctl --invocation= is unstable when debug logging is enabled on service manager.
SAVED_LOG_LEVEL=$(systemctl log-level)
systemctl log-level info

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

systemctl log-level "$SAVED_LOG_LEVEL"

exit 0
