#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# tests for udev watch

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

check_validity() {
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

check() {
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

udevd_inotify_fdinfo() {
    local pid fd

    # Print the path of systemd-udevd's inotify group fdinfo.

    pid="$(systemctl show --property MainPID --value systemd-udevd.service)"
    [[ "${pid:-0}" -gt 0 ]] || return 1

    for fd in /proc/"$pid"/fd/*; do
        if [[ "$(readlink "$fd" 2>/dev/null)" == "anon_inode:inotify" ]]; then
            echo "/proc/$pid/fdinfo/${fd##*/}"
            return 0
        fi
    done

    return 1
}

device_is_watched() {
    local devnode="${1:?}"
    local ino fdinfo

    fdinfo="$(udevd_inotify_fdinfo)" || exit 1
    ino="$(printf '%x' "$(stat -c '%i' "$devnode")")"
    grep -qE "^inotify wd:[0-9a-f]+ ino:${ino} " "$fdinfo"
}

device_is_watched_by_link() {
    local devnode="${1:?}"
    local id

    id="$(udevadm info "$devnode" | awk '$1 == "J:" { print $2 }')"
    test -L "/run/udev/watch/${id}"
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
Environment=SYSTEMD_LOG_LEVEL=debug
Environment=SYSTEMD_UDEV_USE_INOTIFY=1
EOF

systemctl daemon-reload
systemctl restart systemd-udevd.service

udevadm trigger -w --action change --subsystem-match=block

mkdir -p /run/udev/rules.d/

ROOTDEV="$(bootctl -RR)"
ROOTDEV_NAME="$(udevadm info --query=name "$ROOTDEV")"

cat >/run/udev/rules.d/00-debug.rules <<EOF
SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}*", OPTIONS="log_level=debug"
EOF

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="watch"
EOF

# Unfortunately, journalctl --invocation= is unstable when debug logging is enabled on service manager.
SAVED_LOG_LEVEL=$(systemctl log-level)
systemctl log-level info

check

device_is_watched "$ROOTDEV"
device_is_watched_by_link "$ROOTDEV"

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="nowatch"
EOF

check

(! device_is_watched "$ROOTDEV")
(! device_is_watched_by_link "$ROOTDEV")

rm /run/udev/rules.d/00-debug.rules
rm /run/udev/rules.d/50-testsuite.rules

rm -f /run/systemd/system/systemd-udevd.service.d/10-debug.conf
systemctl daemon-reload
systemctl restart systemd-udevd.service

udevadm trigger -w --action change --subsystem-match=block

systemctl log-level "$SAVED_LOG_LEVEL"

exit 0
