#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# tests for udev watch

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

check() {
    for _ in {1..2}; do
        systemctl reset-failed systemd-udevd.service
        systemctl restart systemd-udevd.service
        udevadm settle --timeout=30

        journalctl --sync
        # Also rotate journal to make expected journal entries in an archived journal file.
        journalctl --rotate

        # Check if the fanotify group fd is received from fd store.
        journalctl -n 1 -q -u systemd-udevd.service --invocation=0 --grep 'Received fanotify fd \(\d+\) from service manager.'

        for _ in {1..2}; do
            udevadm trigger -w --action add --subsystem-match=block
        done

        for _ in {1..2}; do
            udevadm trigger -w --action change --subsystem-match=block
        done
    done
}

udevd_fanotify_fdinfo() {
    local pid fd

    # Print the path of systemd-udevd's fanotify group fdinfo.

    pid="$(systemctl show --property MainPID --value systemd-udevd.service)"
    [[ "${pid:-0}" -gt 0 ]] || return 1

    for fd in /proc/"$pid"/fd/*; do
        if [[ "$(readlink "$fd" 2>/dev/null)" == "anon_inode:[fanotify]" ]]; then
            echo "/proc/$pid/fdinfo/${fd##*/}"
            return 0
        fi
    done

    return 1
}

device_is_watched() {
    local devnode="${1:?}"
    local ino fdinfo

    fdinfo="$(udevd_fanotify_fdinfo)" || exit 1
    ino="$(printf '%x' "$(stat -c '%i' "$devnode")")"
    grep -qE "^fanotify ino:${ino} " "$fdinfo"
}

reinitialize_udevd() {
    # Force systemd-udevd to create a fresh fanotify group. The group is kept across restarts in the
    # fd store, so it must be dropped first; otherwise a changed $SYSTEMD_UDEV_USE_FANOTIFY_FID does
    # not take effect.
    systemctl daemon-reload
    systemctl stop systemd-udevd-kernel.socket systemd-udevd-varlink.socket
    systemctl stop systemd-udevd.service
    systemctl clean systemd-udevd.service --what=fdstore
    systemctl start systemd-udevd-kernel.socket systemd-udevd-varlink.socket
    systemctl start systemd-udevd.service
}

# Check if the first invocation (should be in initrd) pushed the fanotify fd to fdstore,
# and the next invocation gained the fd from service manager.
# TNote the service may be started without generating debugging logs. Let's check failure log.
if ! journalctl -n 1 -q -u systemd-udevd.service --invocation=1 --grep 'Pushed fanotify fd to service manager.'; then
    assert_eq "$(journalctl -n 1 -q -u systemd-udevd.service --invocation=1 --grep 'Failed to push fanotify fd to service manager.' || :)" ""
fi
if ! journalctl -n 1 -q -u systemd-udevd.service --invocation=2 --grep 'Received fanotify fd \(\d+\) from service manager.'; then
    assert_eq "$(journalctl -n 1 -q -u systemd-udevd.service --invocation=2 --grep 'Pushed fanotify fd to service manager.' || :)" ""
fi

mkdir -p /run/systemd/system/systemd-udevd.service.d/
cat >/run/systemd/system/systemd-udevd.service.d/10-debug.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

systemctl daemon-reload

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

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="nowatch"
EOF

check

(! device_is_watched "$ROOTDEV")

# Repeat the checks in classic (non-FID) fanotify mode.
cat >/run/systemd/system/systemd-udevd.service.d/20-classic-fanotify.conf <<EOF
[Service]
Environment=SYSTEMD_UDEV_USE_FANOTIFY_FID=0
EOF
reinitialize_udevd

journalctl --sync
journalctl --rotate
# The new group must have been created in classic mode.
journalctl -q -u systemd-udevd.service --invocation=0 --grep 'Initialized new fanotify group \(classic mode\).'

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="watch"
EOF
udevadm control --reload
udevadm trigger -w --action add --subsystem-match=block
device_is_watched "$ROOTDEV"

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="nowatch"
EOF
udevadm control --reload
udevadm trigger -w --action change --subsystem-match=block
(! device_is_watched "$ROOTDEV")

# Cleanup
rm /run/udev/rules.d/00-debug.rules
rm /run/udev/rules.d/50-testsuite.rules

rm -f /run/systemd/system/systemd-udevd.service.d/10-debug.conf
rm -f /run/systemd/system/systemd-udevd.service.d/20-classic-fanotify.conf
reinitialize_udevd

systemctl log-level "$SAVED_LOG_LEVEL"

exit 0
