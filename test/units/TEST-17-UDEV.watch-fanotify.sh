#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# tests for udev watch

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

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

ROOTDEV="$(bootctl -RR)"
ROOTDEV_NAME="$(udevadm info --query=name "$ROOTDEV")"

mkdir -p /run/udev/rules.d/

cat >/run/udev/rules.d/99-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="nowatch"
EOF

udevadm control --reload
udevadm trigger --action change --settle "$ROOTDEV"
(! device_is_watched "$ROOTDEV")

cat >/run/udev/rules.d/99-testsuite.rules <<EOF
ACTION=="change", SUBSYSTEM=="block", KERNEL=="${ROOTDEV_NAME}", OPTIONS:="watch"
EOF

udevadm control --reload
udevadm trigger --action change --settle "$ROOTDEV"
device_is_watched "$ROOTDEV"

rm /run/udev/rules.d/99-testsuite.rules
udevadm control --reload

exit 0
