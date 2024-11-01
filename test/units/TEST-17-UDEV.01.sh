#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

ROOTDEV="$(bootctl -RR)"

rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload
udevadm trigger --settle "$ROOTDEV"

while : ; do
    (
        udevadm info "$ROOTDEV" | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info "$ROOTDEV" | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v "${ROOTDEV#/dev/}"
        systemctl show -p WantedBy waldo.service | grep -q -v "${ROOTDEV#/dev/}"
    ) && break

    sleep .5
done

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="block", KERNEL=="${ROOTDEV#/dev/}", OPTIONS="log_level=debug"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${ROOTDEV#/dev/}", ENV{SYSTEMD_WANTS}="foobar.service"
EOF
udevadm control --reload
udevadm trigger --settle "$ROOTDEV"

while : ; do
    (
        udevadm info "$ROOTDEV" | grep -q SYSTEMD_WANTS=foobar.service
        udevadm info "$ROOTDEV" | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q "${ROOTDEV#/dev/}"
        systemctl show -p WantedBy waldo.service | grep -q -v "${ROOTDEV#/dev/}"
    ) && break

    sleep .5
done

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="block", KERNEL=="${ROOTDEV#/dev/}", OPTIONS="log_level=debug"
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="${ROOTDEV#/dev/}", ENV{SYSTEMD_WANTS}="waldo.service"
EOF
udevadm control --reload
udevadm trigger --settle "$ROOTDEV"

while : ; do
    (
        udevadm info "$ROOTDEV" | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info "$ROOTDEV" | grep -q SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v "${ROOTDEV#/dev/}"
        systemctl show -p WantedBy waldo.service | grep -q "${ROOTDEV#/dev/}"
    ) && break

    sleep .5
done

rm /run/udev/rules.d/50-testsuite.rules

udevadm control --reload
udevadm trigger --settle "$ROOTDEV"

while : ; do
    (
        udevadm info "$ROOTDEV" | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info "$ROOTDEV" | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v "${ROOTDEV#/dev/}"
        systemctl show -p WantedBy waldo.service | grep -q -v "${ROOTDEV#/dev/}"
    ) && break

    sleep .5
done

exit 0
