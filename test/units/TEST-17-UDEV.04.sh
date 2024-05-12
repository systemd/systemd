#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

test ! -f /run/udev/tags/added/c1:3
test ! -f /run/udev/tags/changed/c1:3
udevadm info /dev/null | grep -E 'E: (TAGS|CURRENT_TAGS)=.*:(added|changed):' && exit 1

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="mem", KERNEL=="null", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", TAG+="added"
ACTION=="change", SUBSYSTEM=="mem", KERNEL=="null", TAG+="changed"
EOF

udevadm control --reload
SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --settle --action add /dev/null

test -f /run/udev/tags/added/c1:3
test ! -f /run/udev/tags/changed/c1:3
udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*'
udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*'
udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*' && { echo 'unexpected TAGS='; exit 1; }
udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*' && { echo 'unexpected CURRENT_TAGS='; exit 1; }

SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --settle --action change /dev/null

test -f /run/udev/tags/added/c1:3
test -f /run/udev/tags/changed/c1:3
udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*'
udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*' && { echo 'unexpected CURRENT_TAGS='; exit 1; }
udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*'
udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*'

SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --settle --action add /dev/null

test -f /run/udev/tags/added/c1:3
test -f /run/udev/tags/changed/c1:3
udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*'
udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*'
udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*'
udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*' && { echo 'unexpected CURRENT_TAGS='; exit 1; }

rm /run/udev/rules.d/50-testsuite.rules
udevadm control --reload

exit 0
