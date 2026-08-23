#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="mem", KERNEL=="null", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", IMPORT{program}="/usr/bin/echo -e HOGE=aa\\\\x20\\\\x20\\\\x20bb\nFOO=\\\\x20aaa\\\\x20\n\n\n"
EOF

udevadm control --reload
SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --settle --action add /dev/null

test -f /run/udev/data/c1:3
udevadm info /dev/null | grep 'E: HOGE=aa\\x20\\x20\\x20bb' >/dev/null
udevadm info /dev/null | grep 'E: FOO=\\x20aaa\\x20' >/dev/null

cat >/run/udev/rules.d/50-testsuite.rules <<'EOF'
SUBSYSTEM=="mem", KERNEL=="null", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", IMPORT{program}="/bin/sh -c 'printf \"TRUNCATED_OK=yes\nTRUNCATED_BAD=\"; i=0; while [ \"$i\" -lt 20000 ]; do printf A; i=$((i + 1)); done'"
EOF

udevadm control --reload
SYSTEMD_LOG_LEVEL=debug udevadm trigger --verbose --settle --action add /dev/null

udevadm info /dev/null | grep 'E: TRUNCATED_OK=yes' >/dev/null
(! udevadm info /dev/null | grep 'E: TRUNCATED_BAD=' >/dev/null)

rm /run/udev/rules.d/50-testsuite.rules
udevadm control --reload

exit 0
