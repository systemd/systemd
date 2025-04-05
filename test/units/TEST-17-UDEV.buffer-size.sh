#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# This is a test for issue #24987.

mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM!="mem", GOTO="test-end"
KERNEL!="null", GOTO="test-end"
ACTION=="remove", GOTO="test-end"

# add 100 * 100byte of properties
$(for i in {1..100}; do printf 'ENV{XXX%03i}="0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"\n' "$i"; done)

LABEL="test-end"
EOF

udevadm control --reload

TMPDIR=$(mktemp -d -p /tmp udev-tests.XXXXXX)
SYSTEMD_LOG_LEVEL=debug udevadm monitor --udev --property --subsystem-match=mem >"$TMPDIR"/monitor.txt 2>&1 &
KILL_PID="$!"

FOUND=
for _ in {1..40}; do
    if grep -F 'UDEV - the event which udev sends out after rule processing' "$TMPDIR"/monitor.txt; then
        FOUND=1
        break
    fi
    sleep .5
done
[[ -n "$FOUND" ]]

udevadm trigger --verbose --settle --action add /dev/null

FOUND=
for _ in {1..40}; do
    if ! grep -e 'UDEV *\[[0-9.]*\] *add *\/devices\/virtual\/mem\/null (mem)' "$TMPDIR"/monitor.txt; then
        sleep .5
        continue
    fi

    FOUND=1
    for i in {1..100}; do
        if ! grep -F "$(printf 'XXX%03i=0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' "$i")" "$TMPDIR"/monitor.txt; then
            FOUND=
            break
        fi
    done
    if [[ -n "$FOUND" ]]; then
        break;
    fi

    sleep .5
done
[[ -n "$FOUND" ]]

# cleanup
rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload

kill "$KILL_PID"
rm -rf "$TMPDIR"

exit 0
