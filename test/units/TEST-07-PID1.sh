#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# Issue: https://github.com/systemd/systemd/issues/2730
# See TEST-07-PID1/test.sh for the first "half" of the test
mountpoint /issue2730

# Verify that a per-device terminal type is applied when /dev/console is backed by a serial TTY.
assert_eq "$(cat /sys/class/tty/console/active)" ttyS0

TERM_FILE=/run/TEST-07-PID1-console-term
systemd-run --wait \
        --unit=TEST-07-PID1-console-term.service \
        -p TTYPath=/dev/console \
        -p StandardInput=tty \
        -p StandardOutput=null \
        -p StandardError=null \
        /bin/sh -c 'printf "%s" "$TERM" >/run/TEST-07-PID1-console-term'
assert_eq "$(cat "$TERM_FILE")" linux

rm -f "$TERM_FILE"

run_subtests

touch /testok
systemctl --no-block exit 123
