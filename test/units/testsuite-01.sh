#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

STTY_ORIGINAL="$(stty --file=/dev/console --save)"

at_exit() {
    set +e
    stty --file=/dev/console "${STTY_ORIGINAL:?}"
}

trap at_exit EXIT

# Do one reexec beforehand to get /dev/console into some predictable state
systemctl daemon-reexec

# Check if we do skip the early setup when doing daemon-reexec
# See: https://github.com/systemd/systemd/issues/27106
#
# Change a couple of console settings, do a reexec, and then check if our
# changes persisted, since we reset the terminal stuff only on "full" reexec
#
# Relevant function: reset_terminal_fd() from terminal-util.cs
stty --file=/dev/console brkint igncr inlcr istrip iuclc -icrnl -imaxbel -iutf8 \
     kill ^K quit ^I
STTY_NEW="$(stty --file=/dev/console --save)"
systemctl daemon-reexec
diff <(echo "$STTY_NEW") <(stty --file=/dev/console --save)

if ! systemd-detect-virt -qc; then
    # We also disable coredumps when doing a "full" reexec, so check for that too
    sysctl -w kernel.core_pattern=dont-overwrite-me
    systemctl daemon-reexec
    diff <(echo dont-overwrite-me) <(sysctl --values kernel.core_pattern)
fi

# Collect failed units & do one daemon-reload to a basic sanity check
systemctl --state=failed --no-legend --no-pager | tee /failed
systemctl daemon-reload

echo OK >/testok
