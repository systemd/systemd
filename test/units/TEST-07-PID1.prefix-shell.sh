#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-run --wait --uid=nobody \
            -p ExecStartPre="|true" \
            -p ExecStartPre="|@echo a >/tmp/TEST-07-PID1.prefix-shell.flag" \
            true
assert_eq "$(cat /tmp/TEST-07-PID1.prefix-shell.flag)" "a"
rm /tmp/TEST-07-PID1.prefix-shell.flag

systemctl start prefix-shell.service
assert_eq "$(cat /tmp/TEST-07-PID1.prefix-shell.flag)" "YAY!"

# Ensure journal entries are fully written and available for reading
# Multiple sync attempts to handle potential timing issues
journalctl --sync
journalctl --sync
sleep 0.1
journalctl --sync

# Verify journal entries are available with proper error handling
if ! journalctl -b -u prefix-shell.service --grep "with login shell .*: lvl 101" >/dev/null 2>&1; then
    echo "ERROR: Expected journal entry 'with login shell' not found"
    journalctl -b -u prefix-shell.service --no-pager || true
    exit 1
fi

if ! journalctl -b -u prefix-shell.service --grep "with normal shell" >/dev/null 2>&1; then
    echo "ERROR: Expected journal entry 'with normal shell' not found"
    journalctl -b -u prefix-shell.service --no-pager || true
    exit 1
fi

# Final verification that both patterns are found
journalctl -b -u prefix-shell.service --grep "with login shell .*: lvl 101"
journalctl -b -u prefix-shell.service --grep "with normal shell"
