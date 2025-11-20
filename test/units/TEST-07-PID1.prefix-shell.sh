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

# If the service exits too early, journald cannot find the source process of the log message.
# Hence, we cannot use 'journalctl -u' below. Instead, let's use --since=.
journalctl --sync
TS="$(date '+%H:%M:%S')"

systemctl start prefix-shell.service
assert_eq "$(cat /tmp/TEST-07-PID1.prefix-shell.flag)" "YAY!"

journalctl --sync
journalctl --since "$TS" --grep "with login shell .*: lvl 101"
journalctl --since "$TS" --grep "with normal shell"
