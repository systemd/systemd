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

journalctl --sync
timeout 30 bash -c "until journalctl -b -u prefix-shell.service --grep 'with login shell .*: lvl 101'; do sleep 0.5; done"
timeout 30 bash -c "until journalctl -b -u prefix-shell.service --grep 'with normal shell'; do sleep 0.5; done"
