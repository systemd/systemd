#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemctl start prefix-shell.service
journalctl --sync

journalctl -b -u prefix-shell.service | grep "with login shell: .*" | grep "lvl: 101"
journalctl -b -u prefix-shell.service | grep "with normal shell baz"
assert_eq "$(cat /tmp/TEST-07-PID1.prefix-shell.flag)" "YAY!"
