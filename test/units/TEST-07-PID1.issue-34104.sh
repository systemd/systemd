#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-run -u test-sleep.service sleep 1h
SLEEP_PID=$(systemctl show test-sleep.service -p ExecMainPID --value)
SLEEP_OBJECT=$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnitByPID "u" "$SLEEP_PID")
assert_eq "$SLEEP_OBJECT" "o \"/org/freedesktop/systemd1/unit/test_2dsleep_2eservice\""
systemctl stop test-sleep.service

# For https://github.com/systemd/systemd/issues/34104
for ((i = 10000; i < 11000; i++)); do
    busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnitByPID "u" "$i" || :
done

exit 0
