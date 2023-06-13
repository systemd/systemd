#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-analyze log-level debug

systemctl disable --now systemd-timesyncd.service

timedatectl set-timezone Europe/Berlin
timedatectl set-time 1980-10-15

systemd-run --on-timezone-change touch /tmp/timezone-changed
systemd-run --on-clock-change touch /tmp/clock-changed

test ! -f /tmp/timezone-changed
test ! -f /tmp/clock-changed

timedatectl set-timezone Europe/Kiev

wait_for_file /tmp/timezone-changed

timedatectl set-time 2018-1-1

wait_for_file /tmp/clock-changed

systemd-analyze log-level info

echo OK >/testok

exit 0
