#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug

systemctl disable --now systemd-timesyncd.service

timedatectl set-timezone Europe/Berlin
timedatectl set-time 1980-10-15

systemd-run --on-timezone-change touch /tmp/timezone-changed
systemd-run --on-clock-change touch /tmp/clock-changed

test ! -f /tmp/timezone-changed
test ! -f /tmp/clock-changed

timedatectl set-timezone Europe/Kyiv

# Get current time and add a future offset (e.g., 1 year and 1 month ahead)
# Using date to calculate the future timestamp

current_time=$(date)
future_time=$(date -d "$current_time + 1 year + 1 month" +"%Y-%m-%d %H:%M:%S")

# Set system time to the calculated future time
timedatectl set-time "$future_time"

while test ! -f /tmp/timezone-changed ; do sleep .5 ; done

systemd-analyze log-level info

touch /testok
