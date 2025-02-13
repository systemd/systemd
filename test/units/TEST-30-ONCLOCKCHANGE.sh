#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug

systemctl disable --now systemd-timesyncd.service

timedatectl set-timezone Europe/Berlin

# A future timestamp needs to be used, otherwise 'timedatectl set-time' fails
# if a timestamp older than the TIME_EPOCH is specified.
current_time=$(date)

future_time=$(date -d "$current_time + 1 year" +"%Y-%m-%d %H:%M:%S")

timedatectl set-time "$future_time"

systemd-run --on-timezone-change touch /tmp/timezone-changed
systemd-run --on-clock-change touch /tmp/clock-changed

test ! -f /tmp/timezone-changed
test ! -f /tmp/clock-changed

timedatectl set-timezone Europe/Kyiv

while test ! -f /tmp/timezone-changed ; do sleep .5 ; done

future_time=$(date -d "$current_time + 1 year + 1 month" +"%Y-%m-%d %H:%M:%S")

timedatectl set-time "$future_time"

while test ! -f /tmp/clock-changed ; do sleep .5 ; done

systemd-analyze log-level info

touch /testok
