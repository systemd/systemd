#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

# Reset host date to current time, 3 days in the past.
date -s "-3 days"

# Run a timer for every 15 minutes.
systemd-run --unit test-timer --on-calendar "*:0/15:0" true

next_elapsed=$(systemctl show test-timer.timer -p NextElapseUSecRealtime --value)
next_elapsed=$(date -d "${next_elapsed}" +%s)
now=$(date +%s)
time_delta=$((next_elapsed - now))

# Check that the timer will elapse in less than 20 minutes.
((0 < time_delta && time_delta < 1200)) || {
    echo 'Timer elapse outside of the expected 20 minute window.'
    echo "  next_elapsed=${next_elapsed}"
    echo "  now=${now}"
    echo "  time_delta=${time_delta}"
    echo ''
} >>/failed

if test ! -s /failed ; then
    rm -f /failed
    touch /testok
fi
