#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

# Run a timer for every 15 minutes before setting the current time
systemd-run --unit test-timer-1 --on-calendar "*:0/15:0" true

# Reset host date to current time, 3 days in the past.
date -s "-3 days"

# Run another timer for every 15 minutes, after setting the time
systemd-run --unit test-timer-2 --on-calendar "*:0/15:0" true

next_elapsed_t1=$(systemctl show test-timer-1.timer -p NextElapseUSecRealtime --value)
next_elapsed_t1=$(date -d "${next_elapsed_t1}" +%s)
now=$(date +%s)
time_delta_t1=$((next_elapsed_t1 - now))

next_elapsed_t2=$(systemctl show test-timer-2.timer -p NextElapseUSecRealtime --value)
next_elapsed_t2=$(date -d "${next_elapsed_t2}" +%s)
now=$(date +%s)
time_delta_t2=$((next_elapsed_t2 - now))

# Check that the timer will elapse in less than 20 minutes.
((0 < time_delta_t1 && time_delta_t1 < 1200)) || {
    echo 'Timer elapse outside of the expected 20 minute window.'
    echo "  next_elapsed_t1=${next_elapsed_t1}"
    echo "  now=${now}"
    echo "  time_delta_t1=${time_delta_t1}"
    echo ''
} >>/failed_t1

# Check that the timer will elapse in less than 20 minutes.
((0 < time_delta_t2 && time_delta_t2 < 1200)) || {
    echo 'Timer elapse outside of the expected 20 minute window.'
    echo "  next_elapsed_t2=${next_elapsed_t2}"
    echo "  now=${now}"
    echo "  time_delta_t2=${time_delta_t2}"
    echo ''
} >>/failed_t2

if test ! -s /failed_t1 && test ! -s /failed_t2; then
    rm -f /failed_t*
    touch /testok
fi
