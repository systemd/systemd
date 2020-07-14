#!/usr/bin/env bash
set -ex
set -o pipefail

>/failed

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

# Check timestamp from `systemd-analyze dump` output.
userspace_time=$(systemd-analyze dump | sed -ne 's/^Timestamp userspace: //p')
userspace_time=$(date -d "${userspace_time}" +%s)
time_delta=$((now - userspace_time))

# Check that the timestamp from `systemd-analyze dump` is at most
# 5 minutes in the past.
((0 < time_delta && time_delta < 300)) || {
    echo '`systemd-analyze dump` output outside of the expected 5 minute window.'
    echo "  userspace_time=${userspace_time}"
    echo "  now=${now}"
    echo "  time_delta=${time_delta}"
    echo ''
} >>/failed

# Check timestamp from the UserspaceTimestamp property of the
# org.freedesktop.systemd1.Manager D-Bus instance.
dbus_time=$(
    busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager UserspaceTimestamp |
    awk '{print int($2/1000000)}'
)
time_delta=$((now - dbus_time))

# Check that the timestamp from the UserspaceTimestamp property
# is at most 5 minutes in the past.
((0 < time_delta && time_delta < 300)) || {
    echo 'D-Bus UserspaceTimestamp property outside of the expected 5 minute window.'
    echo "  dbus_time=${dbus_time}"
    echo "  now=${now}"
    echo "  time_delta=${time_delta}"
    echo ''
} >>/failed

if test ! -s /failed ; then
    rm -f /failed
    touch /testok
fi
