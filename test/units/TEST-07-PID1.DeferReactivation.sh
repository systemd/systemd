#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemctl start defer-reactivation.timer

timeout 20 bash -c 'until [[ -e /tmp/defer-reactivation.log ]]; do sleep .5; done'
timeout 60 bash -c 'until (( $(cat /tmp/defer-reactivation.log | wc -l) >= 3 )); do sleep 5; done'

systemctl stop defer-reactivation.timer

# If the 'date' command is the service called instantaneously when the timer is triggered, each time delta
# must be 10 seconds. But in a realistic situation, the command is slightly delayed after the timer is
# triggered, and the delay has some fluctuations. If a trigger event calls the command at 00:00:01.01, and
# the next event does at 00:00:10.99, the delta is calculated as 9 seconds. So, let's accept 9 here.
mindelta=9

last=
while read -r time; do
    if [[ -n "$last" ]]; then
        delta=$(( time - last ))
        if (( delta < mindelta )); then
            echo "Timer fired too early: $delta < $mindelta" >/failed
            exit 1
        fi
    fi
    last=$time
done </tmp/defer-reactivation.log
