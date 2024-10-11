#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl start realtime-test.timer

sleep 35
mindelta=10

last=
while read -r time; do
    if [ -n "$last" ]; then
        delta=$((time - last))
        if [ "$delta" -lt $mindelta ]; then
            echo "Timer fired too early: $delta < $mindelta" >/failed
            break
        fi
    fi
    last=$time
done </tmp/realtime-test.log

test ! -s /failed
