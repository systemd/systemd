#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

if [ -f /tmp/TEST-23-UNIT-FILE.counter ] ; then
    read -r counter < /tmp/TEST-23-UNIT-FILE.counter
    counter=$((counter + 1))
else
    counter=0
fi

echo "$counter" >/tmp/TEST-23-UNIT-FILE.counter

if [ "$counter" -eq 5 ] ; then
    systemctl kill --kill-whom=main -sUSR1 TEST-23-UNIT-FILE.service
fi

exec sleep 1.5
