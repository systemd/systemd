#!/usr/bin/env bash

set -ex

if [ -f /tmp/testsuite-57.counter ] ; then
    read -r counter < /tmp/testsuite-57.counter
    counter=$(("$counter" + 1))
else
    counter=0
fi

echo "$counter" > /tmp/testsuite-57.counter

if [ "$counter" -eq 5 ] ; then
    systemctl kill --kill-who=main -sUSR1 testsuite-57.service
fi

exec sleep 1.5
