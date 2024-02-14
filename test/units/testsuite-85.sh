#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

if systemd-detect-virt --quiet --container; then
    echo "Running on a container, skipping."
    touch /skipped
    exit 0
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

: >/failed

# Check that we're the ones to receive coredumps
sysctl kernel.core_pattern | grep systemd-coredump

mkdir -p /run/systemd/coredump.conf.d/
printf '[Coredump]\nStorage=external' >/run/systemd/coredump.conf.d/99-external.conf

ulimit -c unlimited
systemctl start coredumping.service
sleep 1

killall --verbose -s ABRT sleep
sleep 1
killall --verbose -s ABRT sleep
sleep 1
killall --verbose -s ABRT sleep
sleep 1
killall --verbose -s ABRT sleep
sleep 1
killall --verbose -s ABRT sleep
sleep 1

assert_le "$(ls /var/lib/systemd/coredump | wc -l)" "3"

sleep 10
killall --verbose -s ABRT sleep
sleep 10
killall --verbose -s ABRT sleep
sleep 10
killall --verbose -s ABRT sleep
sleep 10
killall --verbose -s ABRT sleep
sleep 10
killall --verbose -s ABRT sleep
sleep 2

assert_le "$(ls /var/lib/systemd/coredump | wc -l)" "5"

systemctl stop coredumping.service
rm -f /run/systemd/coredump.conf.d/99-external.conf /var/lib/systemd/coredump/*

touch /testok
rm /failed