#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

COUNTER=0

sync_in() {
    read -r x < /tmp/syncfifo2
    test "$x" = "$1"
}

wait_for_signal() {
    sleep infinity &
    wait "$!" || :
}

sighup_handler() {
    echo "hup$(( ++COUNTER ))" > /tmp/syncfifo1
}

trap sighup_handler SIGHUP

export SYSTEMD_LOG_LEVEL=debug

systemd-notify --ready

wait_for_signal
systemd-notify --reloading

wait_for_signal
systemd-notify --reloading
sync_in ready
systemd-notify --ready

wait_for_signal
systemd-notify --reloading --ready

exec sleep infinity
