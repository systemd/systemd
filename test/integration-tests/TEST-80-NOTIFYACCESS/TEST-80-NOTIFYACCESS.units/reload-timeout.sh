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
    local notify="${1:?}"
    local p

    sleep infinity &
    p=$!

    # Notify readiness after 'sleep' is running to avoid race
    # condition where the SIGHUP is sent before 'sleep' is ready to
    # receive it and we get stuck
    if [ "$notify" -eq 1 ]; then
        systemd-notify --ready
    fi

    wait "$p" || :
}

sighup_handler() {
    echo "hup$(( ++COUNTER ))" >/tmp/syncfifo1
}

trap sighup_handler SIGHUP

export SYSTEMD_LOG_LEVEL=debug

wait_for_signal 1
systemd-notify --reloading

wait_for_signal 0
systemd-notify --reloading
sync_in ready

wait_for_signal 1
systemd-notify --reloading --ready

exec sleep infinity
