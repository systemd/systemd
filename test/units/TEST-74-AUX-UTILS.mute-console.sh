#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-mute-console >/dev/null; then
    echo "systemd-mute-console is not installed, skipping the test"
    exit 77
fi

# Kernel output is only muted outside of containers, so only check the console log level there.
if systemd-detect-virt --quiet --container; then
    IN_CONTAINER=1
else
    IN_CONTAINER=0
fi

# Unmuting happens asynchronously after the client went away, hence poll.
wait_printk_level() {
    local level _

    if (( IN_CONTAINER )); then
        return 0
    fi

    for _ in {1..100}; do
        read -r level _ </proc/sys/kernel/printk
        if [[ "$level" -eq "$1" ]]; then
            return 0
        fi
        sleep .1
    done

    return 1
}

if (( ! IN_CONTAINER )); then
    read -r PRINTK_SAVED _ </proc/sys/kernel/printk
    trap 'echo "$PRINTK_SAVED" >/proc/sys/kernel/printk' EXIT
    echo 4 >/proc/sys/kernel/printk
fi

# systemd-notify --fork returns once the command sent READY=1: systemd-mute-console does that once it
# muted, varlinkctl once it received the reply which confirms the mute.
PID="$(systemd-notify --fork -- systemd-mute-console)"
wait_printk_level 0
kill "$PID"
wait_printk_level 4
unset PID

(! systemd-mute-console --kernel=no --pid1=no)

PID="$(systemd-notify --fork -- systemd-mute-console --kernel=yes --pid1=yes)"
wait_printk_level 0
kill "$PID"
wait_printk_level 4
unset PID

varlinkctl introspect "$(which systemd-mute-console)"

PID="$(systemd-notify --fork -- varlinkctl call -E "$(which systemd-mute-console)" io.systemd.MuteConsole.Mute '{}')"
wait_printk_level 0
kill "$PID"
wait_printk_level 4
unset PID

PID="$(systemd-notify --fork -- varlinkctl call -E "$(which systemd-mute-console)" io.systemd.MuteConsole.Mute '{"pid1":true, "kernel":true}')"
wait_printk_level 0
kill "$PID"
wait_printk_level 4
unset PID

varlinkctl introspect /run/systemd/io.systemd.MuteConsole

PID="$(systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{}')"
wait_printk_level 0
kill "$PID"
wait_printk_level 4
unset PID
