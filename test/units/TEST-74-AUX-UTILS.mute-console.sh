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

# Stopping the service while a client holds the mute must unmute. This also disconnects the client.
PID="$(systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{}')"
wait_printk_level 0
systemctl stop systemd-mute-console.service
wait_printk_level 4
timeout 10 tail --pid="$PID" -f /dev/null
unset PID

# Muting is refcounted: a second client gets an immediate response while the first one still holds
# the mute, and output is only unmuted when the last client disconnects. Nothing gets queued, as
# pending jobs block boot completion.
PID_A="$(systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{}')"
PID_B="$(timeout 10 systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{}')"
wait_printk_level 0
[[ -z "$(systemctl list-jobs --no-legend systemd-mute-console.service)" ]]
kill "$PID_A"
sleep .5
wait_printk_level 0
kill "$PID_B"
wait_printk_level 4
unset PID_A PID_B

# Each client only mutes what was requested: kernel output is unmuted once the last client that muted it
# disconnects, even while another client still holds the PID 1 mute.
PID_A="$(systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{"kernel":false}')"
PID_B="$(systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{}')"
wait_printk_level 0
kill "$PID_B"
wait_printk_level 4
kill "$PID_A"
timeout 10 tail --pid="$PID_A" -f /dev/null
systemctl is-active systemd-mute-console.service
unset PID_A PID_B

# Bursts of short connections must not run into the service's start rate limit, which would fail the socket.
systemctl stop systemd-mute-console.service
for _ in {1..10}; do
    varlinkctl introspect /run/systemd/io.systemd.MuteConsole >/dev/null
done
systemctl is-active systemd-mute-console.socket
systemctl is-active systemd-mute-console.service
