#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-mute-console >/dev/null; then
    echo "systemd-mute-console is not installed, skipping the test"
    exit 0
fi

PID="$(systemd-notify --fork -- systemd-mute-console)"
sleep .5
kill "$PID"
unset PID

(! systemd-mute-console --kernel=no --pid1=no)

PID="$(systemd-notify --fork -- systemd-mute-console --kernel=yes --pid1=yes)"
sleep .5
kill "$PID"
unset PID

varlinkctl introspect "$(which systemd-mute-console)"

PID="$(systemd-notify --fork -- varlinkctl call -E "$(which systemd-mute-console)" io.systemd.MuteConsole.Mute '{}')"
sleep .5
kill "$PID"
unset PID

PID="$(systemd-notify --fork -- varlinkctl call -E "$(which systemd-mute-console)" io.systemd.MuteConsole.Mute '{"pid1":true, "kernel":true}')"
sleep .5
kill "$PID"
unset PID

varlinkctl introspect /run/systemd/io.systemd.MuteConsole

PID="$(systemd-notify --fork -- varlinkctl call -E /run/systemd/io.systemd.MuteConsole io.systemd.MuteConsole.Mute '{}')"
sleep .5
kill "$PID"
unset PID
