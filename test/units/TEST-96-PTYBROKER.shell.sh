#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# This subtest calls AcquirePty() with the shell backend directly through
# varlinkctl, without run0.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

SOCKET_PATH=/run/systemd/io.systemd.PTYBroker

at_exit() {
    set +e
    systemctl stop shell-pty96busy.service shell-pty96race.service
    rm -f /tmp/pty96-shell-*
}

trap at_exit EXIT

acquire_shell() {
    local name="$1" error="$2"

    varlinkctl call --graceful="$error" "$SOCKET_PATH" io.systemd.PTYBroker.AcquirePty \
        "{\"frontendType\":\"null\",\"backendType\":\"shell\",\"name\":\"$name\",\"commandLine\":[\"sleep\",\"infinity\"]}"
}

# The name of the shell's unit contains the PTY name. The service manager
# refuses to start the shell if that unit already exists. The broker must
# return the service manager's error to the client. The failed call must not
# leave the PTY or a reservation of its name behind.
systemd-run --unit=shell-pty96busy.service sleep infinity
acquire_shell pty96busy io.systemd.Unit.UnitExists >/tmp/pty96-shell-busy
(! jq -e .name /tmp/pty96-shell-busy >/dev/null)
wait_for_pty_deregistration pty96busy
systemctl stop shell-pty96busy.service

acquire_shell pty96busy io.systemd.PTYBroker.PtyExists | jq -e '.name == "pty96busy"' >/dev/null
# The service manager replies to StartTransient() when it has queued the start
# job. The shell's unit can still be activating when AcquirePty() returns.
timeout 30 bash -c 'until systemctl is-active shell-pty96busy.service >/dev/null; do sleep .5; done'
systemctl stop shell-pty96busy.service
wait_for_pty_deregistration pty96busy

# Eight concurrent calls with the same name must start exactly one shell. Every
# other call must fail with PtyExists, also when it arrives before the service
# manager has replied to the first call.
pids=()
for i in {1..8}; do
    acquire_shell pty96race io.systemd.PTYBroker.PtyExists >"/tmp/pty96-shell-race-$i" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid"
done

[[ "$(cat /tmp/pty96-shell-race-* | jq -s '[.[] | select(.name == "pty96race")] | length')" == 1 ]]
timeout 30 bash -c 'until systemctl is-active shell-pty96race.service >/dev/null; do sleep .5; done'
ptyctl list | grep -F pty96race >/dev/null
systemctl stop shell-pty96race.service
wait_for_pty_deregistration pty96race
