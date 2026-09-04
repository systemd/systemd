#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for the pid1 side of the PTY broker integration:
# StandardInput=/StandardOutput=/StandardError= broker and broker-log.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e
    systemctl stop pty95-exec-long.service
    rm -f /tmp/pty95-exec-*
}

trap at_exit EXIT

# All three streams connected to the broker PTY: the service must see a real TTY
# on its stdio, have it as controlling terminal, and get the fallback terminal
# environment (franken-vt220 with truecolor)
# shellcheck disable=SC2016
systemd-run --wait \
    -p StandardInput=broker -p StandardOutput=broker -p StandardError=broker \
    bash -xec '
        test -t 0; test -t 1; test -t 2
        [[ "$(tty)" == /dev/pts/* ]]
        [[ "$TERM" == vt220 ]]
        [[ "$COLORTERM" == truecolor ]]
        # stdin is a broker PTY, so it must also be our controlling terminal
        : </dev/tty'

# Explicitly configured TTYRows=/TTYColumns= must be applied to the allocated PTY
# shellcheck disable=SC2016
systemd-run --wait \
    -p StandardInput=broker -p StandardOutput=broker \
    -p TTYRows=42 -p TTYColumns=111 \
    bash -xec '[[ "$(stty size)" == "42 111" ]]'

# Explicitly configured Environment=TERM= wins over the fallback, for both the
# service and the terminal registered with the broker
# shellcheck disable=SC2016
systemd-run --wait \
    -p StandardInput=broker -p StandardOutput=broker \
    -p Environment=TERM=xterm \
    bash -xec '[[ "$TERM" == xterm ]]'

# In broker-log mode the service's terminal output must land in the journal,
# under the configured SyslogIdentifier=
systemd-run --wait -u pty95-exec-log.service \
    -p StandardOutput=broker-log -p StandardError=broker-log \
    -p SyslogIdentifier=pty95-exec-tag \
    sh -xc 'echo hello-pty95-exec-marker'
timeout 30 bash -c 'until journalctl -q -t pty95-exec-tag | grep hello-pty95-exec-marker >/dev/null; do journalctl --sync; sleep 1; done'

# Units using broker stdio gain an implicit After= on the broker socket, the
# broker registration carries the unit name as description, and it goes away
# again when the unit stops
systemd-run -u pty95-exec-long.service -p StandardOutput=broker sleep infinity
systemctl show -p After pty95-exec-long.service | grep systemd-ptybrokerd.socket >/dev/null
timeout 10 bash -c 'until ptyctl list | grep pty95-exec-long.service >/dev/null; do sleep .5; done'
systemctl stop pty95-exec-long.service
wait_for_pty_deregistration pty95-exec-long.service

# The transient Varlink interface accepts the new stdio types, too. Without a
# SyslogIdentifier= the broker tags the output with the unit name.
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.StartTransient '
{
    "context" : {
        "ID" : "pty95-exec-varlink.service",
        "CollectMode" : "inactive_or_failed",
        "Exec" : {
            "StandardOutput" : "broker_log"
        },
        "Service" : {
            "Type" : "oneshot",
            "ExecStart" : [ { "path" : "/bin/sh", "arguments" : [ "sh", "-c", "echo hello-pty95-exec-varlink-marker" ] } ]
        }
    },
    "mode" : "replace"
}'
timeout 30 bash -c 'until journalctl -q -t pty95-exec-varlink.service | grep hello-pty95-exec-varlink-marker >/dev/null; do journalctl --sync; sleep 1; done'
