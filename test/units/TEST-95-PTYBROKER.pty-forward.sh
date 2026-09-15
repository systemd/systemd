#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for "systemd-pty-forward --console=broker|broker-log", and for driving the
# resulting registrations with ptyctl (list, monitor, hangup).

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e
    [[ -n "${FWD_PID:-}" ]] && kill "$FWD_PID"
    [[ -n "${MON_PID:-}" ]] && kill "$MON_PID"
    rm -f /tmp/pty95-fwd-*
}

trap at_exit EXIT

# The invoked command must get a real pseudo TTY on its stdio, even though the
# frontend lives in the broker. Note that the payload deliberately ends in an
# external command (which coreutils-style closes its stdio before exiting): this
# is a regression test for the payload getting spuriously killed by SIGHUP when
# the broker reacted to that with an immediate pty teardown.
systemd-pty-forward --quiet --console=broker --pty-name=pty95-fwd-basic -- \
    bash -xec 'test -t 0; test -t 1; test -t 2; tty; touch /tmp/pty95-fwd-basic-ok'
test -e /tmp/pty95-fwd-basic-ok

# Once the command is gone the PTY should be deregistered again
wait_for_pty_deregistration pty95-fwd-basic

# Spawn a long-running payload that keeps producing output
systemd-pty-forward --quiet --console=broker --pty-name=pty95-fwd-mon -- \
    bash -c 'touch /tmp/pty95-fwd-mon-ready; while sleep 1; do echo ping-pty95; done' &
FWD_PID=$!
timeout 10 bash -c 'until test -e /tmp/pty95-fwd-mon-ready; do sleep .2; done'

# It must show up in the list, with the expected frontend/backend types
timeout 10 bash -c 'until ptyctl list | grep pty95-fwd-mon >/dev/null; do sleep .5; done'
ptyctl list | grep pty95-fwd-mon | grep null | grep take

# The name must be unique: enrolling a second PTY under the same name must fail
(! systemd-pty-forward --quiet --console=broker --pty-name=pty95-fwd-mon -- true)

# A monitor connection should receive the payload's output
ptyctl --quiet monitor pty95-fwd-mon </dev/null >/tmp/pty95-fwd-mon.log &
MON_PID=$!
timeout 10 bash -c 'until grep ping-pty95 /tmp/pty95-fwd-mon.log >/dev/null; do sleep .5; done'

# Hanging up the PTY must tear everything down: the monitor gets disconnected,
# and the registration disappears
ptyctl hangup pty95-fwd-mon
timeout 10 bash -c "while kill -0 $MON_PID 2>/dev/null; do sleep .5; done"
MON_PID=
wait_for_pty_deregistration pty95-fwd-mon
kill "$FWD_PID" 2>/dev/null || :
wait "$FWD_PID" || :
FWD_PID=

# In broker-log mode the payload's terminal output must end up in the journal,
# tagged with the PTY name
systemd-pty-forward --quiet --console=broker-log --pty-name=pty95-fwd-log -- \
    sh -xc 'echo hello-pty95-fwd-log-marker'
timeout 30 bash -c 'until journalctl -q -t pty95-fwd-log | grep hello-pty95-fwd-log-marker >/dev/null; do journalctl --sync; sleep 1; done'
journalctl -q PTY=pty95-fwd-log | grep hello-pty95-fwd-log-marker >/dev/null

# In plain broker mode nothing may be logged
systemd-pty-forward --quiet --console=broker --pty-name=pty95-fwd-quiet -- \
    sh -xc 'echo hello-pty95-fwd-quiet-marker'
journalctl --sync
(! journalctl -q -t pty95-fwd-quiet | grep hello-pty95-fwd-quiet-marker >/dev/null)
