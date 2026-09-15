#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for OSC 2811 based window size propagation: dimension changes on the
# terminal a "ptyctl monitor" runs on must reach the frontend (master) of the
# monitored PTY in systemd-ptybrokerd. Runs "ptyctl monitor" on a synthetic
# pty, resizes it, and verifies the broker's pty follows, including the
# per-dimension minimum across multiple monitors.

at_exit() {
    set +e
    [[ -n "${FWD_PID:-}" ]] && kill "$FWD_PID"
    rm -f /tmp/pty95-winsize-*
}

trap at_exit EXIT

systemctl start systemd-ptybrokerd.socket

# Register a PTY with the broker, with a long-running payload keeping it around
systemd-pty-forward --quiet --console=broker --pty-name=pty95-winsize -- \
    bash -c 'touch /tmp/pty95-winsize-ready; exec sleep infinity' &
FWD_PID=$!
timeout 10 bash -c 'until test -e /tmp/pty95-winsize-ready; do sleep .2; done'
timeout 10 bash -c 'until ptyctl list | grep pty95-winsize >/dev/null; do sleep .5; done'

BACKEND_PTS=$(varlinkctl call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.ListPty '{"name":"pty95-winsize"}' | jq -r .backendPath)
test -e "$BACKEND_PTS"

# The whole thing is bounded, so that a stuck monitor fails here rather than at the global test timeout
BACKEND_PTS="$BACKEND_PTS" timeout 120 python3 <<'EOF'
import fcntl
import json
import os
import pty
import signal
import struct
import subprocess
import sys
import termios
import time

BACKEND = os.environ['BACKEND_PTS']
NAME = 'pty95-winsize'

monitors = {}  # pid -> master fd of the synthetic pty the monitor runs on
drained = b''


def get_size(fd):
    rows, cols = struct.unpack('HHHH', fcntl.ioctl(fd, termios.TIOCGWINSZ, b'\0' * 8))[:2]
    return rows, cols


def set_size(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


def spawn_monitor():
    pid, master = pty.fork()
    if pid == 0:
        # Make sure the forwarder treats the synthetic pty as a fully capable terminal
        os.environ['TERM'] = 'xterm'
        os.environ['SYSTEMD_COLORS'] = '1'
        os.execvp('ptyctl', ['ptyctl', '--quiet', 'monitor', NAME])
    os.set_blocking(master, False)
    monitors[pid] = master
    return pid, master


def drain():
    # Keep the monitors' output flowing, and collect it for the leak check below
    global drained
    for master in monitors.values():
        while True:
            try:
                d = os.read(master, 4096)
            except (BlockingIOError, OSError):
                break
            if not d:
                break
            drained += d


def wait_for(rows, cols, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        drain()
        if get_size(bfd) == (rows, cols):
            print(f'OK: broker pty is now {rows}x{cols}', file=sys.stderr)
            return
        # Recover from any lost SIGWINCH: a pending OSC 2811 subscription is
        # (re-)answered from the forwarder's signal handler
        for pid in monitors:
            os.kill(pid, signal.SIGWINCH)
        time.sleep(0.2)
    sys.exit(f'Timed out waiting for {rows}x{cols}, broker pty is {get_size(bfd)}')


def wait_for_output(marker, timeout=30):
    # Waits until the monitors have produced the specified marker
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        drain()
        if marker in drained:
            return
        time.sleep(0.2)
    sys.exit(f'Timed out waiting for {marker!r} in monitor output: {drained!r}')


def expect_unchanged(rows, cols, duration=3):
    # The negative counterpart of wait_for(): the broker pty must keep its dimensions for a while,
    # even though we keep poking the monitors with SIGWINCH
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        drain()
        assert get_size(bfd) == (rows, cols), f'broker pty unexpectedly changed to {get_size(bfd)}'
        for pid in monitors:
            os.kill(pid, signal.SIGWINCH)
        time.sleep(0.2)


def kill_monitor(pid):
    master = monitors.pop(pid)
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while os.waitpid(pid, os.WNOHANG) == (0, 0):
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            sys.exit(f'Monitor {pid} did not exit on SIGTERM')
        time.sleep(0.1)
    os.close(master)


bfd = os.open(BACKEND, os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)
print(f'broker pty initially {get_size(bfd)}', file=sys.stderr)

# Whatever is written to the backend must show up in the monitors' output; we use
# this both to make the leak check below meaningful and to inject sequences
bwfd = os.open(BACKEND, os.O_WRONLY | os.O_NOCTTY | os.O_CLOEXEC)

# ConfigurePty must apply explicitly requested dimensions to the broker pty, and report the settled
# settings back
out = subprocess.run(
    ['varlinkctl', 'call', '/run/systemd/io.systemd.PTYBroker', 'io.systemd.PTYBroker.ConfigurePty',
     json.dumps({'name': NAME, 'terminalSettings': {'columns': 101, 'lines': 33}})],
    check=True, stdout=subprocess.PIPE, text=True).stdout
ts = json.loads(out)['terminalSettings']
assert (ts['lines'], ts['columns']) == (33, 101), ts
assert get_size(bfd) == (33, 101), get_size(bfd)

# A single monitor: its terminal dimensions must propagate to the broker pty (and take precedence over
# what was configured explicitly before)
pid1, m1 = spawn_monitor()
set_size(m1, 45, 123)
wait_for(45, 123)

# Output written through the monitored pty must reach the monitor
os.write(bwfd, b'pty95-winsize-marker-1\n')
wait_for_output(b'pty95-winsize-marker-1')

# A live resize must propagate too
set_size(m1, 22, 77)
wait_for(22, 77)

# A second monitor: the per-dimension minimum of all monitors must win
pid2, m2 = spawn_monitor()
set_size(m2, 20, 100)
wait_for(20, 77)

# Disconnecting the second monitor must lift its constraints again
kill_monitor(pid2)
wait_for(22, 77)

# Growing the remaining monitor propagates as well
set_size(m1, 50, 200)
wait_for(50, 200)

# An OSC 2811 cancel sequence reaching the monitor's forwarder must drop its pending
# subscription: further resizes of that monitor's terminal must go unreported. (The
# marker written after it tells us when the forwarder has processed the cancel.)
os.write(bwfd, b'\x1b]2811;?\x1b\\' + b'pty95-winsize-marker-2\n')
wait_for_output(b'pty95-winsize-marker-2')
set_size(m1, 30, 90)
expect_unchanged(50, 200)

# A fresh monitor subscribes anew, and is not affected by the cancel
pid3, m3 = spawn_monitor()
set_size(m3, 30, 90)
wait_for(30, 90)
kill_monitor(pid3)

# Neither the OSC 2811 subscribe sequences nor the cancel sequence may leak to the
# monitor's terminal. Make sure we actually saw output before concluding that.
assert b'pty95-winsize-marker-1' in drained and b'pty95-winsize-marker-2' in drained
assert b'2811' not in drained, f'OSC 2811 sequence leaked into monitor output: {drained!r}'

kill_monitor(pid1)
EOF

ptyctl hangup pty95-winsize
kill "$FWD_PID" 2>/dev/null || :
wait "$FWD_PID" || :
FWD_PID=
