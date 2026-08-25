#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for the input direction of monitor connections: whatever a monitor writes
# to its connection must reach the payload on the backend of the monitored PTY.
# Talks the Varlink protocol (and the upgraded raw monitor stream) directly, so
# that every byte travelling monitor→broker is under the test's control. Covers
# plain keystrokes, an ANSI sequence split across two reads (which the broker
# must hold back and reinsert intact), OSC 2811 replies (which must be excised
# from the stream and applied to the PTY), and back-pressure once the payload
# stops reading.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e
    [[ -n "${FWD_PID:-}" ]] && kill "$FWD_PID"
    rm -f /tmp/pty95-input-*
}

trap at_exit EXIT

systemctl start systemd-ptybrokerd.socket

# Register a PTY with the broker. The payload switches its terminal to raw mode
# without echo, so that input arrives byte-for-byte and nothing is echoed back to
# the monitor, and then copies everything it reads to a file for us to inspect.
# It also announces its PID, so that we can stop it below.
# shellcheck disable=SC2016
systemd-pty-forward --quiet --console=broker --pty-name=pty95-input -- \
    bash -c 'stty raw -echo
             echo $$ >/tmp/pty95-input-pid.tmp && mv /tmp/pty95-input-pid.tmp /tmp/pty95-input-pid
             exec cat >/tmp/pty95-input-received' &
FWD_PID=$!
timeout 10 bash -c 'until test -e /tmp/pty95-input-pid; do sleep .2; done'
timeout 10 bash -c 'until ptyctl list | grep pty95-input >/dev/null; do sleep .5; done'

BACKEND_PTS=$(varlinkctl call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.ListPty '{"name":"pty95-input"}' | jq -r .backendPath)
test -e "$BACKEND_PTS"

# The whole thing is bounded, so that a stuck monitor fails here rather than at the global test timeout
BACKEND_PTS="$BACKEND_PTS" PAYLOAD_PID="$(cat /tmp/pty95-input-pid)" timeout 120 python3 <<'EOF'
import fcntl
import json
import os
import signal
import socket
import struct
import sys
import termios
import time

BACKEND = os.environ['BACKEND_PTS']
PAYLOAD_PID = int(os.environ['PAYLOAD_PID'])
NAME = 'pty95-input'
RECEIVED = '/tmp/pty95-input-received'

# Matches BUFFER_MAX in src/ptybroker/ptybroker.h
BUFFER_MAX = 4 * 1024 * 1024

OSC = b'\x1b]'
ST = b'\x1b\\'


def osc2811(*fields):
    return OSC + b';'.join((b'2811',) + fields) + ST


def get_size(fd):
    rows, cols = struct.unpack('HHHH', fcntl.ioctl(fd, termios.TIOCGWINSZ, b'\0' * 8))[:2]
    return rows, cols


def received():
    with open(RECEIVED, 'rb') as f:
        return f.read()


def wait_for_received(marker, timeout=30):
    # Waits until the payload has copied the specified marker to its output file, and returns everything
    # it received so far
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = received()
        if marker in data:
            return data
        time.sleep(0.2)
    sys.exit(f'Timed out waiting for {marker!r} to reach the payload, got: {received()!r}')


def wait_for_size(rows, cols, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if get_size(bfd) == (rows, cols):
            return
        time.sleep(0.2)
    sys.exit(f'Timed out waiting for {rows}x{cols}, broker pty is {get_size(bfd)}')


# Establish the monitor connection: a MonitorPty() call with connection upgrade, after which the socket
# carries the raw monitor stream. Talk the Varlink protocol by hand, so that we fully control what we send.
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('/run/systemd/io.systemd.PTYBroker')
sock.sendall(json.dumps({
    'method': 'io.systemd.PTYBroker.MonitorPty',
    'parameters': {'name': NAME, 'osc2811': True},
    'upgrade': True,
}).encode() + b'\0')

stream = b''
while b'\0' not in stream:
    d = sock.recv(4096)
    assert d, 'Broker closed the connection before replying'
    stream += d
reply, _, stream = stream.partition(b'\0')  # Anything after the reply belongs to the monitor stream already
reply = json.loads(reply)
assert 'error' not in reply, reply
assert reply['parameters']['name'] == NAME, reply
sock.setblocking(False)


def read_stream(timeout):
    # Collects whatever the broker sends us for the specified time
    global stream
    deadline = time.monotonic() + timeout
    while True:
        try:
            d = sock.recv(4096)
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return
            time.sleep(0.05)
            continue
        assert d, 'Broker closed the monitor connection'
        stream += d


def expect_sequence(seq, timeout=30):
    # Waits for the specified sequence to arrive on the monitor stream, and consumes everything up to and
    # including it
    global stream
    deadline = time.monotonic() + timeout
    while seq not in stream:
        if time.monotonic() >= deadline:
            sys.exit(f'Timed out waiting for {seq!r} on the monitor stream, got: {stream!r}')
        read_stream(0.2)
    stream = stream[stream.index(seq) + len(seq):]


def send(data):
    # Sends data down the monitor connection, waiting as long as necessary
    view = memoryview(data)
    while view:
        try:
            n = sock.send(view)
        except BlockingIOError:
            read_stream(0.05)  # Keep the other direction flowing meanwhile
            continue
        view = view[n:]


bfd = os.open(BACKEND, os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)

# The broker must ask us for our dimensions right away, declaring that it doesn't know them yet…
expect_sequence(osc2811(b'?', b'columns=0', b'lines=0'))

# … apply what we report, and then resubscribe declaring the dimensions it just learnt
send(osc2811(b'columns=80', b'lines=24'))
wait_for_size(24, 80)
expect_sequence(osc2811(b'?', b'columns=80', b'lines=24'))

expected = b''  # Everything the payload should have received so far

# Plain keystrokes must reach the payload
marker = b'hello-pty95-input-marker-1\n'
send(marker)
expected += marker
assert wait_for_received(marker) == expected

# An ANSI sequence other than OSC 2811 must reach the payload intact, even if it arrives at the broker in
# two parts: the broker cannot know whether to excise a sequence before it has seen its end, hence must
# hold the incomplete part back meanwhile, and reinsert it once the rest arrives.
seq = OSC + b'52;c;cHR5OTU=' + ST
send(seq[:8])
time.sleep(0.5)
assert received() == expected, f'Incomplete sequence leaked to the payload: {received()!r}'
send(seq[8:])
marker = b'hello-pty95-input-marker-2\n'
send(marker)
expected += seq + marker
assert wait_for_received(marker) == expected

# An OSC 2811 report on the other hand must be excised from the stream (also if it arrives in two parts),
# and its dimensions applied to the pty, after which the broker resubscribes
seq = osc2811(b'columns=100', b'lines=40')
send(seq[:10])
time.sleep(0.5)
send(seq[10:])
marker = b'hello-pty95-input-marker-3\n'
send(marker)
expected += marker
assert wait_for_received(marker) == expected
wait_for_size(40, 100)
expect_sequence(osc2811(b'?', b'columns=100', b'lines=40'))

# An OSC 2811 request (as opposed to a report) is not addressed to the broker, and must pass through
seq = osc2811(b'?', b'columns=1', b'lines=1')
send(seq)
marker = b'hello-pty95-input-marker-4\n'
send(marker)
expected += seq + marker
assert wait_for_received(marker) == expected
assert get_size(bfd) == (40, 100), get_size(bfd)

# Back-pressure: if the payload stops reading, the broker must buffer a bounded amount of input and then
# stop accepting more, rather than growing its buffers without bounds or dropping data. Once the payload
# resumes reading, everything must arrive, in order.
os.kill(PAYLOAD_PID, signal.SIGSTOP)

bulk = b''.join(b'pty95-input-bulk-%08d\n' % i for i in range(2 * BUFFER_MAX // 26))
view = memoryview(bulk)
stalled_since = None
while view:
    try:
        n = sock.send(view)
    except BlockingIOError:
        if stalled_since is None:
            stalled_since = time.monotonic()
        elif time.monotonic() - stalled_since > 3:
            break
        read_stream(0.05)
        continue
    stalled_since = None
    view = view[n:]

sent = len(bulk) - len(view)
print(f'Monitor connection stalled after {sent} bytes', file=sys.stderr)
assert view, 'Broker accepted all input even though the payload was stopped'
assert sent >= BUFFER_MAX, f'Broker stalled prematurely, after {sent} bytes'

os.kill(PAYLOAD_PID, signal.SIGCONT)
send(view)
marker = b'hello-pty95-input-marker-5\n'
send(marker)
expected += bulk + marker
assert wait_for_received(marker, timeout=60) == expected

sock.close()
EOF

ptyctl hangup pty95-input
kill "$FWD_PID" 2>/dev/null || :
wait "$FWD_PID" || :
FWD_PID=
wait_for_pty_deregistration pty95-input
