#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test systemd-socket-proxyd by setting up a backend server, a proxy in front of it,
# and verifying that data passes through correctly.

BACKEND_SOCK="/tmp/test-proxyd-backend.sock"

at_exit() {
    set +e
    systemctl stop test-proxyd-backend.service 2>/dev/null
    systemctl stop test-proxyd.socket 2>/dev/null
    systemctl stop test-proxyd.service 2>/dev/null
    rm -f "$BACKEND_SOCK"
}
trap at_exit EXIT

# Start a backend echo server via systemd-run
systemd-run --unit=test-proxyd-backend --service-type=simple \
    socat UNIX-LISTEN:"$BACKEND_SOCK",fork EXEC:cat

# Ensure socket is ready
timeout 5 bash -c "until [[ -S $BACKEND_SOCK ]]; do sleep 0.1; done"

# Create a socket unit for the proxy
cat >/run/systemd/system/test-proxyd.socket <<EOF
[Socket]
ListenStream=12345
EOF

cat >/run/systemd/system/test-proxyd.service <<EOF
[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd $BACKEND_SOCK
EOF

systemctl daemon-reload
systemctl start test-proxyd.socket

proxy_echo() {
    python3 -c "
import socket, sys
data = sys.stdin.buffer.read()
s = socket.create_connection(('localhost', 12345), timeout=15)
s.sendall(data)
received = b''
while len(received) < len(data):
    chunk = s.recv(65536)
    if not chunk:
        break
    received += chunk
sys.stdout.buffer.write(received)
s.close()
"
}

# Test basic forwarding
assert_eq "$(echo -n hello | proxy_echo)" "hello"

# Test a second connection (socket re-activates the proxy)
assert_eq "$(echo -n world | proxy_echo)" "world"

# Test with larger data (64KB random, base64-encoded)
LARGE_DATA="$(dd if=/dev/urandom bs=1024 count=64 status=none | base64)"
assert_eq "$(echo -n "$LARGE_DATA" | proxy_echo)" "$LARGE_DATA"
