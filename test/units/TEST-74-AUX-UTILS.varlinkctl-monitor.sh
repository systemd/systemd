#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! socket_inode_supports_user_xattrs; then
    echo "Socket inode extended attributes unsupported on this kernel, skipping." >&2
    exit 0
fi

MONITOR_OUT=/run/test-varlinkctl-monitor.log
MONITOR_UNIT=

at_exit() {
    [[ -n "$MONITOR_UNIT" ]] && systemctl stop "$MONITOR_UNIT" 2>/dev/null || :
    rm -f "$MONITOR_OUT"
}
trap at_exit EXIT

start_monitor() {
    MONITOR_UNIT="test-varlinkctl-monitor-$RANDOM.service"
    : >"$MONITOR_OUT"
    systemd-run --unit="$MONITOR_UNIT" --service-type=notify --quiet \
        --property=StandardOutput=file:"$MONITOR_OUT" \
        --property=StandardError=file:"$MONITOR_OUT" \
        varlinkctl monitor "$@"
}

stop_monitor() {
    systemctl stop "$MONITOR_UNIT"
    MONITOR_UNIT=
}

wait_for_output() {
    local pattern="$1"
    local timeout_sec="${2:-10}"
    timeout "$timeout_sec" bash -c "until grep -q '$pattern' '$MONITOR_OUT'; do sleep 0.5; done"
}

# -----------------------------------------------------------------------
# Test 1: pre-existing sockets
#
# systemd services like io.systemd.Hostname are already listening. Make a
# varlink call while monitoring and verify the traffic shows up.
# -----------------------------------------------------------------------
echo "=== Test 1: pre-existing sockets ==="
start_monitor

varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor
grep "io.systemd.Hostname.Describe" "$MONITOR_OUT" >/dev/null

# -----------------------------------------------------------------------
# Test 2: new sockets
#
# Create a fresh varlink entrypoint socket via socket activation, then
# make a call to it. The monitor must pick up traffic on sockets that
# were created after monitoring started.
# -----------------------------------------------------------------------
echo "=== Test 2: new sockets ==="
start_monitor

SOCK_PATH="/run/test-monitor-new.sock"
rm -f "$SOCK_PATH"

systemd-run \
    --unit=test-monitor-new \
    --service-type=oneshot \
    --remain-after-exit \
    --socket-property=ListenStream="$SOCK_PATH" \
    --socket-property=SocketMode=0666 \
    --socket-property=FileDescriptorName=varlink \
    --socket-property=XAttrEntryPoint="user.varlink=entrypoint" \
    --socket-property=RemoveOnStop=true \
    true

# Make a varlink call to the new socket — the service behind it is just
# "true" so the call will fail, but the monitor should still see the
# outgoing message on the wire.
timeout 2 varlinkctl info "$SOCK_PATH" || true

wait_for_output "$SOCK_PATH"

stop_monitor
grep "$SOCK_PATH" "$MONITOR_OUT" >/dev/null

systemctl stop test-monitor-new.socket 2>/dev/null || true
rm -f "$SOCK_PATH"

# -----------------------------------------------------------------------
# Test 3: --pid filter
#
# Start the monitor with --pid filtering and verify only matching traffic
# appears.
# -----------------------------------------------------------------------
echo "=== Test 3: --pid filter ==="

# Filter for PID 1 (systemd). Our varlinkctl calls have PID 1 as the peer
# (the service side), so the Hostname call should still be captured.
start_monitor --pid=1

varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor
grep "io.systemd.Hostname.Describe" "$MONITOR_OUT" >/dev/null

# -----------------------------------------------------------------------
# Test 4: --path filter
#
# Start the monitor with --path filtering and verify only matching traffic
# appears.
# -----------------------------------------------------------------------
echo "=== Test 4: --path filter ==="
start_monitor --path=/run/systemd/io.systemd.Hostname

varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'
varlinkctl call /run/systemd/journal/io.systemd.journal io.systemd.Journal.Rotate '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor

# The Hostname call must be captured
grep "io.systemd.Hostname.Describe" "$MONITOR_OUT" >/dev/null
# The Journal call must NOT be captured (different path)
(! grep "io.systemd.Journal.Rotate" "$MONITOR_OUT" >/dev/null)

# -----------------------------------------------------------------------
# Test 5: --path=anonymous filter
#
# Anonymous sockets are created via socketpair() and fd-passed over an
# existing varlink connection. We cannot easily trigger that from shell,
# but we can verify that --path=anonymous correctly suppresses all
# named-path traffic.
# -----------------------------------------------------------------------
echo "=== Test 5: --path=anonymous filter ==="
start_monitor --path=anonymous

varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

# We cannot produce anonymous socket traffic from shell, so there is no
# positive signal to wait for. Sleep to let the BPF pipeline process
# the named-path message (which should be filtered out).
sleep 1

stop_monitor

# Named-path traffic must be suppressed
(! grep "io.systemd.Hostname.Describe" "$MONITOR_OUT" >/dev/null)

# -----------------------------------------------------------------------
# Test 6: large messages (> 1024 bytes BPF capture buffer)
#
# Messages larger than MONITOR_VARLINK_MAX_DATA get truncated by the BPF
# program. Verify the monitor handles truncated data gracefully and
# subsequent messages on new connections are still captured.
# -----------------------------------------------------------------------
echo "=== Test 6: large message ==="
start_monitor --json=short

# Send a varlink call large enough to exceed the 1024-byte BPF capture limit.
# The BPF program splits it into multiple packets and the monitor must
# reassemble them into a single valid JSON message.
PADDING=$(python3 -c "print('x' * 2000)")
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.LargeTest.Fake "{\"padding\":\"$PADDING\"}" || true

# Send a normal call to verify the monitor still works after large messages
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor

# Verify the large message was reassembled correctly — the padding field must
# be present and complete
python3 -c "
import json
found = False
for line in open('$MONITOR_OUT'):
    line = line.strip().lstrip('\x1e')
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    data = obj.get('data', {})
    if not isinstance(data, dict):
        continue
    params = data.get('parameters', {})
    if isinstance(params, dict) and 'padding' in params:
        assert len(params['padding']) == 2000, f'padding truncated: {len(params[\"padding\"])} != 2000'
        found = True
        break
assert found, 'did not find reassembled large message in monitor output'
"

# -----------------------------------------------------------------------
# Test 7: garbage data
#
# Send raw non-JSON data to a varlink socket. The monitor should handle
# invalid data gracefully and continue capturing subsequent messages.
# -----------------------------------------------------------------------
echo "=== Test 7: garbage data ==="
start_monitor

# Send garbage to a varlink socket
python3 -c "
import socket, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
os.setxattr(s.fileno(), 'user.varlink', b'client')
s.connect('/run/systemd/io.systemd.Hostname')
s.sendall(b'this is not json\0')
s.close()
" || true

# Send a normal call to verify the monitor still works
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor
grep "invalid JSON" "$MONITOR_OUT" >/dev/null
grep "io.systemd.Hostname.Describe" "$MONITOR_OUT" >/dev/null

# -----------------------------------------------------------------------
# Test 8: JSON output mode
#
# Verify that --json=short produces machine-readable JSON-SEQ output with
# all expected metadata fields.
# -----------------------------------------------------------------------
echo "=== Test 8: JSON output mode ==="
start_monitor --json=short

varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor

# Verify the output contains JSON with expected metadata fields
python3 -c "
import json, sys
found = False
for line in open('$MONITOR_OUT'):
    line = line.strip().lstrip('\x1e')  # strip JSON-SEQ RS prefix
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if 'data' not in obj:
        continue
    data = obj['data']
    if isinstance(data, dict) and data.get('method') == 'io.systemd.Hostname.Describe':
        assert 'timestamp' in obj, 'missing timestamp'
        assert 'pid' in obj, 'missing pid'
        assert 'uid' in obj, 'missing uid'
        assert 'peerPid' in obj, 'missing peerPid'
        assert 'peerUID' in obj, 'missing peerUID'
        assert 'sockCookie' in obj, 'missing sockCookie'
        found = True
        break
assert found, 'did not find Hostname.Describe call in JSON output'
"

echo "All varlinkctl monitor tests passed."
