#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! socket_inode_supports_user_xattrs; then
    echo "Socket inode extended attributes unsupported on this kernel, skipping." >&2
    exit 77
fi

if ! test -x /usr/lib/systemd/systemd-varlink-monitord; then
    echo "systemd-varlink-monitord not installed, skipping." >&2
    exit 77
fi

if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM not active, skipping." >&2
    exit 77
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool not found, skipping." >&2
    exit 77
fi

if ! bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep 'bpf_sock_read_xattr' >/dev/null; then
    echo "Kernel lacks bpf_sock_read_xattr kfunc, skipping."
    exit 77
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

# Start a background Unix socket server that accepts one connection.
# Sets UNIX_SERVER_PID. Paths starting with '@' are treated as abstract sockets.
start_unix_server() {
    local sock_path="$1"
    local ready_fifo
    ready_fifo=$(mktemp -u)
    mkfifo "$ready_fifo"
    [[ "$sock_path" != @* ]] && rm -f "$sock_path"
    python3 -c "
import socket, sys
path = sys.argv[1]
if path.startswith('@'):
    path = '\0' + path[1:]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(1)
open(sys.argv[2], 'w').write('ready')
conn, _ = srv.accept()
while conn.recv(65536):
    pass
conn.close()
srv.close()
" "$sock_path" "$ready_fifo" &
    UNIX_SERVER_PID=$!
    timeout 5 cat "$ready_fifo" >/dev/null
    rm -f "$ready_fifo"
}

# Connect to a Unix socket with the user.varlink xattr and send data from
# stdin. Paths starting with '@' are treated as abstract sockets.
# Double newlines (\n\n) split into separate writev() calls (writes);
# single newlines (\n) split into iov segments within each writev().
varlink_raw_send() {
    local sock_path="$1"
    python3 -c "
import socket, os, sys
path = sys.argv[1]
if path.startswith('@'):
    path = '\0' + path[1:]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
os.setxattr(s.fileno(), 'user.varlink', b'client')
s.connect(path)
for write in sys.stdin.buffer.read().split(b'\n\n'):
    os.writev(s.fileno(), write.split(b'\n'))
s.close()
" "$sock_path"
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
# appears and other processes' traffic is excluded. We create a custom
# server so we have a known PID to filter on — the BPF matches if either
# sender or peer PID equals the filter value.
# -----------------------------------------------------------------------
echo "=== Test 3: --pid filter ==="
FILTER_SOCK="/run/test-monitor-pid-filter.sock"

start_unix_server "$FILTER_SOCK"

start_monitor --pid=$UNIX_SERVER_PID

# Positive: connecting to FILTER_SOCK sets peer PID = $UNIX_SERVER_PID — should be captured
printf '{"method":"io.systemd.PidFilterTest.Matched","parameters":{}}\0' | \
    varlink_raw_send "$FILTER_SOCK" || true

wait_for_output "PidFilterTest.Matched"

# Negative: neither sender nor peer PID is $UNIX_SERVER_PID — should NOT be captured
(exec varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}')

sleep 1

stop_monitor
wait "$UNIX_SERVER_PID" 2>/dev/null || true
rm -f "$FILTER_SOCK"

grep "PidFilterTest.Matched" "$MONITOR_OUT" >/dev/null
(! grep "io.systemd.Hostname.Describe" "$MONITOR_OUT" >/dev/null)

# -----------------------------------------------------------------------
# Test 4: --path filter
#
# Start the monitor with --path filtering and verify only matching traffic
# appears.
# -----------------------------------------------------------------------
echo "=== Test 4: --path filter ==="
start_monitor --path=/run/systemd/io.systemd.Hostname

# Journal call first: since the ringbuf is FIFO, placing the filtered-out call
# before the expected one ensures it has been processed by the time we stop.
varlinkctl call /run/systemd/journal/io.systemd.journal io.systemd.Journal.Rotate '{}'
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

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
PADDING=$(printf 'x%.0s' {1..2000})
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.LargeTest.Fake "{\"padding\":\"$PADDING\"}" || true

# Send a normal call to verify the monitor still works after large messages
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

wait_for_output "io.systemd.Hostname.Describe"

stop_monitor

# Verify the large message was reassembled correctly — the padding field must
# be present and complete
sed -n 's/^\x1e//p' "$MONITOR_OUT" | \
    jq -e 'select(.data.parameters.padding) | .data.parameters.padding | length == 2000' >/dev/null

# -----------------------------------------------------------------------
# Test 7: garbage data
#
# Send raw non-JSON data to a varlink socket. The monitor should handle
# invalid data gracefully and continue capturing subsequent messages.
# -----------------------------------------------------------------------
echo "=== Test 7: garbage data ==="
start_monitor

# Send garbage to a varlink socket
printf 'this is not json\0' | varlink_raw_send /run/systemd/io.systemd.Hostname || true

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
sed -n 's/^\x1e//p' "$MONITOR_OUT" | \
    jq -e 'select(.data.method == "io.systemd.Hostname.Describe") |
           has("timestamp", "pid", "uid", "peerPid", "peerUid", "sockCookie")' >/dev/null

# -----------------------------------------------------------------------
# Test 9: writev (multi-segment writes)
#
# Use writev() to send a varlink message split across multiple iov
# segments. The BPF program captures each segment separately and the
# monitor must reassemble them into a single message.
# -----------------------------------------------------------------------
echo "=== Test 9: writev (multi-segment writes) ==="
start_monitor

printf '{"method":"io.systemd.\nWritevTest.Call",\n"parameters":{}}\0' | \
    varlink_raw_send /run/systemd/io.systemd.Hostname || true

# Send a normal call so we have something to wait for
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'
wait_for_output "io.systemd.Hostname.Describe"

stop_monitor
# The writev message should have been reassembled from multiple segments
grep "WritevTest.Call" "$MONITOR_OUT" >/dev/null

# -----------------------------------------------------------------------
# Test 10: abstract sockets
#
# Verify that traffic on abstract unix sockets is captured and the path
# is displayed with the '@' prefix convention.
# -----------------------------------------------------------------------
echo "=== Test 10: abstract sockets ==="
start_unix_server '@test-monitor-abstract'

start_monitor --json=short

printf '{"method":"io.systemd.AbstractTest.Call","parameters":{}}\0' | \
    varlink_raw_send '@test-monitor-abstract' || true
wait "$UNIX_SERVER_PID" 2>/dev/null || true

# Send a normal call so we have something reliable to wait for
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'
wait_for_output "io.systemd.Hostname.Describe"

stop_monitor
# The abstract socket path must appear with '@' prefix
grep '@test-monitor-abstract' "$MONITOR_OUT" >/dev/null

# -----------------------------------------------------------------------
# Test 11: truncation detection and re-sync
#
# Send a message larger than the BPF capture limit (32 packets × 1024
# bytes = 32768 bytes) followed by a normal message on the same
# connection. The monitor must flush the truncated fragment immediately
# and then receive the subsequent message correctly.
# -----------------------------------------------------------------------
echo "=== Test 11: truncation detection and re-sync ==="
TRUNC_SOCK="/run/test-monitor-truncation.sock"
start_unix_server "$TRUNC_SOCK"

start_monitor --json=short

# Two writes on the same connection (separated by \n\n): the first
# contains the start of a large message that exceeds the capture limit,
# the second contains the tail of that message followed by a normal
# message. The monitor must flush the truncated fragment, skip the
# continuation tail to re-sync at the NUL, then deliver the next message.
{
    printf '{"method":"io.systemd.TruncTest.Big","parameters":{"data":"'
    head -c 90000 /dev/zero | tr '\0' 'A'
    printf '\n\n'
    head -c 10000 /dev/zero | tr '\0' 'A'
    printf '"}}\0{"method":"io.systemd.TruncTest.After","parameters":{}}\0'
} | varlink_raw_send "$TRUNC_SOCK" || true

wait "$UNIX_SERVER_PID" 2>/dev/null || true

wait_for_output "TruncTest.After"

stop_monitor
rm -f "$TRUNC_SOCK"

# The truncated fragment must have been flushed
sed -n 's/^\x1e//p' "$MONITOR_OUT" | \
    jq -e 'select(.truncated == true)' >/dev/null
# The message after re-sync must arrive correctly
sed -n 's/^\x1e//p' "$MONITOR_OUT" | \
    jq -e 'select(.data.method == "io.systemd.TruncTest.After")' >/dev/null

echo "All varlinkctl monitor tests passed."
