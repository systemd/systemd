#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test systemd-socket-proxyd by setting up a backend server, a proxy in front of it,
# and verifying that data passes through correctly.

BACKEND_SOCK="/tmp/test-proxyd-backend.sock"

at_exit() (
    set +e
    systemctl stop test-proxyd-backend.service 2>/dev/null
    systemctl stop test-proxyd.socket 2>/dev/null
    systemctl stop test-proxyd.service 2>/dev/null
    rm -f "$BACKEND_SOCK"
    rm -f /run/systemd/system/test-proxyd.socket /run/systemd/system/test-proxyd.service
    systemctl daemon-reload 2>/dev/null
)
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
LimitNOFILE=1024:4096
CapabilityBoundingSet=~CAP_SYS_RESOURCE
EOF

systemctl daemon-reload
systemctl start test-proxyd.socket

proxy_echo() {
    /usr/lib/systemd/tests/testdata/TEST-74-AUX-UTILS.units/proxy-echo.py
}

# Test basic forwarding
assert_eq "$(echo -n hello | proxy_echo)" "hello"

# Test a second connection (socket re-activates the proxy)
assert_eq "$(echo -n world | proxy_echo)" "world"

# Test with larger data (64KB random, base64-encoded)
LARGE_DATA="$(dd if=/dev/urandom bs=1024 count=64 status=none | base64)"
assert_eq "$(echo -n "$LARGE_DATA" | proxy_echo)" "$LARGE_DATA"

# Every connection costs the proxy several fds, so it raises its soft RLIMIT_NOFILE. Without
# CAP_SYS_RESOURCE it cannot raise the hard limit, so the result is exactly the unit's hard limit.
PROXY_PID="$(systemctl show -P MainPID test-proxyd.service)"
read -r _ _ _ SOFT HARD _ < <(grep '^Max open files' "/proc/$PROXY_PID/limits")
assert_eq "$SOFT" 4096
assert_eq "$HARD" 4096

# --connections-max= is a hard cap: while one connection is held open, the next one is closed unserved
systemctl stop test-proxyd.socket test-proxyd.service
cat >/run/systemd/system/test-proxyd.service <<EOF
[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd --connections-max=1 $BACKEND_SOCK
EOF
systemctl daemon-reload
systemctl start test-proxyd.socket

exec {HELD}<>/dev/tcp/127.0.0.1/12345
echo -n held >&"$HELD"
read -r -N 4 -t 15 REPLY <&"$HELD"
assert_eq "$REPLY" "held"
# Assigned rather than passed to assert_eq, so that set -e fails the test when the client errors out
REFUSED="$(echo -n refused | proxy_echo)"
assert_eq "$REFUSED" ""
journalctl --sync
journalctl -b -u test-proxyd.service --grep "Hit connection limit" >/dev/null
echo -n still >&"$HELD"
read -r -N 5 -t 15 REPLY <&"$HELD"
assert_eq "$REPLY" "still"
exec {HELD}>&-
