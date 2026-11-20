#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v ss >/dev/null; then
    echo "ss not found, skipping test." >&2
    exit 0
fi

UNIT_NAME="TEST-07-PID1-mptcp-auto-$RANDOM"
PORT=7419
MPTCP_ENABLED=

at_exit() {
    set +e
    systemctl stop "$UNIT_NAME.socket"
    rm -f /run/systemd/system/"$UNIT_NAME".socket /run/systemd/system/"$UNIT_NAME"@.service
    systemctl daemon-reload
    if [[ -n "$MPTCP_ENABLED" ]]; then
        sysctl -w net.mptcp.enabled="$MPTCP_ENABLED"
    fi
}

trap at_exit EXIT

cat >/run/systemd/system/"$UNIT_NAME"@.service <<EOF
[Service]
ExecStart=cat
StandardInput=socket
EOF

# Also include an AF_UNIX socket, which SocketProtocol= must not be applied to
cat >/run/systemd/system/"$UNIT_NAME".socket <<EOF
[Socket]
ListenStream=127.0.0.1:$PORT
ListenStream=/run/$UNIT_NAME.sock
SocketProtocol=mptcp-auto
Accept=yes
EOF

systemctl daemon-reload
assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME.socket")" "$((262 | (1 << 30)))"

is_mptcp() {
    ss -MlnH "sport = :$PORT" | grep "127.0.0.1:$PORT" >/dev/null
}

is_listening() {
    ss -tlnH "sport = :$PORT" | grep "127.0.0.1:$PORT" >/dev/null
}

if [[ -e /proc/sys/net/mptcp/enabled ]]; then
    MPTCP_ENABLED="$(sysctl -n net.mptcp.enabled)"

    sysctl -w net.mptcp.enabled=1
    systemctl start "$UNIT_NAME.socket"
    test -S "/run/$UNIT_NAME.sock"
    is_listening
    is_mptcp
    systemctl stop "$UNIT_NAME.socket"

    # With MPTCP turned off we should fall back to plain TCP
    sysctl -w net.mptcp.enabled=0
    systemctl start "$UNIT_NAME.socket"
    test -S "/run/$UNIT_NAME.sock"
    is_listening
    (! is_mptcp)
    systemctl stop "$UNIT_NAME.socket"

    # And we should pick MPTCP up again once it is turned back on
    sysctl -w net.mptcp.enabled=1
    systemctl start "$UNIT_NAME.socket"
    is_listening
    is_mptcp
    systemctl stop "$UNIT_NAME.socket"
else
    # Kernel without MPTCP support, must fall back to TCP
    systemctl start "$UNIT_NAME.socket"
    test -S "/run/$UNIT_NAME.sock"
    is_listening
    systemctl stop "$UNIT_NAME.socket"
fi

# Plain "mptcp" must not be applied to the AF_UNIX socket either
sed -i 's/^SocketProtocol=.*/SocketProtocol=mptcp/' /run/systemd/system/"$UNIT_NAME".socket
sed -i "/^ListenStream=127.0.0.1/d" /run/systemd/system/"$UNIT_NAME".socket
systemctl daemon-reload
assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME.socket")" "262"
systemctl start "$UNIT_NAME.socket"
test -S "/run/$UNIT_NAME.sock"
systemctl stop "$UNIT_NAME.socket"

# Transient units via systemd-run
systemd-run --unit="$UNIT_NAME-transient" \
            --socket-property=ListenStream="127.0.0.1:$((PORT + 1))" \
            --socket-property=SocketProtocol=mptcp-auto \
            cat
assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME-transient.socket")" "$((262 | (1 << 30)))"
systemctl stop "$UNIT_NAME-transient.socket"

(! systemd-run --unit="$UNIT_NAME-transient-bad" \
               --socket-property=ListenStream="127.0.0.1:$((PORT + 2))" \
               --socket-property=SocketProtocol=sctp-auto \
               cat)
