#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

UNIT_NAME="TEST-07-PID1-mptcp-auto-$RANDOM"
PORT=7419
MPTCP_ENABLED=

at_exit() {
    set +e
    systemctl stop "$UNIT_NAME.socket" "$UNIT_NAME-transient.socket" "$UNIT_NAME-bus.socket" "$UNIT_NAME-bad.socket"
    rm -f /run/systemd/system/"$UNIT_NAME".socket \
          /run/systemd/system/"$UNIT_NAME"@.service \
          /run/systemd/system/"$UNIT_NAME"-bus@.service \
          /run/systemd/system/"$UNIT_NAME"-bad.socket \
          /run/systemd/system/"$UNIT_NAME"-bad@.service \
          /run/"$UNIT_NAME".sock
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
RemoveOnStop=yes
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

    # Plain "mptcp" must not fall back to TCP, though
    sed -i 's/^SocketProtocol=.*/SocketProtocol=mptcp/' /run/systemd/system/"$UNIT_NAME".socket
    systemctl daemon-reload
    (! systemctl start "$UNIT_NAME.socket")
    (! is_listening)
    systemctl stop "$UNIT_NAME.socket"
    systemctl reset-failed "$UNIT_NAME.socket"
    sed -i 's/^SocketProtocol=.*/SocketProtocol=mptcp-auto/' /run/systemd/system/"$UNIT_NAME".socket
    systemctl daemon-reload

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
test ! -e "/run/$UNIT_NAME.sock"

# An empty assignment resets the setting
cat >>/run/systemd/system/"$UNIT_NAME".socket <<EOF
SocketProtocol=
EOF
systemctl daemon-reload
assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME.socket")" "0"

# Invalid values in unit files are ignored, i.e. the setting is left at its default. The numeric value is
# IPPROTO_SCTP with the SOCKET_PROTOCOL_AUTO flag set, which is only valid for MPTCP.
cat >/run/systemd/system/"$UNIT_NAME"-bad@.service <<EOF
[Service]
ExecStart=cat
StandardInput=socket
EOF
for v in sctp-auto "$((132 | (1 << 30)))"; do
    cat >/run/systemd/system/"$UNIT_NAME"-bad.socket <<EOF
[Socket]
ListenStream=127.0.0.1:$((PORT + 3))
SocketProtocol=$v
Accept=yes
EOF
    systemctl daemon-reload
    assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME-bad.socket")" "0"
done

# Transient units via systemd-run
systemd-run --unit="$UNIT_NAME-transient" \
            --socket-property=ListenStream="127.0.0.1:$((PORT + 1))" \
            --socket-property=SocketProtocol=mptcp-auto \
            cat
assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME-transient.socket")" "$((262 | (1 << 30)))"
systemctl stop "$UNIT_NAME-transient.socket"

# Transient units via the bus directly, bypassing the client-side parser. Check that the value is
# serialized correctly into the transient unit file, i.e. survives a daemon-reload.
cat >/run/systemd/system/"$UNIT_NAME"-bus@.service <<EOF
[Service]
ExecStart=cat
StandardInput=socket
EOF
systemctl daemon-reload

start_bus_socket() {
    busctl call \
           org.freedesktop.systemd1 \
           /org/freedesktop/systemd1 \
           org.freedesktop.systemd1.Manager \
           StartTransientUnit 'ssa(sv)a(sa(sv))' \
           "$UNIT_NAME-bus.socket" fail \
           3 \
           Listen 'a(ss)' 1 Stream "127.0.0.1:$((PORT + 2))" \
           Accept b true \
           SocketProtocol i "$1" \
           0
}

for v in 0 "$((262 | (1 << 30)))"; do
    start_bus_socket "$v"
    assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME-bus.socket")" "$v"
    systemctl daemon-reload
    assert_eq "$(systemctl show -P SocketProtocol "$UNIT_NAME-bus.socket")" "$v"
    systemctl stop "$UNIT_NAME-bus.socket"
    # Wait until the transient unit is garbage collected, so that we can create it again
    timeout 30 bash -c "until [[ \"\$(systemctl show -P LoadState '$UNIT_NAME-bus.socket')\" == not-found ]]; do sleep .5; done"
done

# SOCKET_PROTOCOL_AUTO is only valid in combination with MPTCP
(! start_bus_socket "$((132 | (1 << 30)))")
(! start_bus_socket "$((1 << 30))")
