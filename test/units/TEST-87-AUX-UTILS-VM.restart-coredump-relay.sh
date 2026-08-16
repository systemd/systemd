#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

USER_NAME="testuser"
USER_UID="$(id -u "$USER_NAME")"
USER_MACHINE="$USER_NAME@"
USER_MANAGER="user@$USER_UID.service"
USER_HELPER="/run/restart-coredump-relay-crash"
SOCKET_HELPER="/run/restart-coredump-socket-server"
RECEIVER_DROPIN="/run/systemd/system/systemd-coredump@.service.d/50-restart-coredump-relay-gate.conf"
RECEIVER_READY="/run/restart-coredump-relay-receiver-ready"
RECEIVER_RELEASE="/run/restart-coredump-relay-receiver-release"
suffix="$RANDOM"

USER_UNIT="restart-coredump-relay-$suffix.service"
USER_STATE="/run/user/$USER_UID/restart-coredump-relay-$suffix"
SOCKET_BASENAME="restart-coredump-socket-$suffix"
SOCKET_UNIT="$SOCKET_BASENAME.socket"
SOCKET_SERVICE="$SOCKET_BASENAME.service"
SOCKET_PATH="/run/$SOCKET_BASENAME.sock"
SOCKET_STATE="/run/$SOCKET_BASENAME"
SOCKET_FILE="/run/systemd/system/$SOCKET_UNIT"
SERVICE_FILE="/run/systemd/system/$SOCKET_SERVICE"
linger_was_enabled="$(loginctl show-user "$USER_NAME" -P Linger 2>/dev/null || true)"

systemctl_user() {
    systemctl --user --machine "$USER_MACHINE" "$@"
}

wait_for_core() {
    local pid="$1"

    timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$pid/status' >/dev/null; do sleep 0.05; done"
}

wait_for_receiver() {
    timeout 30 bash -c "until [[ -e '$RECEIVER_READY' ]]; do sleep 0.05; done"
}

wait_for_coredump_helpers() {
    timeout 60 bash -c 'while systemctl --quiet is-active "systemd-coredump@*.service"; do sleep 0.1; done'
}

release_receiver() {
    : >"$RECEIVER_RELEASE"
    wait_for_coredump_helpers
}

reset_receiver_gate() {
    rm -f "$RECEIVER_READY" "$RECEIVER_RELEASE"
}

cleanup() {
    set +e

    : >"$RECEIVER_RELEASE"
    wait_for_coredump_helpers
    systemctl_user stop "$USER_UNIT"
    systemctl stop "$SOCKET_SERVICE" "$SOCKET_UNIT"

    rm -f \
        "$RECEIVER_DROPIN" \
        "$RECEIVER_READY" \
        "$RECEIVER_RELEASE" \
        "$USER_HELPER" \
        "$SOCKET_HELPER" \
        "$SOCKET_FILE" \
        "$SERVICE_FILE" \
        "$SOCKET_PATH" \
        "$USER_STATE".* \
        "$SOCKET_STATE".*
    rmdir "${RECEIVER_DROPIN%/*}"
    systemctl daemon-reload
    systemctl_user daemon-reload
    systemctl_user reset-failed "$USER_UNIT"

    if [[ "$linger_was_enabled" != yes ]]; then
        loginctl disable-linger "$USER_NAME"
    fi
}

trap cleanup EXIT

(! systemd-detect-virt -cq)
sysctl kernel.core_pattern | grep systemd-coredump >/dev/null
sysctl kernel.core_pattern | grep '%F' >/dev/null

cat >"$USER_HELPER" <<'EOF'
#!/usr/bin/env bash
set -eu

state="${1:?}"
generation=0
if [[ -r "$state.generation" ]]; then
    read -r generation <"$state.generation"
fi
generation=$((generation + 1))
printf '%s\n' "$generation" >"$state.generation"
printf '%s\n' "$$" >"$state.pid.$generation"

if (( generation > 1 )); then
    exec /usr/bin/sleep infinity
fi

# Keep enough dirty anonymous memory resident to block the kernel on the gated receiver.
printf -v dirty '%*s' $((8 * 1024 * 1024)) x
: >"$state.ready"
while [[ ! -e "$state.trigger" ]]; do
    :
done

kill -SEGV "$$"
EOF
chmod +x "$USER_HELPER"

cat >"$SOCKET_HELPER" <<'EOF'
#!/usr/bin/env bash
set -eu

if [[ "${1:?}" == client ]]; then
    exec python3 -c '
import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(10)
    client.connect(sys.argv[1])
    client.sendall(sys.argv[2].encode())
    client.shutdown(socket.SHUT_WR)

    reply = bytearray()
    while data := client.recv(65536):
        reply.extend(data)

print(reply.decode())
' "${2:?}" "${3:?}"
fi

state="${2:?}"
generation=0
if [[ -r "$state.generation" ]]; then
    read -r generation <"$state.generation"
fi
generation=$((generation + 1))
printf '%s\n' "$generation" >"$state.generation"
printf '%s\n' "$$" >"$state.pid.$generation"

# Keep the coredumping main process large, but accept one connection at a time in a child. The
# child is synchronously reaped before generation one crashes, preserving the one-TGID condition.
printf -v dirty '%*s' $((8 * 1024 * 1024)) x
: >"$state.ready.$generation"
while :; do
    python3 -c '
import socket
import sys

with socket.socket(fileno=3) as listener:
    connection, _ = listener.accept()
    with connection:
        request = connection.recv(65536)
        connection.sendall(f"{sys.argv[1]}:".encode() + request)
' "$generation"

    if (( generation == 1 )) && [[ -e "$state.trigger" ]]; then
        kill -SEGV "$$"
    fi
done
EOF
chmod +x "$SOCKET_HELPER"

mkdir -p "${RECEIVER_DROPIN%/*}"
cat >"$RECEIVER_DROPIN" <<EOF
[Service]
ExecStartPre=/bin/bash -c 'touch "$RECEIVER_READY"; while [[ ! -e "$RECEIVER_RELEASE" ]]; do sleep 0.05; done'
EOF
systemctl daemon-reload

loginctl enable-linger "$USER_NAME"
systemctl start "$USER_MANAGER"

systemd-run \
    --user \
    --machine "$USER_MACHINE" \
    --unit "$USER_UNIT" \
    --service-type exec \
    --property LimitCORE=infinity \
    --property Restart=on-failure \
    --property RestartDuringCoredump=yes \
    --property RestartSec=0 \
    -- "$USER_HELPER" "$USER_STATE"

timeout 30 bash -c "until [[ -e '$USER_STATE.ready' ]]; do sleep 0.05; done"
user_pid="$(<"$USER_STATE.pid.1")"
user_invocation="$(systemctl_user show -P InvocationID "$USER_UNIT")"

[[ "$(systemctl_user show -P MainPID "$USER_UNIT")" -eq "$user_pid" ]]
[[ "$(systemctl_user show -P RestartDuringCoredump "$USER_UNIT")" == yes ]]
grep -F "/user.slice/user-$USER_UID.slice/user@$USER_UID.service/" "/proc/$user_pid/cgroup" >/dev/null

: >"$USER_STATE.trigger"
wait_for_receiver
wait_for_core "$user_pid"

# The kernel helper reports to PID 1. PID 1 must map the cgroup owner and relay the pidfd to this
# user manager before it can replace the still-coredumping user service process.
timeout 30 bash -c "until [[ \$(systemctl --user --machine '$USER_MACHINE' show -P NRestarts '$USER_UNIT') -eq 1 && -e '$USER_STATE.pid.2' ]]; do sleep 0.05; done"
new_user_pid="$(systemctl_user show -P MainPID "$USER_UNIT")"
new_user_invocation="$(systemctl_user show -P InvocationID "$USER_UNIT")"
[[ "$new_user_pid" -eq "$(<"$USER_STATE.pid.2")" ]]
[[ "$new_user_pid" -ne "$user_pid" ]]
[[ "$new_user_invocation" != "$user_invocation" ]]
systemctl_user --quiet is-active "$USER_UNIT"
grep '^CoreDumping:[[:space:]]*1$' "/proc/$user_pid/status" >/dev/null

release_receiver
timeout 60 bash -c "until [[ ! -e '/proc/$user_pid' ]]; do sleep 0.1; done"
timeout 60 bash -c "until coredumpctl info '$user_pid' >/dev/null 2>&1; do sleep 0.1; done"
[[ "$(systemctl_user show -P MainPID "$USER_UNIT")" -eq "$new_user_pid" ]]
[[ "$(systemctl_user show -P InvocationID "$USER_UNIT")" == "$new_user_invocation" ]]
[[ "$(systemctl_user show -P NRestarts "$USER_UNIT")" -eq 1 ]]

reset_receiver_gate

cat >"$SOCKET_FILE" <<EOF
[Socket]
Accept=no
ListenStream=$SOCKET_PATH
RemoveOnStop=yes
EOF

cat >"$SERVICE_FILE" <<EOF
[Service]
Type=exec
ExecStart=$SOCKET_HELPER server $SOCKET_STATE
Restart=on-failure
RestartDuringCoredump=yes
RestartSec=0
LimitCORE=infinity
EOF

systemctl daemon-reload
systemctl start "$SOCKET_UNIT"

[[ "$("$SOCKET_HELPER" client "$SOCKET_PATH" before)" == "1:before" ]]
timeout 30 bash -c "until [[ -e '$SOCKET_STATE.ready.1' ]]; do sleep 0.05; done"
socket_pid="$(<"$SOCKET_STATE.pid.1")"
socket_invocation="$(systemctl show -P InvocationID "$SOCKET_SERVICE")"

: >"$SOCKET_STATE.trigger"
[[ "$("$SOCKET_HELPER" client "$SOCKET_PATH" crash)" == "1:crash" ]]
wait_for_receiver
wait_for_core "$socket_pid"
timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$SOCKET_SERVICE') -eq 1 && -e '$SOCKET_STATE.ready.2' ]]; do sleep 0.05; done"

new_socket_pid="$(systemctl show -P MainPID "$SOCKET_SERVICE")"
new_socket_invocation="$(systemctl show -P InvocationID "$SOCKET_SERVICE")"
[[ "$new_socket_pid" -eq "$(<"$SOCKET_STATE.pid.2")" ]]
[[ "$new_socket_pid" -ne "$socket_pid" ]]
[[ "$new_socket_invocation" != "$socket_invocation" ]]
systemctl --quiet is-active "$SOCKET_UNIT"
systemctl --quiet is-active "$SOCKET_SERVICE"
grep '^CoreDumping:[[:space:]]*1$' "/proc/$socket_pid/status" >/dev/null

# Accept=no leaves the listening socket in the socket unit, so the replacement can immediately
# inherit it and serve a new connection before the old process has finished dumping.
[[ "$("$SOCKET_HELPER" client "$SOCKET_PATH" after)" == "2:after" ]]

release_receiver
timeout 60 bash -c "until [[ ! -e '/proc/$socket_pid' ]]; do sleep 0.1; done"
timeout 60 bash -c "until coredumpctl info '$socket_pid' >/dev/null 2>&1; do sleep 0.1; done"
[[ "$(systemctl show -P MainPID "$SOCKET_SERVICE")" -eq "$new_socket_pid" ]]
[[ "$(systemctl show -P InvocationID "$SOCKET_SERVICE")" == "$new_socket_invocation" ]]
[[ "$(systemctl show -P NRestarts "$SOCKET_SERVICE")" -eq 1 ]]
[[ "$("$SOCKET_HELPER" client "$SOCKET_PATH" final)" == "2:final" ]]

systemctl_user stop "$USER_UNIT"
systemctl stop "$SOCKET_SERVICE" "$SOCKET_UNIT"
