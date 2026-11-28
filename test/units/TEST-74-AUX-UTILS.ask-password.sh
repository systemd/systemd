#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

KEY=""
SOCKET_DIR=""

at_exit() {
    set +e
    systemctl stop waldo-ask-pw-agent.service
    systemctl stop test-askpw.service
    systemctl stop test-askpw-file.service
    [[ -n "$KEY" ]] && keyctl unlink "$KEY" @u
    rm -rf "$SOCKET_DIR"
}

trap at_exit EXIT

systemd-ask-password --help
systemd-tty-ask-password-agent --list

varlinkctl introspect /run/systemd/io.systemd.AskPassword

# Spawn an agent that always replies all ask password requests with "waldo"
systemd-run -u waldo-ask-pw-agent.service -p Environment=SYSTEMD_ASK_PASSWORD_AGENT_PASSWORD=waldo -p Type=notify systemd-tty-ask-password-agent --watch --console=/dev/console
assert_eq "$(systemd-ask-password --no-tty)" "waldo"
assert_eq "$(varlinkctl call /usr/bin/systemd-ask-password io.systemd.AskPassword.Ask '{"message":"foobar"}' | jq '.passwords[0]')" "\"waldo\""

# Per-request Varlink Ask flags must not leak across calls sharing one connection
SOCKET_DIR="$(mktemp -d)"
sock="$SOCKET_DIR/ask.sock"
KEY="$(keyctl add user test-askpw hunter2 @u)"

systemd-run --unit=test-askpw.service -p Type=notify -p KeyringMode=shared \
    systemd-socket-activate --accept --fdname=varlink -l "$sock" -- \
        systemd-ask-password

# timeoutUSec:0 disables the agent, so the keyring cache is the only source.
req_cached='{"method":"io.systemd.AskPassword.Ask","parameters":{"keyname":"test-askpw","timeoutUSec":0,"acceptCached":true}}'
req_plain='{"method":"io.systemd.AskPassword.Ask","parameters":{"keyname":"test-askpw","timeoutUSec":0}}'
printf '%s\0%s\0' "$req_cached" "$req_plain" | socat -t20 - "UNIX-CONNECT:$sock" >"$SOCKET_DIR/replies"
mapfile -d '' -t replies <"$SOCKET_DIR/replies"

assert_eq "${#replies[@]}" "2"
assert_in "hunter2" "${replies[0]}"
assert_not_in "hunter2" "${replies[1]}"
assert_in "NoPasswordAvailable" "${replies[1]}"

# A request that names a keyring has already been checked against that keyring, so agents must not answer
# it from their own cache, which isn't keyed by purpose (plymouth would hand a TPM2 PIN to a passphrase
# prompt). Without a keyring the agent's cache is the only one, so it remains allowed.
systemctl stop waldo-ask-pw-agent.service

check_ask_file_accept_cached() {
    local expected="${1:?}" pid
    shift

    systemd-run --unit=test-askpw-file.service --service-type=exec --collect \
        systemd-ask-password --no-tty --timeout=60 "$@" "Cache check"
    pid="$(systemctl show -P MainPID test-askpw-file.service)"
    timeout 30 bash -c "until grep -l '^PID=$pid\$' /run/systemd/ask-password/ask.* >/dev/null 2>&1; do sleep .1; done"
    grep "^AcceptCached=$expected\$" "$(grep -l "^PID=$pid\$" /run/systemd/ask-password/ask.*)"
    systemctl stop test-askpw-file.service
}

check_ask_file_accept_cached 0 --accept-cached --keyname=test-askpw-missing
check_ask_file_accept_cached 1 --accept-cached
check_ask_file_accept_cached 0
