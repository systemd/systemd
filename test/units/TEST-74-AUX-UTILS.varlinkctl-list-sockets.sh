#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# "varlinkctl list-sockets" relies on extended attributes on socket inodes, which
# require Linux 7.0 or newer. Skip on older kernels.
if ! systemd-analyze compare-versions "$(uname -r)" ge 7.0; then
    echo "Kernel is older than 7.0, socket inode extended attributes unsupported, skipping." >&2
    exit 0
fi

ENTRYPOINT_PATH="/run/test-list-sockets-entrypoint.sock"
PLAIN_PATH="/run/test-list-sockets-plain.sock"

at_exit() {
    set +e
    systemctl stop test-list-sockets-entrypoint.socket
    systemctl reset-failed test-list-sockets-entrypoint.socket test-list-sockets-entrypoint.service
    systemctl stop test-list-sockets-plain.socket
    systemctl reset-failed test-list-sockets-plain.socket test-list-sockets-plain.service
    rm -f "$ENTRYPOINT_PATH" "$PLAIN_PATH"
}
trap at_exit EXIT

rm -f "$ENTRYPOINT_PATH" "$PLAIN_PATH"

# A listening socket tagged as a Varlink entrypoint.
systemd-run \
    --unit=test-list-sockets-entrypoint \
    --service-type=oneshot \
    --remain-after-exit \
    --socket-property=ListenStream="$ENTRYPOINT_PATH" \
    --socket-property=SocketMode=0666 \
    --socket-property=XAttrEntryPoint=user.varlink=entrypoint \
    --socket-property=RemoveOnStop=true \
    true

# A listening socket *without* the entrypoint marker, which must be ignored.
systemd-run \
    --unit=test-list-sockets-plain \
    --service-type=oneshot \
    --remain-after-exit \
    --socket-property=ListenStream="$PLAIN_PATH" \
    --socket-property=SocketMode=0666 \
    --socket-property=RemoveOnStop=true \
    true

test -S "$ENTRYPOINT_PATH"
test -S "$PLAIN_PATH"

# Plain text output should run cleanly and mention the entrypoint socket.
varlinkctl list-sockets
varlinkctl list-sockets | grep "$ENTRYPOINT_PATH" >/dev/null

# JSON output is an array of {path, access} objects. The entrypoint socket must be
# present...
json="$(varlinkctl --json=short list-sockets)"
echo "$json" | jq -e --arg p "$ENTRYPOINT_PATH" 'any(.[]; .path == $p)' >/dev/null
# ...and carry an "access" field (either "yes" or "No (…)").
echo "$json" | jq -e --arg p "$ENTRYPOINT_PATH" 'any(.[]; .path == $p and (.access | type == "string"))' >/dev/null

# The socket without the entrypoint xattr must NOT be listed.
(! echo "$json" | jq -e --arg p "$PLAIN_PATH" 'any(.[]; .path == $p)' >/dev/null)

# Stopping the socket unit must make the entrypoint disappear from the listing again.
systemctl stop test-list-sockets-entrypoint.socket
test ! -S "$ENTRYPOINT_PATH"
(! varlinkctl --json=short list-sockets | jq -e --arg p "$ENTRYPOINT_PATH" 'any(.[]; .path == $p)' >/dev/null)

systemctl stop test-list-sockets-plain.socket
test ! -S "$PLAIN_PATH"
