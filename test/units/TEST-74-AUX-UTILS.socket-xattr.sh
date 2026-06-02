#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Extended attributes on socket inodes (and hence the XAttr*= socket settings and
# "varlinkctl list-sockets") require Linux 7.0 or newer. Skip on older kernels.
if ! systemd-analyze compare-versions "$(uname -r)" ge 7.0; then
    echo "Kernel is older than 7.0, socket inode extended attributes unsupported, skipping." >&2
    exit 0
fi

UNIT_SOCKET_PATH="/run/test-socket-xattr.sock"
RUN_SOCKET_PATH="/run/test-socket-xattr-run.sock"

at_exit() {
    set +e
    systemctl stop test-socket-xattr.socket test-socket-xattr-run.socket
    systemctl reset-failed test-socket-xattr-run.socket test-socket-xattr-run.service
    rm -f /run/systemd/system/test-socket-xattr.socket
    rm -f /run/systemd/system/test-socket-xattr.service
    systemctl daemon-reload
}
trap at_exit EXIT

# Read the single user.varlink extended attribute value off the given path.
read_role() {
    getfattr --absolute-names --only-values --name=user.varlink "$1"
}

# ------------------------------------------------------------------------------
# 1) XAttr*= configured in a unit file on disk
# ------------------------------------------------------------------------------

# A matching .service unit is required to be able to start the .socket unit. It is
# never actually triggered here (we only check the listening socket), so a trivial
# service is sufficient.
cat >/run/systemd/system/test-socket-xattr.service <<EOF
[Service]
ExecStart=/bin/true
EOF

cat >/run/systemd/system/test-socket-xattr.socket <<EOF
[Unit]
Description=Socket xattr test (on-disk unit)

[Socket]
ListenStream=$UNIT_SOCKET_PATH
SocketMode=0666
XAttrEntryPoint=user.varlink=entrypoint
XAttrListen=user.varlink=listen
XAttrAccept=user.varlink=server
RemoveOnStop=true
EOF

systemctl daemon-reload
systemctl start test-socket-xattr.socket

# The socket node bound into the file system must carry the entrypoint xattr.
test -S "$UNIT_SOCKET_PATH"
[[ "$(read_role "$UNIT_SOCKET_PATH")" == "entrypoint" ]]

# The configured settings must be exposed again via the manager's D-Bus properties.
systemctl show -P XAttrEntryPoint test-socket-xattr.socket | grep "user.varlink=entrypoint" >/dev/null
systemctl show -P XAttrListen test-socket-xattr.socket | grep "user.varlink=listen" >/dev/null
systemctl show -P XAttrAccept test-socket-xattr.socket | grep "user.varlink=server" >/dev/null

# ------------------------------------------------------------------------------
# 2) XAttr*= set via "systemd-run --socket-property="
# ------------------------------------------------------------------------------

rm -f "$RUN_SOCKET_PATH"

# systemd-run synthesizes the matching test-socket-xattr-run.service for us.
systemd-run \
    --unit=test-socket-xattr-run \
    --service-type=oneshot \
    --remain-after-exit \
    --socket-property=ListenStream="$RUN_SOCKET_PATH" \
    --socket-property=SocketMode=0666 \
    --socket-property=XAttrEntryPoint=user.varlink=entrypoint \
    --socket-property=XAttrListen=user.varlink=listen \
    --socket-property=XAttrAccept=user.varlink=server \
    --socket-property=RemoveOnStop=true \
    true

systemctl cat test-socket-xattr-run.socket

# The XAttr*= settings must have been serialized into the transient socket unit.
grep "^XAttrEntryPoint=user.varlink=entrypoint$" /run/systemd/transient/test-socket-xattr-run.socket >/dev/null
grep "^XAttrListen=user.varlink=listen$" /run/systemd/transient/test-socket-xattr-run.socket >/dev/null
grep "^XAttrAccept=user.varlink=server$" /run/systemd/transient/test-socket-xattr-run.socket >/dev/null

# And the transient socket must validate cleanly.
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/test-socket-xattr-run.socket"

# Wait for the transient socket to be bound, then check the entrypoint xattr.
test -S "$RUN_SOCKET_PATH"
[[ "$(read_role "$RUN_SOCKET_PATH")" == "entrypoint" ]]

systemctl show -P XAttrEntryPoint test-socket-xattr-run.socket | grep "user.varlink=entrypoint" >/dev/null
systemctl show -P XAttrListen test-socket-xattr-run.socket | grep "user.varlink=listen" >/dev/null
systemctl show -P XAttrAccept test-socket-xattr-run.socket | grep "user.varlink=server" >/dev/null
