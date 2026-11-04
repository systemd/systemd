#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    systemctl stop inherit-slice.socket
    rm -f /run/systemd/system/inherit-slice{-client.service,@.service,.socket} /tmp/client.out
    systemctl daemon-reload
}

trap at_exit EXIT

cat >/run/systemd/system/inherit-slice.socket <<EOF
[Socket]
ListenStream=/run/inherit-slice.sk
Accept=yes
PropagateSlice=yes
EOF

cat >/run/systemd/system/inherit-slice@.service <<EOF
[Unit]
BindsTo=inherit-slice.socket
After=inherit-slice.socket

[Service]
ExecStartPre=echo waldo
ExecStart=sleep infinity
StandardOutput=socket
EOF

cat >/run/systemd/system/inherit-slice-client.service <<EOF
[Unit]
BindsTo=inherit-slice.socket
After=inherit-slice.socket

[Service]
Slice=system-test.slice
ExecStart=socat -U - UNIX-CONNECT:/run/inherit-slice.sk
StandardOutput=file:/tmp/client.out
EOF

systemctl daemon-reload
systemctl start inherit-slice-client.service

waitfor() {
    local file="${1:?}"

    for _ in {0..20}; do
        if grep -q waldo "$file"; then
            return 0
        fi

        sleep .5
    done

    echo >&2 "Timeout while waiting for the expected output"
    return 1
}

# Wait until the word "waldo" shows in the output file, to know that a connection
# was made
waitfor /tmp/client.out

# Verify that the service handling the connection was started under the client's slice
systemctl show -P Slice 'inherit-slice@*.service' | grep system-test.slice >/dev/null

# Verify that we don't lose track of state when we re-exec the daemon
systemctl daemon-reexec
systemctl show -P Slice 'inherit-slice@*.service' | grep system-test.slice >/dev/null
