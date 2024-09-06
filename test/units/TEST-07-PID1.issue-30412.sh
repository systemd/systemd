#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that socket FDs are not double closed on error: https://github.com/systemd/systemd/issues/30412

mkdir -p /run/systemd/system

rm -f /tmp/badbin
touch /tmp/badbin
chmod 744 /tmp/badbin

cat >/run/systemd/system/badbin_assert.service <<EOF
[Service]
ExecStart=/tmp/badbin
Restart=no
EOF

cat >/run/systemd/system/badbin_assert.socket <<EOF
[Socket]
ListenStream=@badbin_assert.socket
FlushPending=yes
EOF

systemctl daemon-reload
systemctl start badbin_assert.socket

socat - ABSTRACT-CONNECT:badbin_assert.socket

timeout 10 sh -c 'while systemctl is-active badbin_assert.service; do sleep .5; done'
[[ "$(systemctl show -P ExecMainStatus badbin_assert.service)" == 203 ]]
