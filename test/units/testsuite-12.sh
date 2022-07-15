#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

echo "g adm - - -" | systemd-sysusers -

U=/run/systemd/system/test12.socket
cat >$U <<EOF
[Unit]
Description=Test 12 socket
[Socket]
Accept=yes
ListenStream=/run/test12.socket
SocketGroup=adm
SocketMode=0660
EOF

cat >/run/systemd/system/test12@.service <<EOF
[Unit]
Description=Test service
[Service]
StandardInput=socket
ExecStart=/bin/sh -x -c cat
EOF

systemctl start test12.socket
systemctl is-active test12.socket
[[ "$(stat --format='%G' /run/test12.socket)" == adm ]]
echo A | nc -w1 -U /run/test12.socket

mv $U ${U}.disabled
systemctl daemon-reload
systemctl is-active test12.socket
[[ "$(stat --format='%G' /run/test12.socket)" == adm ]]
echo B | nc -w1 -U /run/test12.socket && exit 1

mv ${U}.disabled $U
systemctl daemon-reload
systemctl is-active test12.socket
echo C | nc -w1 -U /run/test12.socket && exit 1
[[ "$(stat --format='%G' /run/test12.socket)" == adm ]]

systemctl restart test12.socket
systemctl is-active test12.socket
echo D | nc -w1 -U /run/test12.socket
[[ "$(stat --format='%G' /run/test12.socket)" == adm ]]

touch /testok
