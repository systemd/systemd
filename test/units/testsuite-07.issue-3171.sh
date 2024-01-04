#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# SocketGroup lost on daemon-reload with unit moving away temporarily
# Issue: https://github.com/systemd/systemd/issues/3171

echo "g adm - - -" | systemd-sysusers -

U=/run/systemd/system/issue-3171.socket
cat >$U <<EOF
[Unit]
Description=Test 12 socket
[Socket]
Accept=yes
ListenStream=/run/issue-3171.socket
SocketGroup=adm
SocketMode=0660
EOF

cat >/run/systemd/system/issue-3171@.service <<EOF
[Unit]
Description=Test service
[Service]
StandardInput=socket
ExecStart=sh -x -c cat
EOF

systemctl start issue-3171.socket
systemctl is-active issue-3171.socket
[[ "$(stat --format='%G' /run/issue-3171.socket)" == adm ]]
echo A | nc -w1 -U /run/issue-3171.socket

mv $U ${U}.disabled
systemctl daemon-reload
systemctl is-active issue-3171.socket
[[ "$(stat --format='%G' /run/issue-3171.socket)" == adm ]]
echo B | nc -w1 -U /run/issue-3171.socket && exit 1

mv ${U}.disabled $U
systemctl daemon-reload
systemctl is-active issue-3171.socket
echo C | nc -w1 -U /run/issue-3171.socket && exit 1
[[ "$(stat --format='%G' /run/issue-3171.socket)" == adm ]]

systemctl restart issue-3171.socket
systemctl is-active issue-3171.socket
echo D | nc -w1 -U /run/issue-3171.socket
[[ "$(stat --format='%G' /run/issue-3171.socket)" == adm ]]
