#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for the ":" uid/gid/mode modifier
#
set -eux
set -o pipefail

rm -rf /tmp/somedir
mkdir -p /tmp/somedir
touch /tmp/somedir/somefile

systemd-tmpfiles --remove - <<EOF
R_ /tmp/somedir
EOF

test -f /tmp/somedir/somefile

systemd-tmpfiles --remove --factory-reset - <<EOF
R_ /tmp/somedir
EOF

test ! -f /tmp/somedir/somefile
test ! -d /tmp/somedir/
