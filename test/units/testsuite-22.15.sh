#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for the "@" factory reset modifier
#
set -eux
set -o pipefail

rm -rf /tmp/somedir
mkdir -p /tmp/somedir
echo bar >/tmp/somedir/somefile

systemd-tmpfiles --remove - <<EOF
R@ /tmp/somedir
f /tmp/somedir/somefile - - - - baz
EOF

test -f /tmp/somedir/somefile
grep -q bar /tmp/somedir/somefile

systemd-tmpfiles --remove --create --factory-reset=true - <<EOF
R@ /tmp/somedir
f /tmp/somedir/somefile - - - - baz
EOF

test -f /tmp/somedir/somefile
grep -q baz /tmp/somedir/somefile

systemd-tmpfiles --remove --factory-reset=true - <<EOF
R@ /tmp/somedir
EOF

test ! -f /tmp/somedir/somefile
test ! -d /tmp/somedir/
