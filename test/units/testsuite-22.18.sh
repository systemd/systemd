#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for the "@" factory reset modifier
#
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

systemd-tmpfiles --create - <<EOF
d /tmp/somedir
f /tmp/somedir/somefile - - - - baz
EOF

test -f /tmp/somedir/somefile
grep -q baz /tmp/somedir/somefile

systemd-tmpfiles --purge-owned - <<EOF
d /tmp/somedir
f /tmp/somedir/somefile - - - - baz
EOF

test ! -f /tmp/somedir/somefile
test ! -d /tmp/somedir/
