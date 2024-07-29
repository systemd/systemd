#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for character and block device creation
#
set -eux
set -o pipefail

rm -rf /tmp/dev
mkdir /tmp/dev

# We are running tests in /tmp, which would normally be mounted nodev,
# so we only try with --dry-run.

systemd-tmpfiles --dry-run --create - <<EOF
c /tmp/dev/char  - - - - 11:12
b /tmp/dev/block - - - - 11:14
EOF

test ! -e /tmp/dev/char
test ! -e /tmp/dev/block

systemd-tmpfiles --dry-run --create - <<EOF
c+ /tmp/dev/char  - - - - 11:12
b+ /tmp/dev/block - - - - 11:14
EOF

test ! -e /tmp/dev/char
test ! -e /tmp/dev/block
