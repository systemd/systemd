#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Verifies the issues described by https://github.com/systemd/systemd/issues/10191
set -eux
set -o pipefail

rm -rf /tmp/test-prefix

mkdir /tmp/test-prefix
touch /tmp/test-prefix/file

systemd-tmpfiles --remove - <<EOF
r /tmp/test-prefix
r /tmp/test-prefix/file
EOF

test ! -f /tmp/test-prefix/file
test ! -f /tmp/test-prefix

mkdir /tmp/test-prefix
touch /tmp/test-prefix/file

systemd-tmpfiles --remove - <<EOF
r /tmp/test-prefix/file
r /tmp/test-prefix
EOF

test ! -f /tmp/test-prefix/file
test ! -f /tmp/test-prefix
