#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Basic tests for types creating fifos
set -eux
set -o pipefail

rm -fr /tmp/p
mkdir  /tmp/p
touch  /tmp/p/f1

systemd-tmpfiles --dry-run --create - <<EOF
p     /tmp/p/fifo1    0666 - - - -
EOF

test ! -p /tmp/p/fifo1

systemd-tmpfiles --create - <<EOF
p     /tmp/p/fifo1    0666 - - - -
EOF

test -p /tmp/p/fifo1
test "$(stat -c %U:%G:%a /tmp/p/fifo1)" = "root:root:666"

# Refuse to overwrite an existing file. Error is not propagated.
systemd-tmpfiles --create - <<EOF
p     /tmp/p/f1    0666 - - - -
EOF

test -f /tmp/p/f1

# unless '+' prefix is used
systemd-tmpfiles --create - <<EOF
p+     /tmp/p/f1    0666 - - - -
EOF

test -p /tmp/p/f1
test "$(stat -c %U:%G:%a /tmp/p/f1)" = "root:root:666"

#
# Must be fixed
#
# mkdir /tmp/p/daemon
# #ln -s /root /tmp/F/daemon/unsafe-symlink
# chown -R --no-dereference daemon:daemon /tmp/p/daemon
#
# systemd-tmpfiles --create - <<EOF
# p      /tmp/p/daemon/fifo2    0666 daemon daemon - -
# EOF
