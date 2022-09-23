#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for the ":" uid/gid/mode modifier
#
set -eux

rm -rf /tmp/someinode

systemd-tmpfiles --create - <<EOF
d /tmp/someinode :0123 :1 :1
EOF
test "$(stat -c %F:%u:%g:%a /tmp/someinode)" = "directory:1:1:123"

systemd-tmpfiles --create - <<EOF
d /tmp/someinode :0321 :2 :2
EOF
test "$(stat -c %F:%u:%g:%a /tmp/someinode)" = "directory:1:1:123"

systemd-tmpfiles --create - <<EOF
d /tmp/someinode 0321 2 2
EOF
test "$(stat -c %F:%u:%g:%a /tmp/someinode)" = "directory:2:2:321"

systemd-tmpfiles --create - <<EOF
d /tmp/someinode :0123 :1 :1
EOF
test "$(stat -c %F:%u:%g:%a /tmp/someinode)" = "directory:2:2:321"

rm -rf /tmp/someinode

systemd-tmpfiles --create - <<EOF
d /tmp/someinode :0123 :1 :1
EOF
test "$(stat -c %F:%u:%g:%a /tmp/someinode)" = "directory:1:1:123"

rm -rf /tmp/someinode
