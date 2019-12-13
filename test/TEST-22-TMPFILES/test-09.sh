#!/bin/bash

set -e
set -x

# Make sure that the "stat" output is not locale dependent.
export LANG=C LC_ALL=C

# first, create file without suid/sgid
systemd-tmpfiles --create - <<EOF
f     /tmp/xxx    0755 1 1 - -
f     /tmp/yyy    0755 1 1 - -
EOF

test "$(stat -c %F:%u:%g:%a /tmp/xxx)" = "regular empty file:1:1:755"
test "$(stat -c %F:%u:%g:%a /tmp/yyy)" = "regular empty file:1:1:755"

# then, add suid/sgid
systemd-tmpfiles --create - <<EOF
f     /tmp/xxx    04755
f     /tmp/yyy    02755
EOF

test "$(stat -c %F:%u:%g:%a /tmp/xxx)" = "regular empty file:1:1:4755"
test "$(stat -c %F:%u:%g:%a /tmp/yyy)" = "regular empty file:1:1:2755"

# then, chown the files to somebody else
systemd-tmpfiles --create - <<EOF
f     /tmp/xxx    - 2 2
f     /tmp/yyy    - 2 2
EOF

test "$(stat -c %F:%u:%g:%a /tmp/xxx)" = "regular empty file:2:2:4755"
test "$(stat -c %F:%u:%g:%a /tmp/yyy)" = "regular empty file:2:2:2755"

# then, chown the files to a third user/group but also drop to a mask that has
# both more and fewer bits set
systemd-tmpfiles --create - <<EOF
f     /tmp/xxx    0770 3 3
f     /tmp/yyy    0770 3 3
EOF

test "$(stat -c %F:%u:%g:%a /tmp/xxx)" = "regular empty file:3:3:770"
test "$(stat -c %F:%u:%g:%a /tmp/yyy)" = "regular empty file:3:3:770"

# return to the beginning
systemd-tmpfiles --create - <<EOF
f     /tmp/xxx    0755 1 1 - -
f     /tmp/yyy    0755 1 1 - -
EOF

test "$(stat -c %F:%u:%g:%a /tmp/xxx)" = "regular empty file:1:1:755"
test "$(stat -c %F:%u:%g:%a /tmp/yyy)" = "regular empty file:1:1:755"

# remove everything
systemd-tmpfiles --remove - <<EOF
r /tmp/xxx
r /tmp/yyy
EOF
