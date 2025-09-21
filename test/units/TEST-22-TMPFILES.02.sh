#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Basic tests for types creating directories
set -eux
set -o pipefail

rm -fr /tmp/{C,d,D,e}
mkdir  /tmp/{C,d,D,e}

#
# 'd'
#
mkdir /tmp/d/2
chmod 777 /tmp/d/2

systemd-tmpfiles --dry-run --create - <<EOF
d     /tmp/d/1    0755 daemon daemon - -
d     /tmp/d/2    0755 daemon daemon - -
EOF

test ! -d /tmp/d/1
test -d /tmp/d/2

systemd-tmpfiles --create - <<EOF
d     /tmp/d/1    0755 daemon daemon - -
d     /tmp/d/2    0755 daemon daemon - -
EOF

test -d /tmp/d/1
test "$(stat -c %U:%G:%a /tmp/d/1)" = "daemon:daemon:755"

test -d /tmp/d/2
test "$(stat -c %U:%G:%a /tmp/d/2)" = "daemon:daemon:755"

#
# 'D'
#
mkdir /tmp/D/2
chmod 777 /tmp/D/2
touch /tmp/D/2/foo

systemd-tmpfiles --create - <<EOF
D     /tmp/D/1    0755 daemon daemon - -
D     /tmp/D/2    0755 daemon daemon - -
EOF

test -d /tmp/D/1
test "$(stat -c %U:%G:%a /tmp/D/1)" = "daemon:daemon:755"

test -d /tmp/D/2
test "$(stat -c %U:%G:%a /tmp/D/2)" = "daemon:daemon:755"

systemd-tmpfiles --remove - <<EOF
D     /tmp/D/2    0755 daemon daemon - -
EOF

# the content of '2' should be removed
test "$(echo /tmp/D/2/*)" = "/tmp/D/2/*"

#
# 'e'
#
mkdir -p /tmp/e/2/{d1,d2}
chmod 777 /tmp/e/2
chmod 777 /tmp/e/2/d*

systemd-tmpfiles --create - <<EOF
e     /tmp/e/1     0755 daemon daemon - -
e     /tmp/e/2/*   0755 daemon daemon - -
EOF

test ! -d /tmp/e/1

test -d /tmp/e/2
test "$(stat -c %U:%G:%a /tmp/e/2)" = "root:root:777"

test -d /tmp/e/2/d1
test "$(stat -c %U:%G:%a /tmp/e/2/d1)" = "daemon:daemon:755"
test -d /tmp/e/2/d2
test "$(stat -c %U:%G:%a /tmp/e/2/d2)" = "daemon:daemon:755"

# 'e' operates on directories only
mkdir -p /tmp/e/3/{d1,d2}
chmod 777 /tmp/e/3
chmod 777 /tmp/e/3/d*
touch /tmp/e/3/f1
chmod 644 /tmp/e/3/f1

systemd-tmpfiles --create - <<EOF
e     /tmp/e/3/*   0755 daemon daemon - -
EOF

# the directories should have been processed although systemd-tmpfiles failed
# previously due to the presence of a file.
test -d /tmp/e/3/d1
test "$(stat -c %U:%G:%a /tmp/e/3/d1)" = "daemon:daemon:755"
test -d /tmp/e/3/d2
test "$(stat -c %U:%G:%a /tmp/e/3/d2)" = "daemon:daemon:755"

test -f /tmp/e/3/f1
test "$(stat -c %U:%G:%a /tmp/e/3/f1)" = "root:root:644"

#
# 'C'
#

mkdir /tmp/C/{0,1,2,3}-origin
touch /tmp/C/{1,2,3}-origin/f1
chmod 755 /tmp/C/{1,2,3}-origin/f1

mkdir /tmp/C/{2,3}
touch /tmp/C/3/f1

systemd-tmpfiles --dry-run --create - <<EOF
C     /tmp/C/1    0755 daemon daemon - /tmp/C/1-origin
C     /tmp/C/2    0755 daemon daemon - /tmp/C/2-origin
EOF

test ! -d /tmp/C/1
test -d /tmp/C/2

systemd-tmpfiles --create - <<EOF
C     /tmp/C/1    0755 daemon daemon - /tmp/C/1-origin
C     /tmp/C/2    0755 daemon daemon - /tmp/C/2-origin
EOF

test -d /tmp/C/1
test "$(stat -c %U:%G:%a /tmp/C/1/f1)" = "daemon:daemon:755"
test -d /tmp/C/2
test "$(stat -c %U:%G:%a /tmp/C/2/f1)" = "daemon:daemon:755"

systemd-tmpfiles --create - <<EOF
C     /tmp/C/3    0755 daemon daemon - /tmp/C/3-origin
C     /tmp/C/4    0755 daemon daemon - /tmp/C/definitely-missing
EOF

test "$(stat -c %U:%G:%a /tmp/C/3/f1)" = "root:root:644"
test ! -e /tmp/C/4

touch /tmp/C/3-origin/f{2,3,4}
echo -n ABC > /tmp/C/3/f1

systemd-tmpfiles --create - <<EOF
C+     /tmp/C/3    0755 daemon daemon - /tmp/C/3-origin
EOF

# Test that the trees got merged, even though /tmp/C/3 already exists.
test -e /tmp/C/3/f1
test -e /tmp/C/3/f2
test -e /tmp/C/3/f3
test -e /tmp/C/3/f4

# Test that /tmp/C/3/f1 did not get overwritten.
test "$(cat /tmp/C/3/f1)" = "ABC"

# Check that %U expands to 0, both in the path and in the argument.
home='/tmp/C'
systemd-tmpfiles --create - <<EOF
C     $home/%U    - - - - $home/%U-origin
EOF

test -d "$home/0"

# Check that %h expands to $home, both in the path and in the argument.
HOME="$home" \
systemd-tmpfiles --create - <<EOF
C     %h/5    - - - - %h/3-origin
EOF

test -f "$home/5/f1"

# Check that %h in the path is expanded, but
# the result of this expansion is not expanded once again.
root='/tmp/C/6'
home='/%U'
mkdir -p "$root/usr/share/factory$home"
HOME="$home" \
systemd-tmpfiles --create --root="$root" - <<EOF
C     %h    - - - -
EOF

test -d "$root$home"
