#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for configuration directory and file precedences
#
set -eux

rm -f  /{usr/lib,etc}/tmpfiles.d/{L,w}-*.conf
rm -fr /tmp/precedence/{L,w}

mkdir -p /{usr/lib,etc}/tmpfiles.d
mkdir -p /tmp/precedence/{L,w}

#
# 'L'
#
ln -s /dev/null /tmp/precedence/L

# Overwrite the existing symlink
cat >/usr/lib/tmpfiles.d/L-z.conf<<EOF
L+ /tmp/precedence/L - - - - /usr/lib/tmpfiles.d/L-z.conf
EOF

systemd-tmpfiles --create
test "$(readlink /tmp/precedence/L)" = "/usr/lib/tmpfiles.d/L-z.conf"

# Files in /etc should override those in /usr
cat >/etc/tmpfiles.d/L-z.conf<<EOF
L+ /tmp/precedence/L - - - - /etc/tmpfiles.d/L-z.conf
EOF

systemd-tmpfiles --create
test "$(readlink /tmp/precedence/L)" = "/etc/tmpfiles.d/L-z.conf"

# /usr/…/L-a.conf has higher prio than /etc/…/L-z.conf
cat >/usr/lib/tmpfiles.d/L-a.conf<<EOF
L+ /tmp/precedence/L - - - - /usr/lib/tmpfiles.d/L-a.conf
EOF

systemd-tmpfiles --create
test "$(readlink /tmp/precedence/L)" = "/usr/lib/tmpfiles.d/L-a.conf"

# Files in /etc should override those in /usr
cat >/etc/tmpfiles.d/L-a.conf<<EOF
L+ /tmp/precedence/L - - - - /etc/tmpfiles.d/L-a.conf
EOF

systemd-tmpfiles --create
test "$(readlink /tmp/precedence/L)" = "/etc/tmpfiles.d/L-a.conf"

#
# 'w'
#
touch /tmp/precedence/w/f

# Multiple configuration files specifying 'w+' for the same path is allowed.
for i in a c; do
    cat >/usr/lib/tmpfiles.d/w-$i.conf<<EOF
w+ /tmp/precedence/w/f - - - - /usr/lib/tmpfiles.d/w-$i.conf\n
EOF
    cat >/etc/tmpfiles.d/w-$i.conf<<EOF
w+ /tmp/precedence/w/f - - - - /etc/tmpfiles.d/w-$i.conf\n
EOF
done

cat >/usr/lib/tmpfiles.d/w-b.conf<<EOF
w+ /tmp/precedence/w/f - - - - /usr/lib/tmpfiles.d/w-b.conf\n
EOF

systemd-tmpfiles --create
cmp /tmp/precedence/w/f <<EOF
/etc/tmpfiles.d/w-a.conf
/usr/lib/tmpfiles.d/w-b.conf
/etc/tmpfiles.d/w-c.conf
EOF
