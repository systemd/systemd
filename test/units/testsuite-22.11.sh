#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
set -x

rm -fr /tmp/x
mkdir  /tmp/x

#
# 'x'
#
mkdir -p /tmp/x/{1,2}
touch /tmp/x/1/{x1,x2} /tmp/x/2/{y1,y2} /tmp/x/{z1,z2}

systemd-tmpfiles --clean - <<EOF
d /tmp/x - - - 0
x /tmp/x/1
EOF

find /tmp/x | sort
test -d /tmp/x/1
test -f /tmp/x/1/x1
test -f /tmp/x/1/x2
test ! -d /tmp/x/2
test ! -f /tmp/x/2/x1
test ! -f /tmp/x/2/x2
test ! -f /tmp/x/z1
test ! -f /tmp/x/z2

#
# 'X'
#

mkdir -p /tmp/x/{1,2}
touch /tmp/x/1/{x1,x2} /tmp/x/2/{y1,y2} /tmp/x/{z1,z2}

systemd-tmpfiles --clean - <<EOF
d /tmp/x - - - 0
X /tmp/x/1
EOF

find /tmp/x | sort
test -d /tmp/x/1
test ! -f /tmp/x/1/x1
test ! -f /tmp/x/1/x2
test ! -d /tmp/x/2
test ! -f /tmp/x/2/x1
test ! -f /tmp/x/2/x2
test ! -f /tmp/x/z1
test ! -f /tmp/x/z2

#
# 'x' with glob
#

mkdir -p /tmp/x/{1,2}
touch /tmp/x/1/{x1,x2} /tmp/x/2/{y1,y2} /tmp/x/{z1,z2}

systemd-tmpfiles --clean - <<EOF
d /tmp/x - - - 0
x /tmp/x/[1345]
x /tmp/x/z*
EOF

find /tmp/x | sort
test -d /tmp/x/1
test -f /tmp/x/1/x1
test -f /tmp/x/1/x2
test ! -d /tmp/x/2
test ! -f /tmp/x/2/x1
test ! -f /tmp/x/2/x2
test -f /tmp/x/z1
test -f /tmp/x/z2

#
# 'X' with glob
#

mkdir -p /tmp/x/{1,2}
touch /tmp/x/1/{x1,x2} /tmp/x/2/{y1,y2} /tmp/x/{z1,z2}

systemd-tmpfiles --clean - <<EOF
d /tmp/x - - - 0
X /tmp/x/[1345]
X /tmp/x/?[12]
EOF

find /tmp/x | sort
test -d /tmp/x/1
test ! -f /tmp/x/1/x1
test ! -f /tmp/x/1/x2
test ! -d /tmp/x/2
test ! -f /tmp/x/2/x1
test ! -f /tmp/x/2/x2
test -f /tmp/x/z1
test -f /tmp/x/z2

#
# 'x' with 'r'
#

mkdir -p /tmp/x/{1,2}/a
touch /tmp/x/1/a/{x1,x2} /tmp/x/2/a/{y1,y2}

systemd-tmpfiles --clean - <<EOF
# x/X is not supposed to influence r
x /tmp/x/1/a
X /tmp/x/2/a
r /tmp/x/1
r /tmp/x/2
EOF

find /tmp/x | sort
test -d /tmp/x/1
test -d /tmp/x/1/a
test -f /tmp/x/1/a/x1
test -f /tmp/x/1/a/x2
test -f /tmp/x/2/a/y1
test -f /tmp/x/2/a/y2

#
# 'x' with 'R'
#

mkdir -p /tmp/x/{1,2}/a
touch /tmp/x/1/a/{x1,x2} /tmp/x/2/a/{y1,y2}

systemd-tmpfiles --remove - <<EOF
# Check that X is honoured below R
X /tmp/x/1/a
X /tmp/x/2/a
R /tmp/x/1
EOF

find /tmp/x | sort
test -d /tmp/x/1
test -d /tmp/x/1/a
test -f /tmp/x/1/a/x1
test -f /tmp/x/1/a/x2
test -f /tmp/x/2/a/y1
test -f /tmp/x/2/a/y2

#
# 'r/R/D' and non-directories
#

touch /tmp/x/{11,22,33}

systemd-tmpfiles --remove - <<EOF
# Check that X is honoured below R
r /tmp/x/11
R /tmp/x/22
D /tmp/x/33
EOF

find /tmp/x | sort
test ! -f /tmp/x/11
test ! -f /tmp/x/22
test -f /tmp/x/33
