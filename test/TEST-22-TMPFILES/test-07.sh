#! /bin/bash
#
# Verifies the issues described by https://github.com/systemd/systemd/issues/10191
#

set -e
set -x

rm -rf /tmp/test-prefix

mkdir /tmp/test-prefix
touch /tmp/test-prefix/file

systemd-tmpfiles --remove - <<EOF
r /tmp/test-prefix
r /tmp/test-prefix/file
EOF

! test -f /tmp/test-prefix/file
! test -f /tmp/test-prefix

mkdir /tmp/test-prefix
touch /tmp/test-prefix/file

systemd-tmpfiles --remove - <<EOF
r /tmp/test-prefix/file
r /tmp/test-prefix
EOF

! test -f /tmp/test-prefix/file
! test -f /tmp/test-prefix
