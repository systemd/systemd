#! /bin/bash
#
# Verify tmpfiles can run in a root directory under a path prefix that contains
# directories owned by unprivileged users, for example when a root file system
# is mounted in a regular user's home directory.
#
# https://github.com/systemd/systemd/pull/11820
#

set -e

rm -fr /tmp/root /tmp/user
mkdir -p /tmp/root /tmp/user/root
chown daemon:daemon /tmp/user

# Verify the command works as expected with no prefix or a root-owned prefix.
echo 'd /tmp/root/test1' | systemd-tmpfiles --create -
test -d /tmp/root/test1
echo 'd /test2' | systemd-tmpfiles --root=/tmp/root --create -
test -d /tmp/root/test2

# Verify the command fails to write to a root-owned subdirectory under an
# unprivileged user's directory when it's not part of the prefix, as expected
# by the unsafe_transition function.
! echo 'd /tmp/user/root/test' | systemd-tmpfiles --create -
! test -e /tmp/user/root/test
! echo 'd /user/root/test' | systemd-tmpfiles --root=/tmp --create -
! test -e /tmp/user/root/test

# Verify the above works when all user-owned directories are in the prefix.
echo 'd /test' | systemd-tmpfiles --root=/tmp/user/root --create -
test -d /tmp/user/root/test
