#! /bin/bash
#
# With "e" don't attempt to set permissions when file doesn't exist, see
# https://github.com/systemd/systemd/pull/6682.
#

set -e

rm -fr /tmp/test

echo "e /tmp/test - root root 1d" | systemd-tmpfiles --create -

! test -e /tmp/test
