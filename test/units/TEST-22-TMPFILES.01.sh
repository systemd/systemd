#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# With "e" don't attempt to set permissions when file doesn't exist, see
# https://github.com/systemd/systemd/pull/6682.
set -eux
set -o pipefail

rm -fr /tmp/test

echo "e /tmp/test - root root 1d" | systemd-tmpfiles --create -
test ! -e /tmp/test

touch /tmp/test
echo "r /tmp/test - - - -" | systemd-tmpfiles --remove -
test ! -e /tmp/test

touch /tmp/test
systemd-tmpfiles --remove --inline 'p /tmp/fifo' 'r /tmp/test'
test ! -e /tmp/fifo
test ! -e /tmp/test

# Test invalid config
systemd-tmpfiles --inline --remove 'garbage' || ret=$?
test "$ret" -eq 65   # EX_DATAERR

echo 'garbage' >/tmp/config.conf
systemd-tmpfiles --remove /tmp/config.conf || ret=$?
test "$ret" -eq 65   # EX_DATAERR

systemd-tmpfiles --remove /tmp/config-missing.conf || ret=$?
test "$ret" -eq 1
