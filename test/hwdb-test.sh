#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Call built systemd-hwdb update on our hwdb files to ensure that they parse
# without error
#
# (C) 2016 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>

set -e

export SYSTEMD_LOG_LEVEL=info
ROOTDIR=$(dirname $(dirname $(readlink -f $0)))
SYSTEMD_HWDB=./systemd-hwdb

if [ ! -x "$SYSTEMD_HWDB" ]; then
    echo "$SYSTEMD_HWDB does not exist, please build first"
    exit 1
fi

D=$(mktemp --tmpdir --directory "hwdb-test.XXXXXXXXXX")
trap "rm -rf '$D'" EXIT INT QUIT PIPE
mkdir -p "$D/etc/udev"
ln -s "$ROOTDIR/hwdb.d" "$D/etc/udev/hwdb.d"

# Test "good" properties" — no warnings or errors allowed
err=$("$SYSTEMD_HWDB" update --root "$D" 2>&1 >/dev/null) && rc= || rc=$?
if [ -n "$err" ]; then
    echo "$err"
    exit ${rc:-1}
fi
if [ -n "$rc" ]; then
    echo "$SYSTEMD_HWDB returned $rc"
    exit $rc
fi

if [ ! -e "$D/etc/udev/hwdb.bin" ]; then
    echo "$D/etc/udev/hwdb.bin was not generated"
    exit 1
fi

# Test "bad" properties" — warnings required, errors not allowed
rm -f "$D/etc/udev/hwdb.bin" "$D/etc/udev/hwdb.d"

ln -s "$ROOTDIR/test/hwdb.d" "$D/etc/udev/hwdb.d"
err=$("$SYSTEMD_HWDB" update --root "$D" 2>&1 >/dev/null) && rc= || rc=$?
if [ -n "$rc" ]; then
    echo "$SYSTEMD_HWDB returned $rc"
    exit $rc
fi
if [ -n "$err" ]; then
    echo "Expected warnings"
    echo "$err"
else
    echo "$SYSTEMD_HWDB unexpectedly printed no warnings"
    exit 1
fi

if [ ! -e "$D/etc/udev/hwdb.bin" ]; then
    echo "$D/etc/udev/hwdb.bin was not generated"
    exit 1
fi
