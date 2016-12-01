#!/bin/sh
# call built systemd-hwdb update on our hwdb files to ensure that they parse
# without error
#
# (C) 2016 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

set -e

ROOTDIR=$(dirname $(dirname $(readlink -f $0)))
SYSTEMD_HWDB=${builddir:-.}/systemd-hwdb

if [ ! -x "$SYSTEMD_HWDB" ]; then
    echo "$SYSTEMD_HWDB does not exist, please build first"
    exit 1
fi

D=$(mktemp --directory)
trap "rm -rf '$D'" EXIT INT QUIT PIPE
mkdir -p "$D/etc/udev"
ln -s "$ROOTDIR/hwdb" "$D/etc/udev/hwdb.d"

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

ln -s "$ROOTDIR/test/hwdb" "$D/etc/udev/hwdb.d"
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
