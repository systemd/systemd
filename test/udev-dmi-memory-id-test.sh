#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#

set -e

export SYSTEMD_LOG_LEVEL=info
ROOTDIR=$(dirname $(dirname $(readlink -f $0)))
UDEV_DMI_MEMORY_ID=./src/udev/dmi_memory_id

if [ ! -x "$UDEV_DMI_MEMORY_ID" ]; then
    echo "$UDEV_DMI_MEMORY_ID does not exist, please build first"
    exit 1
fi

D=$(mktemp --tmpdir --directory "udev-dmi-memory-id.XXXXXXXXXX")
trap "rm -rf '$D'" EXIT INT QUIT PIPE

for i in $ROOTDIR/test/dmidecode-dumps/*.bin ; do
    $("$UDEV_DMI_MEMORY_ID" -F "$i" 2>&1 > "$D"/out.txt) && rc= || rc=$?
    if [ -n "$rc" ]; then
        echo "$UDEV_DMI_MEMORY_ID returned $rc"
        exit $rc
    fi
    err=$(diff -u "$D"/out.txt "$i.txt" 2>&1) && rc= || rc=$?
    if [ -n "$rc" ]; then
        echo "Parsing DMI memory information from \"$i\" didn't match expected:"
        echo "$err"
        exit $rc
    fi
done
