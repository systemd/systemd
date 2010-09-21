#!/bin/sh
# Call the udev rule syntax checker on all rules that we ship
#
# (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>

set -e

[ -n "$srcdir" ] || srcdir=`dirname $0`/..

# skip if we don't have python
type python >/dev/null 2>&1 || {
    echo "$0: No python installed, skipping udev rule syntax check"
    exit 0
}

$srcdir/test/rule-syntax-check.py `find $srcdir/rules -type f`
