#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

echo "$0 $*"
test "$(basename "$0")" = "script.sh" || exit 1
test "$1" = "--version" || exit 2
echo "Life is good"
