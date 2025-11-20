#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

CC=${1:?}
shift

$CC -E -dM -include sys/socket.h "$@" - </dev/null | \
       grep -Ev 'AF_UNSPEC|AF_MAX' | \
       awk '/^#define[ \t]+AF_[^ \t]+[ \t]+[AP]F_[^ \t]/ { print $2; }'
