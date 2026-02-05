#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

CC=${1:?}
shift

$CC -E -dM -include linux/stat.h "$@" - </dev/null | \
       grep -Ev '^#define[[:space:]]+(STATX_BASIC_STATS|STATX_ALL|STATX_ATTR_)' | \
       awk '/^#define[ \t]+STATX_[A-Z][A-Z_]*[ \t]+/ { print $2; }'
