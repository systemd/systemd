#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

CC=${1:?}
shift

$CC -dM -include linux/capability.h "$@" - </dev/null | \
       awk '/^#define[ \t]+CAP_[A-Z_]+[ \t]+/ { print $2; }' | \
       grep -v CAP_LAST_CAP
