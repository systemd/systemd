#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

CC="${1:?}"
shift

HEADER="${1:?}"
shift

$CC -dM -include "$HEADER" "$@" - </dev/null | \
     grep -vE 'AUDIT_.*(FIRST|LAST)_' | \
     sed -r -n 's/^#define\s+AUDIT_(\w+)\s+([0-9]{4})\s*$$/\1\t\2/p' | \
     sort -k2
