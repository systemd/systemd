#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

$1 -dM -include errno.h - </dev/null | \
    awk '/^#define[ \t]+E[^ _]+[ \t]+/ { print $2; }'
