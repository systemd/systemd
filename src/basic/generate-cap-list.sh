#!/bin/sh
set -eu

$1 -dM -include linux/capability.h -include "$2" -include "$3" - </dev/null | \
        awk '/^#define[ \t]+CAP_[A-Z_]+[ \t]+/ { print $2; }' | \
        grep -v CAP_LAST_CAP
