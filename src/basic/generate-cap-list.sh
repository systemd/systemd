#!/bin/sh -e

cpp -dM -include linux/capability.h -include "$1" -include "$2" - </dev/null | \
    awk '/^#define[ \t]+CAP_[A-Z_]+[ \t]+/ { print $2; }' | \
    grep -v CAP_LAST_CAP
