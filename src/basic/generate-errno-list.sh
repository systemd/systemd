#!/bin/sh
set -eu

$1 -dM -include errno.h - </dev/null | \
    awk '/^#define[ \t]+E[^ _]+[ \t]+/ { print $2; }'
