#!/bin/sh
set -eu

$1 -dM -include netinet/in.h - </dev/null | \
        awk '/^#define[ \t]+IPPROTO_[^ \t]+[ \t]+[^ \t]/ { print $2; }' | \
        sed -e 's/IPPROTO_//'
