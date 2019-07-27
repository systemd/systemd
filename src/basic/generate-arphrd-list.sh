#!/bin/sh
set -eu

$1 -dM -include linux/if_arp.h -include "$2" - </dev/null | \
    awk '/^#define[ \t]+ARPHRD_[^ \t]+[ \t]+[^ \t]/ { print $2; }' | \
    sed -e 's/ARPHRD_//'
