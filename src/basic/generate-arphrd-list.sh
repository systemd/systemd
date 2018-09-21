#!/bin/sh
set -eu

$1 -dM -include net/if_arp.h - </dev/null | \
        awk '/^#define[ \t]+ARPHRD_[^ \t]+[ \t]+[^ \t]/ { print $2; }' | \
        sed -e 's/ARPHRD_//'
