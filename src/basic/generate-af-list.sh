#!/bin/sh
set -eu

$1 -E -dM -include sys/socket.h -include "$2" -include "$3" - </dev/null | \
    grep -Ev 'AF_UNSPEC|AF_MAX' | \
    awk '/^#define[ \t]+AF_[^ \t]+[ \t]+[AP]F_[^ \t]/ { print $2; }'
