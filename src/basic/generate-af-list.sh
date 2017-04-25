#!/bin/sh -eu

$1 -E -dM -include sys/socket.h - </dev/null | \
        grep -Ev 'AF_UNSPEC|AF_MAX' | \
        awk '/^#define[ \t]+AF_[^ \t]+[ \t]+PF_[^ \t]/ { print $2; }'
