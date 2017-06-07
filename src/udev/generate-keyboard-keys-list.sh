#!/bin/sh -eu

$1 -dM -include linux/input.h - </dev/null | \
        awk '/^#define[ \t]+(KEY|BTN)_[^ ]+[ \t]+[0-9BK]/ { if ($2 != "KEY_MAX") { print $2 } }'
