#!/bin/sh -eu

$1 -dM -include linux/input.h - </dev/null | \
        awk '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9K]/ { if ($2 != "KEY_MAX") { print $2 } }'
