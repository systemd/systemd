#!/bin/env bash

set -eux

TARGET_DIR="${1:?}"

cat <<EOF
/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* We want to check deprecated symbols too, without complaining */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

const struct {
        const char *name;
        const void *symbol;
} symbols_from_source[] = {
EOF

grep -r '^_public_' "$TARGET_DIR" | sed -ne '/[ *][0-9a-zA-Z_]*(/ { s/^.*[ *]\([0-9a-zA-Z_]*\)(.*$/        { "\1", \1 },/; p }'
grep -r '^_public_' "$TARGET_DIR" | sed -ne '/[ *][0-9a-zA-Z_]* =/ { s/^.*[ *]\([0-9a-zA-Z_]*\) =.*$/        { "\1", \&\1 },/; p }'

cat <<EOF
        {}
};
EOF
