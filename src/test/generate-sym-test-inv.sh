#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

TARGET_DIR="${1:?}"

cat <<EOF
/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

const struct {
        const char *name;
        const void *symbol;
} symbols_from_source[] = {
EOF

# functions
grep -r '^_public_' "$TARGET_DIR" | sed -ne '/[ *][0-9a-zA-Z_]*(/ { s/^.*[ *]\([0-9a-zA-Z_]*\)(.*$/        { "\1", \1 },/; p }'
# variables
grep -r '^_public_' "$TARGET_DIR" | sed -ne '/[ *][0-9a-zA-Z_]* =/ { s/^.*[ *]\([0-9a-zA-Z_]*\) =.*$/        { "\1", \&\1 },/; p }'
# ref/unref functions defined through macro
grep -r '^DEFINE_PUBLIC_TRIVIAL_REF_FUNC' "$TARGET_DIR" | sed -e 's/.*DEFINE_PUBLIC_TRIVIAL_REF_FUNC([^,]*, *\([0-9a-zA-Z_]*\) *).*$/        { "\1_ref", \1_ref },/'
grep -r '^DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC' "$TARGET_DIR" | sed -e 's/.*DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC([^,]*, *\([0-9a-zA-Z_]*\),.*$/        { "\1_unref", \1_unref },/'
grep -r '^DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC' "$TARGET_DIR" | sed -e 's/.*DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC([^,]*, *\([0-9a-zA-Z_]*\),.*$/        { "\1_ref", \1_ref },\n        { "\1_unref", \1_unref },/'

cat <<EOF
        {}
};
EOF
