#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

TARGET_DIR="${1:?}"

cat <<EOF
/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct {
        const char *name;
        const void *symbol;
} Item;

Item symbols_from_source[] = {
EOF

while read -r file; do
    awk '
    # Functions
    match($0, /^_public_\s+([^\S]+\s+)+\**(\w+)\s*\(/, m) {
        printf "        { \"%s\", %s },\n", m[2], m[2]
    }
    # Variables
    match($0, /^_public_\s+([^\S]+\s+)+\**(\w+)\s*=/, m) {
        printf "        { \"%s\", &%s },\n", m[2], m[2]
    }
    # Functions defined through a macro
    match($0, /^DEFINE_PUBLIC_TRIVIAL_REF_FUNC\([^,]+,\s*(\w+)\s*,/, m) {
        printf "        { \"%s_ref\", %s_ref },\n", m[1], m[1]
    }
    match($0, /^DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC\([^,]+,\s*(\w+)\s*,/, m) {
        printf "        { \"%s_unref\", %s_unref },\n", m[1], m[1]
    }
    match($0, /^DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC\([^,]+,\s*(\w+)\s*,/, m) {
        printf "        { \"%s_ref\", %s_ref },\n", m[1], m[1]
        printf "        { \"%s_unref\", %s_unref },\n", m[1], m[1]
    }
    ' "$file"
done < <(find "$TARGET_DIR" -type f)

cat <<EOF
        {}
};
EOF
