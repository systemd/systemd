#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

CONFIG="${1:?Missing path to config.h}"
TARGET="${2:?Missing target m4 file}"

if [ ! -f "$CONFIG" ]; then
    echo "$CONFIG not found."
    exit 2
fi

if [ ! -f "$TARGET" ]; then
    echo "$TARGET not found."
    exit 3
fi

DEFINES=()
mapfile -t DEFINES < <(awk '$1 == "#define" && $3 == "1" { printf "-D%s\n", $2 }' "$CONFIG")

m4 -P "${DEFINES[@]}" "$TARGET"
