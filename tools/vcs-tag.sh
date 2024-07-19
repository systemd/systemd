#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

MODE="$1"

if ! [[ -d .git ]] || git describe --tags --exact-match &>/dev/null; then
    exit 0
fi

if [[ "$MODE" == "developer" ]]; then
    DIRTY="--dirty=^"
else
    DIRTY=""
fi

echo "-g$(git describe --abbrev=7 --match="" --always $DIRTY)"
