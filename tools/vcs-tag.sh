#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

INPUT="$1"
MODE="$2"
ENABLED="$3"

if ! ((ENABLED)) || ! [[ -d .git ]] || ! command -v git >/dev/null || git describe --tags --exact-match &>/dev/null
then
    sed "$INPUT" -e "s/@VCS_TAG@//"
    exit 0
fi

if [[ "$MODE" == "developer" ]]; then
    DIRTY="--dirty=^"
else
    DIRTY=""
fi

TAG="-g$(git describe --abbrev=7 --match="" --always $DIRTY)"

sed "$INPUT" -e "s/@VCS_TAG@/$TAG/"
