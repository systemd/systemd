#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

# git describe --dirty opportunistically refreshes and rewrites .git/index, which
# changes its ownership when the build runs as a different user (e.g. root under
# mkosi). Tell git not to update the index.
export GIT_OPTIONAL_LOCKS=0

INPUT="$1"
MODE="$2"
ENABLED="$3"
SOURCE_ROOT="$4"

if ! ((ENABLED)) || ! [[ -e "$SOURCE_ROOT/.git" ]] || ! command -v git >/dev/null || git -C "$SOURCE_ROOT" describe --tags --exact-match &>/dev/null
then
    sed -e "s/@VCS_TAG@//" "$INPUT"
    exit 0
fi

if [[ "$MODE" == "developer" ]]; then
    DIRTY=("--dirty=^")
else
    DIRTY=()
fi

# Git can refuse to read a checkout whose owner differs from the user running the build.
if TAG="$(git -C "$SOURCE_ROOT" describe --abbrev=7 --match="" --always "${DIRTY[@]}")"; then
    TAG="-g$TAG"
else
    echo "Warning: git describe failed; using the configured version without a VCS tag." >&2
    TAG=""
fi

sed -e "s/@VCS_TAG@/$TAG/" "$INPUT"
