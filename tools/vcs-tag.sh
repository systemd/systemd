#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

INPUT="$1"
MODE="$2"
ENABLED="$3"

# meson runs this script from the build directory, so the working directory doesn't contain the repository.
# In a git worktree, .git is a file and not a directory.
SOURCE_ROOT="$(dirname "$0")/.."

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
if TAG="$(git -C "$SOURCE_ROOT" describe --abbrev=7 --match="" --always "${DIRTY[@]}" 2>/dev/null)"; then
    TAG="-g$TAG"
else
    TAG=""
fi

sed -e "s/@VCS_TAG@/$TAG/" "$INPUT"
