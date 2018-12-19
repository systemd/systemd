#!/bin/sh

set -eu
set -o pipefail

dir="$1"
tag="$2"
fallback="$3"

if [ -n "$tag" ]; then
        echo "$tag"
        exit 0
fi

# Apparently git describe has a bug where it always considers the work-tree
# dirty when invoked with --git-dir (even though 'git status' is happy). Work
# around this issue by cd-ing to the source directory.
cd "$dir" && git describe --abbrev=7 --dirty=+ 2>/dev/null | sed 's/^v//' || echo "$fallback"
