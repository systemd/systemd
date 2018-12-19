#!/bin/sh

set -eu
set -o pipefail

dir="$1"
fallback="$2"
file="${3:-}"

# Apparently git describe has a bug where it always considers the work-tree
# dirty when invoked with --git-dir (even though 'git status' is happy). Work
# around this issue by cd-ing to the source directory.
tag="$(cd "$dir" && git describe --dirty=+ 2>/dev/null | sed 's/^v//' || echo "$fallback")"

if [ -z "$file" ]; then
        echo "$tag"
else
        sed "s/%PACKAGE_VERSION%/$tag/" "$file"
fi
