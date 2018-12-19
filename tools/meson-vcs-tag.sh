#!/bin/sh

set -eu
set -o pipefail

gitdir="$1"
fallback="$2"
file="${3:-}"

tag="$(git --git-dir="$gitdir" describe --dirty=+ 2>/dev/null | sed 's/^v//' || echo "$fallback")"

if [ -z "$file" ]; then
        echo "$tag"
else
        sed "s/%PACKAGE_VERSION%/$tag/" "$file"
fi
