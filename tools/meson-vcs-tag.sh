#!/bin/sh

set -eu
set -o pipefail

gitdir="$1"
fallback="$2"

git --git-dir="$gitdir" describe --abbrev=7 --dirty=+ 2>/dev/null | sed 's/^v//' || echo "$fallback"
