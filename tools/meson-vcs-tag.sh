#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu
set -o pipefail

dir="${1:?}"
tag="${2:?}"
fallback="${3:?}"

# Check that we have either .git/ (a normal clone) or a .git file (a work-tree)
# and that we don't get confused if a tarball is extracted in a higher-level
# git repository.
#
# If the working tree has no tags (CI builds), the first git-describe will fail
# and we fall back to project_version-commitid instead.
if [ -n "$tag" ]; then
    echo "$tag"
else
    {
        [ -e .git ] && git -C "$dir" describe --abbrev=7 --dirty=^ 2>/dev/null ||
                echo "$fallback-$(git -C "$1" describe --always --abbrev=7)"
    } | sed 's/^v//; s/-rc/~rc/'
fi
