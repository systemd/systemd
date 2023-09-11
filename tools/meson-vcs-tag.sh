#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu
set -o pipefail

dir="${1:?}"
fallback="${2:?}"
version_tag="$3"

if [ -n "${version_tag}" ]; then
    # If -Dversion_tag= was used, just use that without further changes.
    echo "${version_tag}"
else
    # Check that we have either .git/ (a normal clone) or a .git file (a work-tree)
    # and that we don't get confused if a tarball is extracted in a higher-level
    # git repository.
    #
    # If the working tree has no tags (CI builds), the first git-describe will fail
    # and we fall back to project_version-commitid instead.
    if [ -e "${dir}/.git" ]; then
        c="$(git -C "$dir" describe --abbrev=7 --dirty=^ 2>/dev/null ||
                    echo "${fallback}-$(git -C "$dir" describe --always --abbrev=7)")"
    else
        c="${fallback}"
    fi
    echo "$c" | sed 's/^v//; s/-rc/~rc/'
fi
