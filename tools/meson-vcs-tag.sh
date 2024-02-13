#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -u
set -o pipefail

dir="${1:?}"
fallback="${2:?}"
version_tag="${3:-}"

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

    c=''
    if [ -e "${dir}/.git" ]; then
        c="$(git -C "$dir" describe --abbrev=7 --dirty=^ 2>/dev/null)"
        if [ -z "$c" ]; then
            # This call might still fail with permission issues
            suffix="$(git -C "$dir" describe --always --abbrev=7 --dirty=^ 2>/dev/null)"
            [ -n "$suffix" ] && c="${fallback}-${suffix}"
        fi
    fi
    [ -z "$c" ] && c="${fallback}"
    # Replace any hyphens with carets which are allowed in versions by pacman whereas hyphens are not. Git
    # versions with carets will also sort higher than their non-git version counterpart both in pacman
    # versioning and in version comparison spec versioning.
    echo "$c" | sed 's/^v//; s/-/^/g'
fi
