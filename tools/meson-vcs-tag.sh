#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -u
set -o pipefail

dir="${1:-.}"
version_tag="${2:-}"

if [ -n "${version_tag}" ]; then
    # If -Dversion_tag= was used, just use that without further changes.
    echo "${version_tag}"
else
    read -r project_version <"${dir}/meson.version"

    # Check that we have either .git/ (a normal clone) or a .git file (a work-tree)
    # and that we don't get confused if a tarball is extracted in a higher-level
    # git repository.
    #
    # If the working tree has no tags (CI builds), the first git-describe will fail
    # and we fall back to project_version-commitid instead.

    c=''
    if [ -e "${dir}/.git" ]; then
        c="$(git -C "$dir" describe --abbrev=7 --dirty=^ 2>/dev/null)"
        if [ -n "$c" ]; then
            # git describe uses the most recent tag. However, for development versions (e.g. v256~devel), the
            # most recent tag will be v255 as there is no tag for development versions. To deal with this, we
            # replace the tag with the project version instead.
            c="${project_version}-${c#*-}"
        else
            # This call might still fail with permission issues
            suffix="$(git -C "$dir" describe --always --abbrev=7 --dirty=^ 2>/dev/null)"
            [ -n "$suffix" ] && c="${project_version}-${suffix}"
        fi
    fi
    [ -z "$c" ] && c="${project_version}"
    # Replace any hyphens with carets which are allowed in versions by pacman whereas hyphens are not. Git
    # versions with carets will also sort higher than their non-git version counterpart both in pacman
    # versioning and in version format specification versioning.
    echo "$c" | sed 's/^v//; s/-/^/g'
fi
