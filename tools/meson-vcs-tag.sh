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
    # If the working tree has no tags (CI builds), we fall back to a version without
    # the git commit sha in it.

    c="${project_version}.$(date '+%Y%m%d%H%M%S')"
    if [ -e "${dir}/.git" ]; then
        suffix="$(git -C "$dir" rev-parse --short HEAD 2>/dev/null)"
        c="${c}.g${suffix}"
        # Add a caret if the git tree is dirty.
        [[ "$(git -C "$dir" describe --dirty=^)" == *^ ]] && c="${c}^"
    fi

    echo "$c"
fi
