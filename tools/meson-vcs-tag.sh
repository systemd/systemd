#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu
set -o pipefail

dir="${1:?}"
fallback="${2:?}"

# Apparently git describe has a bug where it always considers the work-tree
# dirty when invoked with --git-dir (even though 'git status' is happy). Work
# around this issue by cd-ing to the source directory.
cd "$dir"
# Check that we have either .git/ (a normal clone) or a .git file (a work-tree)
# and that we don't get confused if a tarball is extracted in a higher-level
# git repository.
[ -e .git ] && \
    git describe --abbrev=7 --dirty=^ 2>/dev/null | sed 's/^v//; s/-rc/~rc/' || \
    echo "$fallback"
