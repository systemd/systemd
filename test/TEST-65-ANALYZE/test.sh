#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test analyze"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {(
    local portable_dir="${1:?}${ROOTLIBDIR:?}/portable"

    # If we're built with -Dportabled=false, tests with systemd-analyze
    # --profile will fail. Since we need just the profile (text) files, let's
    # copy them into the image if they don't exist there.
    if [[ ! -d "$portable_dir/profile/strict" ]]; then
        dinfo "Couldn't find portable profiles in the test image"
        dinfo "Copying them directly from the source tree"
        mkdir -p "$portable_dir"
        cp -frv "${SOURCE_DIR:?}/src/portable/profile" "$portable_dir"
    fi
)}

do_test "$@"
