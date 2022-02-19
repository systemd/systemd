#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="tbd"
TEST_NO_NSPAWN=1
TEST_MASK_SERVICES=0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

command -v dfuzzer >/dev/null || exit 0

test_append_files() {
    (
        image_install dfuzzer
    )
}

do_test "$@"
