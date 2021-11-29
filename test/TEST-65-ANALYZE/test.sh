#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test analyze"
IMAGE_NAME="analyze"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

command -v unzstd >/dev/null 2>&1 || exit 0

test_append_files() {
    (
        unzstd "${SOURCE_DIR}/test/core-dumps/core.crash.zstd" -o "${initdir:-}/usr/share/core.crash"
    )
}

do_test "$@"
