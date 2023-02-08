#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Journal-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    mkdir -p "$workspace/test-journals/"
    cp -av "${TEST_BASE_DIR:?}/test-journals/"* "$workspace/test-journals/"

    inst_binary unzstd
}

do_test "$@"
