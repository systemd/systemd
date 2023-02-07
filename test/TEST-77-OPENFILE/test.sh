#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Openfile tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"
    echo "Open" >"$workspace/test-77-open.dat"
    echo "File" >"$workspace/test-77-file.dat"
}

do_test "$@"
