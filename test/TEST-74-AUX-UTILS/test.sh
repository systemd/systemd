#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for auxiliary utilities"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >"$workspace/etc/machine-id"
}

do_test "$@"
