#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test sysupdate"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        inst_binary sha256sum
    )
}

do_test "$@"
