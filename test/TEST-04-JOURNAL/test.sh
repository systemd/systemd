#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Journal-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
