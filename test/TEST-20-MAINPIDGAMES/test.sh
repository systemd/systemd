#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test changing main PID"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
