#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Resource limits-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@" 05
