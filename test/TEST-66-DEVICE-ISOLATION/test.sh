#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test device isolation"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
