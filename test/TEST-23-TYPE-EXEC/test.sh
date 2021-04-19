#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test Type=exec"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@" 23
