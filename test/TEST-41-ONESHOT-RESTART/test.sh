#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test oneshot unit restart on failure"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@" 41
