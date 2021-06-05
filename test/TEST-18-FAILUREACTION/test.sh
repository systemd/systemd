#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="FailureAction= operation"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

QEMU_TIMEOUT=600

do_test "$@"
