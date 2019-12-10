#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="FailureAction= operation"

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=600

do_test "$@" 18
