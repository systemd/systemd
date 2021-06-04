#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test OnFailure dependency removal via drop ins"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

do_test "$@"
