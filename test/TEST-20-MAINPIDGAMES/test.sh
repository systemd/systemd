#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test changing main PID"

. $TEST_BASE_DIR/test-functions

do_test "$@" 20
