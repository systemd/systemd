#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Journal-related tests"

. $TEST_BASE_DIR/test-functions

do_test "$@" 04
