#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test credentials"

. $TEST_BASE_DIR/test-functions

do_test "$@" 54
