#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test importd"

. $TEST_BASE_DIR/test-functions

do_test "$@" 25
