#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test ExecCondition= does not restart on abnormal or failure"
. $TEST_BASE_DIR/test-functions

do_test "$@" 51
