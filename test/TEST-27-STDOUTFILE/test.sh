#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test StandardOutput=file:"

. $TEST_BASE_DIR/test-functions

do_test "$@" 27
