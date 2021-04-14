#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test OnSuccess= + Uphold="
. $TEST_BASE_DIR/test-functions

do_test "$@" 57
