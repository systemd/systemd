#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test daemon-reload on invalid timers"

. $TEST_BASE_DIR/test-functions

do_test "$@" 54
