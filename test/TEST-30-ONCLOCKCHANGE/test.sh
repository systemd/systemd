#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test OnClockChange= + OnTimezoneChange="
TEST_NO_NSPAWN=1
. $TEST_BASE_DIR/test-functions

do_test "$@" 30
