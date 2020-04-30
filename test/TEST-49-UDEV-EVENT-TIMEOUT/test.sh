#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test udev's event-timeout and timeout-signal options"
TEST_NO_NSPAWN=1
. $TEST_BASE_DIR/test-functions

do_test "$@" 49
