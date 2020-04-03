#!/bin/bash
set -e
TEST_DESCRIPTION="test unit freezing and thawing via DBus and systemctl"
TEST_NO_NSPAWN=1
. $TEST_BASE_DIR/test-functions

do_test "$@" 38
