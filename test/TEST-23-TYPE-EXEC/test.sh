#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test Type=exec"
. $TEST_BASE_DIR/test-functions

do_test "$@" 23
