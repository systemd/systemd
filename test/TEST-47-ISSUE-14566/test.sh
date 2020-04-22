#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test that KillMode=mixed does not leave left over processes with ExecStopPost="
. $TEST_BASE_DIR/test-functions

do_test "$@" 47
