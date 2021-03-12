#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test ExitType=cgroup"
. $TEST_BASE_DIR/test-functions

do_test "$@" 56
