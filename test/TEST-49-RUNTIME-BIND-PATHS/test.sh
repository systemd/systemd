#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test adding new BindPaths while unit is already running"
. $TEST_BASE_DIR/test-functions

do_test "$@" 49
