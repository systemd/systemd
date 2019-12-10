#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Ensure %j Wants directives work"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

. $TEST_BASE_DIR/test-functions

do_test "$@" 28
