#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test OnSuccess= + Uphold= + PropagatesStopTo= + BindsTo="
# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

do_test "$@" 57
