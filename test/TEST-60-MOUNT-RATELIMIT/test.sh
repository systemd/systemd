#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test that mount/unmount storms can enter/exit rate limit state and will not leak units"

# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

do_test "$@"
