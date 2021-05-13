#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test that KillMode=mixed does not leave left over processes with ExecStopPost="

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
