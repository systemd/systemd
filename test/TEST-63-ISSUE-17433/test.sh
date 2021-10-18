#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/17433"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
