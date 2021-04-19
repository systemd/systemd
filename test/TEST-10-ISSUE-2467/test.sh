#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2467"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@" 10
