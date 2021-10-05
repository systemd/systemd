#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test that empty argv in transient units don't crash systemd. See https://github.com/systemd/systemd/issues/20933"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
