#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test for RestartMode= feature"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    mkdir -p "$initdir/usr/local/bin/"
    mkdir -p "$initdir/run"

    gcc -Wall "${TEST_BASE_DIR:?}/TEST-99-RESTART-MODE/service.c" -o "$initdir/usr/local/bin/service" -lsystemd

    inst_binary nc
}

do_test "$@"
