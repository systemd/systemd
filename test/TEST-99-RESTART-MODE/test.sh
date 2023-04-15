#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test for RestartMode= feature"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    mkdir -p "$initdir/usr/local/bin/"
    mkdir -p "$initdir/run"
    cp -fv "${TEST_BASE_DIR:?}/TEST-99-RESTART-MODE/service.py" "$initdir/usr/local/bin/"

    inst_binary nc

    # TODO: make top-level function install_python
    inst_recursive /usr/lib64/python3*
    inst_binary python3
}

do_test "$@"
