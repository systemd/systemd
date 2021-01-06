#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Basic systemd setup"
IMAGE_NAME="basic"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}
TEST_REQUIRE_INSTALL_TESTS=0

. $TEST_BASE_DIR/test-functions

test_append_files() {
    # install tests manually so the test is functional even when -Dinstall-tests=false
    mkdir -p $1/usr/lib/systemd/tests/testdata/units/
    cp -v $(dirname $0)/../units/{testsuite-01,end}.service $1/usr/lib/systemd/tests/testdata/units/
}

do_test "$@" 01
