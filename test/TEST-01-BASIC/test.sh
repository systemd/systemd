#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Basic systemd setup"
IMAGE_NAME="basic"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}
TEST_REQUIRE_INSTALL_TESTS=0

. $(dirname ${BASH_SOURCE[0]})/../test-functions

test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        setup_basic_environment
        mask_supporting_services

        # install tests manually so the test is functional even when -Dinstall-tests=false
        mkdir -p $initdir/usr/lib/systemd/tests/testdata/units/
        cp -v $(dirname ${BASH_SOURCE[0]})/../units/{testsuite-01,end}.service $initdir/usr/lib/systemd/tests/testdata/units/
    )
}

do_test "$@" 01
