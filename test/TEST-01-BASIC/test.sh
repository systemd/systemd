#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Basic systemd setup"
IMAGE_NAME="basic"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}
TEST_REQUIRE_INSTALL_TESTS=0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Explicitly override the default test_create_image() function to avoid the
# call to mask_supporting_services(), since we want to run them in TEST-01-BASIC
test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        setup_basic_environment
    )
}

test_append_files() {
    # install tests manually so the test is functional even when -Dinstall-tests=false
    local dst="${1:?}/usr/lib/systemd/tests/testdata/units/"
    mkdir -p "$dst"
    cp -v "$TEST_UNITS_DIR"/{testsuite-01,end}.service "$TEST_UNITS_DIR/testsuite.target" "$dst"
}

do_test "$@"
