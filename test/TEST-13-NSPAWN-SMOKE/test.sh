#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="systemd-nspawn smoke test"
IMAGE_NAME="nspawn"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        setup_basic_environment
        mask_supporting_services

        ../create-busybox-container $initdir/testsuite-13.nc-container
        initdir="$initdir/testsuite-13.nc-container" dracut_install nc ip md5sum
    )
}

do_test "$@" 13
