#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="/etc/machine-id testing"
IMAGE_NAME="badid"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        setup_basic_environment
        mask_supporting_services
        printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >$initdir/etc/machine-id
    )
}

do_test "$@" 14
