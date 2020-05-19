#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2730"
IMAGE_NAME="test08"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=300
FSTYPE=ext4

test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        setup_basic_environment
    )
    mask_supporting_services
}

do_test "$@" 08
