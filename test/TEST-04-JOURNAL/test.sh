#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Journal-related tests"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services
    )
    setup_nspawn_root
}

do_test "$@" 04
