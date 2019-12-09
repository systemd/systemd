#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="systemd-nspawn smoke test"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        ../create-busybox-container $initdir/nc-container
        initdir="$initdir/nc-container" dracut_install nc ip
    )
}

do_test "$@" 13
