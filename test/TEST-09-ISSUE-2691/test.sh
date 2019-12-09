#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2691"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=300

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services
    )
}

do_test "$@" 09
