#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="FailureAction= operation"

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=600

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services
    )

    setup_nspawn_root
}

do_test "$@" 18
