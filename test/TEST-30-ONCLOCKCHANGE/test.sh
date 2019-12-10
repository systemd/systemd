#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test OnClockChange= + OnTimezoneChange="
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services
    )
}

do_test "$@" 30
