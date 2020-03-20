#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test PrivateUsers=yes on user manager"
. $TEST_BASE_DIR/test-functions

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

has_user_dbus_socket || exit 0

do_test "$@" 43
