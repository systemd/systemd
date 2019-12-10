#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Tmpfiles related tests"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    # create the basic filesystem layout
    setup_basic_environment
    mask_supporting_services

    # create dedicated rootfs for nspawn (located in $TESTDIR/nspawn-root)
    setup_nspawn_root
}

do_test "$@" 22
