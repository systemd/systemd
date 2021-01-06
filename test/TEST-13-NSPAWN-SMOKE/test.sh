#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="systemd-nspawn smoke test"
IMAGE_NAME="nspawn"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_append_files() {
    (
        ../create-busybox-container $1/testsuite-13.nc-container
        initdir="$1/testsuite-13.nc-container" dracut_install nc ip md5sum
    )
}

do_test "$@" 13
