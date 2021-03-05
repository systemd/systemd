#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="UDEV"
IMAGE_NAME="udev"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=500

test_append_files() {
    (
        instmods dummy
        generate_module_dependencies
    )
}

do_test "$@" 17
