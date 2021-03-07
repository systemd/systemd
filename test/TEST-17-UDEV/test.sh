#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="UDEV"
IMAGE_NAME="udev"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

QEMU_TIMEOUT=800

test_append_files() {
    (
        instmods dummy
        generate_module_dependencies
    )
}

do_test "$@"
