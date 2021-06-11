#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="UDEV"
IMAGE_NAME="default"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

QEMU_TIMEOUT=800

do_test "$@"
