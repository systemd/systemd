#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2730"
IMAGE_NAME="test08"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=300
FSTYPE=ext4
TEST_FORCE_NEWIMAGE=1

do_test "$@" 08
