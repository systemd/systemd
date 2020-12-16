#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test NUMAPolicy= and NUMAMask= options"
TEST_NO_NSPAWN=1
. $TEST_BASE_DIR/test-functions
if qemu_min_version "5.2.0"; then
    QEMU_OPTIONS="-object memory-backend-ram,id=mem0,size=512M -numa node,memdev=mem0,nodeid=0"
else
    QEMU_OPTIONS="-numa node,nodeid=0"
fi

do_test "$@" 36
