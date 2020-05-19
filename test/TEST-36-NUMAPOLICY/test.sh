#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test MUMAPolicy= and NUMAMask= options"
TEST_NO_NSPAWN=1
QEMU_OPTIONS="-numa node,nodeid=0"
. $TEST_BASE_DIR/test-functions

do_test "$@" 36
