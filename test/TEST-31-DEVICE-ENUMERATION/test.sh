#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="plugged -> dead -> plugged issue #11997"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=300

do_test "$@" 31
