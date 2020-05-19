#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="testing homed"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

do_test "$@" 46
