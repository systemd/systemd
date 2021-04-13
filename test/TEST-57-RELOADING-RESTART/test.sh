#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test auto restart of exited services which are stuck in reloading state"

TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

do_test "$@" 57
