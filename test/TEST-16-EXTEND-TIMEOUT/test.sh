#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="EXTEND_TIMEOUT_USEC=usec start/runtime/stop tests"
SKIP_INITRD=yes
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

do_test "$@" 16
