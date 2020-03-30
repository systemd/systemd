#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/1981"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

NSPAWN_TIMEOUT=30

do_test "$@" 07
