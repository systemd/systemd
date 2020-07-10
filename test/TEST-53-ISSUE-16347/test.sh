#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test timer units when initial clock is ahead"
TEST_NO_NSPAWN=1

future_date=$(date -u +%Y-%m-%dT%H:%M:%S -d '+3 days')
QEMU_OPTIONS="-rtc base=${future_date}"
. $TEST_BASE_DIR/test-functions

do_test "$@" 53
