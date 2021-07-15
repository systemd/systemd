#!/usr/bin/env bash

TEST_NO_NSPAWN=1

set -e
TEST_DESCRIPTION="test RestrictNetworkInterfaces="
. $TEST_BASE_DIR/test-functions

do_test "$@" 62
