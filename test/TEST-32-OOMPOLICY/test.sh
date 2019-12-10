#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test OOM killer logic"
TEST_NO_NSPAWN=1
. $TEST_BASE_DIR/test-functions

UNIFIED_CGROUP_HIERARCHY=yes

do_test "$@" 32
