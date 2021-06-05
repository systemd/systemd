#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test OOM killer logic"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

UNIFIED_CGROUP_HIERARCHY=yes

do_test "$@"
