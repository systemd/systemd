#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test cgroup delegation in the unified hierarchy"
TEST_NO_NSPAWN=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions
QEMU_TIMEOUT=600
UNIFIED_CGROUP_HIERARCHY=yes

do_test "$@" 19
