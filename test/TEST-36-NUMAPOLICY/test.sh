#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test NUMAPolicy= and NUMAMask= options"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# The test runs strace on pid1 trying to capture some NUMA syscalls, but if the workers are spanwed before
# the test even starts, it won't be able to latch on that, so disable the pre-spawned workers and let this
# run just use direct spawns.
KERNEL_APPEND="${KERNEL_APPEND:=} SYSTEMD_WORKERS_POOL_SIZE=0"

if qemu_min_version "5.2.0"; then
    QEMU_OPTIONS+=" -object memory-backend-ram,id=mem0,size=${QEMU_MEM:-768M} -numa node,memdev=mem0,nodeid=0"
else
    QEMU_OPTIONS+=" -numa node,nodeid=0"
fi

do_test "$@"
