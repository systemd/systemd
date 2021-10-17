#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Run unit tests under qemu"
# this subset of unit tests requires qemu, so they are ran here to avoid slowing down TEST-02
TEST_NO_NSPAWN=1

# embed some newlines in the kernel command line to stress our test suite
KERNEL_APPEND="

frobnicate!

$KERNEL_APPEND
"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

check_result_nspawn() {
    check_result_nspawn_unittests "${1}"
}

check_result_qemu() {
    check_result_qemu_unittests
}

do_test "$@"
