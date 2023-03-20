#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Run unit tests under containers"
RUN_IN_UNPRIVILEGED_CONTAINER=yes
# Some tests make collecting coverage impossible (like test-mount-util, which
# remounts the whole / as read-only), so let's ignore the gcov errors in such
# case
IGNORE_MISSING_COVERAGE=yes

# embed some newlines in the kernel command line to stress our test suite
KERNEL_APPEND="

frobnicate!

$KERNEL_APPEND
"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    if get_bool "$LOOKS_LIKE_SUSE"; then
        dinfo "Install the unit test binaries needed by the TEST-02-UNITTESTS at runtime"
        inst_recursive "${SOURCE_DIR}/unit-tests"
    fi
}

check_result_nspawn() {
    check_result_nspawn_unittests "${1}"
}

check_result_qemu() {
    check_result_qemu_unittests
}

do_test "$@"
