#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

TEST_DESCRIPTION="Run unit tests under containers"
RUN_IN_UNPRIVILEGED_CONTAINER=yes
# Some tests make collecting coverage impossible (like test-mount-util, which
# remounts the whole / as read-only), so let's ignore the gcov errors in such
# case
IGNORE_MISSING_COVERAGE=yes

# Embed some newlines in the kernel command line to stress our test suite
# Also, pass $TEST_PREFER_NSPAWN to the VM/container if set
#
# shellcheck disable=SC2015
KERNEL_APPEND="
$(get_bool "${TEST_PREFER_NSPAWN:-0}" && echo "systemd.setenv=TEST_PREFER_NSPAWN=1" || :)

frobnicate!

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
systemd.setenv=TEST_CMDLINE_NEWLINE=bar

$KERNEL_APPEND
"
# Override $TEST_PREFER_NSPAWN if it was set to always run both the QEMU and
# the nspawn part of the test
TEST_PREFER_NSPAWN=no

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
