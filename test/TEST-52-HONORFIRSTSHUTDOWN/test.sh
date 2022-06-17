#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_REQUIRE_INSTALL_TESTS=0
TEST_DESCRIPTION="testing honor first shutdown"
TEST_NO_QEMU=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Using timeout because if the test fails it can loop.
# The reason is because the poweroff executed by end.service
# could turn into a reboot if the test fails.
NSPAWN_TIMEOUT=60

check_result_nspawn_hook() {
    local workspace="${1:?}"

    "${JOURNALCTL:?}" -D "${workspace:?}/var/log/journal" --grep "Shutdown is already active. Skipping emergency action request" --no-pager
}

do_test "$@"
