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

# Remove this file if it exists. This is used along with
# the make target "finish". Since concrete confirmation is
# only found from the console during the poweroff.
rm -f /tmp/honorfirstshutdown.log >/dev/null

check_result_nspawn_hook() {
    grep -q "Shutdown is already active. Skipping emergency action request" /tmp/honorfirstshutdown.log
}

# Note: don't use a pipe in the following expression, as it breaks the trap
#       handlers we have defined in test/test-functions.
do_test "$@" > >(tee /tmp/honorfirstshutdown.log)
