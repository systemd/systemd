#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test Soft-Rebooting"
# We temporarily remount rootfs read-only, so ignore any missing coverage
IGNORE_MISSING_COVERAGE=yes
# Prevent shutdown in test suite, the expect script does that manually.
TEST_SKIP_SHUTDOWN=yes

# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

do_test "$@"
