#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test Soft-Rebooting"
# We temporarily remount rootfs read-only, so ignore any missing coverage
IGNORE_MISSING_COVERAGE=yes
# Prevent shutdown in test suite, the expect script does that manually.
TEST_SKIP_SHUTDOWN=yes
IMAGE_NAME="softreboot"
TEST_NO_NSPAWN=1
TEST_INSTALL_VERITY_MINIMAL=1

# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

test_require_bin mksquashfs veritysetup sfdisk

test_append_files() {
    instmods squashfs =squashfs
    instmods dm_verity =md
    install_dmevent
    generate_module_dependencies
    install_verity_minimal
}

do_test "$@"
