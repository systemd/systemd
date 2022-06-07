#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Job-related tests"
TEST_NO_QEMU=1
IMAGE_NAME="default"
TEST_SYSTEMD_FORCE_LEGACY_JOB_REMOVED_SIGNAL=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
