#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2730"
IMAGE_NAME="test08"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

TEST_FORCE_NEWIMAGE=1

do_test "$@"
