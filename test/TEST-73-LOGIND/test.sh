#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test various logind features"
IMAGE_NAME="logind"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    image_install -o useradd userdel passwd crond crontab pkill
}

do_test "$@"
