#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemctl-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() (
        workspace="${1:?}"

        image_install script

        mkdir "$workspace/systemd-test-module"
        cp ed-3a "$workspace/systemd-test-module"
)

do_test "$@"
