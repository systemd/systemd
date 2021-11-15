#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="testing homed"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Need loop devices for mounting images
test_append_files() {
    (
        instmods loop =block
        install_dmevent
        install_btrfs
        generate_module_dependencies
    )
}

do_test "$@"
