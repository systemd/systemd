#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="testing homed"

# Skip the qemu version of the test, unless we have btrfs
(modprobe -nv btrfs && command -v mkfs.btrfs) || TEST_NO_QEMU=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Need loop devices for mounting images
test_append_files() {
    (
        if [ "$TEST_NO_QEMU" != "1" ] ; then
            instmods loop =block
            install_dmevent
            install_btrfs
            generate_module_dependencies
        fi
    )
}

do_test "$@"
