#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="testing homed"

# Skip the qemu version of the test, unless we have btrfs
(modprobe -nv btrfs && command -v mkfs.btrfs >/dev/null) || TEST_NO_QEMU=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

get_bool "${NO_BUILD:-}" && HOMECTL_BIN="homectl" || HOMECTL_BIN="${BUILD_DIR:?}/homectl"
test_require_bin "$HOMECTL_BIN"

# Need loop devices for mounting images
test_append_files() {
    if ! get_bool "$TEST_NO_QEMU" ; then
        instmods loop =block
        install_dmevent
        install_btrfs
        generate_module_dependencies
    fi
}

do_test "$@"
