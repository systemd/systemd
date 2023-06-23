#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"
IMAGE_NAME="oomd"

# Need to set up swap
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    # Create a swap file
    (
        image_install mkswap swapon swapoff stress

        dd if=/dev/zero of="${initdir:?}/swapfile" bs=1M count=48
        chmod 0600 "${initdir:?}/swapfile"

        mkdir -p "${initdir:?}/etc/systemd/system/init.scope.d/"
        cat >>"${initdir:?}/etc/systemd/system/init.scope.d/test-55-oomd.conf" <<EOF
[Scope]
MemoryHigh=infinity
StartupMemoryHigh=10G
EOF
    )
}

do_test "$@" 55
