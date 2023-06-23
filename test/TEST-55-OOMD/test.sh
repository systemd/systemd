#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"
IMAGE_NAME="oomd"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    # Create a swap file
    (
        image_install mkswap swapon stress

        fallocate -l 50M "${initdir:?}/var/swapfile"

        mkdir -p "${initdir:?}/etc/systemd/system/init.scope.d/"
        cat >>"${initdir:?}/etc/systemd/system/init.scope.d/test-55-oomd.conf" <<EOF
[Scope]
MemoryHigh=infinity
StartupMemoryHigh=10G
EOF
    )
}

do_test "$@" 55
