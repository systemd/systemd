#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"
IMAGE_NAME="oomd"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    # Create a swap device
    (
        mkswap "${LOOPDEV:?}p2"
        image_install swapon swapoff

        cat >>"${initdir:?}/etc/fstab" <<EOF
UUID=$(blkid -o value -s UUID "${LOOPDEV}p2")    none    swap    defaults 0 0
EOF

        mkdir -p "${initdir:?}/etc/systemd/system/init.scope.d/"
        cat >>"${initdir:?}/etc/systemd/system/init.scope.d/test-55-oomd.conf" <<EOF
[Scope]
MemoryHigh=10G
EOF
    )
}

do_test "$@" 55
