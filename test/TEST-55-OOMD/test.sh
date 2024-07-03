#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"
IMAGE_NAME="oomd"

# Need to set up swap
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# psi support might be present but left disabled by default.
KERNEL_APPEND="${KERNEL_APPEND:-} psi=1"

test_append_files() {
    local workspace="${1:?}"

    image_install mkswap swapon swapoff
    image_install -o btrfs stress stress-ng

    mkdir -p "${workspace:?}/etc/systemd/system/init.scope.d/"
    cat >"${workspace:?}/etc/systemd/system/init.scope.d/test-55-oomd.conf" <<EOF
[Scope]
MemoryHigh=infinity
StartupMemoryHigh=10G
EOF
}

do_test "$@" 55
