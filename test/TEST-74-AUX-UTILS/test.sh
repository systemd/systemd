#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for auxiliary utilities"
NSPAWN_ARGUMENTS="--private-network"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# (Hopefully) a temporary workaround for https://github.com/systemd/systemd/issues/30573
KERNEL_APPEND="${KERNEL_APPEND:-} SYSTEMD_DEFAULT_MOUNT_RATE_LIMIT_BURST=100"

test_append_files() {
    local workspace="${1:?}"

    if ! get_bool "${TEST_PREFER_NSPAWN:-}" && ! get_bool "${TEST_NO_QEMU:-}"; then
        # Check if we can correctly boot with an invalid machine ID only if we run
        # the QEMU test, as nspawn refuses the invalid machine ID with -EUCLEAN
        printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >"$workspace/etc/machine-id"
    fi

    if host_has_btrfs && host_has_mdadm; then
        install_btrfs
        install_mdadm
        generate_module_dependencies
    fi

    image_install socat
}

do_test "$@"
