#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for auxiliary utilities"
NSPAWN_ARGUMENTS="--private-network"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    if ! get_bool "${TEST_PREFER_NSPAWN:-}" && ! get_bool "${TEST_NO_QEMU:-}"; then
        # Check if we can correctly boot with an invalid machine ID only if we run
        # the QEMU test, as nspawn refuses the invalid machine ID with -EUCLEAN
        printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >"$workspace/etc/machine-id"
    fi

    # This container will be used to test that we can forward coredumps back to containers.
    local container="$workspace/var/lib/machines/testsuite-74-container"

    mkdir -p "$container"
    initdir="$container" setup_basic_dirs
    initdir="$container" install_systemd
    initdir="$container" install_missing_libraries
    initdir="$container" install_config_files
    initdir="$container" install_zoneinfo
    initdir="$container" create_rc_local
    initdir="$container" install_basic_tools
    initdir="$container" install_libnss
    initdir="$container" install_pam
    initdir="$container" install_dbus
    initdir="$container" install_debug_tools
    initdir="$container" install_execs
}

do_test "$@"
