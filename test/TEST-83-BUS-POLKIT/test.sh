#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Async Polkit authentication"
IMAGE_NAME="polkit"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"
    local dbuspolicydir="/usr/share/dbus-1/system.d"

    mkdir -p "$workspace/$dbuspolicydir"
    cp -v "$TEST_UNITS_DIR"/*.conf "$workspace/$dbuspolicydir"

    inst_binary runuser
}

do_test "$@"
