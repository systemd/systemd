#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="/etc/machine-id testing"
IMAGE_NAME="badid"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >"${1:?}/etc/machine-id"
}

do_test "$@"
