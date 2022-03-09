#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test PrivateUsers=yes on user manager"
IMAGE_NAME="private-users"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

has_user_dbus_socket || exit 0
command -v mksquashfs >/dev/null 2>&1 || exit 0

test_append_files() {
    (
        inst_binary unsquashfs
        install_verity_minimal
    )
}

do_test "$@"
