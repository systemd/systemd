#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for core PID1 functionality"

# for testing PrivateNetwork=yes
NSPAWN_ARGUMENTS="--capability=CAP_NET_ADMIN"
# for testing PrivatePIDs=yes
TEST_INSTALL_VERITY_MINIMAL=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    image_install logger socat
    inst_binary mksquashfs
    inst_binary unsquashfs
    install_verity_minimal
}

do_test "$@"
