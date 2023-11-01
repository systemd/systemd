#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test storagetm"

TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_require_bin nvme

modprobe -nv nvmet-tcp || exit 0

test_append_files() {
    inst_binary nvme

    instmods "=nvme"
    instmods configfs

    generate_module_dependencies
}

do_test "$@"
