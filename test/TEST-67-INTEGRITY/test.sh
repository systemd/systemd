#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="dm-integrity test"

TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {(

    instmods loop =block
    instmods dm_integrity =md

    inst_binary integritysetup
    inst_binary blkid
    install_dmevent

    generate_module_dependencies

)}

do_test "$@"
