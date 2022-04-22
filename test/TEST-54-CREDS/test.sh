#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test credentials"
NSPAWN_ARGUMENTS="--set-credential=mynspawncredential:strangevalue"
QEMU_OPTIONS="-fw_cfg  name=opt/io.systemd.credentials/myqemucredential,string=othervalue"
KERNEL_APPEND="systemd.set_credential=kernelcmdlinecred:uff"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    instmods qemu_fw_cfg
    generate_module_dependencies
}

do_test "$@"
