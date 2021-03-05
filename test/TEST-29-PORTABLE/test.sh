#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="test systemd-portabled"
IMAGE_NAME="portabled"
TEST_NO_NSPAWN=1
TEST_INSTALL_VERITY_MINIMAL=1

. $TEST_BASE_DIR/test-functions

# Need loop devices for mounting images
test_append_files() {
    (
        instmods loop =block
        instmods squashfs =squashfs
        instmods dm_verity =md
        install_dmevent
        generate_module_dependencies
        inst_binary losetup
        inst_binary mksquashfs
        inst_binary unsquashfs
        install_verity_minimal
    )
}

do_test "$@" 29
