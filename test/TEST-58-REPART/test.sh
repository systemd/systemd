#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test systemd-repart"
IMAGE_NAME="repart"
TEST_FORCE_NEWIMAGE=1

# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

test_append_files() {
    if ! get_bool "${TEST_NO_QEMU:=}"; then
        install_dmevent
        instmods dm_verity =md
        instmods erofs
        generate_module_dependencies
        image_install -o mksquashfs
        image_install -o mkfs.erofs
    fi

    inst_binary setpriv
    inst_binary mcopy
    if command -v openssl >/dev/null 2>&1; then
        inst_binary openssl
    fi
}

do_test "$@"
