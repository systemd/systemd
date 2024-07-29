#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e

TEST_DESCRIPTION="test systemd-dissect"
IMAGE_NAME="dissect"
TEST_NO_NSPAWN=1
TEST_INSTALL_VERITY_MINIMAL=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# On Ubuntu the BPF LSM is not enabled by default, so we need to do it via the
# kernel command line on boot
if [ "$LOOKS_LIKE_UBUNTU" = "yes" ]; then
    KERNEL_OPTIONS=(
        "lsm=lockdown,capability,landlock,yama,apparmor,bpf"
    )
    KERNEL_APPEND+=" ${KERNEL_OPTIONS[*]}"
fi

test_require_bin mksquashfs veritysetup sfdisk

test_append_files() {
    instmods squashfs =squashfs
    instmods dm_verity =md
    install_dmevent
    generate_module_dependencies
    inst_binary wc
    inst_binary sha256sum
    inst_binary tar
    if command -v openssl >/dev/null 2>&1; then
        inst_binary openssl
    fi
    inst_binary mksquashfs
    inst_binary unsquashfs
    inst_binary pkcheck
    inst_binary veritysetup
    install_verity_minimal
}

do_test "$@"
