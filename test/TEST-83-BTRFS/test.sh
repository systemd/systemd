#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test btrfs-util"

TEST_NO_NSPAWN=1
FSTYPE=btrfs
IMAGE_NAME="btrfs"
TEST_FORCE_NEWIMAGE=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

if ! command -v btrfs >/dev/null || ! command -v mkfs.btrfs >/dev/null; then
    echo "TEST: $TEST_DESCRIPTION [SKIPPED]: btrfs not supported by host" >&2
    exit 0
fi

if ! btrfs filesystem mkswapfile --help >/dev/null; then
    echo "TEST: $TEST_DESCRIPTION [SKIPPED]: 'btrfs filesystem' doesn't support 'mkswapfile' subcommand" >&2
    exit 0
fi

test_append_files() {
    install_btrfs
    image_install sync
}

do_test "$@"
