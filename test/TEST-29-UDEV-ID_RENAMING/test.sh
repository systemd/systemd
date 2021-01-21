#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="UDEV ID_RENAMING property"
IMAGE_NAME="udev-id-renaming"
TEST_NO_NSPAWN=1

. $(dirname ${BASH_SOURCE[0]})/../test-functions
QEMU_TIMEOUT=300

test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        setup_basic_environment
        mask_supporting_services

        instmods dummy
        generate_module_dependencies
    )
}

do_test "$@" 29
