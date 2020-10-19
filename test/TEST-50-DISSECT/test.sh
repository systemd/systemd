#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="test systemd-dissect"
IMAGE_NAME="dissect"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

command -v mksquashfs >/dev/null 2>&1 || exit 0
command -v veritysetup >/dev/null 2>&1 || exit 0
command -v sfdisk >/dev/null 2>&1 || exit 0

# Need loop devices for systemd-dissect
test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    # If some pieces are missing from the host, skip rather than fail
    (
        LOG_LEVEL=5
        setup_basic_environment
        mask_supporting_services

        instmods loop =block
        instmods squashfs =squashfs
        instmods dm_verity =md
        install_dmevent
        generate_module_dependencies
        inst_binary losetup

        BASICTOOLS=(
            bash
            cat
            mount
        )
        oldinitdir=$initdir
        export initdir=$TESTDIR/minimal
        mkdir -p $initdir/usr/lib $initdir/etc
        setup_basic_dirs
        install_basic_tools
        cp $os_release $initdir/usr/lib/os-release
        ln -s ../usr/lib/os-release $initdir/etc/os-release
        echo MARKER=1 >> $initdir/usr/lib/os-release
        mksquashfs $initdir $oldinitdir/usr/share/minimal.raw
        veritysetup format $oldinitdir/usr/share/minimal.raw $oldinitdir/usr/share/minimal.verity | grep '^Root hash:' | cut -f2 | tr -d '\n' > $oldinitdir/usr/share/minimal.roothash
        export initdir=$oldinitdir
    )
}

do_test "$@" 50
