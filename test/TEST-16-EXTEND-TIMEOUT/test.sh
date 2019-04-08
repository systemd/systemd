#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="EXTEND_TIMEOUT_USEC=usec start/runtime/stop tests"
SKIP_INITRD=yes
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        for s in success-all success-start success-stop success-runtime \
                 fail-start fail-stop fail-runtime
        do
            cp testsuite-${s}.service ${initdir}/etc/systemd/system
        done
        cp testsuite.service ${initdir}/etc/systemd/system

        cp extend_timeout_test_service.sh ${initdir}/
        cp assess.sh ${initdir}/
        cp $BUILD_DIR/systemd-notify ${initdir}/bin
        cp $BUILD_DIR/src/shared/libsystemd-shared-*.so ${initdir}/usr/lib

        setup_testsuite
    ) || return 1
    # mask some services that we do not want to run in these tests
    ln -s /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

    setup_nspawn_root

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

test_cleanup() {
    return 0
}

do_test "$@"
