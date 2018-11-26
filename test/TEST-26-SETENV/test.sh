#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="test setenv"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/bin/bash -x /testsuite.sh
Type=oneshot
StandardOutput=tty
StandardError=tty
NotifyAccess=all
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    ) || return 1
    setup_nspawn_root

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@"
