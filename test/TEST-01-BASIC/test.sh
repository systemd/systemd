#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="Basic systemd setup"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/bin/sh -x -c 'systemctl --state=failed --no-legend --no-pager > /failed ; echo OK > /testok'
Type=oneshot
EOF

        setup_testsuite
    ) || return 1
    setup_nspawn_root

    # mask some services that we do not want to run in these tests
    ln -s /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@"
