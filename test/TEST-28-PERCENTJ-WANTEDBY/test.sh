#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="Ensure %j Wants directives work"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

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

        # Set up the services.
        cat >$initdir/etc/systemd/system/specifier-j-wants.service << EOF
[Unit]
Description=Wants with percent-j specifier
Wants=specifier-j-depends-%j.service
After=specifier-j-depends-%j.service

[Service]
Type=oneshot
ExecStart=test -f /tmp/test-specifier-j-%j
ExecStart=/bin/sh -c 'echo OK > /testok'
EOF
        cat >$initdir/etc/systemd/system/specifier-j-depends-wants.service << EOF
[Unit]
Description=Dependent service for percent-j specifier

[Service]
Type=oneshot
ExecStart=touch /tmp/test-specifier-j-wants
EOF
        cat >$initdir/etc/systemd/system/testsuite.service << EOF
[Unit]
Description=Testsuite: Ensure %j Wants directives work
Wants=specifier-j-wants.service
After=specifier-j-wants.service

[Service]
Type=oneshot
ExecStart=/bin/true
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
