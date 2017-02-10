#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

TEST_DESCRIPTION="Dropin tests"

. $TEST_BASE_DIR/test-functions


test_run_nspawn() {
        if ! run_nspawn; then
                dwarn "can't run systemd-nspawn, skipping"
                return 0
        fi
        check_result_nspawn
}

test_run() {
        test_run_nspawn || return
}

test_setup() {
        # create the basic filesystem layout
        setup_basic_environment >/dev/null

        # mask some services that we do not want to run in these tests
        ln -s /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
        ln -s /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
        ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
        ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
        ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

        # import the test scripts in the rootfs and plug them in systemd
        cp testsuite.service $initdir/etc/systemd/system/
        cp test-dropin.sh    $initdir/
        setup_testsuite

        # create dedicated rootfs for nspawn (located in $TESTDIR/nspawn-root)
        setup_nspawn_root
}

test_cleanup() {
        return 0
}

do_test "$@"
