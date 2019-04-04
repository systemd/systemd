#!/bin/bash
set -e
TEST_DESCRIPTION="Tmpfiles related tests"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    # create the basic filesystem layout
    setup_basic_environment
    inst_binary mv
    inst_binary stat
    inst_binary seq
    inst_binary xargs
    inst_binary mkfifo
    inst_binary readlink

    # mask some services that we do not want to run in these tests
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-machined.service

    # setup the testsuite service
    cp testsuite.service $initdir/etc/systemd/system/
    setup_testsuite

    mkdir -p $initdir/testsuite
    cp run-tmpfiles-tests.sh $initdir/testsuite/
    cp test-*.sh $initdir/testsuite/

    # create dedicated rootfs for nspawn (located in $TESTDIR/nspawn-root)
    setup_nspawn_root
}

do_test "$@"
