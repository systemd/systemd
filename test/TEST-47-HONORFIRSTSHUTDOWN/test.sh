#!/bin/bash
set -e
. $TEST_BASE_DIR/test-functions
#INTERACTIVE_DEBUG=1

TEST_DESCRIPTION="testing honor first shutdown"
TEST_NO_QEMU=1

#Using timeout because if the test fails it can loop.
# The reason is because the poweroff executed by end.service
# could turn into a reboot if the test fails.
NSPAWN_TIMEOUT=20

#Remove this file if it exists. this is used along with
# the make target "finish". Since concrete confirmaion is
# only found from the console during the poweroff.
rm -f /tmp/honorfirstshutdown.log >/dev/null

test_setup() {

    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        # setup honor first shutdown service
        cp ../../src/test/test-honor-first-shutdown.service $initdir/etc/systemd/system/
        cp ../../src/test/test-honor-first-shutdown.sh $initdir/
        chmod 755 $initdir/test-honor-first-shutdown.sh

        # setup the testsuite service
        cp testsuite.service $initdir/etc/systemd/system
        cp testsuite.sh $initdir/

        setup_testsuite

    ) || return 1
    setup_nspawn_root

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@" > /tmp/honorfirstshutdown.log
