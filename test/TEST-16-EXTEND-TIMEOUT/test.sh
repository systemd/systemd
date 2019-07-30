#!/bin/bash
set -e
TEST_DESCRIPTION="EXTEND_TIMEOUT_USEC=usec start/runtime/stop tests"
SKIP_INITRD=yes
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image

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

        setup_testsuite
    )
    # mask some services that we do not want to run in these tests
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service

    setup_nspawn_root
}

do_test "$@"
