#!/bin/bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/1981"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

NSPAWN_TIMEOUT=30

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/test-segfault.sh
Type=oneshot
EOF

        cp test-segfault.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
