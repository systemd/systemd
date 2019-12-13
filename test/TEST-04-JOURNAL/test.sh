#!/bin/bash
set -e
TEST_DESCRIPTION="Journal-related tests"

. $TEST_BASE_DIR/test-functions

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
ExecStart=/test-journal.sh
Type=oneshot
EOF

        cat >$initdir/etc/systemd/system/forever-print-hola.service <<EOF
[Unit]
Description=ForeverPrintHola service

[Service]
Type=simple
ExecStart=/bin/sh -x -c 'while :; do printf "Hola\n" || touch /i-lose-my-logs; sleep 1; done'
EOF

        cp test-journal.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
