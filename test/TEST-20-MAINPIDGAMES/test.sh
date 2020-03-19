#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test changing main PID"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
Before=getty-pre.target
Wants=getty-pre.target

[Service]
ExecStart=/bin/bash -x /testsuite.sh
Type=oneshot
NotifyAccess=all
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )

    setup_nspawn_root
}

do_test "$@"
