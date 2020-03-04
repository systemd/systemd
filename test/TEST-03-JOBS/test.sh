#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Job-related tests"
TEST_NO_QEMU=1

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
After=multi-user.target

[Service]
ExecStart=/test-jobs.sh
Type=oneshot
EOF

        # copy the units used by this test
        cp $TEST_BASE_DIR/{hello.service,sleep.service,hello-after-sleep.target,unstoppable.service} \
            $initdir/etc/systemd/system
        cp test-jobs.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
