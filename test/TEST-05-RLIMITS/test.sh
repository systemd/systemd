#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Resource limits-related tests"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        cat >$initdir/etc/systemd/system.conf <<EOF
[Manager]
DefaultLimitNOFILE=10000:16384
EOF

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/test-rlimits.sh
Type=oneshot
EOF

        cp test-rlimits.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
