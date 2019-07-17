#!/bin/bash
set -e
TEST_DESCRIPTION="Basic systemd setup"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/bin/sh -e -x -c 'systemctl --state=failed --no-legend --no-pager > /failed ; systemctl daemon-reload ; echo OK > /testok'
Type=oneshot
EOF

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
