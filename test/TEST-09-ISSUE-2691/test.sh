#!/bin/bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2691"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=180

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<'EOF'
[Unit]
Description=Testsuite service

[Service]
Type=oneshot
ExecStart=/bin/sh -c '>/testok'
RemainAfterExit=yes
ExecStop=/bin/sh -c 'kill -SEGV $$$$'
TimeoutStopSec=270s
EOF

        setup_testsuite
    )
}

do_test "$@"
