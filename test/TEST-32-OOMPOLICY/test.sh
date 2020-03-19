#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test OOM killer logic"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

UNIFIED_CGROUP_HIERARCHY=yes

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

[Service]
ExecStart=/testsuite.sh
Type=oneshot
MemoryAccounting=yes
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
}

do_test "$@"
