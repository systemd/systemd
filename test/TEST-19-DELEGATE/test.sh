#!/bin/bash
set -e
TEST_DESCRIPTION="test cgroup delegation in the unified hierarchy"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions
QEMU_TIMEOUT=600
UNIFIED_CGROUP_HIERARCHY=yes

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # mask some services that we do not want to run in these tests
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-machined.service

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/bin/bash -x /testsuite.sh
Type=oneshot
StandardOutput=tty
StandardError=tty
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
}

do_test "$@"
