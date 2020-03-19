#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test log namespaces"

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
Wants=systemd-journald@foobar.socket systemd-journald-varlink@foobar.socket
After=systemd-journald@foobar.socket systemd-journald-varlink@foobar.socket

[Service]
ExecStart=/testsuite.sh
Type=oneshot
LogTarget=foobar
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
