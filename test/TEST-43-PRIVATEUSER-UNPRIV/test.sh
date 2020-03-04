#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Test PrivateUsers=yes on user manager"
. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        inst_binary stat

        mask_supporting_services

        # Allocate user for running test case under
        mkdir -p $initdir/etc/sysusers.d
        cat >$initdir/etc/sysusers.d/testuser.conf <<EOF
u testuser    4711     "Test User" /home/testuser
EOF

        mkdir -p $initdir/home/testuser -m 0700
        chown 4711:4711 $initdir/home/testuser

        enable_user_manager testuser

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=systemd-logind.service user@4711.service
Wants=user@4711.service

[Service]
ExecStart=/testsuite.sh
Type=oneshot
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

has_user_dbus_socket || exit 0

do_test "$@"
