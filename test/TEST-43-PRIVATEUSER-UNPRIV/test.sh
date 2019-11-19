#!/bin/bash
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

        usermod --root $initdir -d /home/nobody -s /bin/bash nobody
        mkdir $initdir/home $initdir/home/nobody
        # Ubuntu's equivalent is nogroup
        chown nobody:nobody $initdir/home/nobody || chown nobody:nogroup $initdir/home/nobody

        enable_user_manager nobody

        nobody_uid=$(id -u nobody)

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=systemd-logind.service user@$nobody_uid.service

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
