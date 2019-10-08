#!/bin/bash
set -e
TEST_DESCRIPTION="test OnClockChange= + OnTimezoneChange="
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        inst_any /usr/share/zoneinfo/Europe/Kiev
        inst_any /usr/share/zoneinfo/Europe/Berlin

        setup_basic_environment
        mask_supporting_services

        # extend the watchdog
        mkdir -p $initdir/etc/systemd/system/systemd-timedated.service.d
        cat >$initdir/etc/systemd/system/systemd-timedated.service.d/watchdog.conf <<EOF
[Service]
WatchdogSec=10min
EOF

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/testsuite.sh
Type=oneshot
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
}

do_test "$@"
