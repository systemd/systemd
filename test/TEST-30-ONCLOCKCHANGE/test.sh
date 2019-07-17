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

        # mask some services that we do not want to run in these tests
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-machined.service

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
StandardOutput=tty
StandardError=tty
NotifyAccess=all
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
}

do_test "$@"
