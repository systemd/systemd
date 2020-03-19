#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test that ExecStopPost= is always run"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        mask_supporting_services

        # setup policy for Type=dbus test
        mkdir -p $initdir/etc/dbus-1/system.d
        cat > $initdir/etc/dbus-1/system.d/systemd.test.ExecStopPost.conf <<EOF
<?xml version="1.0"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
        "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
    <policy user="root">
        <allow own="systemd.test.ExecStopPost"/>
    </policy>
</busconfig>
EOF

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
Before=getty-pre.target
Wants=getty-pre.target

[Service]
ExecStart=/testsuite.sh
Type=oneshot
EOF
        cp testsuite.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root
}

do_test "$@"
