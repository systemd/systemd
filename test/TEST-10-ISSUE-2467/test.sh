#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2467"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        dracut_install true rm

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<'EOF'
[Unit]
Description=Testsuite service

[Service]
Type=oneshot
StandardOutput=tty
StandardError=tty
ExecStart=/bin/sh -e -x -c 'rm -f /tmp/nonexistent; systemctl start test.socket; echo > /run/test.ctl; >/testok'
TimeoutStartSec=10s
EOF

	cat  >$initdir/etc/systemd/system/test.socket <<'EOF'
[Socket]
ListenFIFO=/run/test.ctl
EOF

	cat > $initdir/etc/systemd/system/test.service <<'EOF'
[Unit]
Requires=test.socket
ConditionPathExistsGlob=/tmp/nonexistent

[Service]
ExecStart=/bin/true
EOF

        setup_testsuite
    ) || return 1
    setup_nspawn_root

    # mask some services that we do not want to run in these tests
    ln -s /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@"
