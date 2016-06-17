#!/bin/sh
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2730"

. $TEST_BASE_DIR/test-functions
SKIP_INITRD=yes
QEMU_TIMEOUT=180
FSTYPE=ext4

check_result_qemu() {
    ret=1
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root
    [[ -e $TESTDIR/root/testok ]] && ret=0
    [[ -f $TESTDIR/root/failed ]] && cp -a $TESTDIR/root/failed $TESTDIR
    cp -a $TESTDIR/root/var/log/journal $TESTDIR
    umount $TESTDIR/root
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    ls -l $TESTDIR/journal/*/*.journal
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}

test_run() {
    run_qemu || return 1
    check_result_qemu || return 1
    return 0
}

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/bin/sh -x -c 'mount -o remount,rw /dev/sda1 && echo OK > /testok; systemctl poweroff'
Type=oneshot
EOF

    rm $initdir/etc/fstab
    cat >$initdir/etc/systemd/system/-.mount <<EOF
[Unit]
Before=local-fs.target

[Mount]
What=/dev/sda1
Where=/
Type=ext4
Options=errors=remount-ro,noatime

[Install]
WantedBy=local-fs.target
Alias=root.mount
EOF

    cat >$initdir/etc/systemd/system/systemd-remount-fs.service <<EOF
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
After=systemd-fsck-root.service
Before=local-fs-pre.target local-fs.target shutdown.target
Wants=local-fs-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/systemctl reload /
EOF

        setup_testsuite
    ) || return 1

    ln -s /etc/systemd/system/-.mount $initdir/etc/systemd/system/root.mount
    mkdir -p $initdir/etc/systemd/system/local-fs.target.wants
    ln -s /etc/systemd/system/-.mount $initdir/etc/systemd/system/local-fs.target.wants/-.mount

    # mask some services that we do not want to run in these tests
    ln -s /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

test_cleanup() {
    umount $TESTDIR/root 2>/dev/null
    [[ $LOOPDEV ]] && losetup -d $LOOPDEV
    return 0
}

do_test "$@"
