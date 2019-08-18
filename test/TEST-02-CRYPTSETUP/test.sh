#!/bin/bash
set -e
TEST_DESCRIPTION="cryptsetup systemd setup"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

check_result_qemu() {
    ret=1
    mkdir -p $initdir
    mount ${LOOPDEV}p1 $initdir
    [[ -e $initdir/testok ]] && ret=0
    [[ -f $initdir/failed ]] && cp -a $initdir/failed $TESTDIR
    cryptsetup luksOpen ${LOOPDEV}p2 varcrypt <$TESTDIR/keyfile
    mount /dev/mapper/varcrypt $initdir/var
    cp -a $initdir/var/log/journal $TESTDIR
    umount $initdir/var
    umount $initdir
    cryptsetup luksClose /dev/mapper/varcrypt
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    ls -l $TESTDIR/journal/*/*.journal
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}


test_setup() {
    create_empty_image_rootdir
    echo -n test >$TESTDIR/keyfile
    cryptsetup -q luksFormat --pbkdf pbkdf2 --pbkdf-force-iterations 1000 ${LOOPDEV}p2 $TESTDIR/keyfile
    cryptsetup luksOpen ${LOOPDEV}p2 varcrypt <$TESTDIR/keyfile
    mkfs.ext4 -L var /dev/mapper/varcrypt
    mkdir -p $initdir/var
    mount /dev/mapper/varcrypt $initdir/var

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=/dev/mapper/varcrypt)
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
After=multi-user.target

[Service]
ExecStart=/bin/sh -x -c 'systemctl --state=failed --no-legend --no-pager > /failed ; echo OK > /testok'
Type=oneshot
EOF

        setup_testsuite

        install_dmevent
        generate_module_dependencies
        cat >$initdir/etc/crypttab <<EOF
$DM_NAME UUID=$ID_FS_UUID /etc/varkey
EOF
        echo -n test > $initdir/etc/varkey
        cat $initdir/etc/crypttab | ddebug

        cat >>$initdir/etc/fstab <<EOF
/dev/mapper/varcrypt    /var    ext4    defaults 0 1
EOF
    )
}

cleanup_root_var() {
    ddebug "umount $initdir/var"
    mountpoint $initdir/var && umount $initdir/var
    [[ -b /dev/mapper/varcrypt ]] && cryptsetup luksClose /dev/mapper/varcrypt
}

test_cleanup() {
    # ignore errors, so cleanup can continue
    cleanup_root_var || :
    _test_cleanup
}

test_setup_cleanup() {
    cleanup_root_var
    _test_setup_cleanup
}

do_test "$@"
