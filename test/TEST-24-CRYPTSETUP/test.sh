#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="cryptsetup systemd setup"
IMAGE_NAME="cryptsetup"
TEST_NO_NSPAWN=1
TEST_FORCE_NEWIMAGE=1

. $TEST_BASE_DIR/test-functions

check_result_qemu() {
    ret=1
    mount_initdir
    [[ -e $initdir/testok ]] && ret=0
    [[ -f $initdir/failed ]] && cp -a $initdir/failed $TESTDIR
    cryptsetup luksOpen ${LOOPDEV}p2 varcrypt <$TESTDIR/keyfile
    mount /dev/mapper/varcrypt $initdir/var
    save_journal $initdir/var/log/journal
    _umount_dir $initdir/var
    _umount_dir $initdir
    cryptsetup luksClose /dev/mapper/varcrypt
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    echo $JOURNAL_LIST
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}

test_create_image() {
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
        mask_supporting_services

        install_dmevent
        generate_module_dependencies
        cat >$initdir/etc/crypttab <<EOF
$DM_NAME UUID=$ID_FS_UUID /etc/varkey
EOF
        echo -n test >$initdir/etc/varkey
        cat $initdir/etc/crypttab | ddebug

        cat >>$initdir/etc/fstab <<EOF
/dev/mapper/varcrypt    /var    ext4    defaults 0 1
EOF

        # Forward journal messages to the console, so we have something
        # to investigate even if we fail to mount the encrypted /var
        echo ForwardToConsole=yes >> $initdir/etc/systemd/journald.conf
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
    cleanup_root_var || :
    cleanup_initdir
}

do_test "$@" 24
