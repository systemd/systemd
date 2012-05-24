#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
TEST_DESCRIPTION="Basic systemd setup"

KVERSION=${KVERSION-$(uname -r)}

# Uncomment this to debug failures
#DEBUGFAIL="systemd.unit=multi-user.target"

run_qemu() {
    qemu-kvm \
        -hda $TESTDIR/rootdisk.img \
        -m 256M -nographic \
        -net none -kernel /boot/vmlinuz-$KVERSION \
        -append "root=/dev/sda1 systemd.log_level=debug raid=noautodetect loglevel=2 init=/usr/lib/systemd/systemd rw console=ttyS0,115200n81 selinux=0 $DEBUGFAIL"
    ret=1
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root
    [[ -e $TESTDIR/root/testok ]] && ret=0
    cp -a $TESTDIR/root/var/log/journal $TESTDIR
    cp -a $TESTDIR/root/failed $TESTDIR
    umount $TESTDIR/root
    cat $TESTDIR/failed
    ls -l $TESTDIR/journal/*/*.journal
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}


run_nspawn() {
    systemd-nspawn -b -D $TESTDIR/nspawn-root /usr/lib/systemd/systemd
    ret=1
    [[ -e $TESTDIR/nspawn-root/testok ]] && ret=0
    cp -a $TESTDIR/nspawn-root/var/log/journal $TESTDIR
    cp -a $TESTDIR/nspawn-root/failed $TESTDIR
    cat $TESTDIR/failed
    ls -l $TESTDIR/journal/*/*.journal
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}


test_run() {
    run_qemu || return 1
    if [[ -d /sys/fs/cgroup/systemd ]]; then
        run_nspawn || return 1
    fi
    return 0
}

test_setup() {
    rm -f $TESTDIR/rootdisk.img
    # Create the blank file to use as a root filesystem
    dd if=/dev/null of=$TESTDIR/rootdisk.img bs=1M seek=100
    LOOPDEV=$(losetup --show -P -f $TESTDIR/rootdisk.img)
    [ -b $LOOPDEV ] || return 1
    echo "LOOPDEV=$LOOPDEV" >> $STATEFILE
    sfdisk -C 3200 -H 2 -S 32 -L $LOOPDEV <<EOF
,
EOF

    mkfs.ext3 -L systemd ${LOOPDEV}p1
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root
    mkdir -p $TESTDIR/root/run

    kernel=$KVERSION
    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        initdir=$TESTDIR/root

        # create the basic filesystem layout
        setup_basic_dirs

        # install compiled files
        (cd ../..; make DESTDIR=$initdir install)

        # install possible missing libraries
        for i in $initdir/{sbin,bin}/* $initdir/lib/systemd/*; do
            inst_libs $i
        done

        # activate kmsg import
        echo 'ImportKernel=yes' >> $initdir/etc/systemd/journald.conf

        # make a journal directory
        mkdir -p $initdir/var/log/journal

        # install some basic config files
        inst /etc/sysconfig/init
        inst /etc/passwd
        inst /etc/shadow
        inst /etc/group
        inst /etc/shells
        inst /etc/nsswitch.conf
        inst /etc/pam.conf
        inst /etc/securetty
        inst /etc/os-release
        inst /etc/localtime
        # we want an empty environment
        > $initdir/etc/environment

        # set the hostname
        echo  systemd-testsuite > $initdir/etc/hostname

        # setup the testsuite target
        cat >$initdir/etc/systemd/system/testsuite.target <<EOF
[Unit]
Description=Testsuite target
Requires=multi-user.target
After=multi-user.target
Conflicts=rescue.target
AllowIsolate=yes
EOF

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/bin/sh -c 'systemctl --failed --no-legend --no-pager > /failed ; echo OK > /testok'
ExecStartPost=/usr/sbin/poweroff
Type=oneshot

EOF
        mkdir -p $initdir/etc/systemd/system/testsuite.target.wants
        ln -fs ../testsuite.service $initdir/etc/systemd/system/testsuite.target.wants/testsuite.service

        # make the testsuite the default target
        ln -fs testsuite.target $initdir/etc/systemd/system/default.target
        mkdir -p $initdir/etc/rc.d
        cat >$initdir/etc/rc.d/rc.local <<EOF
#!/bin/bash
exit 0
EOF
        chmod 0755 $initdir/etc/rc.d/rc.local
        # install basic tools needed
        dracut_install sh bash setsid loadkeys setfont \
            login sushell sulogin gzip sleep echo

        # install libnss_files for login
        inst_libdir_file "libnss_files*"

        # install dbus and pam
        find \
            /etc/dbus-1 \
            /etc/pam.d \
            /etc/security \
            /lib64/security \
            /lib/security -xtype f \
            | while read file; do
            inst $file
        done

        # install dbus socket and service file
        inst /usr/lib/systemd/system/dbus.socket
        inst /usr/lib/systemd/system/dbus.service

        # install basic keyboard maps and fonts
        for i in \
            /usr/lib/kbd/consolefonts/latarcyrheb-sun16* \
            /usr/lib/kbd/keymaps/include/* \
            /usr/lib/kbd/keymaps/i386/include/* \
            /usr/lib/kbd/keymaps/i386/qwerty/us.*; do
                [[ -f $i ]] || continue
                inst $i
        done

        # some basic terminfo files
        for _terminfodir in /lib/terminfo /etc/terminfo /usr/share/terminfo; do
            [ -f ${_terminfodir}/l/linux ] && break
        done
        dracut_install -o ${_terminfodir}/l/linux

        # softlink mtab
        ln -fs /proc/self/mounts $initdir/etc/mtab

        # install any Exec's from the service files
        egrep -ho '^Exec[^ ]*=[^ ]+' $initdir/lib/systemd/system/*.service \
            | while read i; do
            i=${i##Exec*=}; i=${i##-}
            inst $i
        done

        # install plymouth, if found... else remove plymouth service files
        if [ -x /usr/libexec/plymouth/plymouth-populate-initrd ]; then
            PLYMOUTH_POPULATE_SOURCE_FUNCTIONS="$TEST_BASE_DIR/test-functions" \
                /usr/libexec/plymouth/plymouth-populate-initrd -t $initdir
                dracut_install plymouth plymouthd
        else
                rm -f $initdir/usr/lib/systemd/system/plymouth* $initdir/usr/lib/systemd/system/*/plymouth*
        fi

        # some helper tools for debugging
        dracut_install sh df free ls shutdown poweroff \
            stty cat ps ln ip route \
            mount dmesg dhclient mkdir cp ping dhclient \
            umount strace less grep id tty touch

        # install ld.so.conf* and run ldconfig
        cp -a /etc/ld.so.conf* $initdir/etc
        ldconfig -r "$initdir"

    )
    rm -fr $TESTDIR/nspawn-root
    cp -avr $TESTDIR/root $TESTDIR/nspawn-root

    umount $TESTDIR/root
}

test_cleanup() {
    umount $TESTDIR/root 2>/dev/null
    [[ $LOOPDEV ]] && losetup -d $LOOPDEV
    return 0
}

. $TEST_BASE_DIR/test-functions
do_test "$@"
