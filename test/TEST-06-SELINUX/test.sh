#!/bin/sh
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
TEST_DESCRIPTION="SELinux tests"

# Requirements:
# Fedora 23
# selinux-policy-targeted
# selinux-policy-devel

. $TEST_BASE_DIR/test-functions
SETUP_SELINUX=yes
KERNEL_APPEND="$KERNEL_APPEND selinux=1"

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
    if run_qemu; then
        check_result_qemu || return 1
    else
        dwarn "can't run QEMU, skipping"
    fi
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
        cat <<EOF >$initdir/etc/systemd/system/testsuite.service
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/test-selinux-checks.sh
Type=oneshot
EOF

        cat <<EOF >$initdir/etc/systemd/system/hola.service
[Service]
Type=oneshot
ExecStart=/bin/echo Start Hola
ExecReload=/bin/echo Reload Hola
ExecStop=/bin/echo Stop Hola
RemainAfterExit=yes
EOF

        setup_testsuite

        cat <<EOF >$initdir/etc/systemd/system/load-systemd-test-module.service
[Unit]
Description=Load systemd-test module
DefaultDependencies=no
Requires=local-fs.target
Conflicts=shutdown.target
After=local-fs.target
Before=sysinit.target shutdown.target autorelabel.service
ConditionSecurity=selinux
ConditionPathExists=|/.load-systemd-test-module

[Service]
ExecStart=/bin/sh -x -c 'echo 0 >/sys/fs/selinux/enforce && cd /systemd-test-module && make -f /usr/share/selinux/devel/Makefile load  && rm /.load-systemd-test-module'
Type=oneshot
TimeoutSec=0
RemainAfterExit=yes
EOF

        touch $initdir/.load-systemd-test-module
        mkdir -p $initdir/etc/systemd/system/basic.target.wants
        ln -fs load-systemd-test-module.service $initdir/etc/systemd/system/basic.target.wants/load-systemd-test-module.service

        local _modules_dir=/var/lib/selinux
        rm -rf $initdir/$_modules_dir
        if ! cp -ar $_modules_dir $initdir/$_modules_dir; then
            dfatal "Failed to copy $_modules_dir"
            exit 1
        fi

        local _policy_headers_dir=/usr/share/selinux/devel
        rm -rf $initdir/$_policy_headers_dir
        inst_dir /usr/share/selinux
        if ! cp -ar $_policy_headers_dir $initdir/$_policy_headers_dir; then
            dfatal "Failed to copy $_policy_headers_dir"
            exit 1
        fi

        mkdir $initdir/systemd-test-module
        cp systemd_test.te $initdir/systemd-test-module
        cp systemd_test.if $initdir/systemd-test-module
        cp test-selinux-checks.sh $initdir
        dracut_install -o sesearch
        dracut_install runcon
        dracut_install checkmodule semodule semodule_package m4 make /usr/libexec/selinux/hll/pp load_policy sefcontext_compile
    ) || return 1

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
