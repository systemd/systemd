#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="Run unit tests under containers"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

. $TEST_BASE_DIR/test-functions

check_result_nspawn() {
    local _ret=1
    [[ -e $TESTDIR/$1/testok ]] && _ret=0
    if [[ -s $TESTDIR/$1/failed ]]; then
        _ret=$(($_ret+1))
        echo "=== Failed test log ==="
        cat $TESTDIR/$1/failed
    else
        if [[ -s $TESTDIR/$1/skipped ]]; then
            echo "=== Skipped test log =="
            cat $TESTDIR/$1/skipped
        fi
        if [[ -s $TESTDIR/$1/testok ]]; then
            echo "=== Passed tests ==="
            cat $TESTDIR/$1/testok
        fi
    fi
    cp -a $TESTDIR/$1/var/log/journal $TESTDIR
    [[ -n "$TIMED_OUT" ]] && _ret=$(($_ret+1))
    return $_ret
}

check_result_qemu() {
    local _ret=1
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root
    [[ -e $TESTDIR/root/testok ]] && _ret=0
    if [[ -s $TESTDIR/root/failed ]]; then
        _ret=$(($_ret+1))
        echo "=== Failed test log ==="
        cat $TESTDIR/root/failed
    else
        if [[ -s $TESTDIR/root/skipped ]]; then
            echo "=== Skipped test log =="
            cat $TESTDIR/root/skipped
        fi
        if [[ -s $TESTDIR/root/testok ]]; then
            echo "=== Passed tests ==="
            cat $TESTDIR/root/testok
        fi
    fi
    cp -a $TESTDIR/root/var/log/journal $TESTDIR
    umount $TESTDIR/root
    [[ -n "$TIMED_OUT" ]] && _ret=$(($_ret+1))
    return $_ret
}

test_setup() {
    if type -P meson && [[ "$(meson configure $BUILD_DIR | grep install-tests | awk '{ print $2 }')" != "true" ]]; then
        dfatal "Needs to be built with -Dinstall-tests=true"
        exit 1
    fi

    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        for i in getfacl dirname basename capsh cut rev stat mktemp rmdir ionice unshare uname tr awk getent diff xzcat lz4cat; do
            inst_binary $i
        done

        inst /etc/hosts

        setup_basic_environment
        install_keymaps yes
        install_zoneinfo
        # Install nproc to determine # of CPUs for correct parallelization
        inst_binary nproc

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
    ) || return 1
    setup_nspawn_root

    # mask some services that we do not want to run in these tests
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -s /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -s /dev/null $initdir/etc/systemd/system/systemd-resolved.service

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@"
