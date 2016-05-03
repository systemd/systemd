#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/3166"

. $TEST_BASE_DIR/test-functions
SKIP_INITRD=yes

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
        dracut_install false touch

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/test-fail-on-restart.sh
Type=oneshot
EOF

        cat >$initdir/etc/systemd/system/fail-on-restart.service <<EOF
[Unit]
Description=Fail on restart

[Service]
Type=simple
ExecStart=/bin/false
Restart=always
EOF


        cat >$initdir/test-fail-on-restart.sh <<'EOF'
#!/bin/bash -x

systemctl start fail-on-restart.service
active_state=$(systemctl show --property ActiveState fail-on-restart.service)
while [[ "$active_state" == "ActiveState=activating" || "$active_state" == "ActiveState=active" ]]; do
    sleep 1
    active_state=$(systemctl show --property ActiveState fail-on-restart.service)
done
systemctl is-failed fail-on-restart.service || exit 1
touch /testok
EOF

        chmod 0755 $initdir/test-fail-on-restart.sh
        setup_testsuite
    ) || return 1

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

test_cleanup() {
    umount $TESTDIR/root 2>/dev/null
    [[ $LOOPDEV ]] && losetup -d $LOOPDEV
    return 0
}

do_test "$@"
