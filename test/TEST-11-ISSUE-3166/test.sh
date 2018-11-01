#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/3166"
TEST_NO_NSPAWN=1

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
        dracut_install false touch

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

do_test "$@"
