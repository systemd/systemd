#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/3171"

. $TEST_BASE_DIR/test-functions

test_run() {
    if check_nspawn; then
        run_nspawn
        check_result_nspawn || return 1
    else
        dwarn "can't run systemd-nspawn, skipping"
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
        dracut_install cat mv stat nc

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/test-socket-group.sh
Type=oneshot
EOF


        cat >$initdir/test-socket-group.sh <<'EOF'
#!/bin/bash
set -x
set -e
set -o pipefail

U=/run/systemd/system/test.socket
cat <<'EOL' >$U
[Unit]
Description=Test socket
[Socket]
Accept=yes
ListenStream=/run/test.socket
SocketGroup=adm
SocketMode=0660
EOL

cat <<'EOL' > /run/systemd/system/test@.service
[Unit]
Description=Test service
[Service]
StandardInput=socket
ExecStart=/bin/sh -x -c cat
EOL

systemctl start test.socket
systemctl is-active test.socket
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]
echo A | nc -U /run/test.socket

mv $U ${U}.disabled
systemctl daemon-reload
systemctl is-active test.socket
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]
echo B | nc -U /run/test.socket && exit 1

mv ${U}.disabled $U
systemctl daemon-reload
systemctl is-active test.socket
echo C | nc -U /run/test.socket && exit 1
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]

systemctl restart test.socket
systemctl is-active test.socket
echo D | nc -U /run/test.socket
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]


touch /testok
EOF

        chmod 0755 $initdir/test-socket-group.sh
        setup_testsuite
    ) || return 1

    setup_nspawn_root

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

test_cleanup() {
    umount $TESTDIR/root 2>/dev/null
    [[ $LOOPDEV ]] && losetup -d $LOOPDEV
    return 0
}

do_test "$@"
