#!/bin/bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/3171"
TEST_NO_QEMU=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        dracut_install cat mv stat nc

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
echo A | nc -w1 -U /run/test.socket

mv $U ${U}.disabled
systemctl daemon-reload
systemctl is-active test.socket
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]
echo B | nc -w1 -U /run/test.socket && exit 1

mv ${U}.disabled $U
systemctl daemon-reload
systemctl is-active test.socket
echo C | nc -w1 -U /run/test.socket && exit 1
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]

systemctl restart test.socket
systemctl is-active test.socket
echo D | nc -w1 -U /run/test.socket
[[ "$(stat --format='%G' /run/test.socket)" == adm ]]


touch /testok
EOF

        chmod 0755 $initdir/test-socket-group.sh
        setup_testsuite
    )

    setup_nspawn_root
}

do_test "$@"
