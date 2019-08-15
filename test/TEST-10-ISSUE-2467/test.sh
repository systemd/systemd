#!/bin/bash
set -e
TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2467"

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        dracut_install true rm socat

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<'EOF'
[Unit]
Description=Testsuite service

[Service]
Type=oneshot
StandardOutput=tty
StandardError=tty
ExecStart=/bin/sh -e -x -c 'rm -f /tmp/nonexistent; systemctl start test.socket; printf x > test.file; socat -t20 OPEN:test.file UNIX-CONNECT:/run/test.ctl; >/testok'
EOF

	cat  >$initdir/etc/systemd/system/test.socket <<'EOF'
[Socket]
ListenStream=/run/test.ctl
EOF

	cat > $initdir/etc/systemd/system/test.service <<'EOF'
[Unit]
Requires=test.socket
ConditionPathExistsGlob=/tmp/nonexistent

[Service]
ExecStart=/bin/true
EOF

        setup_testsuite
    )
    setup_nspawn_root

    # mask some services that we do not want to run in these tests
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
}

do_test "$@"
