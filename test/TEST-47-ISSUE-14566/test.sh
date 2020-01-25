#!/bin/bash
set -e
TEST_DESCRIPTION="Test that KillMode=mixed does not leave left over proccesses with ExecStopPost="
. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    (
        LOG_LEVEL=5
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

[Service]
ExecStart=/testsuite.sh
Type=oneshot
EOF
        cat > $initdir/etc/systemd/system/issue_14566_test.service << EOF
[Unit]
Description=Issue 14566 Repro

[Service]
ExecStart=/repro.sh
ExecStopPost=/bin/true
KillMode=mixed
EOF

        cp testsuite.sh $initdir/
        cp repro.sh $initdir/

        setup_testsuite
    )
    setup_nspawn_root

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@"
