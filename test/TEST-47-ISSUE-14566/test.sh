#!/bin/bash
set -e
TEST_DESCRIPTION="Test that KillMode=mixed does not leave left over proccesses with ExecStopPost="
. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services

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
}

do_test "$@"
