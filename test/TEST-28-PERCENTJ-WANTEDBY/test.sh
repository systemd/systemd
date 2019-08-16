#!/bin/bash
set -e
TEST_DESCRIPTION="Ensure %j Wants directives work"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # Set up the services.
        cat >$initdir/etc/systemd/system/specifier-j-wants.service << EOF
[Unit]
Description=Wants with percent-j specifier
Wants=specifier-j-depends-%j.service
After=specifier-j-depends-%j.service

[Service]
Type=oneshot
ExecStart=test -f /tmp/test-specifier-j-%j
ExecStart=/bin/sh -c 'echo OK > /testok'
EOF
        cat >$initdir/etc/systemd/system/specifier-j-depends-wants.service << EOF
[Unit]
Description=Dependent service for percent-j specifier

[Service]
Type=oneshot
ExecStart=touch /tmp/test-specifier-j-wants
EOF
        cat >$initdir/etc/systemd/system/testsuite.service << EOF
[Unit]
Description=Testsuite: Ensure %j Wants directives work
Wants=specifier-j-wants.service
After=specifier-j-wants.service

[Service]
Type=oneshot
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
