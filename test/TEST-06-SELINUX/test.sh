#!/bin/bash
set -e
TEST_DESCRIPTION="SELinux tests"
TEST_NO_NSPAWN=1

# Requirements:
# Fedora 23
# selinux-policy-targeted
# selinux-policy-devel

# Check if selinux-policy-devel is installed, and if it isn't bail out early instead of failing
test -f /usr/share/selinux/devel/include/system/systemd.if || exit 0

. $TEST_BASE_DIR/test-functions
SETUP_SELINUX=yes
KERNEL_APPEND="$KERNEL_APPEND selinux=1 security=selinux"

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment

        # setup the testsuite service
        cat <<EOF >$initdir/etc/systemd/system/testsuite.service
[Unit]
Description=Testsuite service

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
    )

    # mask some services that we do not want to run in these tests
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
}

do_test "$@"
