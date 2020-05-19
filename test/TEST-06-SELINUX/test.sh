#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="SELinux tests"
IMAGE_NAME="selinux"
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

test_create_image() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5

        setup_basic_environment
        mask_supporting_services

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
        dracut_install -o sesearch
        dracut_install runcon
        dracut_install checkmodule semodule semodule_package m4 make load_policy sefcontext_compile
        dracut_install -o /usr/libexec/selinux/hll/pp # Fedora/RHEL/...
        dracut_install -o /usr/lib/selinux/hll/pp     # Debian/Ubuntu/...
    )
}

do_test "$@" 06
