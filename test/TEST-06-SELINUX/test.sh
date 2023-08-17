#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="SELinux tests"
IMAGE_NAME="selinux"
TEST_NO_NSPAWN=1

# Requirements:
# A selinux policy is installed. Preferably selinux-policy-targeted, but it could work with others
# selinux-policy-devel

# Check if
# - selinux-policy-devel is installed and
# - some selinux policy is installed. To keep this generic just check for the
#   existence of a directory below /etc/selinux/, indicating a SELinux policy is
#   installed
# otherwise bail out early instead of failing
test -f /usr/share/selinux/devel/include/system/systemd.if && find /etc/selinux -mindepth 1 -maxdepth 1 -not -empty -type d | grep -q . || exit 0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

SETUP_SELINUX=yes
KERNEL_APPEND="${KERNEL_APPEND:=} selinux=1 security=selinux"

test_append_files() {
    local workspace="${1:?}"
    local policy_headers_dir=/usr/share/selinux/devel
    local modules_dir=/var/lib/selinux

    setup_selinux
    # Make sure we never expand this to "/..."
    rm -rf "${workspace:?}/$modules_dir"

    if ! cp -ar "$modules_dir" "$workspace/$modules_dir"; then
        dfatal "Failed to copy $modules_dir"
        exit 1
    fi

    rm -rf "${workspace:?}/$policy_headers_dir"
    inst_dir /usr/share/selinux

    if ! cp -ar "$policy_headers_dir" "$workspace/$policy_headers_dir"; then
        dfatal "Failed to copy $policy_headers_dir"
        exit 1
    fi

    mkdir "$workspace/systemd-test-module"
    cp -v systemd_test.* "$workspace/systemd-test-module/"
    image_install checkmodule load_policy m4 make sefcontext_compile semodule semodule_package runcon
    image_install -o sesearch
    image_install -o /usr/libexec/selinux/hll/pp # Fedora/RHEL/...
    image_install -o /usr/lib/selinux/hll/pp     # Debian/Ubuntu/...

    if ! chroot "$workspace" make -C /systemd-test-module -f /usr/share/selinux/devel/Makefile clean load systemd_test.pp QUIET=n; then
        dfatal "Failed to build the systemd test module"
        exit 1
    fi
}

do_test "$@"
