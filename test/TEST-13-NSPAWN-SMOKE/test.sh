#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="systemd-nspawn smoke test"
IMAGE_NAME="nspawn"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        local workspace="${1:?}"
        dracut_install busybox

        if selinuxenabled >/dev/null; then
            dracut_install selinuxenabled
            cp -ar /etc/selinux "$workspace/etc/selinux"
        fi

        "$TEST_BASE_DIR/create-busybox-container" "$workspace/testsuite-13.nc-container"
        initdir="$workspace/testsuite-13.nc-container" dracut_install nc ip md5sum
    )
}

do_test "$@"
