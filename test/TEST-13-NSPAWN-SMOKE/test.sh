#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemd-nspawn smoke test"
IMAGE_NAME="nspawn"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        local workspace="${1:?}"

        # On openSUSE the static linked version of busybox is named "busybox-static".
        busybox="$(type -P busybox-static || type -P busybox)"
        inst_simple "$busybox" "$(dirname "$busybox")/busybox"

        if command -v selinuxenabled >/dev/null && selinuxenabled; then
            image_install selinuxenabled
            cp -ar /etc/selinux "$workspace/etc/selinux"
        fi

        "$TEST_BASE_DIR/create-busybox-container" "$workspace/testsuite-13.nc-container"
        initdir="$workspace/testsuite-13.nc-container" image_install nc ip md5sum
    )
}

do_test "$@"
