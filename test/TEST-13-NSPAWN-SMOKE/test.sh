#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="systemd-nspawn smoke test"
IMAGE_NAME="nspawn"
TEST_NO_NSPAWN=1
# The test containers are missing the $BUILD_DIR with the necessary note files
# which generates lots of errors regarding missing coverage. Since fixing this
# would make the test code unnecessarily messy, let's just ignore them, at least
# for now.
IGNORE_MISSING_COVERAGE=yes

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    # On openSUSE the static linked version of busybox is named "busybox-static".
    busybox="$(type -P busybox-static || type -P busybox)"
    inst_simple "$busybox" "$(dirname "$busybox")/busybox"

    if command -v selinuxenabled >/dev/null && selinuxenabled; then
        image_install chcon selinuxenabled
        cp -ar /etc/selinux "$workspace/etc/selinux"
        sed -i "s/^SELINUX=.*$/SELINUX=permissive/" "$workspace/etc/selinux/config"
    fi

    "$TEST_BASE_DIR/create-busybox-container" "$workspace/testsuite-13.nc-container"
    initdir="$workspace/testsuite-13.nc-container" image_install nc ip md5sum
}

do_test "$@"
