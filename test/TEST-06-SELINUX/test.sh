#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="SELinux tests"
IMAGE_NAME="selinux"
TEST_NO_NSPAWN=1

if [[ -e /etc/selinux/config ]]; then
    SEPOLICY="$(awk -F= '/^SELINUXTYPE=/ {print $2; exit}' /etc/selinux/config)"

    # C8S doesn't set SELINUXTYPE in /etc/selinux/config, so default to 'targeted'
    if [[ -z "$SEPOLICY" ]]; then
        echo "Failed to parse SELinux policy from /etc/selinux/config, falling back to 'targeted'"
        SEPOLICY="targeted"
    fi

    if [[ ! -d "/etc/selinux/$SEPOLICY" ]]; then
        echo "Missing policy directory /etc/selinux/$SEPOLICY, skipping the test"
        exit 0
    fi

    echo "Using SELinux policy '$SEPOLICY'"
else
    echo "/etc/selinux/config is missing, skipping the test"
    exit 0
fi

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

SETUP_SELINUX=yes
KERNEL_APPEND="${KERNEL_APPEND:-} selinux=1 enforcing=0 lsm=selinux"

test_append_files() {
    local workspace="${1:?}"

    setup_selinux
    # Config file has (unfortunately) always precedence, so let's switch it there as well
    sed -i '/^SELINUX=disabled$/s/disabled/permissive/' "$workspace/etc/selinux/config"
}

do_test "$@"
