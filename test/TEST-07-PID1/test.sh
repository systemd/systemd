#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for core PID1 functionality"

# for testing PrivateNetwork=yes
NSPAWN_ARGUMENTS="--capability=CAP_NET_ADMIN"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    # We might not be fast enough to hit the limit (20 triggers per 2 secs)
    # in certain environments, i.e. when running without KVM or when collecting
    # coverage. Let's help it a bit in such case.
    if ! get_bool "$QEMU_KVM" || get_bool "$IS_BUILT_WITH_COVERAGE"; then
        mkdir -p "$workspace/etc/systemd/system/issue2467.socket.d"
        printf "[Socket]\nTriggerLimitIntervalSec=10\n" >"$workspace/etc/systemd/system/issue2467.socket.d/TriggerLimitInterval.conf"
    fi

    image_install logger socat
}

do_test "$@"
