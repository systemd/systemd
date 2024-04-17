#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for core PID1 functionality"

# for testing PrivateNetwork=yes
NSPAWN_ARGUMENTS="--capability=CAP_NET_ADMIN"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# We might not be fast enough to hit the limit (20 triggers per 2 secs)
# in certain environments, i.e. when running without KVM or when collecting
# coverage. Let's help it a bit in such case.
if ! get_bool "$QEMU_KVM" || get_bool "$IS_BUILT_WITH_COVERAGE"; then
    NSPAWN_ARGUMENTS="$NSPAWN_ARGUMENTS --load-credential systemd.unit-dropin.issue2467.socket:$(readlink -f systemd.unit-dropin.issue2467.socket)"
    QEMU_OPTIONS="${QEMU_OPTIONS:-} -smbios type=11,value=io.systemd.credential.binary:systemd.unit-dropin.issue2467.socket=$(base64 systemd.unit-dropin.issue2467.socket)"
fi

test_append_files() {
    image_install logger socat
}

do_test "$@"
