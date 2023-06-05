#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Fuzz our D-Bus interfaces with dfuzzer"
TEST_SUPPORTING_SERVICES_SHOULD_BE_MASKED=0
QEMU_TIMEOUT="${QEMU_TIMEOUT:-1800}"
IMAGE_NAME=dfuzzer
TEST_FORCE_NEWIMAGE=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Run the test either only under nspawn (if $TEST_PREFER_NSPAWN is set to true)
# or only uder qemu otherwise, to avoid running the test twice on machines where
# we can do both.
if ! get_bool "${TEST_PREFER_NSPAWN:=}"; then
    TEST_NO_NSPAWN=1
fi

test_require_bin dfuzzer

if ! get_bool "$IS_BUILT_WITH_ASAN"; then
    echo "systemd is built without ASan, skipping..."
    exit 0
fi

test_append_files() {
    local workspace="${1:?}"

    image_install dfuzzer /etc/dfuzzer.conf

    # Enable all systemd-related services, including the D-Bus ones
    "$SYSTEMCTL" --root="${workspace:?}" preset-all
}

do_test "$@"
