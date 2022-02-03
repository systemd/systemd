#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/17433"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        # Tweak the trigger limit interval in case we are collecting coverage
        # or running without KVM - in both cases we might be slow enough that
        # we could miss the default rate-limit window and cause the test to fail
        # unexpectedly.
        if get_bool "$IS_BUILT_WITH_COVERAGE" || ! get_bool "$QEMU_KVM"; then
            mkdir -p "${initdir:?}/etc/systemd/system/test63.path.d"
            printf "[Path]\nTriggerLimitIntervalSec=10\n" >"${initdir:?}/etc/systemd/system/test63.path.d/triggerlimitinterval-override.conf"
        fi
    )
}

do_test "$@"
