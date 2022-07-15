#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/2467"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        # Collecting coverage slows this particular test quite a bit, causing
        # it to fail with the default settings (20 triggers per 2 secs)
        # to trip over the default limit. Let's help it a bit in such case.
        if get_bool "$IS_BUILT_WITH_COVERAGE"; then
            mkdir -p "${initdir:?}/etc/systemd/system/test10.socket.d"
            printf "[Socket]\nTriggerLimitIntervalSec=10\n" >"${initdir:?}/etc/systemd/system/test10.socket.d/coverage-override.conf"
        fi
    )
}

do_test "$@"
