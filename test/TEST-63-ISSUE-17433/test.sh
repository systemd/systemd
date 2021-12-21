#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="https://github.com/systemd/systemd/issues/17433"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        # Make the test work reliably on slower machines as well, where we might
        # miss the default TriggerLimitIntervalSec= window and end up
        # reactivating the service just slow enough to fly under the rate-limit
        # radar
        mkdir -p "${initdir:?}/etc/systemd/system/test63.path.d"
        printf "[Path]\nTriggerLimitIntervalSec=10\n" >"${initdir:?}/etc/systemd/system/test63.path.d/coverage-override.conf"
    )
}

do_test "$@"
