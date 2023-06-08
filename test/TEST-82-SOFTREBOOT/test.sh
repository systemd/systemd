#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test Soft-Rebooting"
# We temporarily remount rootfs read-only, so ignore any missing coverage
IGNORE_MISSING_COVERAGE=yes

# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

test_append_files() {
    local workspace="${1:?}"
    # prevent shutdown in test suite, the expect script does that manually.
    mkdir -p "${workspace:?}/etc/systemd/system/end.service.d"
    cat >"$workspace/etc/systemd/system/end.service.d/99-override.conf" <<EOF
[Service]
ExecStart=
ExecStart=/bin/true
EOF
}

do_test "$@"
