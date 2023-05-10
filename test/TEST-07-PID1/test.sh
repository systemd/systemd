#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for core PID1 functionality"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    # Issue: https://github.com/systemd/systemd/issues/2730
    mkdir -p "$workspace/etc/systemd/system/"
    cat >"$workspace/etc/systemd/system/issue2730.mount" <<EOF
[Mount]
What=tmpfs
Where=/issue2730
Type=tmpfs

[Install]
WantedBy=local-fs.target
Alias=issue2730-alias.mount
EOF
    "${SYSTEMCTL:?}" enable --root="$workspace" issue2730.mount
    ln -svrf "$workspace/etc/systemd/system/issue2730.mount" "$workspace/etc/systemd/system/issue2730-alias.mount"
}

do_test "$@"
