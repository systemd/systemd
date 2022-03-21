#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="shutdown testing"
IMAGE_NAME="shutdown"
TEST_NO_QEMU=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

_ORIG_NSPAWN="${SYSTEMD_NSPAWN:?}"
SYSTEMD_NSPAWN="${STATEDIR:?}/run-nspawn"

setup_nspawn_root_hook() {
    cat >"${STATEDIR:?}/run-nspawn" <<EOF
#!/bin/bash
exec "${TEST_BASE_DIR:?}/test-shutdown.py" -v -- "$_ORIG_NSPAWN" "\$@"
exit 1
EOF
    chmod 755 "${STATEDIR:?}"/run-nspawn
}

test_append_files() {
    local workspace="${1:?}"
    # prevent shutdown in test suite, the expect script does that manually.
    rm "${workspace:?}/usr/lib/systemd/tests/testdata/units/end.service"
    inst /usr/bin/screen
    echo "PS1='screen\$WINDOW # '" >>"$workspace/root/.bashrc"
    echo 'startup_message off' >"$workspace/etc/screenrc"
    echo 'bell_msg ""' >>"$workspace/etc/screenrc"
}

do_test "$@"
