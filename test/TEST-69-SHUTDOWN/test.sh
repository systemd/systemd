#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="shutdown testing"
IMAGE_NAME="shutdown"
TEST_NO_QEMU=yes
# Prevent shutdown in test suite, the expect script does that manually.
TEST_SKIP_SHUTDOWN=yes

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

    # Shorten the service stop/abort timeouts to let systemd SIGKILL stubborn
    # processes as soon as possible, as we don't really care about them in this
    # particular test
    mkdir -p "$workspace/etc/systemd/system.conf.d"
    cat >"$workspace/etc/systemd/system.conf.d/99-timeout.conf" <<EOF
[Manager]
DefaultTimeoutStopSec=30s
DefaultTimeoutAbortSec=30s
EOF

    inst /usr/bin/screen
    echo "PS1='screen\$WINDOW # '" >>"$workspace/root/.bashrc"
    echo 'startup_message off' >"$workspace/etc/screenrc"
    echo 'bell_msg ""' >>"$workspace/etc/screenrc"
}

do_test "$@"
