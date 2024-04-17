#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Journal-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Since we nuke the journal repeatedly during this test, let's redirect
# stdout/stderr to the console as well to make the test a bit more debug-able.
if ! get_bool "${INTERACTIVE_DEBUG:-}"; then
    NSPAWN_ARGUMENTS="$NSPAWN_ARGUMENTS --load-credential systemd.unit-dropin.testsuite-04.service:$(readlink -f systemd.unit-dropin.testsuite-04.service)"
    QEMU_OPTIONS="${QEMU_OPTIONS:-} -smbios type=11,value=io.systemd.credential.binary:systemd.unit-dropin.testsuite-04.service=$(base64 systemd.unit-dropin.testsuite-04.service)"
fi

test_append_files() {
    local workspace="${1:?}"
    local dropin_dir

    image_install curl setterm unzstd
    image_install -o openssl
    # Necessary for RH-based systems, otherwise MHD fails with:
    #   microhttpd: Failed to initialise TLS session.
    image_install -o /etc/crypto-policies/back-ends/gnutls.config
}

do_test "$@"
