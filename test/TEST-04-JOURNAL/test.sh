#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Journal-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"
    local dropin_dir

    mkdir -p "$workspace/test-journals/"
    cp -av "${TEST_BASE_DIR:?}/test-journals/"* "$workspace/test-journals/"

    image_install curl setterm unzstd
    image_install -o openssl
    # Necessary for RH-based systems, otherwise MHD fails with:
    #   microhttpd: Failed to initialise TLS session.
    image_install -o /etc/crypto-policies/back-ends/gnutls.config

    # Since we nuke the journal repeatedly during this test, let's redirect
    # stdout/stderr to the console as well to make the test a bit more debug-able.
    if ! get_bool "${INTERACTIVE_DEBUG:-}"; then
        dropin_dir="${workspace:?}/etc/systemd/system/testsuite-04.service.d/"
        mkdir -p "$dropin_dir"
        printf '[Service]\nStandardOutput=journal+console\nStandardError=journal+console' >"$dropin_dir/99-stdout.conf"
    fi
}

do_test "$@"
