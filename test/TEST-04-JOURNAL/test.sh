#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Journal-related tests"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    local workspace="${1:?}"

    mkdir -p "$workspace/test-journals/"
    cp -av "${TEST_BASE_DIR:?}/test-journals/"* "$workspace/test-journals/"

    image_install curl setterm unzstd
    image_install -o openssl
    # Necessary for RH-based systems, otherwise MHD fails with:
    #   microhttpd: Failed to initialise TLS session.
    image_install -o /etc/crypto-policies/back-ends/gnutls.config
}

do_test "$@"
