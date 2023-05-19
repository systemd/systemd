#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for systemd-logind"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    instmods uinput
    image_install -o evemu-device evemu-event

    install_locales
    install_x11_keymaps

    generate_module_dependencies
}

do_test "$@"
