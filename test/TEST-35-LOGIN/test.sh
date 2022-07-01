#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="LOGIN"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    if command -v expect >/dev/null && command -v tclsh >/dev/null ; then
        # shellcheck disable=SC2016
        version="$(tclsh <<< 'puts $tcl_version')"

        image_install expect
        inst_recursive /usr/lib64/tcl"$version" /usr/share/tcl"$version"
    fi
}

do_test "$@"
