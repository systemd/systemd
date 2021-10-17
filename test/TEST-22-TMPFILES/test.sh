#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tmpfiles related tests"
TEST_NO_QEMU=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    if get_bool "${IS_BUILT_WITH_ASAN:=}"; then
        if [[ -z "${initdir:=}" ]]; then
            echo >&2 "\$initdir is not defined, can't continue"
            exit 1
        fi

        sed -i "s/systemd//g" "$initdir/etc/nsswitch.conf"
    fi
}

do_test "$@"
