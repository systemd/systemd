#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Tmpfiles related tests"
TEST_NO_QEMU=1
. $TEST_BASE_DIR/test-functions

test_append_files() {
    if [[ "$IS_BUILT_WITH_ASAN" == "yes" ]]; then
        if [[ -z "$initdir" ]]; then
            echo >&2 "\$initdir is not defined, can't continue"
            exit 1
        fi

        sed -i "s/systemd//g" "$initdir/etc/nsswitch.conf"
    fi
}

do_test "$@" 22
