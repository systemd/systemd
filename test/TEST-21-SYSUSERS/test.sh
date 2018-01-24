#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="Sysuser-related tests"

. $TEST_BASE_DIR/test-functions

test_setup() {
        mkdir -p $TESTDIR/etc  $TESTDIR/usr/lib/sysusers.d $TESTDIR/tmp
}

test_run() {
        for f in test-*.input; do
                echo "***** Running $f"
                rm -f $TESTDIR/etc/*
                cp $f $TESTDIR/usr/lib/sysusers.d/test.conf
                ${BUILD_DIR}/systemd-sysusers --root=$TESTDIR
                if ! diff -u $TESTDIR/etc/passwd ${f%.*}.expected-passwd; then
                        echo "**** Unexpected output for $f"
                        exit 1
                fi
                if ! diff -u $TESTDIR/etc/group ${f%.*}.expected-group; then
                        echo "**** Unexpected output for $f"
                        exit 1
                fi
        done
}

do_test "$@"
