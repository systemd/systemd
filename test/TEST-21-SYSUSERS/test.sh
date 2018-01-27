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
        # ensure our build of systemd-sysusers is run
        PATH=${BUILD_DIR}:$PATH

        # happy tests
        for f in test-*.input; do
                echo "*** Running $f"
                rm -f $TESTDIR/etc/*
                cp $f $TESTDIR/usr/lib/sysusers.d/test.conf
                systemd-sysusers --root=$TESTDIR

                if ! diff -u $TESTDIR/etc/passwd ${f%.*}.expected-passwd; then
                        echo "**** Unexpected output for $f"
                        exit 1
                fi
                if ! diff -u $TESTDIR/etc/group ${f%.*}.expected-group; then
                        echo "**** Unexpected output for $f"
                        exit 1
                fi
        done

        # tests for error conditions
        for f in unhappy-*.input; do
                echo "*** Running test $f"
                rm -f $TESTDIR/etc/*
                cp $f $TESTDIR/usr/lib/sysusers.d/test.conf
                systemd-sysusers --root=$TESTDIR 2> /dev/null
                journalctl -t systemd-sysusers -o cat | tail -n1 > $TESTDIR/tmp/err
                if ! diff -u $TESTDIR/tmp/err  ${f%.*}.expected-err; then
                        echo "**** Unexpected error output for $f"
                        cat $TESTDIR/tmp/err
                        exit 1
                fi
        done
}

do_test "$@"
