#!/bin/bash
set -e
TEST_DESCRIPTION="Sysuser-related tests"

. $TEST_BASE_DIR/test-functions

test_setup() {
    mkdir -p $TESTDIR/etc/sysusers.d $TESTDIR/usr/lib/sysusers.d $TESTDIR/tmp
}

prepare_testdir() {
    rm -f $TESTDIR/etc/*{passwd,group,shadow}
    for i in $1.initial-{passwd,group,shadow}; do
        test -f $i && cp $i $TESTDIR/etc/${i#*.initial-}
    done
    return 0
}

preprocess() {
    in="$1"

    # see meson.build how to extract this. gcc -E was used before to
    # get this value from config.h, however the autopkgtest fails with
    # it
    SYSTEM_UID_MAX=$(awk 'BEGIN { uid=999 } /^\s*SYS_UID_MAX\s+/ { uid=$2 } END { print uid }' /etc/login.defs)

    # we can't rely on config.h to get the nologin path, as autopkgtest
    # uses pre-compiled binaries, so extract it from the systemd-sysusers
    # binary which we are about to execute
    NOLOGIN=$(strings $(type -p systemd-sysusers) | grep nologin)

    sed -e "s/SYSTEM_UID_MAX/${SYSTEM_UID_MAX}/g" \
        -e "s#NOLOGIN#${NOLOGIN}#g" "$in"
}

compare() {
    if ! diff -u $TESTDIR/etc/passwd <(preprocess ${1%.*}.expected-passwd); then
        echo "**** Unexpected output for $f"
        exit 1
    fi

    if ! diff -u $TESTDIR/etc/group <(preprocess ${1%.*}.expected-group); then
        echo "**** Unexpected output for $f $2"
        exit 1
    fi
}

test_run() {
    # ensure our build of systemd-sysusers is run
    PATH=${BUILD_DIR}:$PATH

    rm -f $TESTDIR/etc/sysusers.d/* $TESTDIR/usr/lib/sysusers.d/*

    # happy tests
    for f in test-*.input; do
        echo "*** Running $f"
        prepare_testdir ${f%.input}
        cp $f $TESTDIR/usr/lib/sysusers.d/test.conf
        systemd-sysusers --root=$TESTDIR

        compare $f ""
    done

    for f in test-*.input; do
        echo "*** Running $f on stdin"
        prepare_testdir ${f%.input}
        touch $TESTDIR/etc/sysusers.d/test.conf
        cat $f | systemd-sysusers --root=$TESTDIR -

        compare $f "on stdin"
    done

    for f in test-*.input; do
        echo "*** Running $f on stdin with --replace"
        prepare_testdir ${f%.input}
        touch $TESTDIR/etc/sysusers.d/test.conf
        # this overrides test.conf which is masked on disk
        cat $f | systemd-sysusers --root=$TESTDIR --replace=/etc/sysusers.d/test.conf -
        # this should be ignored
        cat test-1.input | systemd-sysusers --root=$TESTDIR --replace=/usr/lib/sysusers.d/test.conf -

        compare $f "on stdin with --replace"
    done

    # test --inline
    echo "*** Testing --inline"
    prepare_testdir
    # copy a random file to make sure it is ignored
    cp $f $TESTDIR/etc/sysusers.d/confuse.conf
    systemd-sysusers --root=$TESTDIR --inline \
                     "u     u1   222 -     - /bin/zsh" \
                     "g     g1   111"

    compare inline "(--inline)"

    # test --replace
    echo "*** Testing --inline with --replace"
    prepare_testdir
    # copy a random file to make sure it is ignored
    cp $f $TESTDIR/etc/sysusers.d/confuse.conf
    systemd-sysusers --root=$TESTDIR \
                     --inline \
                     --replace=/etc/sysusers.d/confuse.conf \
                     "u     u1   222 -     - /bin/zsh" \
                     "g     g1   111"

    compare inline "(--inline --replace=…)"

    rm -f $TESTDIR/etc/sysusers.d/* $TESTDIR/usr/lib/sysusers.d/*

    # tests for error conditions
    for f in unhappy-*.input; do
        echo "*** Running test $f"
        prepare_testdir ${f%.input}
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
