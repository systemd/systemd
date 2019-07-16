#!/bin/bash
set -e
TEST_DESCRIPTION="network-generator tests"

. $TEST_BASE_DIR/test-functions

test_setup() {
    mkdir -p $TESTDIR/run/systemd/network
}

test_run() {
    local generator

    if [[ -x $BUILD_DIR/systemd-network-generator ]]; then
        generator=$BUILD_DIR/systemd-network-generator
    elif [[ -x /usr/lib/systemd/systemd-network-generator ]]; then
        generator=/usr/lib/systemd/systemd-network-generator
    elif [[ -x /lib/systemd/systemd-network-generator ]]; then
        generator=/lib/systemd/systemd-network-generator
    else
        exit 1
    fi

    for f in test-*.input; do
        echo "*** Running $f"
        rm -f $TESTDIR/run/systemd/network/*
        $generator --root $TESTDIR -- $(cat $f)

        if ! diff -u $TESTDIR/run/systemd/network ${f%.input}.expected; then
            echo "**** Unexpected output for $f"
            exit 1
        fi
    done
}

do_test "$@"
