#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Run unit tests under containers"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

. $TEST_BASE_DIR/test-functions

check_result_nspawn() {
    local _ret=1
    [[ -e $TESTDIR/$1/testok ]] && _ret=0
    if [[ -s $TESTDIR/$1/failed ]]; then
        _ret=$(($_ret+1))
        echo "=== Failed test log ==="
        cat $TESTDIR/$1/failed
    else
        if [[ -s $TESTDIR/$1/skipped ]]; then
            echo "=== Skipped test log =="
            cat $TESTDIR/$1/skipped
        fi
        if [[ -s $TESTDIR/$1/testok ]]; then
            echo "=== Passed tests ==="
            cat $TESTDIR/$1/testok
        fi
    fi
    cp -a $TESTDIR/$1/var/log/journal $TESTDIR
    [[ -n "$TIMED_OUT" ]] && _ret=$(($_ret+1))
    return $_ret
}

check_result_qemu() {
    local _ret=1
    mkdir -p $initdir
    mount ${LOOPDEV}p1 $initdir
    [[ -e $initdir/testok ]] && _ret=0
    if [[ -s $initdir/failed ]]; then
        _ret=$(($_ret+1))
        echo "=== Failed test log ==="
        cat $initdir/failed
    else
        if [[ -s $initdir/skipped ]]; then
            echo "=== Skipped test log =="
            cat $initdir/skipped
        fi
        if [[ -s $initdir/testok ]]; then
            echo "=== Passed tests ==="
            cat $initdir/testok
        fi
    fi
    cp -a $initdir/var/log/journal $TESTDIR
    umount $initdir
    [[ -n "$TIMED_OUT" ]] && _ret=$(($_ret+1))
    return $_ret
}

test_setup() {
    if type -P meson && [[ "$(meson configure $BUILD_DIR | grep install-tests | awk '{ print $2 }')" != "true" ]]; then
        dfatal "Needs to be built with -Dinstall-tests=true"
        exit 1
    fi

    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        mask_supporting_services
    )
    setup_nspawn_root
}

do_test "$@" 24
