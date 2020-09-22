#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="Run unit tests under containers"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

# embed some newlines in the kernel command line to stress our test suite
KERNEL_APPEND="

frobnicate!

$KERNEL_APPEND
"

. $TEST_BASE_DIR/test-functions

check_result_nspawn() {
    local _ret=1
    [[ -e $1/testok ]] && _ret=0
    if [[ -s $1/failed ]]; then
        _ret=$(($_ret+1))
        echo "=== Failed test log ==="
        cat $1/failed
    else
        if [[ -s $1/skipped ]]; then
            echo "=== Skipped test log =="
            cat $1/skipped
        fi
        if [[ -s $1/testok ]]; then
            echo "=== Passed tests ==="
            cat $1/testok
        fi
    fi
    save_journal $1/var/log/journal
    _umount_dir $initdir
    [[ -n "$TIMED_OUT" ]] && _ret=$(($_ret+1))
    return $_ret
}

check_result_qemu() {
    local _ret=1
    mount_initdir
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
    save_journal $initdir/var/log/journal
    _umount_dir $initdir
    [[ -n "$TIMED_OUT" ]] && _ret=$(($_ret+1))
    return $_ret
}

do_test "$@" 02
