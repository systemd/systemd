#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"

. $TEST_BASE_DIR/test-functions

check_result_nspawn() {
    local ret=1
    local journald_report=""
    local pids=""
    [[ -e $1/testok ]] && ret=0
    if [[ -e $1/skipped ]]; then
        echo "TEST-56-OOMD was skipped:"
        cat $1/skipped
        ret=0
    fi
    [[ -f $1/failed ]] && cp -a $1/failed $TESTDIR
    save_journal $1/var/log/journal
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    echo $JOURNAL_LIST
    test -s $TESTDIR/failed && ret=$(($ret+1))
    [ -n "$TIMED_OUT" ] && ret=$(($ret+1))
    check_asan_reports "$1" || ret=$(($ret+1))
    _umount_dir $initdir
    return $ret
}

check_result_qemu() {
    local ret=1
    mount_initdir
    [[ -e $initdir/testok ]] && ret=0
    if [[ -e $initdir/skipped ]]; then
        echo "TEST-56-OOMD was skipped:"
        cat $initdir/skipped
        ret=0
    fi
    [[ -f $initdir/failed ]] && cp -a $initdir/failed $TESTDIR
    save_journal $initdir/var/log/journal
    check_asan_reports "$initdir" || ret=$(($ret+1))
    _umount_dir $initdir
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    echo $JOURNAL_LIST
    test -s $TESTDIR/failed && ret=$(($ret+1))
    [ -n "$TIMED_OUT" ] && ret=$(($ret+1))
    return $ret
}

do_test "$@" 55
