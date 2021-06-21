#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Run unit tests under containers"
RUN_IN_UNPRIVILEGED_CONTAINER=yes

# embed some newlines in the kernel command line to stress our test suite
KERNEL_APPEND="

frobnicate!

$KERNEL_APPEND
"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

check_result_nspawn() {
    local workspace="${1:?}"
    local ret=1

    [[ -e "$workspace/testok" ]] && ret=0

    if [[ -s "$workspace/failed" ]]; then
        ret=$((ret + 1))
        echo "=== Failed test log ==="
        cat "$workspace/failed"
    else
        if [[ -s "$workspace/skipped" ]]; then
            echo "=== Skipped test log =="
            cat "$workspace/skipped"
            # We might have only skipped tests - that should not fail the job
            ret=0
        fi
        if [[ -s "$workspace/testok" ]]; then
            echo "=== Passed tests ==="
            cat "$workspace/testok"
        fi
    fi

    save_journal "$workspace/var/log/journal"
    _umount_dir "${initdir:?}"

    [[ -n "${TIMED_OUT:=}" ]] && ret=1
    return $ret
}

check_result_qemu() {
    local ret=1

    mount_initdir
    [[ -e "${initdir:?}/testok" ]] && ret=0

    if [[ -s "$initdir/failed" ]]; then
        ret=$((ret + 1))
        echo "=== Failed test log ==="
        cat "$initdir/failed"
    else
        if [[ -s "$initdir/skipped" ]]; then
            echo "=== Skipped test log =="
            cat "$initdir/skipped"
            # We might have only skipped tests - that should not fail the job
            ret=0
        fi
        if [[ -s "$initdir/testok" ]]; then
            echo "=== Passed tests ==="
            cat "$initdir/testok"
        fi
    fi

    save_journal "$initdir/var/log/journal"
    _umount_dir "$initdir"

    [[ -n "${TIMED_OUT:=}" ]] && ret=1
    return $ret
}

do_test "$@"
