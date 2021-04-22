#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    # Create a swap device
    (
        mkswap "${LOOPDEV:?}p2"
        dracut_install swapon swapoff

        cat >>"${initdir:?}/etc/fstab" <<EOF
UUID=$(blkid -o value -s UUID "${LOOPDEV}p2")    none    swap    defaults 0 0
EOF
    )
}

check_result_nspawn() {
    local workspace="${1:?}"
    local ret=1
    local journald_report=""
    local pids=""

    [[ -e "$workspace/testok" ]] && ret=0
    if [[ -e "$workspace/skipped" ]]; then
        echo "TEST-56-OOMD was skipped:"
        cat "$workspace/skipped"
        ret=0
    fi

    [[ -f "$workspace/failed" ]] && cp -a "$workspace/failed" "${TESTDIR:?}"
    save_journal "$workspace/var/log/journal"
    [[ -f "$TESTDIR/failed" ]] && cat "$TESTDIR/failed"
    echo "${JOURNAL_LIST:-No journals were saved}"

    test -s "$TESTDIR/failed" && ret=$((ret + 1))
    [ -n "${TIMED_OUT:=}" ] && ret=$((ret + 1))
    check_asan_reports "$workspace" || ret=$((ret + 1))
    _umount_dir "${initdir:?}"
    return $ret
}

check_result_qemu() {
    local ret=1

    mount_initdir
    [[ -e "${initdir:?}/testok" ]] && ret=0
    if [[ -e "$initdir/skipped" ]]; then
        echo "TEST-56-OOMD was skipped:"
        cat "$initdir/skipped"
        ret=0
    fi

    [[ -f "$initdir/failed" ]] && cp -a "$initdir/failed" "${TESTDIR:?}"
    save_journal "$initdir/var/log/journal"
    check_asan_reports "$initdir" || ret=$((ret + 1))
    _umount_dir "$initdir"
    [[ -f "$TESTDIR/failed" ]] && cat "$TESTDIR/failed"
    echo "${JOURNAL_LIST:-No journals were saved}"

    test -s "$TESTDIR/failed" && ret=$((ret + 1))
    [ -n "${TIMED_OUT:=}" ] && ret=$((ret + 1))
    return $ret
}

do_test "$@" 55
