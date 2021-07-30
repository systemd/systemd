#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="systemd-udev storage tests"
IMAGE_NAME="default"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    (
        instmods "=block"
        instmods "=md"
        instmods "=scsi"
        install_dmevent
        generate_module_dependencies
        inst_binary lsblk
        inst_binary wc

        for i in {0..64}; do
            dd if=/dev/zero of="${TESTDIR:?}/disk$i.img" bs=1M count=8
        done
    )
}

test_run_one() {
    local test_id="${1:?}"

    if run_qemu "$test_id"; then
        check_result_qemu || { echo "QEMU test failed"; return 1; }
    fi

    return 0
}

test_run() {
    local test_id="${1:?}"
    local passed=0
    local failed=0
    local skipped=0
    local ec

    mount_initdir

    if get_bool "${TEST_NO_QEMU:=}"; then
        dwarn "can't run QEMU, skipping"
        return 0
    fi

    # Make sure we have a working QEMU for the feature checks
    find_qemu_bin || return 1

    # Execute each currently defined function starting with "testcase_"
    while read -r testcase; do
        { "$testcase" "$test_id"; ec=$?; } || :
        case $ec in
            0)
                ((passed+=1))
                ;;
            77)
                ((skipped+=1))
                ;;
            *)
                ((failed+=1))
        esac
    done < <(declare -F | awk '$3 ~ /^testcase_/ {print $3;}')

    echo "Passed tests: $passed"
    echo "Skipped tests: $skipped"
    echo "Failed tests: $failed"

    [[ $failed -eq 0 ]] || return 1

    return 0
}

testcase_megasas() {
    if ! "${QEMU_BIN:?}" -device help | grep 'name "megasas"'; then
        echo "megasas device driver is not available, skipping test..."
        return 77
    fi

    local qemu_opts=(
        "-device megasas,id=scsi0"
        "-device scsi-hd,drive=drive0,bus=scsi0.0,channel=0,scsi-id=0,lun=0"
        "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk0.img,if=none,id=drive0"
        "-device scsi-hd,drive=drive1,bus=scsi0.0,channel=0,scsi-id=1,lun=0"
        "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk1.img,if=none,id=drive1"
    )

    for i in {2..64}; do
        qemu_opts+=(
            "-device scsi-hd,drive=drive$i,bus=scsi0.0,channel=0,scsi-id=$i,lun=0"
            "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${QEMU_OPTIONS:-}"
    test_run_one "${1:?}"
}

do_test "$@"
