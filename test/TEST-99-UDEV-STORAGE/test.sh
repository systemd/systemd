#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="systemd-udev storage tests"
IMAGE_NAME="default"
TEST_NO_NSPAWN=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

USER_QEMU_OPTIONS="${QEMU_OPTIONS:-}"
USER_KERNEL_APPEND="${KERNEL_APPEND:-}"

test_append_files() {
    (
        instmods "=block"
        instmods "=md"
        instmods "=scsi"
        instmods "=nvme"
        install_dmevent
        generate_module_dependencies
        inst_binary lsblk
        inst_binary wc

        for i in {0..127}; do
            dd if=/dev/zero of="${TESTDIR:?}/disk$i.img" bs=1M count=1
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

    if get_bool "${TEST_NO_QEMU:=}" || ! find_qemu_bin; then
        dwarn "can't run QEMU, skipping"
        return 0
    fi

    # Execute each currently defined function starting with "testcase_"
    for testcase in "${TESTCASES[@]}"; do
        { "$testcase" "$test_id"; ec=$?; } || :
        ec=0
        case $ec in
            0)
                ((passed+=1)) || :
                ;;
            77)
                ((skipped+=1))
                ;;
            *)
                ((failed+=1))
        esac
    done

    echo "Passed tests: $passed"
    echo "Skipped tests: $skipped"
    echo "Failed tests: $failed"

    [[ $failed -eq 0 ]] || return 1

    return 0
}

testcase_megasas2() {
    if ! "${QEMU_BIN:?}" -device help | grep 'name "megasas-gen2"'; then
        echo "megasas-gen2 device driver is not available, skipping test..."
        return 77
    fi

    local qemu_opts=(
        "-device megasas-gen2,id=scsi0"
        "-device megasas-gen2,id=scsi1"
        "-device megasas-gen2,id=scsi2"
        "-device megasas-gen2,id=scsi3"
    )

    for i in {0..127}; do
        # Add 128 drives, 32 per bus
        qemu_opts+=(
            "-device scsi-hd,drive=drive$i,bus=scsi$((i / 32)).0,channel=0,scsi-id=$((i % 32)),lun=0"
            "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}"
}

testcase_nvme() {
    if ! "${QEMU_BIN:?}" -device help | grep 'name "nvme"'; then
        echo "nvme device driver is not available, skipping test..."
        return 77
    fi

    local qemu_opts=()

    for i in {0..27}; do
        qemu_opts+=(
            "-device nvme,drive=nvme$i,serial=deadbeef$i,max_ioqpairs=8"
            "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=nvme$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}"
}


mapfile -t TESTCASES < <(declare -F | awk '$3 ~ /^testcase_/ {print $3;}')

do_test "$@"
