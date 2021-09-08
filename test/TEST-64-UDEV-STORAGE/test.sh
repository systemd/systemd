#!/usr/bin/env bash
# vi: ts=4 sw=4 tw=0 et:
set -e

TEST_DESCRIPTION="systemd-udev storage tests"
IMAGE_NAME="default"
TEST_NO_NSPAWN=1
QEMU_TIMEOUT="${QEMU_TIMEOUT:-600}"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

USER_QEMU_OPTIONS="${QEMU_OPTIONS:-}"
USER_KERNEL_APPEND="${KERNEL_APPEND:-}"

if ! get_bool "$QEMU_KVM"; then
    echo "This test requires KVM, skipping..."
    exit 0
fi

test_append_files() {
    (
        instmods "=block" "=md" "=nvme" "=scsi"
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
    local passed=()
    local failed=()
    local skipped=()
    local ec state

    mount_initdir

    if get_bool "${TEST_NO_QEMU:=}" || ! find_qemu_bin; then
        dwarn "can't run QEMU, skipping"
        return 0
    fi

    # Execute each currently defined function starting with "testcase_"
    for testcase in "${TESTCASES[@]}"; do
        echo "------ $testcase: BEGIN ------"
        { "$testcase" "$test_id"; ec=$?; } || :
        case $ec in
            0)
                passed+=("$testcase")
                state="PASS"
                ;;
            77)
                skipped+=("$testcase")
                state="SKIP"
                ;;
            *)
                failed+=("$testcase")
                state="FAIL"
        esac
        echo "------ $testcase: END ($state) ------"
    done

    echo "Passed tests: ${#passed[@]}"
    printf "    * %s\n" "${passed[@]}"
    echo "Skipped tests: ${#skipped[@]}"
    printf "    * %s\n" "${skipped[@]}"
    echo "Failed tests: ${#failed[@]}"
    printf "    * %s\n" "${failed[@]}"

    [[ ${#failed[@]} -eq 0 ]] || return 1

    return 0
}

testcase_megasas2_basic() {
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

testcase_nvme_basic() {
    if ! "${QEMU_BIN:?}" -device help | grep 'name "nvme"'; then
        echo "nvme device driver is not available, skipping test..."
        return 77
    fi

    for i in {0..27}; do
        qemu_opts+=(
            "-device nvme,drive=nvme$i,serial=deadbeef$i,num_queues=8"
            "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=nvme$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}"
}

# Test for issue https://github.com/systemd/systemd/issues/20212
testcase_virtio_scsi_identically_named_partitions() {
    if ! "${QEMU_BIN:?}" -device help | grep 'name "virtio-scsi-pci"'; then
        echo "virtio-scsi-pci device driver is not available, skipping test..."
        return 77
    fi

    # Create 16 disks, with 8 partitions per disk (all identically named)
    # and attach them to a virtio-scsi controller
    local qemu_opts=("-device virtio-scsi-pci,id=scsi0,num_queues=4")
    local diskpath="${TESTDIR:?}/namedpart0.img"
    local lodev

    # Save some time (and storage life) during local testing
    if [[ ! -e "$diskpath" ]]; then
        dd if=/dev/zero of="$diskpath" bs=1M count=18
        lodev="$(losetup --show -f -P "$diskpath")"
        sfdisk "${lodev:?}" <<EOF
label: gpt

name="Hello world", size=2M
name="Hello world", size=2M
name="Hello world", size=2M
name="Hello world", size=2M
name="Hello world", size=2M
name="Hello world", size=2M
name="Hello world", size=2M
name="Hello world", size=2M
EOF
        losetup -d "$lodev"
    fi

    for i in {0..15}; do
        diskpath="${TESTDIR:?}/namedpart$i.img"
        if [[ $i -gt 0 ]]; then
            cp -uv "${TESTDIR:?}/namedpart0.img" "$diskpath"
        fi

        qemu_opts+=(
            "-device scsi-hd,drive=drive$i,bus=scsi0.0,channel=0,scsi-id=0,lun=$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    # Limit the number of VCPUs and set a timeout to make sure we trigger the issue
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    QEMU_SMP=1 QEMU_TIMEOUT=60 test_run_one "${1:?}"
}

# Allow overriding which tests should be run from the "outside", useful for manual
# testing (make -C test/... TESTCASES="testcase1 testcase2")
if [[ -v "TESTCASES" && -n "$TESTCASES" ]]; then
    read -ra TESTCASES <<< "$TESTCASES"
else
    # This must run after all functions were defined, otherwise `declare -F` won't
    # see them
    mapfile -t TESTCASES < <(declare -F | awk '$3 ~ /^testcase_/ {print $3;}')
fi

do_test "$@"
