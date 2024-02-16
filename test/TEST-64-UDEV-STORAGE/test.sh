#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: ts=4 sw=4 tw=0 et:
#
# TODO:
#   * SW raid (mdadm)
#   * MD (mdadm) -> dm-crypt -> LVM
#   * iSCSI -> dm-crypt -> LVM
set -e

TEST_DESCRIPTION="systemd-udev storage tests"
TEST_NO_NSPAWN=1
# Save only journals of failing test cases by default (to conserve space)
TEST_SAVE_JOURNAL="${TEST_SAVE_JOURNAL:-fail}"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

USER_QEMU_OPTIONS="${QEMU_OPTIONS:-}"
USER_KERNEL_APPEND="${KERNEL_APPEND:-}"

_host_has_feature() {(
    set -e

    case "${1:?}" in
        btrfs)
            host_has_btrfs
            ;;
        iscsi)
            # Client/initiator (Open-iSCSI)
            command -v iscsiadm && command -v iscsid || return $?
            # Server/target (TGT)
            command -v tgtadm && command -v tgtd || return $?
            ;;
        lvm)
            command -v lvm || return $?
            ;;
        mdadm)
            host_has_mdadm
            ;;
        multipath)
            command -v multipath && command -v multipathd || return $?
            ;;
        *)
            echo >&2 "ERROR: Unknown feature '$1'"
            # Make this a hard error to distinguish an invalid feature from
            # a missing feature
            exit 1
    esac
)}

test_append_files() {(
    local feature
    # An associative array of requested (but optional) features and their
    # respective "handlers" from test/test-functions
    #
    # Note: we install cryptsetup unconditionally, hence it's not explicitly
    # checked for here
    local -A features=(
        [btrfs]=install_btrfs
        [iscsi]=install_iscsi
        [lvm]=install_lvm
        [mdadm]=install_mdadm
        [multipath]=install_multipath
    )

    instmods "=block" "=md" "=nvme" "=scsi"
    install_dmevent
    image_install lsblk swapoff swapon wc wipefs

    # Install the optional features if the host has the respective tooling
    for feature in "${!features[@]}"; do
        if _host_has_feature "$feature"; then
            "${features[$feature]}"
        fi
    done

    generate_module_dependencies

    for i in {0..127}; do
        dd if=/dev/zero of="${TESTDIR:?}/disk$i.img" bs=1M count=1
        echo "device$i" >"${TESTDIR:?}/disk$i.img"
    done
)}

_image_cleanup() {
    mount_initdir
    # Clean up certain "problematic" files which may be left over by failing tests
    : >"${initdir:?}/etc/fstab"
    : >"${initdir:?}/etc/crypttab"
    # Clear previous assignment
    QEMU_OPTIONS_ARRAY=()
}

test_run_one() {
    local test_id="${1:?}"

    if run_qemu "$test_id"; then
        check_result_qemu || { echo "qemu test failed"; return 1; }
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
        dwarn "can't run qemu, skipping"
        return 0
    fi

    # Execute each currently defined function starting with "testcase_"
    for testcase in "${TESTCASES[@]}"; do
        _image_cleanup
        echo "------ $testcase: BEGIN ------"
        # Note for my future frustrated self: `fun && xxx` (as well as ||, if, while,
        # until, etc.) _DISABLES_ the `set -e` behavior in _ALL_ nested function
        # calls made from `fun()`, i.e. the function _CONTINUES_ even when a called
        # command returned non-zero EC. That may unexpectedly hide failing commands
        # if not handled properly. See: bash(1) man page, `set -e` section.
        #
        # So, be careful when adding clean up snippets in the testcase_*() functions -
        # if the `test_run_one()` function isn't the last command, you have propagate
        # the exit code correctly (e.g. `test_run_one() || return $?`, see below).
        ec=0
        "$testcase" "$test_id" || ec=$?
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

    local i
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

    local i
    local qemu_opts=()

    for (( i = 0; i < 5; i++ )); do
        qemu_opts+=(
            "-device" "nvme,drive=nvme$i,serial=deadbeef$i,num_queues=8"
            "-drive" "format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=nvme$i"
        )
    done
    for (( i = 5; i < 10; i++ )); do
        qemu_opts+=(
            "-device" "nvme,drive=nvme$i,serial=    deadbeef  $i   ,num_queues=8"
            "-drive" "format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=nvme$i"
        )
    done
    for (( i = 10; i < 15; i++ )); do
        qemu_opts+=(
            "-device" "nvme,drive=nvme$i,serial=    dead/beef/$i   ,num_queues=8"
            "-drive" "format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=nvme$i"
        )
    done
    for (( i = 15; i < 20; i++ )); do
        qemu_opts+=(
            "-device" "nvme,drive=nvme$i,serial=dead/../../beef/$i,num_queues=8"
            "-drive" "format=raw,cache=unsafe,file=${TESTDIR:?}/disk$i.img,if=none,id=nvme$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${USER_QEMU_OPTIONS}"
    QEMU_OPTIONS_ARRAY=("${qemu_opts[@]}")
    test_run_one "${1:?}"
}

# Testcase for:
#   * https://github.com/systemd/systemd/pull/24748
#   * https://github.com/systemd/systemd/pull/24766
#   * https://github.com/systemd/systemd/pull/24946
# Docs: https://qemu.readthedocs.io/en/latest/system/devices/nvme.html#nvm-subsystems
testcase_nvme_subsystem() {
    if ! "${QEMU_BIN:?}" -device help | grep 'name "nvme-subsys"'; then
        echo "nvme-subsystem device driver is not available, skipping test..."
        return 77
    fi

    local i
    local qemu_opts=(
        # Create an NVM Subsystem Device
        "-device nvme-subsys,id=nvme-subsys-64,nqn=subsys64"
        # Attach two NVM controllers to it
        "-device nvme,subsys=nvme-subsys-64,serial=deadbeef"
        "-device nvme,subsys=nvme-subsys-64,serial=deadbeef"
        # And create two shared namespaces attached to both controllers
        "-device nvme-ns,drive=nvme0,nsid=16,shared=on"
        "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk0.img,if=none,id=nvme0"
        "-device nvme-ns,drive=nvme1,nsid=17,shared=on"
        "-drive format=raw,cache=unsafe,file=${TESTDIR:?}/disk1.img,if=none,id=nvme1"
    )

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
    local i lodev num_disk num_part qemu_timeout

    if get_bool "${IS_BUILT_WITH_ASAN:=}" || ! get_bool "$QEMU_KVM"; then
        num_disk=4
        num_part=4
    else
        num_disk=16
        num_part=8
    fi

    dd if=/dev/zero of="$diskpath" bs=1M count=18
    lodev="$(losetup --show -f -P "$diskpath")"
    sfdisk "${lodev:?}" <<EOF
label: gpt

$(for ((i = 1; i <= num_part; i++)); do echo 'name="Hello world", size=2M'; done)
EOF
    losetup -d "$lodev"

    for ((i = 0; i < num_disk; i++)); do
        diskpath="${TESTDIR:?}/namedpart$i.img"
        if [[ $i -gt 0 ]]; then
            cp -uv "${TESTDIR:?}/namedpart0.img" "$diskpath"
        fi

        qemu_opts+=(
            "-device scsi-hd,drive=drive$i,bus=scsi0.0,channel=0,scsi-id=0,lun=$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    # Bump the timeout when collecting test coverage, since the test is a bit
    # slower in that case
    if get_bool "${IS_BUILT_WITH_ASAN:=}" || ! get_bool "$QEMU_KVM"; then
        qemu_timeout=240
    elif is_built_with_coverage; then
        qemu_timeout=120
    else
        qemu_timeout=60
    fi

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    # Limit the number of VCPUs and set a timeout to make sure we trigger the issue
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    QEMU_SMP=1 QEMU_TIMEOUT=$qemu_timeout test_run_one "${1:?}" || return $?

    rm -f "${TESTDIR:?}"/namedpart*.img
}

testcase_multipath_basic_failover() {
    if ! _host_has_feature "multipath"; then
        echo "Missing multipath tools, skipping the test..."
        return 77
    fi

    local qemu_opts=("-device virtio-scsi-pci,id=scsi")
    local partdisk="${TESTDIR:?}/multipathpartitioned.img"
    local image lodev nback ndisk wwn

    dd if=/dev/zero of="$partdisk" bs=1M count=16
    lodev="$(losetup --show -f -P "$partdisk")"
    sfdisk "${lodev:?}" <<EOF
label: gpt

name="first_partition", size=5M
uuid="deadbeef-dead-dead-beef-000000000000", name="failover_part", size=5M
EOF
    udevadm settle
    mkfs.ext4 -U "deadbeef-dead-dead-beef-111111111111" -L "failover_vol" "${lodev}p2"
    losetup -d "$lodev"

    # Add 16 multipath devices, each backed by 4 paths
    for ndisk in {0..15}; do
        wwn="0xDEADDEADBEEF$(printf "%.4d" "$ndisk")"
        # Use a partitioned disk for the first device to test failover
        [[ $ndisk -eq 0 ]] && image="$partdisk" || image="${TESTDIR:?}/disk$ndisk.img"

        for nback in {0..3}; do
            qemu_opts+=(
                "-device scsi-hd,drive=drive${ndisk}x${nback},serial=MPIO$ndisk,wwn=$wwn"
                "-drive format=raw,cache=unsafe,file=$image,file.locking=off,if=none,id=drive${ndisk}x${nback}"
            )
        done
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "$partdisk"
}

# Test case for issue https://github.com/systemd/systemd/issues/19946
testcase_simultaneous_events() {
    local qemu_opts=("-device virtio-scsi-pci,id=scsi")
    local diskpath i

    for i in {0..9}; do
        diskpath="${TESTDIR:?}/simultaneousevents${i}.img"

        dd if=/dev/zero of="$diskpath" bs=1M count=128
        qemu_opts+=(
            "-device scsi-hd,drive=drive$i,serial=deadbeeftest$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "$diskpath"
}

testcase_lvm_basic() {
    if ! _host_has_feature "lvm"; then
        echo "Missing lvm tools, skipping the test..."
        return 77
    fi

    local qemu_opts=("-device ahci,id=ahci0")
    local diskpath i

    # Attach 4 SATA disks to the VM (and set their model and serial fields
    # to something predictable, so we can refer to them later)
    for i in {0..3}; do
        diskpath="${TESTDIR:?}/lvmbasic${i}.img"
        dd if=/dev/zero of="$diskpath" bs=1M count=32
        qemu_opts+=(
            "-device ide-hd,bus=ahci0.$i,drive=drive$i,model=foobar,serial=deadbeeflvm$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "${TESTDIR:?}"/lvmbasic*.img
}

testcase_btrfs_basic() {
    if ! _host_has_feature "btrfs"; then
        echo "Missing btrfs tools/modules, skipping the test..."
        return 77
    fi

    local qemu_opts=("-device ahci,id=ahci0")
    local diskpath i size

    for i in {0..3}; do
        diskpath="${TESTDIR:?}/btrfsbasic${i}.img"
        # Make the first disk larger for multi-partition tests
        [[ $i -eq 0 ]] && size=350 || size=128

        dd if=/dev/zero of="$diskpath" bs=1M count="$size"
        qemu_opts+=(
            "-device ide-hd,bus=ahci0.$i,drive=drive$i,model=foobar,serial=deadbeefbtrfs$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "${TESTDIR:?}"/btrfsbasic*.img
}

testcase_iscsi_lvm() {
    if ! _host_has_feature "iscsi" || ! _host_has_feature "lvm"; then
        echo "Missing iSCSI client/server tools (Open-iSCSI/TGT) or LVM utilities, skipping the test..."
        return 77
    fi

    local qemu_opts=("-device ahci,id=ahci0")
    local diskpath i size

    for i in {0..3}; do
        diskpath="${TESTDIR:?}/iscsibasic${i}.img"
        # Make the first disk larger for multi-partition tests
        [[ $i -eq 0 ]] && size=150 || size=64
        # Make the first disk larger for multi-partition tests

        dd if=/dev/zero of="$diskpath" bs=1M count="$size"
        qemu_opts+=(
            "-device ide-hd,bus=ahci0.$i,drive=drive$i,model=foobar,serial=deadbeefiscsi$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "${TESTDIR:?}"/iscsibasic*.img
}

testcase_long_sysfs_path() {
    local brid
    local testdisk="${TESTDIR:?}/longsysfspath.img"
    local qemu_opts=(
        "-drive if=none,id=drive0,format=raw,cache=unsafe,file=$testdisk"
        "-device pci-bridge,id=pci_bridge0,chassis_nr=64"
    )

    dd if=/dev/zero of="$testdisk" bs=1M count=64
    lodev="$(losetup --show -f -P "$testdisk")"
    sfdisk "${lodev:?}" <<EOF
label: gpt

name="test_swap", size=32M
uuid="deadbeef-dead-dead-beef-000000000000", name="test_part", size=5M
EOF
    udevadm settle
    mkswap -U "deadbeef-dead-dead-beef-111111111111" -L "swap_vol" "${lodev}p1"
    mkfs.ext4 -U "deadbeef-dead-dead-beef-222222222222" -L "data_vol" "${lodev}p2"
    losetup -d "$lodev"

    # Create 25 additional PCI bridges, each one connected to the previous one
    # (basically a really long extension cable), and attach a virtio drive to
    # the last one. This should force udev into attempting to create a device
    # unit with a _really_ long name.
    for brid in {1..25}; do
        qemu_opts+=("-device pci-bridge,id=pci_bridge$brid,bus=pci_bridge$((brid-1)),chassis_nr=$((64+brid))")
    done

    qemu_opts+=("-device virtio-blk-pci,drive=drive0,scsi=off,bus=pci_bridge$brid")

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "${testdisk:?}"
}

testcase_mdadm_basic() {
    if ! _host_has_feature "mdadm"; then
        echo "Missing mdadm tools/modules, skipping the test..."
        return 77
    fi

    local qemu_opts=("-device ahci,id=ahci0")
    local diskpath i size

    for i in {0..4}; do
        diskpath="${TESTDIR:?}/mdadmbasic${i}.img"

        dd if=/dev/zero of="$diskpath" bs=1M count=64
        qemu_opts+=(
            "-device ide-hd,bus=ahci0.$i,drive=drive$i,model=foobar,serial=deadbeefmdadm$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "${TESTDIR:?}"/mdadmbasic*.img
}

testcase_mdadm_lvm() {
    if ! _host_has_feature "mdadm" || ! _host_has_feature "lvm"; then
        echo "Missing mdadm tools/modules or LVM tools, skipping the test..."
        return 77
    fi

    local qemu_opts=("-device ahci,id=ahci0")
    local diskpath i size

    for i in {0..4}; do
        diskpath="${TESTDIR:?}/mdadmlvm${i}.img"

        dd if=/dev/zero of="$diskpath" bs=1M count=64
        qemu_opts+=(
            "-device ide-hd,bus=ahci0.$i,drive=drive$i,model=foobar,serial=deadbeefmdadmlvm$i"
            "-drive format=raw,cache=unsafe,file=$diskpath,if=none,id=drive$i"
        )
    done

    KERNEL_APPEND="systemd.setenv=TEST_FUNCTION_NAME=${FUNCNAME[0]} ${USER_KERNEL_APPEND:-}"
    QEMU_OPTIONS="${qemu_opts[*]} ${USER_QEMU_OPTIONS:-}"
    test_run_one "${1:?}" || return $?

    rm -f "${TESTDIR:?}"/mdadmlvm*.img
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
