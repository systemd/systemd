#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# vi: ts=4 sw=4 tw=0 et:

set -eux
set -o pipefail

# Check if all symlinks under /dev/disk/ are valid
# shellcheck disable=SC2120
helper_check_device_symlinks() {(
    set +x

    local dev link path paths target

    [[ $# -gt 0 ]] && paths=("$@") || paths=("/dev/disk" "/dev/mapper")

    # Check if all given paths are valid
    for path in "${paths[@]}"; do
        if ! test -e "$path"; then
            echo >&2 "Path '$path' doesn't exist"
            return 1
        fi
    done

    while read -r link; do
        target="$(readlink -f "$link")"
        # Both checks should do virtually the same thing, but check both to be
        # on the safe side
        if [[ ! -e "$link" || ! -e "$target" ]]; then
            echo >&2 "ERROR: symlink '$link' points to '$target' which doesn't exist"
            return 1
        fi

        # Check if the symlink points to the correct device in /dev
        dev="/dev/$(udevadm info -q name "$link")"
        if [[ "$target" != "$dev" ]]; then
            echo >&2 "ERROR: symlink '$link' points to '$target' but '$dev' was expected"
            return 1
        fi
    done < <(find "${paths[@]}" -type l)
)}

helper_check_udev_watch() {(
    set +x

    local link target id dev

    while read -r link; do
        target="$(readlink "$link")"
        if [[ ! -L "/run/udev/watch/$target" ]]; then
            echo >&2 "ERROR: symlink /run/udev/watch/$target does not exist"
            return 1
        fi
        if [[ "$(readlink "/run/udev/watch/$target")" != "$(basename "$link")" ]]; then
            echo >&2 "ERROR: symlink target of /run/udev/watch/$target is inconsistent with $link"
            return 1
        fi

        if [[ "$target" =~ ^[0-9]+$ ]]; then
            # $link is ID -> wd
            id="$(basename "$link")"
        else
            # $link is wd -> ID
            id="$target"
        fi

        if [[ "${id:0:1}" == "b" ]]; then
            dev="/dev/block/${id:1}"
        elif [[ "${id:0:1}" == "c" ]]; then
            dev="/dev/char/${id:1}"
        else
            echo >&2 "ERROR: unexpected device ID '$id'"
            return 1
        fi

        if [[ ! -e "$dev" ]]; then
            echo >&2 "ERROR: device '$dev' corresponding to symlink '$link' does not exist"
            return 1
        fi
    done < <(find /run/udev/watch -type l)
)}

check_device_unit() {(
    set +x

    local log_level link links path syspath unit

    log_level="${1?}"
    path="${2?}"
    unit=$(systemd-escape --path --suffix=device "$path")

    [[ "$log_level" == 1 ]] && echo "INFO: check_device_unit($unit)"

    syspath=$(systemctl show --value --property SysFSPath "$unit" 2>/dev/null)
    if [[ -z "$syspath" ]]; then
        [[ "$log_level" == 1 ]] && echo >&2 "ERROR: $unit not found."
        return 1
    fi

    if [[ ! -L "$path" ]]; then
        if [[ ! -d "$syspath" ]]; then
            [[ "$log_level" == 1 ]] && echo >&2 "ERROR: $unit exists for $syspath but it does not exist."
            return 1
        fi
        return 0
    fi

    if [[ ! -b "$path" && ! -c "$path" ]]; then
        [[ "$log_level" == 1 ]] && echo >&2 "ERROR: invalid file type $path"
        return 1
    fi

    read -r -a links < <(udevadm info -q symlink "$syspath" 2>/dev/null)
    for link in "${links[@]}"; do
        if [[ "/dev/$link" == "$path" ]]; then # DEVLINKS= given by -q symlink are relative to /dev
            return 0
        fi
    done

    read -r -a links < <(udevadm info -q property --property SYSTEMD_ALIAS --value "$syspath" 2>/dev/null)
    for link in "${links[@]}"; do
        if [[ "$link" == "$path" ]]; then # SYSTEMD_ALIAS= are absolute
            return 0
        fi
    done

    [[ "$log_level" == 1 ]] && echo >&2 "ERROR: $unit exists for $syspath but it does not have the corresponding DEVLINKS or SYSTEMD_ALIAS."
    return 1
)}

check_device_units() {(
    set +x

    local log_level path paths unit units

    log_level="${1?}"
    shift
    paths=("$@")

    for path in "${paths[@]}"; do
        if ! check_device_unit "$log_level" "$path"; then
           return 1
        fi
    done

    read -r -a units < <(systemctl list-units --all --type=device --no-legend dev-* | awk '$1 !~ /dev-tty.+/ && $4 == "plugged" { print $1 }' | sed -e 's/\.device$//')
    for unit in "${units[@]}"; do
        path=$(systemd-escape --path --unescape "$unit")
        if ! check_device_unit "$log_level" "$path"; then
           return 1
        fi
    done

    return 0
)}

helper_check_device_units() {(
    set +x

    local i

    for i in {1..20}; do
        (( i > 1 )) && sleep 0.5
        if check_device_units 0 "$@"; then
            return 0
        fi
    done

    check_device_units 1 "$@"
)}

testcase_virtio_scsi_basic() {
    lsblk -S
    [[ "$(lsblk --scsi --noheadings | wc -l)" -ge 128 ]]
}

testcase_nvme_basic() {
    local expected_symlinks=()
    local i

    for i in {0..4}; do
        expected_symlinks+=(
            # both replace mode provides the same devlink
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_deadbeef"$i"
            # with nsid
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_deadbeef"$i"_1
        )
    done
    for i in {5..9}; do
        expected_symlinks+=(
            # old replace mode
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl__deadbeef_"$i"
            # newer replace mode
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_____deadbeef__"$i"
            # with nsid
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_____deadbeef__"$i"_1
        )
    done
    for i in {10..14}; do
        expected_symlinks+=(
            # old replace mode does not provide devlink, as serial contains "/"
            # newer replace mode
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_____dead_beef_"$i"
            # with nsid
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_____dead_beef_"$i"_1
        )
    done
    for i in {15..19}; do
        expected_symlinks+=(
            # old replace mode does not provide devlink, as serial contains "/"
            # newer replace mode
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_dead_.._.._beef_"$i"
            # with nsid
            /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_dead_.._.._beef_"$i"_1
        )
    done

    ls /dev/disk/by-id
    for i in "${expected_symlinks[@]}"; do
        udevadm wait --settle --timeout=30 "$i"
    done
    test ! -e /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_deadbeef

    lsblk --noheadings | grep "^nvme"
    [[ "$(lsblk --noheadings | grep -c "^nvme")" -ge 20 ]]
}

testcase_nvme_subsystem() {
    local expected_symlinks=(
        # Controller(s)
        /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_deadbeef_16
        /dev/disk/by-id/nvme-QEMU_NVMe_Ctrl_deadbeef_17
        # Shared namespaces
        /dev/disk/by-path/*pci*-nvme-16
        /dev/disk/by-path/*pci*-nvme-17
    )

    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
}

testcase_virtio_scsi_identically_named_partitions() {
    local num_part num_disk i j

    if [[ -v ASAN_OPTIONS || "$(systemd-detect-virt -v)" == "qemu" ]]; then
        num_part=4
        num_disk=4
    else
        num_part=8
        num_disk=16
    fi

    for ((i = 0; i < num_disk; i++)); do
        udevadm lock --timeout=30 --device "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive$i" \
                sfdisk "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive$i" <<EOF
label: gpt

$(for ((j = 1; j <= num_part; j++)); do echo 'name="Hello world", size=2M'; done)
EOF
    done

    udevadm settle --timeout=30
    lsblk --noheadings -a -o NAME,PARTLABEL
    [[ "$(lsblk --noheadings -a -o NAME,PARTLABEL | grep -c "Hello world")" -eq "$((num_part * num_disk))" ]]
}

testcase_multipath_basic_failover() {
    local dmpath i path wwid

    . /etc/os-release
    if [[ "${ID_LIKE:-}" == "alpine" ]]; then
        echo "multipath on alpine/postmarketos is broken, skipping the test" | tee --append /skipped
        exit 77
    fi

    # Configure multipath
    cat >/etc/multipath.conf <<\EOF
defaults {
    # Use /dev/mapper/$WWN paths instead of /dev/mapper/mpathX
    user_friendly_names no
    find_multipaths yes
    enable_foreign "^$"
}

blacklist_exceptions {
    property "(SCSI_IDENT_|ID_WWN)"
}

blacklist {
}
EOF

    udevadm lock --timeout=30 --device /dev/disk/by-id/wwn-0xdeaddeadbeef0000 \
            sfdisk /dev/disk/by-id/wwn-0xdeaddeadbeef0000 <<EOF
label: gpt

name="first_partition", size=5M
uuid="deadbeef-dead-dead-beef-000000000000", name="failover_part", size=5M
EOF
    # Partitioning triggers a synthesized event. Wait for the event being finished.
    udevadm settle --timeout=30

    udevadm lock --timeout=30 --device /dev/disk/by-id/wwn-0xdeaddeadbeef0000-part2 \
            mkfs.ext4 -U "deadbeef-dead-dead-beef-111111111111" -L "failover_vol" /dev/disk/by-id/wwn-0xdeaddeadbeef0000-part2
    # Making filesystem triggers a synthesized event. Wait for the event being finished.
    udevadm settle --timeout=30

    modprobe -v dm_multipath
    systemctl start multipathd.service
    systemctl status multipathd.service
    # multipathd touches many devices on start. multipath command may fail if it is invoked before the
    # initial setup finished. Let's wait for a while.
    udevadm settle --timeout=30
    multipath -ll
    ls -l /dev/disk/by-id/

    for i in {0..15}; do
        wwid="deaddeadbeef$(printf "%.4d" "$i")"
        path="/dev/disk/by-id/wwn-0x$wwid"
        dmpath="$(readlink -f "$path")"

        lsblk "$path"
        multipath -C "$dmpath"
        # We should have 4 active paths for each multipath device
        [[ "$(multipath -l "$path" | grep -c running)" -eq 4 ]]
    done

    # Test failover (with the first multipath device that has a partitioned disk)
    echo "${FUNCNAME[0]}: test failover"
    local device expected link mpoint part
    local -a devices
    mkdir -p /mnt
    mpoint="$(mktemp -d /mnt/mpathXXX)"
    wwid="deaddeadbeef0000"
    path="/dev/disk/by-id/wwn-0x$wwid"

    # All following symlinks should exists and should be valid
    local -a part_links=(
        "/dev/disk/by-id/wwn-0x$wwid-part2"
        "/dev/disk/by-partlabel/failover_part"
        "/dev/disk/by-partuuid/deadbeef-dead-dead-beef-000000000000"
        "/dev/disk/by-label/failover_vol"
        "/dev/disk/by-uuid/deadbeef-dead-dead-beef-111111111111"
    )
    udevadm wait --settle --timeout=30 "${part_links[@]}"
    helper_check_device_units "${part_links[@]}"

    # Choose a random symlink to the failover data partition each time, for
    # a better coverage
    part="${part_links[$RANDOM % ${#part_links[@]}]}"

    # Get all devices attached to a specific multipath device (in H:C:T:L format)
    # and sort them in a random order, so we cut off different paths each time
    mapfile -t devices < <(multipath -l "$path" | grep -Eo '[0-9]+:[0-9]+:[0-9]+:[0-9]+' | sort -R)
    if [[ "${#devices[@]}" -ne 4 ]]; then
        echo "Expected 4 devices attached to WWID=$wwid, got ${#devices[@]} instead"
        return 1
    fi
    # Drop the last path from the array, since we want to leave at least one path active
    unset "devices[3]"
    # Mount the first multipath partition, write some data we can check later,
    # and then disconnect the remaining paths one by one while checking if we
    # can still read/write from the mount
    mount -t ext4 "$part" "$mpoint"
    expected=0
    echo -n "$expected" >"$mpoint/test"
    # Sanity check we actually wrote what we wanted
    [[ "$(<"$mpoint/test")" == "$expected" ]]

    for device in "${devices[@]}"; do
        echo offline >"/sys/class/scsi_device/$device/device/state"
        [[ "$(<"$mpoint/test")" == "$expected" ]]
        expected="$((expected + 1))"
        echo -n "$expected" >"$mpoint/test"

        # Make sure all symlinks are still valid
        udevadm wait --settle --timeout=30 "${part_links[@]}"
        helper_check_device_units "${part_links[@]}"
    done

    multipath -l "$path"
    # Three paths should be now marked as 'offline' and one as 'running'
    [[ "$(multipath -l "$path" | grep -c offline)" -eq 3 ]]
    [[ "$(multipath -l "$path" | grep -c running)" -eq 1 ]]

    umount "$mpoint"
    rm -fr "$mpoint"
}

testcase_simultaneous_events_1() {
    local disk expected i iterations link num_part part partscript rule target timeout
    local -a devices symlinks running

    if [[ -v ASAN_OPTIONS || "$(systemd-detect-virt -v)" == "qemu" ]]; then
        num_part=2
        iterations=10
        timeout=240
    else
        num_part=10
        iterations=100
        timeout=60
    fi

    for disk in {0..9}; do
        link="/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_deadbeeftest${disk}"
        target="$(readlink -f "$link")"
        if [[ ! -b "$target" ]]; then
            echo "ERROR: failed to find the test SCSI block device $link"
            return 1
        fi

        devices+=("$target")
    done

    for ((part = 1; part <= num_part; part++)); do
        symlinks+=(
            "/dev/disk/by-partlabel/test${part}"
        )
    done

    partscript="$(mktemp)"

    cat >"$partscript" <<EOF
$(for ((part = 1; part <= num_part; part++)); do printf 'name="test%d", size=2M\n' "$part"; done)
EOF

    rule=/run/udev/rules.d/50-test.rules
    mkdir -p "${rule%/*}"
    cat >"$rule" <<EOF
SUBSYSTEM=="block", KERNEL=="${devices[4]##*/}*|${devices[5]##*/}*", OPTIONS="link_priority=10"
EOF

    udevadm control --reload

    # initialize partition table
    for disk in {0..9}; do
        echo 'label: gpt' | udevadm lock --timeout=30 --device="${devices[$disk]}" sfdisk -q "${devices[$disk]}"
    done

    # Delete the partitions, immediately recreate them, wait for udev to settle
    # down, and then check if we have any dangling symlinks in /dev/disk/. Rinse
    # and repeat.
    #
    # On unpatched udev versions the delete-recreate cycle may trigger a race
    # leading to dead symlinks in /dev/disk/
    for ((i = 1; i <= iterations; i++)); do
        running=()
        for disk in {0..9}; do
            if ((disk % 2 == i % 2)); then
                udevadm lock --timeout=30 --device="${devices[$disk]}" sfdisk -q --delete "${devices[$disk]}" &
            else
                udevadm lock --timeout=30 --device="${devices[$disk]}" sfdisk -q -X gpt "${devices[$disk]}" <"$partscript" &
            fi

            # shellcheck disable=SC2190
            running+=( "$!" )
        done

        for j in "${running[@]}"; do
            wait "$j"
        done

        if ((i % 10 <= 1)); then
            udevadm wait --settle --timeout="$timeout" "${devices[@]}" "${symlinks[@]}"
            helper_check_device_symlinks
            helper_check_udev_watch
            for ((part = 1; part <= num_part; part++)); do
                link="/dev/disk/by-partlabel/test${part}"
                target="$(readlink -f "$link")"
                if ((i % 2 == 0)); then
                    expected="${devices[5]}$part"
                else
                    expected="${devices[4]}$part"
                fi
                if [[ "$target" != "$expected" ]]; then
                    echo >&2 "ERROR: symlink '/dev/disk/by-partlabel/test${part}' points to '$target' but '$expected' was expected"
                    return 1
                fi
            done
        fi
    done

    helper_check_device_units

    # Cleanup and check if unnecessary devlinks are removed.
    for disk in {0..9}; do
        udevadm lock --timeout="$timeout" --device="${devices[$disk]}" sfdisk -q --delete "${devices[$disk]}" || :
    done
    udevadm settle --timeout="$timeout"
    for ((part = 1; part <= num_part; part++)); do
        udevadm wait --timeout=10 --removed "/dev/disk/by-partlabel/test${part}"
    done

    rm -f "$rule" "$partscript"
    udevadm control --reload
}

testcase_simultaneous_events_2() {
    local disk i iterations link num_part part script_dir target timeout
    local -a devices running

    script_dir="$(mktemp --directory "/tmp/test-udev-storage.script.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$script_dir'" RETURN

    if [[ -v ASAN_OPTIONS || "$(systemd-detect-virt -v)" == "qemu" ]]; then
        num_part=10
        iterations=2
        timeout=300
    else
        num_part=40
        iterations=5
        timeout=200
    fi

    for disk in {0..9}; do
        link="/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_deadbeeftest${disk}"
        target="$(readlink -f "$link")"
        if [[ ! -b "$target" ]]; then
            echo "ERROR: failed to find the test SCSI block device $link"
            return 1
        fi

        devices+=("$target")
    done

    for ((i = 1; i <= iterations; i++)); do
        cat >"$script_dir/partscript-$i" <<EOF
$(for ((part = 1; part <= num_part; part++)); do printf 'name="testlabel-%d", size=1M\n' "$i"; done)
EOF
    done

    ls -l /dev/disk/by-partlabel

    echo "## $iterations iterations start: $(date '+%H:%M:%S.%N')"
    running=()
    for disk in "${devices[@]}"; do
        udevadm lock --timeout=30 --device="$disk" \
                bash -c "for ((i = 1; i <= $iterations; i++)); do sfdisk -q --delete $disk; sfdisk -q -X gpt $disk <$script_dir/partscript-\$i; done" &

        # shellcheck disable=SC2190
        running+=( "$!" )
    done

    for i in "${running[@]}"; do
        wait "$i"
    done

    udevadm settle --timeout="$timeout"
    echo "## $iterations iterations end: $(date '+%H:%M:%S.%N')"

    ls -l /dev/disk/by-partlabel

    # Check if unnecessary devlinks are removed.
    for ((i = 1; i < iterations; i++)); do
        udevadm wait --timeout=10 --removed "/dev/disk/by-partlabel/testlabel-$i"
    done

    helper_check_device_units

    # Cleanup
    for disk in "${devices[@]}"; do
        udevadm lock --timeout=30 --device="$disk" sfdisk -q --delete "$disk"
    done
    udevadm settle --timeout="$timeout"
    udevadm wait --timeout=10 --removed "/dev/disk/by-partlabel/testlabel-$iterations"
}

testcase_simultaneous_events_3() {
    local device i iterations link num_part part script_dir target timeout

    # for issue #37823

    script_dir="$(mktemp --directory "/tmp/test-udev-storage.script.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$script_dir'" RETURN

    num_part=5
    iterations=30
    if [[ -v ASAN_OPTIONS || "$(systemd-detect-virt -v)" == "qemu" ]]; then
        timeout=120
    else
        timeout=60
    fi

    link="/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_deadbeeftest0"
    device="$(readlink -f "$link")"
    if [[ ! -b "$device" ]]; then
        echo "ERROR: failed to find the test SCSI block device $link"
        return 1
    fi

    for ((i = 1; i <= iterations; i++)); do
        cat >"$script_dir/partscript-$i" <<EOF
$(for ((part = 1; part <= num_part; part++)); do printf 'name="test3-%d", size=1M\n' "$i"; done)
EOF
    done

    ls -l /dev/disk/by-partlabel/

    echo "## $iterations iterations start: $(date '+%H:%M:%S.%N')"
    udevadm lock --timeout="$timeout" --device="$device" \
            bash -c "for ((i = 1; i <= $iterations; i++)); do sfdisk -q -X gpt $device <$script_dir/partscript-\$i; done"
    udevadm settle --timeout="$timeout"
    echo "## $iterations iterations end: $(date '+%H:%M:%S.%N')"

    ls -l /dev/disk/by-partlabel/

    # Check devlinks
    for ((i = 1; i < iterations; i++)); do
        udevadm wait --settle --timeout=10 --removed "/dev/disk/by-partlabel/test3-$i"
    done
    udevadm wait --settle --timeout=10 "/dev/disk/by-partlabel/test3-$iterations"

    # Cleanup and check if the last devlink is removed
    udevadm lock --timeout="$timeout" --device="$device" sfdisk -q --delete "$device"
    udevadm wait --settle --timeout="$timeout" --removed "/dev/disk/by-partlabel/test3-$iterations"
}

testcase_simultaneous_events() {
    . /etc/os-release
    if [[ "$ID" == "debian" ]]; then
        # See https://github.com/systemd/systemd/issues/39552
        echo "Simultaneous events test cases are not working on Debian, skipping the test" | tee --append /skipped
        exit 77
    fi

    testcase_simultaneous_events_1
    testcase_simultaneous_events_2
    testcase_simultaneous_events_3
}

testcase_lvm_basic() {
    local i iterations partitions part timeout
    local vgroup="MyTestGroup$RANDOM"
    local devices=(
        /dev/disk/by-id/scsi-0systemd_foobar_deadbeeflvm{0..3}
    )

    . /etc/os-release
    if [[ "$ID" == "ubuntu" || "${ID_LIKE:-}" == "alpine" ]]; then
        echo "LVM on Ubuntu/alpine/postmarketos is broken, skipping the test" | tee --append /skipped
        exit 77
    fi

    if [[ -v ASAN_OPTIONS || "$(systemd-detect-virt -v)" == "qemu" ]]; then
        timeout=180
    else
        timeout=30
    fi
    # Make sure all the necessary soon-to-be-LVM devices exist
    ls -l "${devices[@]}"

    # Add all test devices into a volume group, create two logical volumes,
    # and check if necessary symlinks exist (and are valid)
    lvm pvcreate -y "${devices[@]}"
    lvm pvs
    lvm vgcreate "$vgroup" -y "${devices[@]}"
    lvm vgs
    lvm vgchange -ay "$vgroup"
    lvm lvcreate -y -L 4M "$vgroup" -n mypart1
    lvm lvcreate -y -L 32M "$vgroup" -n mypart2
    lvm lvs
    udevadm wait --settle --timeout="$timeout" "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2"
    mkfs.ext4 -L mylvpart1 "/dev/$vgroup/mypart1"
    udevadm trigger --settle "/dev/$vgroup/mypart1"
    udevadm wait --settle --timeout="$timeout" "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units

    # Mount mypart1 through by-label devlink
    mkdir -p /tmp/mypart1-mount-point
    mount /dev/disk/by-label/mylvpart1 /tmp/mypart1-mount-point
    timeout 30 bash -c "until systemctl -q is-active /tmp/mypart1-mount-point; do sleep .2; done"
    # Extend the partition and check if the device and mount units are still active.
    # See https://bugzilla.redhat.com/show_bug.cgi?id=2158628
    # Note, the test below may be unstable with LVM2 without the following patch:
    # https://github.com/lvmteam/lvm2/pull/105
    # But, to reproduce the issue, udevd must start to process the first 'change' uevent
    # earlier than extending the volume has been finished, and in most case, the extension
    # is hopefully fast.
    lvm lvextend -y --size 8M "/dev/$vgroup/mypart1"
    udevadm wait --settle --timeout="$timeout" "/dev/disk/by-label/mylvpart1"
    timeout 30 bash -c "until systemctl -q is-active '/dev/$vgroup/mypart1'; do sleep .2; done"
    timeout 30 bash -c "until systemctl -q is-active /tmp/mypart1-mount-point; do sleep .2; done"
    # Umount the partition, otherwise the underlying device unit will stay in
    # the inactive state and not be collected, and helper_check_device_units() will fail.
    systemctl show /tmp/mypart1-mount-point
    umount /tmp/mypart1-mount-point

    # Rename partitions (see issue #24518)
    lvm lvrename "/dev/$vgroup/mypart1" renamed1
    lvm lvrename "/dev/$vgroup/mypart2" renamed2
    udevadm wait --settle --timeout="$timeout" --removed "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2"
    udevadm wait --settle --timeout="$timeout" "/dev/$vgroup/renamed1" "/dev/$vgroup/renamed2"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units

    # Rename them back
    lvm lvrename "/dev/$vgroup/renamed1" mypart1
    lvm lvrename "/dev/$vgroup/renamed2" mypart2
    udevadm wait --settle --timeout="$timeout" --removed "/dev/$vgroup/renamed1" "/dev/$vgroup/renamed2"
    udevadm wait --settle --timeout="$timeout" "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units

    # Do not "unready" suspended encrypted devices w/o superblock info
    # See:
    #   - https://github.com/systemd/systemd/pull/24177
    #   - https://bugzilla.redhat.com/show_bug.cgi?id=1985288
    dd if=/dev/urandom of=/etc/lvm_keyfile bs=64 count=1 iflag=fullblock
    chmod 0600 /etc/lvm_keyfile
    # Intentionally use weaker cipher-related settings, since we don't care
    # about security here as it's a throwaway LUKS partition
    cryptsetup luksFormat -q --use-urandom --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
                          "/dev/$vgroup/mypart2" /etc/lvm_keyfile
    # Mount the LUKS partition & create a filesystem on it
    mkdir -p /tmp/lvmluksmnt
    cryptsetup open --key-file=/etc/lvm_keyfile "/dev/$vgroup/mypart2" "lvmluksmap"
    udevadm wait --settle --timeout="$timeout" "/dev/mapper/lvmluksmap"
    mkfs.ext4 -L lvmluksfs "/dev/mapper/lvmluksmap"
    udevadm trigger --settle "/dev/mapper/lvmluksmap"
    udevadm wait --settle --timeout="$timeout" "/dev/disk/by-label/lvmluksfs"
    # Make systemd "interested" in the mount by adding it to /etc/fstab
    echo "/dev/disk/by-label/lvmluksfs /tmp/lvmluksmnt ext4 defaults 0 2" >>/etc/fstab
    systemctl daemon-reload
    mount "/tmp/lvmluksmnt"
    mountpoint "/tmp/lvmluksmnt"
    # Temporarily suspend the LUKS device and trigger udev - basically what `cryptsetup resize`
    # does but in a more deterministic way suitable for a test/reproducer
    for _ in {0..5}; do
        dmsetup suspend "/dev/mapper/lvmluksmap"
        udevadm trigger -v --settle "/dev/mapper/lvmluksmap"
        dmsetup resume "/dev/mapper/lvmluksmap"
        # The mount should survive this sequence of events
        mountpoint "/tmp/lvmluksmnt"
    done
    # Cleanup
    umount "/tmp/lvmluksmnt"
    cryptsetup close "/dev/mapper/lvmluksmap"
    sed -i "/lvmluksfs/d" "/etc/fstab"
    systemctl daemon-reload

    # Disable the VG and check symlinks...
    lvm vgchange -an "$vgroup"
    udevadm wait --settle --timeout="$timeout" --removed "/dev/$vgroup" "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk"
    helper_check_device_units

    # reenable the VG and check the symlinks again if all LVs are properly activated
    lvm vgchange -ay "$vgroup"
    udevadm wait --settle --timeout="$timeout" "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2" "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units

    # Same as above, but now with more "stress"
    if [[ -v ASAN_OPTIONS || "$(systemd-detect-virt -v)" == "qemu" ]]; then
        iterations=10
    else
        iterations=50
    fi

    for ((i = 1; i <= iterations; i++)); do
        lvm vgchange -an "$vgroup"
        lvm vgchange -ay "$vgroup"

        if ((i % 5 == 0)); then
            udevadm wait --settle --timeout="$timeout" "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2" "/dev/disk/by-label/mylvpart1"
            helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
            helper_check_device_units
        fi
    done

    # Remove the first LV
    lvm lvremove -y "$vgroup/mypart1"
    udevadm wait --settle --timeout="$timeout" --removed "/dev/$vgroup/mypart1"
    udevadm wait --timeout=0 "/dev/$vgroup/mypart2"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units

    # Create & remove LVs in a loop, i.e. with more "stress"
    if [[ -v ASAN_OPTIONS ]]; then
        iterations=8
        partitions=16
    elif [[ "$(systemd-detect-virt -v)" == "qemu" ]]; then
        iterations=8
        partitions=8
    else
        iterations=16
        partitions=16
    fi

    for ((i = 1; i <= iterations; i++)); do
        # 1) Create some logical volumes
        for ((part = 0; part < partitions; part++)); do
            lvm lvcreate -y -L 4M "$vgroup" -n "looppart$part"
        done

        # 2) Immediately remove them
        lvm lvremove -y $(seq -f "$vgroup/looppart%g" 0 "$((partitions - 1))")

        # 3) On every 4th iteration settle udev and check if all partitions are
        #    indeed gone, and if all symlinks are still valid
        if ((i % 4 == 0)); then
            for ((part = 0; part < partitions; part++)); do
                udevadm wait --settle --timeout="$timeout" --removed "/dev/$vgroup/looppart$part"
            done
            helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
            helper_check_device_units
        fi
    done
}

testcase_btrfs_basic() {
    local dev_stub i label mpoint uuid
    local devices=(
        /dev/disk/by-id/scsi-0systemd_foobar_deadbeefbtrfs{0..3}
    )

    if ! modinfo btrfs; then
        echo "This test requires the btrfs kernel module but it is not installed, skipping the test" | tee --append /skipped
        exit 77
    fi

    ls -l "${devices[@]}"

    echo "Single device: default settings"
    uuid="deadbeef-dead-dead-beef-000000000000"
    label="btrfs_root"
    udevadm lock --timeout=30 --device="${devices[0]}" mkfs.btrfs -f -L "$label" -U "$uuid" "${devices[0]}"
    udevadm wait --settle --timeout=30 "${devices[0]}" "/dev/disk/by-uuid/$uuid" "/dev/disk/by-label/$label"
    btrfs filesystem show
    helper_check_device_symlinks
    helper_check_device_units

    echo "Multiple devices: using partitions, data: single, metadata: raid1"
    uuid="deadbeef-dead-dead-beef-000000000001"
    label="btrfs_mpart"
    udevadm lock --timeout=30 --device="${devices[0]}" sfdisk --wipe=always "${devices[0]}" <<EOF
label: gpt

name="diskpart1", size=85M
name="diskpart2", size=85M
name="diskpart3", size=85M
name="diskpart4", size=85M
EOF
    udevadm wait --settle --timeout=30 /dev/disk/by-partlabel/diskpart{1..4}
    udevadm lock --timeout=30 --device="${devices[0]}" mkfs.btrfs -f -d single -m raid1 -L "$label" -U "$uuid" /dev/disk/by-partlabel/diskpart{1..4}
    udevadm wait --settle --timeout=30 "/dev/disk/by-uuid/$uuid" "/dev/disk/by-label/$label"
    btrfs filesystem show
    helper_check_device_symlinks
    helper_check_device_units
    udevadm lock --timeout=30 --device="${devices[0]}" wipefs -a "${devices[0]}"
    udevadm wait --settle --timeout=30 --removed /dev/disk/by-partlabel/diskpart{1..4}

    echo "Multiple devices: using disks, data: raid10, metadata: raid10, mixed mode"
    uuid="deadbeef-dead-dead-beef-000000000002"
    label="btrfs_mdisk"
    udevadm lock \
            --timeout=30 \
            --device=/dev/disk/by-id/scsi-0systemd_foobar_deadbeefbtrfs0 \
            --device=/dev/disk/by-id/scsi-0systemd_foobar_deadbeefbtrfs1 \
            --device=/dev/disk/by-id/scsi-0systemd_foobar_deadbeefbtrfs2 \
            --device=/dev/disk/by-id/scsi-0systemd_foobar_deadbeefbtrfs3 \
            mkfs.btrfs -f -M -d raid10 -m raid10 -L "$label" -U "$uuid" "${devices[@]}"
    udevadm wait --settle --timeout=30 "/dev/disk/by-uuid/$uuid" "/dev/disk/by-label/$label"
    btrfs filesystem show
    helper_check_device_symlinks
    helper_check_device_units

    echo "Multiple devices: using LUKS encrypted disks, data: raid1, metadata: raid1, mixed mode"
    uuid="deadbeef-dead-dead-beef-000000000003"
    label="btrfs_mencdisk"
    mpoint="/btrfs_enc$RANDOM"
    mkdir "$mpoint"
    # Create a key-file
    dd if=/dev/urandom of=/etc/btrfs_keyfile bs=64 count=1 iflag=fullblock
    chmod 0600 /etc/btrfs_keyfile
    # Encrypt each device and add it to /etc/crypttab, so it can be mounted
    # automagically later
    : >/etc/crypttab
    for ((i = 0; i < ${#devices[@]}; i++)); do
        # Intentionally use weaker cipher-related settings, since we don't care
        # about security here as it's a throwaway LUKS partition
        SYSTEMD_LOG_LEVEL=debug udevadm lock --timeout=30 --device="${devices[$i]}" \
                cryptsetup luksFormat -q --debug \
                --use-urandom --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
                --uuid "deadbeef-dead-dead-beef-11111111111$i" --label "encdisk$i" "${devices[$i]}" /etc/btrfs_keyfile
        udevadm wait --settle --timeout=30 "/dev/disk/by-uuid/deadbeef-dead-dead-beef-11111111111$i" "/dev/disk/by-label/encdisk$i"
        # Add the device into /etc/crypttab, reload systemd, and then activate
        # the device so we can create a filesystem on it later
        echo "encbtrfs$i UUID=deadbeef-dead-dead-beef-11111111111$i /etc/btrfs_keyfile luks" >>/etc/crypttab
        systemctl daemon-reload
        systemctl start "systemd-cryptsetup@encbtrfs$i"
    done
    helper_check_device_symlinks
    helper_check_device_units
    # Check if we have all necessary DM devices
    ls -l /dev/mapper/encbtrfs{0..3}
    # Create a multi-device btrfs filesystem on the LUKS devices
    udevadm lock \
            --timeout=30 \
            --device=/dev/mapper/encbtrfs0 \
            --device=/dev/mapper/encbtrfs1 \
            --device=/dev/mapper/encbtrfs2 \
            --device=/dev/mapper/encbtrfs3 \
            mkfs.btrfs -f -M -d raid1 -m raid1 -L "$label" -U "$uuid" /dev/mapper/encbtrfs{0..3}
    udevadm wait --settle --timeout=30 "/dev/disk/by-uuid/$uuid" "/dev/disk/by-label/$label"
    btrfs filesystem show
    helper_check_device_symlinks
    helper_check_device_units
    # Mount it and write some data to it we can compare later
    mount -t btrfs /dev/mapper/encbtrfs0 "$mpoint"
    echo "hello there" >"$mpoint/test"
    # "Deconstruct" the btrfs device and check if we're in a sane state (symlink-wise)
    umount "$mpoint"
    systemctl stop systemd-cryptsetup@encbtrfs{0..3}
    udevadm wait --settle --timeout=30 --removed "/dev/disk/by-uuid/$uuid"
    helper_check_device_symlinks
    helper_check_device_units
    # Add the mount point to /etc/fstab and check if the device can be put together
    # automagically. The source device is the DM name of the first LUKS device
    # (from /etc/crypttab). We have to specify all LUKS devices manually, as
    # registering the necessary devices is usually initrd's job (via btrfs device scan)
    dev_stub="/dev/mapper/encbtrfs"
    echo "/dev/mapper/encbtrfs0 $mpoint btrfs device=${dev_stub}0,device=${dev_stub}1,device=${dev_stub}2,device=${dev_stub}3 0 2" >>/etc/fstab
    # Tell systemd about the new mount
    systemctl daemon-reload
    # Restart cryptsetup.target to trigger autounlock of partitions in /etc/crypttab
    systemctl restart cryptsetup.target
    # Start the corresponding mount unit and check if the btrfs device was reconstructed
    # correctly
    systemctl start "${mpoint##*/}.mount"
    udevadm wait --settle --timeout=30 "/dev/disk/by-uuid/$uuid" "/dev/disk/by-label/$label"
    btrfs filesystem show
    helper_check_device_symlinks
    helper_check_device_units
    grep "hello there" "$mpoint/test"
    # Cleanup
    systemctl stop "${mpoint##*/}.mount"
    systemctl stop systemd-cryptsetup@encbtrfs{0..3}
    sed -i "/${mpoint##*/}/d" /etc/fstab
    : >/etc/crypttab
    rm -fr "$mpoint"
    systemctl daemon-reload
    udevadm settle --timeout=30
}

testcase_iscsi_lvm() {
    local dev i label link lun_id mpoint target_name uuid
    local target_ip="127.0.0.1"
    local target_port="3260"
    local vgroup="iscsi_lvm$RANDOM"
    local expected_symlinks=()
    local devices=(
        /dev/disk/by-id/scsi-0systemd_foobar_deadbeefiscsi{0..3}
    )

    . /etc/os-release
    if [[ "$ID" == "ubuntu" ]]; then
        echo "LVM on Ubuntu is broken, skipping the test" | tee --append /skipped
        exit 77
    fi

    ls -l "${devices[@]}"

    # Start the target daemon (debian names it tgt.service so make sure we handle that)
    if systemctl list-unit-files tgt.service; then
        systemctl start tgt
        systemctl status tgt
    elif systemctl list-unit-files tgtd.service; then
        systemctl start tgtd
        systemctl status tgtd
    else
        echo "This test requires tgtd but it is not installed, skipping ..." | tee --append /skipped
        exit 77
    fi

    echo "iSCSI LUNs backed by devices"
    # See RFC3721 and RFC7143
    target_name="iqn.2021-09.com.example:iscsi.test"
    # Initialize a new iSCSI target <$target_name> consisting of 4 LUNs, each
    # backed by a device
    tgtadm --lld iscsi --op new --mode target --tid=1 --targetname "$target_name"
    for ((i = 0; i < ${#devices[@]}; i++)); do
        # lun-0 is reserved by iSCSI
        lun_id="$((i + 1))"
        tgtadm --lld iscsi --op new --mode logicalunit --tid 1 --lun "$lun_id" -b "${devices[$i]}"
        tgtadm --lld iscsi --op update --mode logicalunit --tid 1 --lun "$lun_id"
        expected_symlinks+=(
            "/dev/disk/by-path/ip-$target_ip:$target_port-iscsi-$target_name-lun-$lun_id"
        )
    done
    tgtadm --lld iscsi --op bind --mode target --tid 1 -I ALL
    # Configure the iSCSI initiator
    iscsiadm --mode discoverydb --type sendtargets --portal "$target_ip" --discover
    iscsiadm --mode node --targetname "$target_name" --portal "$target_ip:$target_port" --login
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    helper_check_device_symlinks
    helper_check_device_units
    # Cleanup
    iscsiadm --mode node --targetname "$target_name" --portal "$target_ip:$target_port" --logout
    tgtadm --lld iscsi --op delete --mode target --tid=1

    echo "iSCSI LUNs backed by files + LVM"
    # Note: we use files here to "trick" LVM the disks are indeed on a different
    #       host, so it doesn't automagically detect another path to the backing
    #       device once we disconnect the iSCSI devices
    target_name="iqn.2021-09.com.example:iscsi.lvm.test"
    mpoint="$(mktemp -d /iscsi_storeXXX)"
    expected_symlinks=()
    # Use the first device as it's configured with larger capacity
    udevadm lock --timeout=30 --device "${devices[0]}" mkfs.ext4 -L iscsi_store "${devices[0]}"
    udevadm wait --settle --timeout=30 "${devices[0]}"
    mount "${devices[0]}" "$mpoint"
    for i in {1..4}; do
        dd if=/dev/zero of="$mpoint/lun$i.img" bs=1M count=32
    done
    # Initialize a new iSCSI target <$target_name> consisting of 4 LUNs, each
    # backed by a file
    tgtadm --lld iscsi --op new --mode target --tid=2 --targetname "$target_name"
    # lun-0 is reserved by iSCSI
    for i in {1..4}; do
        tgtadm --lld iscsi --op new --mode logicalunit --tid 2 --lun "$i" -b "$mpoint/lun$i.img"
        tgtadm --lld iscsi --op update --mode logicalunit --tid 2 --lun "$i"
        expected_symlinks+=(
            "/dev/disk/by-path/ip-$target_ip:$target_port-iscsi-$target_name-lun-$i"
        )
    done
    tgtadm --lld iscsi --op bind --mode target --tid 2 -I ALL
    # Configure the iSCSI initiator
    iscsiadm --mode discoverydb --type sendtargets --portal "$target_ip" --discover
    iscsiadm --mode node --targetname "$target_name" --portal "$target_ip:$target_port" --login
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    helper_check_device_symlinks
    helper_check_device_units
    # Add all iSCSI devices into a LVM volume group, create two logical volumes,
    # and check if necessary symlinks exist (and are valid)
    lvm pvcreate -y "${expected_symlinks[@]}"
    lvm pvs
    lvm vgcreate "$vgroup" -y "${expected_symlinks[@]}"
    lvm vgs
    lvm vgchange -ay "$vgroup"
    lvm lvcreate -y -L 4M "$vgroup" -n mypart1
    lvm lvcreate -y -L 8M "$vgroup" -n mypart2
    lvm lvs
    udevadm wait --settle --timeout=30 "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2"
    mkfs.ext4 -L mylvpart1 "/dev/$vgroup/mypart1"
    udevadm trigger --settle "/dev/$vgroup/mypart1"
    udevadm wait --settle --timeout=30 "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units
    # Disconnect the iSCSI devices and check all the symlinks
    iscsiadm --mode node --targetname "$target_name" --portal "$target_ip:$target_port" --logout
    # "Reset" the DM state, since we yanked the backing storage from under the LVM,
    # so the currently active VGs/LVs are invalid
    dmsetup remove_all --deferred
    # The LVM and iSCSI related symlinks should be gone
    udevadm wait --settle --timeout=30 --removed "/dev/$vgroup" "/dev/disk/by-label/mylvpart1" "${expected_symlinks[@]}"
    helper_check_device_symlinks "/dev/disk"
    helper_check_device_units
    # Reconnect the iSCSI devices and check if everything get detected correctly
    iscsiadm --mode discoverydb --type sendtargets --portal "$target_ip" --discover
    iscsiadm --mode node --targetname "$target_name" --portal "$target_ip:$target_port" --login
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}" "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2" "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
    helper_check_device_units
    # Cleanup
    iscsiadm --mode node --targetname "$target_name" --portal "$target_ip:$target_port" --logout
    tgtadm --lld iscsi --op delete --mode target --tid=2
    umount "$mpoint"
    rm -rf "$mpoint"
}

testcase_long_sysfs_path() {
    local cursor link logfile mpoint
    local expected_symlinks=(
        "/dev/disk/by-label/data_vol"
        "/dev/disk/by-label/swap_vol"
        "/dev/disk/by-partlabel/test_swap"
        "/dev/disk/by-partlabel/test_part"
        "/dev/disk/by-partuuid/deadbeef-dead-dead-beef-000000000000"
        "/dev/disk/by-uuid/deadbeef-dead-dead-beef-111111111111"
        "/dev/disk/by-uuid/deadbeef-dead-dead-beef-222222222222"
    )

    # Create a cursor file to skip messages generated by udevd in initrd, as it
    # might not be the same up-to-date version as we currently run (hence generating
    # messages we check for later and making the test fail)
    cursor="$(mktemp)"
    journalctl --cursor-file="${cursor:?}" -n0 -q

    # Make sure the test device is connected and show its "wonderful" path
    dev="$(udevadm info -e --property-match=ID_SERIAL=long-sysfs-path --property-match DEVTYPE=disk --json=short | jq -r .DEVNAME)"
    dev="${dev#/dev/}"

    stat "/sys/block/${dev}"
    readlink -f "/sys/block/${dev}/dev"

    udevadm lock --timeout=30 --device "/dev/${dev}" sfdisk "/dev/${dev}" <<EOF
label: gpt

name="test_swap", size=32M
uuid="deadbeef-dead-dead-beef-000000000000", name="test_part", size=5M
EOF
    udevadm settle --timeout=30
    udevadm lock --timeout=30 --device "/dev/${dev}1" mkswap -U "deadbeef-dead-dead-beef-111111111111" -L "swap_vol" "/dev/${dev}1"
    udevadm lock --timeout=30 --device "/dev/${dev}2" mkfs.ext4 -U "deadbeef-dead-dead-beef-222222222222" -L "data_vol" "/dev/${dev}2"
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"

    # Try to mount the data partition manually (using its label)
    mpoint="$(mktemp -d /logsysfsXXX)"
    mount LABEL=data_vol "$mpoint"
    touch "$mpoint/test"
    umount "$mpoint"
    # Do the same, but with UUID and using fstab
    echo "UUID=deadbeef-dead-dead-beef-222222222222 $mpoint ext4 defaults 0 0" >>/etc/fstab
    systemctl daemon-reload
    mount "$mpoint"
    timeout 30 bash -c "until systemctl -q is-active '$mpoint'; do sleep .2; done"
    test -e "$mpoint/test"
    umount "$mpoint"

    # Test out the swap partition
    swapon -v -L swap_vol
    swapoff -v -L swap_vol

    udevadm settle --timeout=30

    logfile="$(mktemp)"
    # Check state of affairs after https://github.com/systemd/systemd/pull/22759
    # Note: can't use `--cursor-file` here, since we don't want to update the cursor
    #       after using it
    [[ "$(journalctl --after-cursor="$(<"$cursor")" -q --no-pager -o short-monotonic -p info --grep "Device path.*${dev}.?' too long to fit into unit name" | wc -l)" -eq 0 ]]
    [[ "$(journalctl --after-cursor="$(<"$cursor")" -q --no-pager -o short-monotonic --grep "Unit name .*${dev}.?\.device\" too long, falling back to hashed unit name" | wc -l)" -gt 0 ]]
    # Check if the respective "hashed" units exist and are active (plugged)
    systemctl status --no-pager "$(readlink -f "/sys/block/${dev}/${dev}1")"
    systemctl status --no-pager "$(readlink -f "/sys/block/${dev}/${dev}2")"
    # Make sure we don't unnecessarily spam the log
    { journalctl -b -q --no-pager -o short-monotonic -p info --grep "/sys/devices/.+/${dev}[0-9]?" _PID=1 + UNIT=systemd-udevd.service || :;} | tee "$logfile"
    [[ "$(wc -l <"$logfile")" -lt 10 ]]

    : >/etc/fstab
    rm -fr "${cursor:?}" "${logfile:?}" "${mpoint:?}"
}

testcase_mdadm_basic() {
    local i part_name raid_name raid_dev uuid
    local expected_symlinks=()
    local devices=(
        /dev/disk/by-id/scsi-0systemd_foobar_deadbeefmdadm{0..4}
    )

    ls -l "${devices[@]}"

    echo "Mirror raid (RAID 1)"
    raid_name="mdmirror"
    raid_dev="/dev/md/$raid_name"
    part_name="${raid_name}_part"
    uuid="aaaaaaaa:bbbbbbbb:cccccccc:00000001"
    expected_symlinks=(
        "$raid_dev"
        "/dev/disk/by-id/md-name-H:$raid_name"
        "/dev/disk/by-id/md-uuid-$uuid"
        "/dev/disk/by-label/$part_name" # ext4 partition
    )
    # Create a simple RAID 1 with an ext4 filesystem
    printf 'y\ny\n' | mdadm --create "$raid_dev" --name "$raid_name" --uuid "$uuid" /dev/disk/by-id/scsi-0systemd_foobar_deadbeefmdadm{0..1} -v -f --level=1 --raid-devices=2
    udevadm wait --settle --timeout=30 "$raid_dev"
    # udevd does not lock md devices, hence we need to trigger uevent after creating filesystem.
    mkfs.ext4 -L "$part_name" "$raid_dev"
    udevadm trigger --settle "$raid_dev"
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    for i in {0..9}; do
        echo "Disassemble - reassemble loop, iteration #$i"
        mdadm -v --stop "$raid_dev"
        udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
        mdadm --assemble "$raid_dev" --name "$raid_name" -v
        udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    done
    helper_check_device_symlinks
    helper_check_device_units
    # Cleanup
    mdadm -v --stop "$raid_dev"
    udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"

    echo "Parity raid (RAID 5)"
    raid_name="mdparity"
    raid_dev="/dev/md/$raid_name"
    part_name="${raid_name}_part"
    uuid="aaaaaaaa:bbbbbbbb:cccccccc:00000101"
    expected_symlinks=(
        "$raid_dev"
        "/dev/disk/by-id/md-name-H:$raid_name"
        "/dev/disk/by-id/md-uuid-$uuid"
        "/dev/disk/by-label/$part_name" # ext4 partition
    )
    # Create a simple RAID 5 with an ext4 filesystem
    printf 'y\ny\n' | mdadm --create "$raid_dev" --name "$raid_name" --uuid "$uuid" /dev/disk/by-id/scsi-0systemd_foobar_deadbeefmdadm{0..2} -v -f --level=5 --raid-devices=3
    udevadm wait --settle --timeout=30 "$raid_dev"
    mkfs.ext4 -L "$part_name" "$raid_dev"
    udevadm trigger --settle "$raid_dev"
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    for i in {0..9}; do
        echo "Disassemble - reassemble loop, iteration #$i"
        mdadm -v --stop "$raid_dev"
        udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
        mdadm --assemble "$raid_dev" --name "$raid_name" -v
        udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    done
    helper_check_device_symlinks
    helper_check_device_units
    # Cleanup
    mdadm -v --stop "$raid_dev"
    udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
    helper_check_device_units

    echo "Mirror + parity raid (RAID 10) + multiple partitions"
    raid_name="mdmirpar"
    raid_dev="/dev/md/$raid_name"
    part_name="${raid_name}_part"
    uuid="aaaaaaaa:bbbbbbbb:cccccccc:00001010"
    expected_symlinks=(
        "$raid_dev"
        "/dev/disk/by-id/md-name-H:$raid_name"
        "/dev/disk/by-id/md-uuid-$uuid"
        "/dev/disk/by-label/$part_name" # ext4 partition
        # Partitions
        "${raid_dev}1"
        "${raid_dev}2"
        "${raid_dev}3"
        "/dev/disk/by-id/md-name-H:$raid_name-part1"
        "/dev/disk/by-id/md-name-H:$raid_name-part2"
        "/dev/disk/by-id/md-name-H:$raid_name-part3"
        "/dev/disk/by-id/md-uuid-$uuid-part1"
        "/dev/disk/by-id/md-uuid-$uuid-part2"
        "/dev/disk/by-id/md-uuid-$uuid-part3"
    )
    # Create a simple RAID 10 with an ext4 filesystem
    printf 'y\ny\n' | mdadm --create "$raid_dev" --name "$raid_name" --uuid "$uuid" /dev/disk/by-id/scsi-0systemd_foobar_deadbeefmdadm{0..3} -v -f --level=10 --raid-devices=4
    udevadm wait --settle --timeout=30 "$raid_dev"
    # Partition the raid device
    # Here, 'udevadm lock' is meaningless, as udevd does not lock MD devices.
    # We need to trigger uevents after sfdisk and mkfs.
    sfdisk --wipe=always "$raid_dev" <<EOF
label: gpt

uuid="deadbeef-dead-dead-beef-111111111111", name="mdpart1", size=8M
uuid="deadbeef-dead-dead-beef-222222222222", name="mdpart2", size=32M
uuid="deadbeef-dead-dead-beef-333333333333", name="mdpart3", size=16M
EOF
    udevadm wait --settle --timeout=30 "$raid_dev" "${raid_dev}1" "${raid_dev}2" "${raid_dev}3"
    # FIXME: For some reasons, the command sometimes stuck and the test will timeout.
    # Let's enable debug logging and set a timeout to make not consume CI resource.
    # UPDATE: The above 'udevadm wait' command should fix the issue.
    # But, let's keep the debug option for a while.
    SYSTEMD_LOG_LEVEL=debug timeout 30 udevadm trigger --settle --parent-match "$raid_dev"
    udevadm wait --settle --timeout=30 "/dev/disk/by-id/md-uuid-$uuid-part2"
    mkfs.ext4 -L "$part_name" "/dev/disk/by-id/md-uuid-$uuid-part2"
    udevadm trigger --settle "/dev/disk/by-id/md-uuid-$uuid-part2"
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    for i in {0..9}; do
        echo "Disassemble - reassemble loop, iteration #$i"
        mdadm -v --stop "$raid_dev"
        udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
        mdadm --assemble "$raid_dev" --name "$raid_name" -v
        udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    done
    helper_check_device_symlinks
    helper_check_device_units
    # Cleanup
    mdadm -v --stop "$raid_dev"

    # Clear superblocks to make the MD device will not be restarted even if the VM is restarted.
    # This is a workaround for issue #38240.
    udevadm settle --timeout=30
    # shellcheck disable=SC2046
    mdadm -v --zero-superblock --force $(readlink -f "${devices[@]}")
    udevadm settle --timeout=30

    # Check if all expected symlinks were removed after the cleanup
    udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
    helper_check_device_units
}

testcase_mdadm_lvm() {
    local part_name raid_name raid_dev uuid vgroup
    local expected_symlinks=()
    local devices=(
        /dev/disk/by-id/scsi-0systemd_foobar_deadbeefmdadmlvm{0..4}
    )

    ls -l "${devices[@]}"

    raid_name="mdlvm"
    raid_dev="/dev/md/$raid_name"
    part_name="${raid_name}_part"
    vgroup="${raid_name}_vg"
    uuid="aaaaaaaa:bbbbbbbb:ffffffff:00001010"
    expected_symlinks=(
        "$raid_dev"
        "/dev/$vgroup/mypart1"          # LVM partition
        "/dev/$vgroup/mypart2"          # LVM partition
        "/dev/disk/by-id/md-name-H:$raid_name"
        "/dev/disk/by-id/md-uuid-$uuid"
        "/dev/disk/by-label/$part_name" # ext4 partition
    )
    # Create a RAID 10 with LVM + ext4
    printf 'y\ny\n' | mdadm --create "$raid_dev" --name "$raid_name" --uuid "$uuid" /dev/disk/by-id/scsi-0systemd_foobar_deadbeefmdadmlvm{0..3} -v -f --level=10 --raid-devices=4
    udevadm wait --settle --timeout=30 "$raid_dev"
    # Create an LVM on the MD
    lvm pvcreate -y -ff "$raid_dev"
    lvm pvs
    lvm vgcreate "$vgroup" -y "$raid_dev"
    lvm vgs
    lvm vgchange -ay "$vgroup"
    lvm lvcreate -y -L 4M "$vgroup" -n mypart1
    lvm lvcreate -y -L 8M "$vgroup" -n mypart2
    lvm lvs
    udevadm wait --settle --timeout=30 "/dev/$vgroup/mypart1" "/dev/$vgroup/mypart2"
    mkfs.ext4 -L "$part_name" "/dev/$vgroup/mypart2"
    udevadm trigger --settle "/dev/$vgroup/mypart2"
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    # Disassemble the array
    lvm vgchange -an "$vgroup"
    mdadm -v --stop "$raid_dev"
    udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
    helper_check_device_symlinks
    helper_check_device_units
    # Reassemble it and check if all required symlinks exist
    mdadm --assemble "$raid_dev" --name "$raid_name" -v
    udevadm wait --settle --timeout=30 "${expected_symlinks[@]}"
    helper_check_device_symlinks
    helper_check_device_units
    # Cleanup
    lvm vgchange -an "$vgroup"
    mdadm -v --stop "$raid_dev"

    # Clear superblocks to make the MD device will not be restarted even if the VM is restarted.
    # This is a workaround for issue #38240.
    udevadm settle --timeout=30
    # shellcheck disable=SC2046
    mdadm -v --zero-superblock --force $(readlink -f "${devices[@]}")
    udevadm settle --timeout=30

    # Check if all expected symlinks were removed after the cleanup
    udevadm wait --settle --timeout=30 --removed "${expected_symlinks[@]}"
    helper_check_device_units
}

udevadm settle
udevadm control --log-level debug
lsblk -a

echo "Check if all symlinks under /dev/disk/ are valid (pre-test)"
helper_check_device_symlinks

# TEST_FUNCTION_NAME is passed on the kernel command line via systemd.setenv=
# in the respective test.sh file
if ! command -v "${TEST_FUNCTION_NAME:?}"; then
    echo >&2 "Missing verification handler for test case '$TEST_FUNCTION_NAME'"
    exit 1
fi

echo "TEST_FUNCTION_NAME=$TEST_FUNCTION_NAME"
"$TEST_FUNCTION_NAME"
udevadm settle --timeout=60

echo "Check if all symlinks under /dev/disk/ are valid (post-test)"
helper_check_device_symlinks

udevadm control --log-level info

systemctl status systemd-udevd

touch /testok
