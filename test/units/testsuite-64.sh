#!/usr/bin/env bash
# vi: ts=4 sw=4 tw=0 et:

set -eux
set -o pipefail

# Check if all symlinks under /dev/disk/ are valid
# shellcheck disable=SC2120
helper_check_device_symlinks() {
    # Disable verbose logging only for this function (and reset the signal handler
    # when leaving the function)
    set +x; trap "trap - RETURN; set -x" RETURN

    local dev link path paths target

    [[ $# -gt 0 ]] && paths=("$@") || paths=("/dev/disk")

    # Check if all given paths are valid
    for path in "${paths[@]}"; do
        if ! test -e "$path"; then
            echo >&2 "Path '$path' doesn't exist"
            return 1
        fi
    done

    while read -r link; do
        target="$(readlink -f "$link")"
        echo "$link -> $target"
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
}

testcase_megasas2_basic() {
    lsblk -S
    [[ "$(lsblk --scsi --noheadings | wc -l)" -ge 128 ]]
}

testcase_nvme_basic() {
    lsblk --noheadings | grep "^nvme"
    [[ "$(lsblk --noheadings | grep -c "^nvme")" -ge 28 ]]
}

testcase_virtio_scsi_identically_named_partitions() {
    lsblk --noheadings -a -o NAME,PARTLABEL
    [[ "$(lsblk --noheadings -a -o NAME,PARTLABEL | grep -c "Hello world")" -eq $((16 * 8)) ]]
}

testcase_multipath_basic_failover() {
    local dmpath i path wwid

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
    modprobe -v dm_multipath
    systemctl start multipathd.service
    systemctl status multipathd.service
    multipath -ll
    ls -l /dev/disk/by-id/

    for i in {0..63}; do
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
    for link in "${part_links[@]}"; do
        test -e "$link"
    done

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
        for link in "${part_links[@]}"; do
            test -e "$link"
        done
    done

    multipath -l "$path"
    # Three paths should be now marked as 'offline' and one as 'running'
    [[ "$(multipath -l "$path" | grep -c offline)" -eq 3 ]]
    [[ "$(multipath -l "$path" | grep -c running)" -eq 1 ]]

    umount "$mpoint"
    rm -fr "$mpoint"
}

testcase_simultaneous_events() {
    local blockdev part partscript

    blockdev="$(readlink -f /dev/disk/by-id/scsi-*_deadbeeftest)"
    partscript="$(mktemp)"

    if [[ ! -b "$blockdev" ]]; then
        echo "ERROR: failed to find the test SCSI block device"
        return 1
    fi

    cat >"$partscript" <<EOF
$(printf 'name="test%d", size=2M\n' {1..50})
EOF

    # Initial partition table
    sfdisk -q -X gpt "$blockdev" <"$partscript"

    # Delete the partitions, immediatelly recreate them, wait for udev to settle
    # down, and then check if we have any dangling symlinks in /dev/disk/. Rinse
    # and repeat.
    #
    # On unpatched udev versions the delete-recreate cycle may trigger a race
    # leading to dead symlinks in /dev/disk/
    for i in {1..100}; do
        sfdisk -q --delete "$blockdev"
        sfdisk -q -X gpt "$blockdev" <"$partscript"

        if ((i % 10 == 0)); then
            udevadm settle
            helper_check_device_symlinks
        fi
    done

    rm -f "$partscript"
}

testcase_lvm_basic() {
    local i part
    local vgroup="MyTestGroup$RANDOM"
    local devices=(
        /dev/disk/by-id/ata-foobar_deadbeeflvm{0..3}
    )

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
    lvm lvcreate -y -L 8M "$vgroup" -n mypart2
    lvm lvs
    udevadm settle
    test -e "/dev/$vgroup/mypart1"
    test -e "/dev/$vgroup/mypart2"
    mkfs.ext4 -L mylvpart1 "/dev/$vgroup/mypart1"
    udevadm settle
    test -e "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"

    # Disable the VG and check symlinks...
    lvm vgchange -an "$vgroup"
    udevadm settle
    test ! -e "/dev/$vgroup"
    test ! -e "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk"

    # reenable the VG and check the symlinks again if all LVs are properly activated
    lvm vgchange -ay "$vgroup"
    udevadm settle
    test -e "/dev/$vgroup/mypart1"
    test -e "/dev/$vgroup/mypart2"
    test -e "/dev/disk/by-label/mylvpart1"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"

    # Same as above, but now with more "stress"
    for i in {1..100}; do
        lvm vgchange -an "$vgroup"
        lvm vgchange -ay "$vgroup"

        if ((i % 10 == 0)); then
            udevadm settle
            test -e "/dev/$vgroup/mypart1"
            test -e "/dev/$vgroup/mypart2"
            test -e "/dev/disk/by-label/mylvpart1"
            helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
        fi
    done

    # Remove the first LV
    lvm lvremove -y "$vgroup/mypart1"
    udevadm settle
    test ! -e "/dev/$vgroup/mypart1"
    test -e "/dev/$vgroup/mypart2"
    helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"

    # Create & remove LVs in a loop, i.e. with more "stress"
    for i in {1..50}; do
        # 1) Create 16 logical volumes
        for part in {0..15}; do
            lvm lvcreate -y -L 4M "$vgroup" -n "looppart$part"
        done

        # 2) Immediately remove them
        lvm lvremove -y "$vgroup"/looppart{0..15}

        # 3) On every 10th iteration settle udev and check if all partitions are
        #    indeed gone, and if all symlinks are still valid
        if ((i % 10 == 0)); then
            udevadm settle
            for part in {0..15}; do
                test ! -e "/dev/$vgroup/looppart$part"
            done
            helper_check_device_symlinks "/dev/disk" "/dev/$vgroup"
        fi
    done
}

: >/failed

udevadm settle
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

echo "Check if all symlinks under /dev/disk/ are valid (post-test)"
helper_check_device_symlinks

systemctl status systemd-udevd

touch /testok
rm /failed
