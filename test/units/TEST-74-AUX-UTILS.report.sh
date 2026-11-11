#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail
shopt -s nullglob

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/metric-util.sh
. "$(dirname "$0")"/metric-util.sh

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

REPORT=/usr/lib/systemd/systemd-report
FAKE_SERVER=/usr/lib/systemd/tests/integration-tests/TEST-74-AUX-UTILS/TEST-74-AUX-UTILS.units/fake-report-server.py

# systemd-report is optional
[ -x "$REPORT" ] || exit 77

testcase_cli() {
    "$REPORT" --help
    "$REPORT" help
    "$REPORT" --version
    "$REPORT" --json=help

    "$REPORT" metrics
    "$REPORT" metrics -j
    "$REPORT" metrics --no-legend
    "$REPORT" describe
    "$REPORT" describe -j
    "$REPORT" describe --no-legend
    "$REPORT" list-sources
    "$REPORT" list-sources -j
    "$REPORT" list-sources --no-legend

    "$REPORT" metrics io
    "$REPORT" metrics io.systemd piff
    "$REPORT" metrics piff
    "$REPORT" describe io
    "$REPORT" describe io.systemd piff
    "$REPORT" describe piff
}

testcase_cgroup() {
    # test io.systemd.CGroup Metrics
    systemctl start systemd-report-cgroup.socket
    varlinkctl info /run/systemd/report/io.systemd.CGroup
    varlinkctl list-methods /run/systemd/report/io.systemd.CGroup
    varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {}
    varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.Describe {}

    cgroup_describe=$(varlinkctl --more --json=short call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.Describe {})
    for family_type in PressureAvg10:gauge PressureStallSeconds:counter; do
        assert_metric_type_eq "$cgroup_describe" "io.systemd.CGroup.${family_type%:*}" "${family_type#*:}"
    done

    # CpuUsage emits one row per (cgroup, type) where type is total, user, or system.
    # Confirm all three are present and numeric.
    cgroup_metrics=$(varlinkctl --more --json=short call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {})
    assert_metric_value_is_number "$cgroup_metrics" io.systemd.CGroup.CpuUsage --field type total
    assert_metric_value_is_number "$cgroup_metrics" io.systemd.CGroup.CpuUsage --field type user
    assert_metric_value_is_number "$cgroup_metrics" io.systemd.CGroup.CpuUsage --field type system

    PSI_UNIT="test-report-psi-$RANDOM.service"
    trap 'systemctl stop "$PSI_UNIT"' EXIT
    systemd-run --unit="$PSI_UNIT" --service-type=exec sleep infinity
    psi_cgroup="/sys/fs/cgroup$(systemctl show -P ControlGroup "$PSI_UNIT")"

    if cat /proc/pressure/cpu /proc/pressure/io /proc/pressure/memory >/dev/null 2>&1 &&
           cpu_pressure=$(cat "$psi_cgroup/cpu.pressure" 2>/dev/null); then
        cgroup_metrics=$(varlinkctl --more --json=short call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {})

        for resource in cpu memory io; do
            types=(some)
            # No full for cpu prior to 5.13
            if [ "$resource" != cpu ] || grep '^full ' <<<"$cpu_pressure" >/dev/null; then
                types+=(full)
            fi

            for type in "${types[@]}"; do
                assert_metric_values_in_range "$cgroup_metrics" io.systemd.CGroup.PressureAvg10 0 100 \
                    --object "$PSI_UNIT" --field resource "$resource" --field type "$type"

                # The stall counter only grows, so the value sampled above cannot exceed what the unit's
                # own pressure file (in microseconds) shows now. Allow 1us for floating-point rounding
                # when converting the kernel's microseconds to seconds.
                stall_max="$(awk -v type="$type" '
                    $1 == type {
                        for (i = 2; i <= NF; i++)
                            if (sub(/^total=/, "", $i)) { printf "%.17g\n", ($i + 1) / 1e6; found = 1; exit }
                    }
                    END { exit !found }' "$psi_cgroup/$resource.pressure")"
                assert_metric_values_in_range "$cgroup_metrics" io.systemd.CGroup.PressureStallSeconds 0 "$stall_max" \
                    --object "$PSI_UNIT" --field resource "$resource" --field type "$type"
            done
        done
    fi

    systemctl stop "$PSI_UNIT"
    trap - EXIT
}

testcase_network() {
    # shellcheck disable=SC2329
    network_cleanup() {
        set +e
        ip address del 192.0.2.1/32 dev lo
    }

    # test io.systemd.Network Metrics
    varlinkctl info /run/systemd/report/io.systemd.Network
    varlinkctl list-methods /run/systemd/report/io.systemd.Network
    varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {}
    varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {}

    net_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {})"
    assert_metric_type_eq "$net_describe" io.systemd.Network.Address string
    # we do not send "lo"
    net_metrics="$(varlinkctl call --more --json=short /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {})"
    assert_metric_absent "$net_metrics" io.systemd.Network.Address --object lo
    # add a scratch address and check that it shows up.
    trap network_cleanup EXIT
    ip address add 192.0.2.1/32 dev lo
    timeout 30 bash -c 'until varlinkctl call --more --json=short /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {} | grep -F "192.0.2.1/32" >/dev/null; do sleep .5; done'
    net_metrics="$(varlinkctl call --more --json=short /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {})"
    assert_metric_value_eq "$net_metrics" io.systemd.Network.Address 192.0.2.1/32 --object lo --field family ipv4
}

# test io.systemd.HWMon Metrics
testcase_hwmon() {
    # The hwmon socket is conditioned out in containers, since temperature sensors belong to the host
    if systemd-detect-virt --quiet --container; then
        echo "Skipping io.systemd.HWMon tests in container."
        return 0
    fi

    systemctl start systemd-report-hwmon.socket
    varlinkctl info /run/systemd/report/io.systemd.HWMon
    varlinkctl list-methods /run/systemd/report/io.systemd.HWMon
    hwmon_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.HWMon io.systemd.Metrics.Describe {})"
    assert_metric_type_eq "$hwmon_describe" io.systemd.HWMon.TemperatureCelsius gauge
    # An empty result set is signalled through the io.systemd.Metrics.NoSuchMetric sentinel error, which is what
    # VMs without any hwmon devices produce, hence treat it as success.
    hwmon_metrics="$(varlinkctl call --more --graceful=io.systemd.Metrics.NoSuchMetric /run/systemd/report/io.systemd.HWMon io.systemd.Metrics.List {})"
    # At most one row per readable, non-faulted temp<N>_input attribute in sysfs. A sensor may become
    # transiently unreadable between the two samples, hence only check the bound. VMs typically expose no hwmon
    # devices at all, in which case both counts are zero.
    hwmon_expected=0
    for f in /sys/class/hwmon/hwmon*/temp*_input; do
        hwmon_fault="${f%_input}_fault"
        if [[ -f "$hwmon_fault" ]] && [[ "$(cat "$hwmon_fault")" == 1 ]]; then
            continue
        fi
        if cat "$f" >/dev/null 2>&1; then
            hwmon_expected=$((hwmon_expected + 1))
        fi
    done
    hwmon_reported="$(metric_count "$hwmon_metrics" --name io.systemd.HWMon.TemperatureCelsius)"
    assert_le "$hwmon_reported" "$hwmon_expected"
    if [[ "$hwmon_reported" -gt 0 ]]; then
        # Every row must carry a numeric value, an object and a sensor field of the form temp<N>
        assert_eq "$(echo "$hwmon_metrics" | jq --seq -r 'select(.name == "io.systemd.HWMon.TemperatureCelsius") | ((.value | type) == "number") and ((.object | type) == "string") and (.fields.sensor | test("^temp[0-9]+$")) | tostring' | sort -u)" "true"
    fi
    "$REPORT" describe io.systemd.HWMon
    "$REPORT" metrics io.systemd.HWMon
}

testcase_network_statistics() {
    # test io.systemd.NetworkStatistics Metrics
    systemctl start systemd-report-netstat.socket
    varlinkctl info /run/systemd/report/io.systemd.NetworkStatistics
    varlinkctl list-methods /run/systemd/report/io.systemd.NetworkStatistics
    netstat_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.NetworkStatistics io.systemd.Metrics.Describe {})"
    for m in CarrierChanges Collisions ReceiveBytes ReceiveDropped ReceiveErrors ReceiveMulticastPackets ReceivePackets \
             TransmitBytes TransmitDropped TransmitErrors TransmitPackets; do
        assert_metric_type_eq "$netstat_describe" "io.systemd.NetworkStatistics.$m" counter
    done
    for m in MTU SpeedBitsPerSecond TransmitQueueLength; do
        assert_metric_type_eq "$netstat_describe" "io.systemd.NetworkStatistics.$m" gauge
    done

    # Create a veth pair with the peer in a scratch network namespace, push some traffic through it, and check
    # that our end is reported with plausible values, while the peer (which lives in a different network
    # namespace) is not.
    netstat_cleanup() {
        ip link del report-ns0 || :
        ip netns del report-netstat || :
    }
    trap netstat_cleanup EXIT

    ip netns add report-netstat
    ip link add report-ns0 mtu 1400 type veth peer name report-ns1 mtu 1400 netns report-netstat
    ip address add 192.0.2.10/24 dev report-ns0
    ip -n report-netstat address add 192.0.2.11/24 dev report-ns1
    ip link set report-ns0 up
    ip -n report-netstat link set report-ns1 up
    ping -c 5 -i 0.2 -W 5 192.0.2.11

    netstat_tx_bytes_before="$(cat /sys/class/net/report-ns0/statistics/tx_bytes)"
    netstat_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.NetworkStatistics io.systemd.Metrics.List {})"
    netstat_tx_bytes_after="$(cat /sys/class/net/report-ns0/statistics/tx_bytes)"

    # Every metric of the interface carries the same fields
    assert_metric_field_eq "$netstat_metrics" ifindex "$(cat /sys/class/net/report-ns0/ifindex)" --object report-ns0
    assert_metric_field_eq "$netstat_metrics" kind veth --object report-ns0
    assert_metric_field_eq "$netstat_metrics" type ether --object report-ns0
    assert_metric_count_eq "$netstat_metrics" 14 --object report-ns0
    assert_metric_absent_full "$netstat_metrics" --object report-ns1

    assert_metric_value_eq "$netstat_metrics" io.systemd.NetworkStatistics.MTU 1400 --object report-ns0
    # veth reports a fixed link speed of 10 Gbit/s
    assert_metric_value_eq "$netstat_metrics" io.systemd.NetworkStatistics.SpeedBitsPerSecond 10000000000 --object report-ns0
    assert_metric_value_ge "$netstat_metrics" io.systemd.NetworkStatistics.TransmitPackets 5 --object report-ns0
    assert_metric_value_ge "$netstat_metrics" io.systemd.NetworkStatistics.ReceivePackets 5 --object report-ns0
    assert_metric_value_eq "$netstat_metrics" io.systemd.NetworkStatistics.ReceiveErrors 0 --object report-ns0
    assert_metric_value_eq "$netstat_metrics" io.systemd.NetworkStatistics.TransmitErrors 0 --object report-ns0
    # The interface may still see some traffic (IPv6 router solicitations, …), hence only check the bounds
    netstat_tx_bytes="$(metric_value "$netstat_metrics" io.systemd.NetworkStatistics.TransmitBytes --object report-ns0)"
    assert_metric_value_ge "$netstat_metrics" io.systemd.NetworkStatistics.TransmitBytes "$netstat_tx_bytes_before" --object report-ns0
    assert_metric_value_le "$netstat_metrics" io.systemd.NetworkStatistics.TransmitBytes "$netstat_tx_bytes_after" --object report-ns0
    assert_metric_value_ge "$netstat_metrics" io.systemd.NetworkStatistics.TransmitBytes $((5 * 84)) --object report-ns0

    # Loopback is reported too, but has no link speed
    assert_metric_field_eq "$netstat_metrics" type loopback --object lo
    assert_metric_value_is_number "$netstat_metrics" io.systemd.NetworkStatistics.ReceivePackets --object lo
    assert_metric_absent "$netstat_metrics" io.systemd.NetworkStatistics.SpeedBitsPerSecond --object lo

    # Counters must not go backwards
    netstat_tx_packets="$(metric_value "$netstat_metrics" io.systemd.NetworkStatistics.TransmitPackets --object report-ns0)"
    ping -c 2 -i 0.2 -W 5 192.0.2.11
    netstat_metrics2="$(varlinkctl call --more /run/systemd/report/io.systemd.NetworkStatistics io.systemd.Metrics.List {})"
    assert_metric_value_ge "$netstat_metrics2" io.systemd.NetworkStatistics.TransmitPackets "$((netstat_tx_packets + 2))" --object report-ns0
    assert_metric_value_gt "$netstat_metrics2" io.systemd.NetworkStatistics.TransmitBytes "$netstat_tx_bytes" --object report-ns0

    # Once removed, the interface is not reported anymore
    netstat_cleanup
    trap - EXIT
    netstat_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.NetworkStatistics io.systemd.Metrics.List {})"
    assert_metric_absent_full "$netstat_metrics" --object report-ns0

    "$REPORT" describe io.systemd.NetworkStatistics
    "$REPORT" metrics io.systemd.NetworkStatistics
}

# test io.systemd.DiskHealth Metrics
testcase_diskhealth() {
    # The disk health socket is conditioned out in containers, since disks belong to the host
    if systemd-detect-virt --quiet --container; then
        echo "Skipping io.systemd.DiskHealth tests in container."
        return 0
    fi

    systemctl start systemd-report-diskhealth.socket
    varlinkctl info /run/systemd/report/io.systemd.DiskHealth
    varlinkctl list-methods /run/systemd/report/io.systemd.DiskHealth
    diskhealth_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.DiskHealth io.systemd.Metrics.Describe {})"
    for name in ATAReallocatedSectors DiskPowerCycles DiskPowerOnHours NVMeMediaErrors; do
        assert_metric_type_eq "$diskhealth_describe" "io.systemd.DiskHealth.$name" counter
    done
    for name in ATAOfflineUncorrectable ATAPendingSectors ATASmartStatusFailing DiskLogicalSectorSizeBytes DiskPhysicalSectorSizeBytes DiskSizeBytes \
                NVMeAvailableSparePercent NVMeCriticalWarning NVMePercentageUsed; do
        assert_metric_type_eq "$diskhealth_describe" "io.systemd.DiskHealth.$name" gauge
    done
    for name in DiskModel DiskSerial DiskVendor; do
        assert_metric_type_eq "$diskhealth_describe" "io.systemd.DiskHealth.$name" string
    done

    diskhealth_metrics="$(varlinkctl call --more --graceful=io.systemd.Metrics.NoSuchMetric /run/systemd/report/io.systemd.DiskHealth io.systemd.Metrics.List {})"

    # Every whole hardware disk with a medium must be reported, with the numbers from sysfs and the strings
    # from the udev database, and nothing else may be reported.
    diskhealth_expected=""
    for dev in /sys/block/*; do
        devpath="$(udevadm info --query=property --value --property=DEVPATH "$dev" || :)"
        devname="$(udevadm info --query=property --value --property=DEVNAME "$dev" || :)"
        initialized="$(udevadm info --query=property --value --property=USEC_INITIALIZED "$dev" || :)"
        # Hidden NVMe multipath path devices have no device node, and devices not (yet) in the udev database
        # are skipped by the service
        [[ -n "$devpath" && -n "$devname" && -n "$initialized" ]] || continue
        [[ "$devpath" =~ ^/devices/virtual/ && ! "$devpath" =~ ^/devices/virtual/nvme-subsystem/ ]] && continue
        [[ "$(cat "$dev/size")" -gt 0 ]] || continue
        diskhealth_expected+="$devname"$'\n'

        assert_metric_value_eq "$diskhealth_metrics" io.systemd.DiskHealth.DiskSizeBytes "$(( $(cat "$dev/size") * 512 ))" --object "$devname"
        assert_metric_value_eq "$diskhealth_metrics" io.systemd.DiskHealth.DiskLogicalSectorSizeBytes "$(cat "$dev/queue/logical_block_size")" --object "$devname"
        assert_metric_value_eq "$diskhealth_metrics" io.systemd.DiskHealth.DiskPhysicalSectorSizeBytes "$(cat "$dev/queue/physical_block_size")" --object "$devname"

        model="$(udevadm info --query=property --value --property=ID_MODEL_FROM_DATABASE "$dev")"
        [[ -n "$model" ]] || model="$(udevadm info --query=property --value --property=ID_MODEL "$dev")"
        if [[ -n "$model" ]]; then
            assert_metric_value_eq "$diskhealth_metrics" io.systemd.DiskHealth.DiskModel "$model" --object "$devname"
        fi

        vendor="$(udevadm info --query=property --value --property=ID_VENDOR_FROM_DATABASE "$dev")"
        [[ -n "$vendor" ]] || vendor="$(udevadm info --query=property --value --property=ID_VENDOR "$dev")"
        if [[ -n "$vendor" ]]; then
            assert_metric_value_eq "$diskhealth_metrics" io.systemd.DiskHealth.DiskVendor "$vendor" --object "$devname"
        fi

        serial="$(udevadm info --query=property --value --property=ID_SERIAL_SHORT "$dev")"
        [[ -n "$serial" ]] || serial="$(udevadm info --query=property --value --property=ID_SERIAL "$dev")"
        if [[ -n "$serial" ]]; then
            assert_metric_value_eq "$diskhealth_metrics" io.systemd.DiskHealth.DiskSerial "$serial" --object "$devname"
        else
            assert_metric_absent "$diskhealth_metrics" io.systemd.DiskHealth.DiskSerial --object "$devname"
        fi
    done
    diff <(echo -n "$diskhealth_expected" | sort) <(echo "$diskhealth_metrics" | jq --seq -r '.object' | sort -u)

    "$REPORT" describe io.systemd.DiskHealth
    "$REPORT" metrics io.systemd.DiskHealth
}

# test io.systemd.DiskSpace Metrics
diskspace_mount_tests() {
    # Mount a scratch ext4 file system and check that it is reported with plausible numbers, that a tmpfs next to
    # it is not, that additional bind mounts of it do not result in additional rows but the shortest writable
    # mount path wins regardless of mount order, that it disappears from the report once remounted read-only,
    # and that a device mapper device stacked on top of it is reported with the loop device as originating
    # source.

    # Loop devices and device mapper are not available in containers
    if systemd-detect-virt --quiet --container; then
        echo "Skipping io.systemd.DiskSpace mount tests in container."
        return
    fi

    DISKSPACE_WORK="$(mktemp -d /var/tmp/report-diskspace.XXXXXX)"
    diskspace_cleanup() {
        set +e
        umount "$DISKSPACE_WORK/tmpfs" "$DISKSPACE_WORK/a" "$DISKSPACE_WORK/b" "$DISKSPACE_WORK/longer" "$DISKSPACE_WORK/ext4" "$DISKSPACE_WORK/dm"
        dmsetup remove report-diskspace
        systemd-dissect --detach "$DISKSPACE_WORK/scratch.raw"
        rm -rf "$DISKSPACE_WORK"
        set -e
    }
    trap diskspace_cleanup EXIT
    mkdir "$DISKSPACE_WORK/ext4" "$DISKSPACE_WORK/a" "$DISKSPACE_WORK/b" "$DISKSPACE_WORK/longer" "$DISKSPACE_WORK/dm" "$DISKSPACE_WORK/tmpfs"
    truncate -s 64M "$DISKSPACE_WORK/scratch.raw"
    mkfs.ext4 -q "$DISKSPACE_WORK/scratch.raw"
    DISKSPACE_LOOP="$(systemd-dissect --attach --loop-ref=report-diskspace "$DISKSPACE_WORK/scratch.raw")"
    mount "$DISKSPACE_LOOP" "$DISKSPACE_WORK/ext4"
    # "a" sorts before "b" and is just as short, but is read-only, hence "b" must be picked
    mount --bind -o ro "$DISKSPACE_WORK/ext4" "$DISKSPACE_WORK/a"
    mount --bind "$DISKSPACE_WORK/ext4" "$DISKSPACE_WORK/b"
    # "longer" is writable too, but has a longer path, hence must not win even though it is mounted last
    mount --bind "$DISKSPACE_WORK/ext4" "$DISKSPACE_WORK/longer"
    mount -t tmpfs tmpfs "$DISKSPACE_WORK/tmpfs"
    dd if=/dev/urandom of="$DISKSPACE_WORK/ext4/fill" bs=1M count=8
    sync -f "$DISKSPACE_WORK/ext4"

    diskspace_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.DiskSpace io.systemd.Metrics.List {})"
    # Exactly one row per metric for the scratch file system, reported under the shortest writable mount path
    assert_metric_object_eq "$diskspace_metrics" io.systemd.DiskSpace.SizeBytes "$DISKSPACE_WORK/b" --field source "$DISKSPACE_LOOP"
    assert_metric_object_eq "$diskspace_metrics" io.systemd.DiskSpace.FreeBytes "$DISKSPACE_WORK/b" --field source "$DISKSPACE_LOOP"
    # df(1) derives the same two numbers from statfs(), hence they must match exactly.
    read -r diskspace_df_size diskspace_df_avail < <(df -B1 --output=size,avail "$DISKSPACE_WORK/ext4" | sed 1d)
    assert_metric_value_eq "$diskspace_metrics" io.systemd.DiskSpace.SizeBytes "$diskspace_df_size" --object "$DISKSPACE_WORK/b"
    assert_metric_value_eq "$diskspace_metrics" io.systemd.DiskSpace.FreeBytes "$diskspace_df_avail" --object "$DISKSPACE_WORK/b"
    # The file system cannot be larger than the image, and at least the 8M we wrote must be missing from the
    # free space.
    assert_metric_value_gt "$diskspace_metrics" io.systemd.DiskSpace.SizeBytes 0 --object "$DISKSPACE_WORK/b"
    assert_metric_value_le "$diskspace_metrics" io.systemd.DiskSpace.SizeBytes $((64 * 1024 * 1024)) --object "$DISKSPACE_WORK/b"
    assert_metric_value_gt "$diskspace_metrics" io.systemd.DiskSpace.FreeBytes 0 --object "$DISKSPACE_WORK/b"
    assert_metric_value_le "$diskspace_metrics" io.systemd.DiskSpace.FreeBytes $((diskspace_df_size - 8 * 1024 * 1024)) --object "$DISKSPACE_WORK/b"
    # Both rows must carry the file system type as field, and no originating source, as a loop device is not
    # stacked on anything
    assert_metric_field_eq "$diskspace_metrics" fileSystemType ext4 --object "$DISKSPACE_WORK/b"
    assert_metric_field_absent "$diskspace_metrics" originatingSource --object "$DISKSPACE_WORK/b"
    # The tmpfs may not be reported
    assert_metric_absent_full "$diskspace_metrics" --object "$DISKSPACE_WORK/tmpfs"

    # Once remounted read-only the file system must no longer be reported, regardless of the mount path
    mount -o remount,ro "$DISKSPACE_WORK/ext4"
    diskspace_metrics="$(varlinkctl call --more --graceful=io.systemd.Metrics.NoSuchMetric /run/systemd/report/io.systemd.DiskSpace io.systemd.Metrics.List {})"
    assert_metric_absent_full "$diskspace_metrics" --field source "$DISKSPACE_LOOP"

    # Now stack a (linear) device mapper device on top of the loop device, and mount the file system through
    # that: the DM device must be reported as source, and the loop device it sits on as originating source. The
    # loop device must be unmounted first, as DM needs exclusive access to it.
    umount "$DISKSPACE_WORK/a" "$DISKSPACE_WORK/b" "$DISKSPACE_WORK/longer" "$DISKSPACE_WORK/ext4"
    dmsetup create report-diskspace --table "0 $(blockdev --getsz "$DISKSPACE_LOOP") linear $DISKSPACE_LOOP 0"
    udevadm wait --timeout=30 --settle /dev/mapper/report-diskspace
    mount /dev/mapper/report-diskspace "$DISKSPACE_WORK/dm"
    diskspace_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.DiskSpace io.systemd.Metrics.List {})"
    assert_metric_field_eq "$diskspace_metrics" source /dev/mapper/report-diskspace --object "$DISKSPACE_WORK/dm"
    assert_metric_field_eq "$diskspace_metrics" originatingSource "$DISKSPACE_LOOP" --object "$DISKSPACE_WORK/dm"

    diskspace_cleanup
    trap - EXIT
}

testcase_diskspace() {
    # The socket and service are only built if libmount is available
    if ! systemctl cat systemd-report-diskspace.socket &>/dev/null; then
        echo "systemd-report-diskspace.socket is not installed, skipping io.systemd.DiskSpace tests."
    else
        systemctl start systemd-report-diskspace.socket
        varlinkctl info /run/systemd/report/io.systemd.DiskSpace
        varlinkctl list-methods /run/systemd/report/io.systemd.DiskSpace
        diskspace_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.DiskSpace io.systemd.Metrics.Describe {})"
        assert_metric_type_eq "$diskspace_describe" io.systemd.DiskSpace.FreeBytes gauge
        assert_metric_type_eq "$diskspace_describe" io.systemd.DiskSpace.SizeBytes gauge

        diskspace_mount_tests

        "$REPORT" describe io.systemd.DiskSpace
        "$REPORT" metrics io.systemd.DiskSpace
    fi
}

testcase_basic() {
    # test io.systemd.Basic Metrics
    # ensure the socket is running, as some distros don't enable it by default
    systemctl start systemd-report-basic.socket
    varlinkctl info /run/systemd/report/io.systemd.Basic
    varlinkctl list-methods /run/systemd/report/io.systemd.Basic
    varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {}
    varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.Describe {}

    basic_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"
    os_id="$(. /etc/os-release; echo "$ID")"
    assert_metric_value_eq "$basic_metrics" io.systemd.Basic.OSRelease.ID "$os_id"

    # test io.systemd.Basic load average and swap metrics
    basic_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"

    # The three classic load average fields must be present and numeric.
    for field in LoadAverage1Min LoadAverage5Min LoadAverage15Min; do
        assert_metric_value_is_number "$basic_metrics" "io.systemd.Basic.$field"
    done

    # SwapBytes must match the total the kernel reports in /proc/meminfo (which is in kB).
    swap_expected=$(( $(awk '/^SwapTotal:/ { print $2; found=1 } END { if (!found) print 0 }' /proc/meminfo) * 1024 ))
    assert_metric_value_eq "$basic_metrics" io.systemd.Basic.SwapBytes "$swap_expected"

    # SwapUsedBytes must be numeric and cannot exceed the configured total.
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.SwapUsedBytes
    assert_metric_value_le "$basic_metrics" io.systemd.Basic.SwapUsedBytes "$swap_expected"

    # Those fields must be reported with a numeric nanoseconds value.
    for type in user system; do
        assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.CPUUsage --field type "$type"
    done

    # iowait/idle/steal must be valid nanoseconds values, but can go up and down.
    for type in idle iowait steal; do
        assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.CPUWait --field type "$type"
    done

    # The values are USER_HZ ticks converted to nanoseconds. The metrics were sampled before the
    # current /proc/stat state, and the idle counter mostly grows, so the reported idle time
    # should be positive and no larger than what /proc/stat shows now with some margin.
    cpu_idle_max="$(awk -v hz="$(getconf CLK_TCK)" \
        '/^cpu / { printf "%.0f\n", int(($5 + 1) / hz * 1e9); found = 1; exit } END { exit !found }' /proc/stat)"
    assert_metric_value_gt "$basic_metrics" io.systemd.Basic.CPUWait 0 --field type idle
    assert_metric_value_le "$basic_metrics" io.systemd.Basic.CPUWait "$cpu_idle_max" --field type idle

    # MemoryUsedBytes is MemTotal − MemAvailable, so it cannot exceed the MemTotal reported by the
    # same file. (PhysicalMemoryBytes is not a valid bound here: it is capped by the root cgroup's
    # memory limit, so it can legitimately be smaller than the value computed from /proc/meminfo.)
    mem_total=$(( $(awk '/^MemTotal:/ { print $2 }' /proc/meminfo) * 1024 ))
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.MemoryUsedBytes
    assert_metric_value_le "$basic_metrics" io.systemd.Basic.MemoryUsedBytes "$mem_total"

    # Pressure metrics are only reported if the kernel supports PSI.
    if cat /proc/pressure/cpu >/dev/null 2>&1; then
        for family in PressureAvg10 PressureStallSeconds; do
            for resource in cpu memory io; do
                assert_metric_value_is_number "$basic_metrics" "io.systemd.Basic.$family" \
                    --field resource "$resource" --field type some
                # "full" is deliberately not emitted for cpu, where the kernel always reports 0.
                if [ "$resource" = cpu ]; then
                    assert_metric_absent "$basic_metrics" "io.systemd.Basic.$family" \
                        --field resource "$resource" --field type full
                else
                    assert_metric_value_is_number "$basic_metrics" "io.systemd.Basic.$family" \
                        --field resource "$resource" --field type full
                fi
            done
        done

        # The avg10 values are percentages, so they must lie in the 0…100 range. This would catch a
        # wrong fixed-point conversion, which would inflate the value 2048x.
        assert_metric_values_in_range "$basic_metrics" io.systemd.Basic.PressureAvg10 0 100
    fi

    # Every whole physical block device (not partitions, not virtual or stacked devices) must be
    # reported, with byte values derived from the 512-byte sector counters in sysfs. Those counters
    # only grow, so the values sampled above cannot exceed what sysfs shows now.
    for dev in /sys/block/*; do
        devpath="$(udevadm info --query=property --value --property=DEVPATH "$dev" || :)"
        devname="$(udevadm info --query=property --value --property=DEVNAME "$dev" || :)"
        [[ -n "$devpath" && -n "$devname" ]] || continue

        [[ "$devpath" =~ "/devices/virtual/" ]] && continue

        assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.DiskReadBytes --object "$devname"
        assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.DiskWriteBytes --object "$devname"

        read -r _ _ read_sectors _ _ _ write_sectors _ <"$dev/stat"
        assert_metric_value_le "$basic_metrics" io.systemd.Basic.DiskReadBytes "$(( read_sectors * 512 ))" --object "$devname"
        assert_metric_value_le "$basic_metrics" io.systemd.Basic.DiskWriteBytes "$(( write_sectors * 512 ))" --object "$devname"
    done

    # Sample the clock metrics anew, right before comparing them against /proc/uptime and date, so that the
    # margins below do not have to cover the time the checks above took.
    basic_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"

    # The clock metrics are sampled together, hence boottime (which includes time spent suspended) can
    # never be smaller than monotonic. Use whole-second bounds for the system clock comparisons below
    # to allow for rounding of large realtime values by jq.
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.ClockMonotonicNSec
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.ClockRealtimeNSec
    monotonic_ns="$(metric_value "$basic_metrics" io.systemd.Basic.ClockMonotonicNSec)"
    assert_metric_value_gt "$basic_metrics" io.systemd.Basic.ClockMonotonicNSec 0
    assert_metric_value_ge "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec "$monotonic_ns"

    # /proc/uptime is CLOCK_BOOTTIME too, read after the metrics were sampled; allow for a generous margin.
    uptime_s="$(cut -d. -f1 /proc/uptime)"
    assert_metric_value_lt "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec $(( (uptime_s + 1) * 1000000000 ))
    assert_metric_value_ge "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec $(( (uptime_s - 60) * 1000000000 ))

    now_s="$(date +%s)"
    assert_metric_value_lt "$basic_metrics" io.systemd.Basic.ClockRealtimeNSec $(( (now_s + 1) * 1000000000 ))
    assert_metric_value_ge "$basic_metrics" io.systemd.Basic.ClockRealtimeNSec $(( (now_s - 60) * 1000000000 ))

    # Boottime and monotonic are counters, hence must not go backwards between two calls.
    boottime_ns="$(metric_value "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec)"
    basic_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec
    assert_metric_value_ge "$basic_metrics" io.systemd.Basic.ClockBoottimeNSec "$boottime_ns"
    assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.ClockMonotonicNSec
    assert_metric_value_ge "$basic_metrics" io.systemd.Basic.ClockMonotonicNSec "$monotonic_ns"

    # DeploymentTimestampNSec is the birth time of the file system backing /var/, or of the root file system
    # if /var/ is not a mount point of its own. It is only reported if the file system records birth times
    # (which stat reports as 0 otherwise). Allow one second of rounding error, including the entire
    # second above the expected birth time.
    if mountpoint -q /var/; then deploy_dir=/var/; else deploy_dir=/; fi
    deploy_expected_s="$(stat -c %W "$deploy_dir")"
    if [ "$deploy_expected_s" -gt 0 ]; then
        assert_metric_value_is_number "$basic_metrics" io.systemd.Basic.DeploymentTimestampNSec
        assert_metric_value_ge "$basic_metrics" io.systemd.Basic.DeploymentTimestampNSec $(( (deploy_expected_s - 1) * 1000000000 ))
        assert_metric_value_lt "$basic_metrics" io.systemd.Basic.DeploymentTimestampNSec $(( (deploy_expected_s + 2) * 1000000000 ))
    else
        assert_metric_absent "$basic_metrics" io.systemd.Basic.DeploymentTimestampNSec
    fi

    # Every new metric family must be described, even those whose values depend on the environment.
    basic_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.Describe {})"
    for name in ClockBoottimeNSec ClockMonotonicNSec ClockRealtimeNSec CPUUsage CPUWait DeploymentTimestampNSec DiskReadBytes DiskWriteBytes MemoryUsedBytes PressureAvg10 PressureStallSeconds SwapUsedBytes; do
        echo "$basic_describe" | grep -F "io.systemd.Basic.$name" >/dev/null
    done
}

testcase_manager() {
    # io.systemd.Manager.Version should be non-empty and match what `systemctl --version` reports
    manager_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {})"
    assert_metric_value_not_empty "$manager_metrics" io.systemd.Manager.Version
    metrics_version="$(metric_value "$manager_metrics" io.systemd.Manager.Version)"
    systemctl --version | grep -F "($metrics_version)" >/dev/null

    # Boot timeline timestamps. The kernel CLOCK_MONOTONIC is 0 by definition, so only its realtime is
    # reported; userspace reports both realtime and monotonic. We don't check FinishTimestamp here:
    # the test runs as a service, so manager_check_finished() typically hasn't fired yet and the
    # timestamp is unset (the metric is then suppressed). Likewise KernelTimestamp is cleared when
    # systemd runs inside a container (see main.c), so the metric is suppressed there too.
    manager_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {})"
    if ! systemd-detect-virt --quiet --container; then
        assert_metric_value_gt "$manager_metrics" io.systemd.Manager.KernelTimestamp.Realtime 0
    fi
    assert_metric_value_gt "$manager_metrics" io.systemd.Manager.UserspaceTimestamp.Realtime 0
    assert_metric_value_gt "$manager_metrics" io.systemd.Manager.UserspaceTimestamp.Monotonic 0

    # These startup phases are captured unconditionally by manager_startup() on every boot (in containers
    # too, where they are not redirected to the InitRD* variants), so both clocks are always set on the
    # system manager by the time this service runs. We don't check UnitsLoadTimestamp (the last load, only
    # set on the reload/reexec triggered by switch-root) nor the Security/Firmware/Loader/InitRD timestamps,
    # which depend on the boot environment and may legitimately be unset (the metric is then suppressed).
    for phase in GeneratorsStartTimestamp GeneratorsFinishTimestamp \
                 UnitsLoadStartTimestamp UnitsLoadFinishTimestamp; do
        assert_metric_value_gt "$manager_metrics" "io.systemd.Manager.$phase.Realtime" 0
        assert_metric_value_gt "$manager_metrics" "io.systemd.Manager.$phase.Monotonic" 0
    done

    # The sub_state field on UnitActiveState is what tells a running unit from one that stayed active after exiting
    assert_metric_field_eq "$manager_metrics" sub_state running --name io.systemd.Manager.UnitActiveState --object init.scope
    assert_metric_field_eq "$manager_metrics" sub_state exited --name io.systemd.Manager.UnitActiveState --object systemd-tmpfiles-setup.service
}

testcase_machine_info() {
    systemctl start systemd-report-basic.socket

    # test io.systemd.Basic.MachineInfo.* metrics, sourced from /etc/machine-info
    if [ -e /etc/machine-info ]; then
        MACHINE_INFO_BACKUP="$(mktemp)"
        cp /etc/machine-info "$MACHINE_INFO_BACKUP"
        MACHINE_INFO_EXISTED=1
    else
        MACHINE_INFO_EXISTED=0
    fi

    restore_machine_info() {
        set +e
        if [ "$MACHINE_INFO_EXISTED" = 1 ]; then
            cp "$MACHINE_INFO_BACKUP" /etc/machine-info
            rm -f "$MACHINE_INFO_BACKUP"
        else
            rm -f /etc/machine-info
        fi
        set -e
    }
    trap restore_machine_info EXIT

    cat >/etc/machine-info <<EOF
PRETTY_HOSTNAME="Test Machine"
DEPLOYMENT=test
LOCATION="Test Lab, Rack 3"
TAGS=foo:bar:baz
EOF

    # The metric source re-reads /etc/machine-info on every call, so no service restart is needed.
    machine_info_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"

    assert_metric_value_eq "$machine_info_metrics" io.systemd.Basic.MachineInfo.PRETTY_HOSTNAME "Test Machine"
    assert_metric_value_eq "$machine_info_metrics" io.systemd.Basic.MachineInfo.DEPLOYMENT "test"
    assert_metric_value_eq "$machine_info_metrics" io.systemd.Basic.MachineInfo.LOCATION "Test Lab, Rack 3"
    assert_metric_value_eq "$machine_info_metrics" io.systemd.Basic.MachineInfo.TAGS "foo:bar:baz"

    restore_machine_info
    trap - EXIT
}

testcase_generate() {
    "$REPORT" generate io.systemd.Manager.UnitsTotal

    "$REPORT" generate io.systemd.Manager.UnitsTotal | jq .

    # Without --nonce= no nonce field is included, with it the nonce is included verbatim
    "$REPORT" generate io.systemd.Manager.UnitsTotal | jq -e 'has("nonce") | not' >/dev/null
    NONCE="$(openssl rand -base64 32)"
    assert_eq "$("$REPORT" generate --nonce="$NONCE" io.systemd.Manager.UnitsTotal | jq -r .nonce)" "$NONCE"
    assert_fail "$REPORT" generate --nonce='!!!not base64!!!' io.systemd.Manager.UnitsTotal
}

testcase_upload_http() {
    trap 'systemctl stop fake-report-server' EXIT

    systemd-run -p Type=notify --unit=fake-report-server "$FAKE_SERVER"
    systemctl status fake-report-server

    "$REPORT" upload --url=http://localhost:8089/
}

testcase_upload_https() {
    CERTDIR=$(mktemp -d)
    trap 'set +e; systemctl stop fake-report-server-tls; rm -rf "$CERTDIR"' EXIT

    # Test HTTPS upload with generated TLS certificates.
    # Build a basic CA and sign a cert for the server. The client will
    # use the CA cert as a trust anchor.
    openssl req -x509 -newkey rsa:2048 -keyout "$CERTDIR/ca.key" -out "$CERTDIR/ca.crt" \
        -days 1 -nodes -subj "/CN=systemd-report test CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

    cat >"$CERTDIR/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

    openssl req -newkey rsa:2048 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.csr" \
        -nodes -subj "/CN=localhost" 2>/dev/null
    openssl x509 -req -in "$CERTDIR/server.csr" -CA "$CERTDIR/ca.crt" -CAkey "$CERTDIR/ca.key" \
        -CAcreateserial -days 1 -extfile "$CERTDIR/server.ext" \
        -out "$CERTDIR/server.crt" 2>/dev/null

    cat "$CERTDIR/server.crt" "$CERTDIR/ca.crt" >"$CERTDIR/server-chain.crt"

    systemd-run -p Type=notify --unit=fake-report-server-tls \
        "$FAKE_SERVER" --cert="$CERTDIR/server-chain.crt" --key="$CERTDIR/server.key" --port=8090
    systemctl status fake-report-server-tls

    "$REPORT" upload --url=https://localhost:8090/ --key=- --trust="$CERTDIR/ca.crt" \
              --extra-header='Authorization: Bearer magic string'
}

testcase_files() {
    # shellcheck disable=SC2329
    at_exit() {
        set +e
        systemctl stop systemd-report-files.socket
        rm -f /run/systemd/report.files/testreportfile /run/systemd/report.files/binaryfile
        rm -f /run/systemd/report.files/maskedfile /var/lib/systemd/report.files/maskedfile /var/lib/systemd/report.files/dirshadowed
        rm -f /run/systemd/report.files/fifoshadowed /var/lib/systemd/report.files/fifoshadowed
        rmdir /run/systemd/report.files/dirshadowed 2>/dev/null
    }
    trap at_exit EXIT

    # Test the systemd-report-files@.service metric provider: files dropped into one
    # of the report.files directories are exposed verbatim as io.systemd.Files.*
    # metrics, keyed by their file name.
    mkdir -p /run/systemd/report.files
    REPORT_FILE_CONTENT="hello from the report files metric provider"
    printf '%s' "$REPORT_FILE_CONTENT" >/run/systemd/report.files/testreportfile

    systemctl start systemd-report-files.socket
    varlinkctl info /run/systemd/report/io.systemd.Files
    varlinkctl list-methods /run/systemd/report/io.systemd.Files

    # The metric value must be the exact file contents.
    files_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.List {})"
    assert_metric_value_eq "$files_metrics" io.systemd.Files.testreportfile "$REPORT_FILE_CONTENT"

    # Describe must list the very same metric, of type string.
    files_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.Describe {})"
    assert_metric_type_eq "$files_describe" io.systemd.Files.testreportfile string

    # Files that aren't valid UTF-8 text must be skipped silently (the value is a
    # JSON string, so only text files can be reported).
    printf '\xff\xfe binary garbage' >/run/systemd/report.files/binaryfile
    files_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.List {})"
    assert_metric_absent "$files_metrics" io.systemd.Files.binaryfile
    rm -f /run/systemd/report.files/binaryfile

    # An entry in an earlier directory that is a symlink to /dev/null masks the one
    # in a later directory: it must be neither listed nor described. An entry that
    # isn't a regular file is ignored, so the later one is reported instead.
    mkdir -p /var/lib/systemd/report.files
    echo masked >/var/lib/systemd/report.files/maskedfile
    echo shadowed >/var/lib/systemd/report.files/dirshadowed
    ln -s /dev/null /run/systemd/report.files/maskedfile
    mkdir /run/systemd/report.files/dirshadowed
    echo fifo-shadowed >/var/lib/systemd/report.files/fifoshadowed
    mkfifo /run/systemd/report.files/fifoshadowed
    files_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.List {})"
    files_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.Describe {})"
    assert_metric_absent "$files_metrics" io.systemd.Files.maskedfile
    assert_metric_absent "$files_describe" io.systemd.Files.maskedfile
    assert_metric_value_eq "$files_metrics" io.systemd.Files.dirshadowed "shadowed"
    assert_metric_value_eq "$files_metrics" io.systemd.Files.fifoshadowed "fifo-shadowed"
    rm -f /run/systemd/report.files/fifoshadowed /var/lib/systemd/report.files/fifoshadowed
    rm -f /run/systemd/report.files/maskedfile /var/lib/systemd/report.files/maskedfile /var/lib/systemd/report.files/dirshadowed
    rmdir /run/systemd/report.files/dirshadowed
}

# -----------------------------------------------------------------------------
# Test the systemd-report-geoip@.service metric provider: the geolocation data
# is downloaded from the configured endpoint (our fake server here), cached, and
# exposed as io.systemd.GeoIP.* metrics. The provider is only built with libcurl
# support, so skip if unavailable.
testcase_geoip() {
    local geoip_metrics geoip_describe family

    if ! systemctl cat systemd-report-geoip.socket &>/dev/null; then
        echo "systemd-report-geoip.socket is not installed, skipping geoip metrics test."
        return 0
    fi

    # shellcheck disable=SC2329
    geoip_cleanup() {
        set +e
        systemctl stop systemd-report-geoip.socket fake-geoip-server fake-geoip-server-bogus
        rm -rf /run/systemd/report-geoip.conf.d
        rm -f /var/lib/systemd/report-geoip/cache.json
    }
    trap geoip_cleanup EXIT

    systemd-run -p Type=notify --unit=fake-geoip-server "$FAKE_SERVER" --port=8092

    mkdir -p /run/systemd/report-geoip.conf.d
    cat >/run/systemd/report-geoip.conf.d/99-test.conf <<EOF
[GeoIP]
Endpoint=http://localhost:8092/json/
RefreshSec=1h
EOF
    rm -f /var/lib/systemd/report-geoip/cache.json

    systemctl start systemd-report-geoip.socket
    varlinkctl info /run/systemd/report/io.systemd.GeoIP
    varlinkctl list-methods /run/systemd/report/io.systemd.GeoIP

    geoip_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.GeoIP io.systemd.Metrics.List {})"

    # The address must be reported in normalized form, not as the server sent it.
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.PublicAddress "2001:db8::1"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ASN "AS3320"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ASName "Deutsche Telekom AG"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ASDomain "telekom.de"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ContinentCode "EU"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ContinentName "Europe"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.CountryCode "DE"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.CountryName "Germany"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.RegionCode "BE"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.RegionName "State of Berlin"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.City "Berlin"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ZipCode "10785"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.Timezone "Europe/Berlin"
    # Coordinates use exponent notation, so compare numerically with a tolerance.
    assert_metric_value_float_eq "$geoip_metrics" io.systemd.GeoIP.Latitude 52.5061 1e-9
    assert_metric_value_float_eq "$geoip_metrics" io.systemd.GeoIP.Longitude 13.3684 1e-9
    # Freshly downloaded: the acquisition timestamp is "now", i.e. not older than a minute.
    assert_metric_value_gt "$geoip_metrics" io.systemd.GeoIP.Timestamp "$(( ($(date +%s) - 60) * 1000000 ))"

    # The obsolete metro_code field must not be reported.
    (! echo "$geoip_metrics" | grep -i metro >/dev/null)

    # The answer must have been cached.
    test -s /var/lib/systemd/report-geoip/cache.json
    jq . /var/lib/systemd/report-geoip/cache.json

    # Describe must list all sixteen metric families, with the right types.
    geoip_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.GeoIP io.systemd.Metrics.Describe {})"
    assert_metric_count_eq "$geoip_describe" 16 --name-prefix io.systemd.GeoIP.
    for family in PublicAddress ASN ASName ASDomain ContinentCode ContinentName CountryCode CountryName \
                  RegionCode RegionName City ZipCode Timezone; do
        assert_metric_type_eq "$geoip_describe" "io.systemd.GeoIP.$family" string
    done
    for family in Latitude Longitude Timestamp; do
        assert_metric_type_eq "$geoip_describe" "io.systemd.GeoIP.$family" gauge
    done

    # With the endpoint gone the (still fresh) cache must be used, and the acquisition timestamp must then
    # be the cache file's modification time.
    systemctl stop fake-geoip-server
    geoip_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.GeoIP io.systemd.Metrics.List {})"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.PublicAddress "2001:db8::1"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.ASN "AS3320"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.City "Berlin"
    cache_mtime_s="$(stat -c %Y /var/lib/systemd/report-geoip/cache.json)"
    assert_metric_value_is_number "$geoip_metrics" io.systemd.GeoIP.Timestamp
    assert_metric_value_ge "$geoip_metrics" io.systemd.GeoIP.Timestamp $(( cache_mtime_s * 1000000 ))
    assert_metric_value_lt "$geoip_metrics" io.systemd.GeoIP.Timestamp $(( (cache_mtime_s + 1) * 1000000 ))

    # Force a refresh: the download fails, so the stale cache must be used.
    cat >/run/systemd/report-geoip.conf.d/99-test.conf <<EOF
[GeoIP]
Endpoint=http://localhost:8092/json/
RefreshSec=0
EOF
    geoip_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.GeoIP io.systemd.Metrics.List {})"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.PublicAddress "2001:db8::1"
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.City "Berlin"

    # An endpoint returning something that isn't an IP address: the address must
    # be skipped, but the other fields still be reported.
    systemd-run -p Type=notify --unit=fake-geoip-server-bogus \
        "$FAKE_SERVER" --port=8091 --geoip-address="not an address"
    cat >/run/systemd/report-geoip.conf.d/99-test.conf <<EOF
[GeoIP]
Endpoint=http://localhost:8091/json/
RefreshSec=0
EOF
    geoip_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.GeoIP io.systemd.Metrics.List {})"
    assert_metric_absent "$geoip_metrics" io.systemd.GeoIP.PublicAddress
    assert_metric_value_eq "$geoip_metrics" io.systemd.GeoIP.City "Berlin"
    systemctl stop fake-geoip-server-bogus

    # An unreachable endpoint and no cache: nothing is reported, which the metrics helpers signal with
    # the NoSuchMetric sentinel error (as any source without metrics does).
    rm -f /var/lib/systemd/report-geoip/cache.json
    assert_fail varlinkctl call --more /run/systemd/report/io.systemd.GeoIP io.systemd.Metrics.List {} 2>&1 | grep NoSuchMetric >/dev/null
}

testcase_sign_plain() {
    # Test report signing through the plain software backend, driven entirely via
    # the io.systemd.Report Varlink interface (the GenerateSigned method). The plain
    # backend is only built/installed with OpenSSL support, so skip if unavailable.
    if ! systemctl cat systemd-report-sign-plain.socket &>/dev/null; then
        echo "systemd-report-sign-plain.socket is not installed, skipping report signing test."
        return 0
    fi

    trap 'set +e; systemctl stop systemd-report.socket systemd-report-sign-plain.socket; rm -rf "${SIGN_WORK:-}"' EXIT

    systemctl start systemd-report.socket
    systemctl start systemd-report-sign-plain.socket

    SIGN_WORK="$(mktemp -d)"

    # Ask systemd-report to generate a *signed* report over Varlink. The reply
    # carries the signed report as base64-encoded JSON-SEQ data.
    varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
        '{"matches":["io.systemd.Manager.UnitsTotal"]}' | jq -r .reportData | base64 -d >"$SIGN_WORK/report.seq"

    # The first JSON-SEQ record is the report itself. This is exactly the byte
    # sequence that got signed, including the leading record separator (0x1e) and
    # the trailing newline, so 'head -n1' reproduces it verbatim.
    head -n1 "$SIGN_WORK/report.seq" >"$SIGN_WORK/message.bin"
    tr -d '\036' <"$SIGN_WORK/message.bin" | jq -e '.mediaType == "application/vnd.io.systemd.report"' >/dev/null
    tr -d '\036' <"$SIGN_WORK/message.bin" | jq -e 'has("nonce") | not' >/dev/null

    # A nonce passed to GenerateSigned must show up in the signed report object
    NONCE="$(openssl rand -base64 32)"
    varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
        "{\"matches\":[\"io.systemd.Manager.UnitsTotal\"],\"nonce\":\"$NONCE\"}" |
        jq -r .reportData | base64 -d | jq --seq -r 'select(.mediaType == "application/vnd.io.systemd.report") | .nonce' |
        grep -Fx "$NONCE" >/dev/null

    # The remaining record(s) are signature objects. With only the plain backend
    # enabled there is exactly one, with mechanism "plain".
    sig_json="$(tail -n +2 "$SIGN_WORK/report.seq" | tr -d '\036')"
    assert_eq "$(echo "$sig_json" | jq -r .mechanism)" "plain"
    assert_eq "$(echo "$sig_json" | jq -r .mediaType)" "application/vnd.io.systemd.report.signature"

    # The sha256 recorded in the signature must match the digest of the report bytes.
    assert_eq "$(echo "$sig_json" | jq -r .sha256)" "$(sha256sum "$SIGN_WORK/message.bin" | cut -d' ' -f1)"

    # Extract the embedded public key and the raw Ed25519 signature.
    echo "$sig_json" | jq -r .data.key >"$SIGN_WORK/pub.pem"
    echo "$sig_json" | jq -r .data.signature | base64 -d >"$SIGN_WORK/sig.bin"

    # The signature is made over the SHA256 digest bytes directly (Ed25519, the
    # signer does not pre-hash), so verify the raw digest against the signature.
    openssl dgst -sha256 -binary "$SIGN_WORK/message.bin" >"$SIGN_WORK/digest.bin"
    openssl pkeyutl -verify -pubin -inkey "$SIGN_WORK/pub.pem" -rawin \
        -in "$SIGN_WORK/digest.bin" -sigfile "$SIGN_WORK/sig.bin"

    # The public key embedded in the report must be the very key the plain backend
    # generated and persisted on disk.
    diff <(openssl pkey -pubin -in "$SIGN_WORK/pub.pem" -pubout) \
         <(openssl pkey -pubin -in /var/lib/systemd/report.sign.plain/local.public -pubout)

    # A tampered report must no longer verify against the signature.
    printf 'x' >>"$SIGN_WORK/message.bin"
    openssl dgst -sha256 -binary "$SIGN_WORK/message.bin" >"$SIGN_WORK/digest-bad.bin"
    assert_fail openssl pkeyutl -verify -pubin -inkey "$SIGN_WORK/pub.pem" -rawin \
        -in "$SIGN_WORK/digest-bad.bin" -sigfile "$SIGN_WORK/sig.bin"

    # -----------------------------------------------------------------------------
    # The plain backend also acts as a metric provider, exposing its public signing
    # key as the io.systemd.Report.SignPlain.PublicKey metric. This is served off the
    # very same socket as the signer, reachable in the metrics directory under
    # /run/systemd/report/ (the signer endpoint is just a symlink into the root-only
    # /run/systemd/report.sign/ directory pointing at the same socket).
    varlinkctl info /run/systemd/report/io.systemd.Report.SignPlain
    varlinkctl list-methods /run/systemd/report/io.systemd.Report.SignPlain

    # The exposed public key must be the very key persisted on disk.
    sign_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Report.SignPlain io.systemd.Metrics.List {})"
    metric_value "$sign_metrics" io.systemd.Report.SignPlain.PublicKey >"$SIGN_WORK/metric-pub.pem"
    diff <(openssl pkey -pubin -in "$SIGN_WORK/metric-pub.pem" -pubout) \
         <(openssl pkey -pubin -in /var/lib/systemd/report.sign.plain/local.public -pubout)

    # Describe must list the very same metric, of type string.
    sign_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.Report.SignPlain io.systemd.Metrics.Describe {})"
    assert_metric_type_eq "$sign_describe" io.systemd.Report.SignPlain.PublicKey string
}

run_testcases
