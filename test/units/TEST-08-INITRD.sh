#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-detect-virt -qc; then
    echo >&2 "This test can't run in a container"
    exit 1
fi

# This test requires systemd to run in the initrd as well, which is not the case
# for mkinitrd-based initrd (Ubuntu/Debian)
if [[ "$(systemctl show -P InitRDTimestampMonotonic)" -eq 0 ]]; then
    echo "systemd didn't run in the initrd, skipping the test"
    touch /skipped
    exit 77
fi

# We should've created a mount under /run in initrd (see the other half of the test)
# that should've survived the transition from initrd to the real system
test -d /run/initrd-mount-target
mountpoint /run/initrd-mount-target
[[ -e /run/initrd-mount-target/hello-world ]]

# The initrd-run-initramfs.service in the initrd should have populated /run/initramfs
# from the initrd's own contents before switch-root.
test -x /run/initramfs/shutdown

# systemd.memory_hugetlb_accounting=yes is set on the kernel command line. The control group file system
# is mounted in the initrd already, hence the option has to be honoured there.
# initrd-cgroup-remount.service then turns memory_hugetlb_accounting off again, like a service manager in
# the initrd that does not know the kernel command line option would leave it, and turns
# memory_localevents on. The service manager of the host has to turn memory_hugetlb_accounting on once
# more and keep the other options. It does so at boot only: a change made later survives daemon-reexec.
if grep -w memory_hugetlb_accounting /sys/kernel/cgroup/features >/dev/null; then
    CGROUP_OPTIONS="$(awk '$5 == "/sys/fs/cgroup" { print $NF }' /run/initrd-mountinfo)"
    [[ "$CGROUP_OPTIONS" == *memory_hugetlb_accounting* ]]

    CGROUP_OPTIONS="$(awk '$5 == "/sys/fs/cgroup" { print $NF }' /run/initrd-mountinfo-remounted)"
    [[ "$CGROUP_OPTIONS" == *memory_localevents* ]]
    [[ "$CGROUP_OPTIONS" != *memory_hugetlb_accounting* ]]

    CGROUP_OPTIONS="$(findmnt --noheadings --output OPTIONS /sys/fs/cgroup)"
    [[ "$CGROUP_OPTIONS" == *nosuid* ]]
    [[ "$CGROUP_OPTIONS" == *nsdelegate* ]]
    [[ "$CGROUP_OPTIONS" == *memory_recursiveprot* ]]
    [[ "$CGROUP_OPTIONS" == *memory_localevents* ]]
    [[ "$CGROUP_OPTIONS" == *memory_hugetlb_accounting* ]]

    mount -o remount,nosuid,nodev,noexec,nsdelegate,memory_recursiveprot cgroup2 /sys/fs/cgroup
    CGROUP_OPTIONS="$(findmnt --noheadings --output OPTIONS /sys/fs/cgroup)"
    [[ "$CGROUP_OPTIONS" != *memory_hugetlb_accounting* ]]
    systemctl daemon-reexec
    [[ "$(findmnt --noheadings --output OPTIONS /sys/fs/cgroup)" == "$CGROUP_OPTIONS" ]]
fi

touch /testok
