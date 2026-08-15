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

touch /testok
