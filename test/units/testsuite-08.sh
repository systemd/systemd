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
    exit 0
fi

# We should've created a mount under /run in initrd (see the other half of the test)
# that should've survived the transition from initrd to the real system
test -d /run/initrd-mount-target
mountpoint /run/initrd-mount-target
[[ -e /run/initrd-mount-target/hello-world ]]

# Copy the prepared shutdown initrd to its intended location. Check the respective
# test.sh file for details
mkdir -p /run/initramfs
cp -r /shutdown-initrd/* /run/initramfs/

touch /testok
