#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test clonesetup generator and systemd-clonesetup

at_exit() {
    set +e

    rm -f /etc/clonetab
    [[ -e /tmp/clonetab.bak ]] && cp -fv /tmp/clonetab.bak /etc/clonetab
    [[ -n "${LOOP_SRC:-}" ]] && losetup -d "$LOOP_SRC"
    [[ -n "${LOOP_DST:-}" ]] && losetup -d "$LOOP_DST"
    [[ -n "${LOOP_META:-}" ]] && losetup -d "$LOOP_META"
    [[ -n "${WORKDIR:-}" ]] && rm -rf "$WORKDIR"
    dmsetup remove testclonesetup 2>/dev/null || true

    systemctl daemon-reload
}

trap at_exit EXIT

clonesetup_start_and_check() {
    local volume unit

    volume="${1:?}"
    unit="systemd-clonesetup@$volume.service"

    # The unit existence check should always pass
    [[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
    systemctl list-unit-files "$unit"

    systemctl start "$unit"
    systemctl status "$unit"
    test -e "/dev/mapper/$volume"
    dmsetup status "$volume"

    systemctl stop "$unit"
    # wait for udev to finish processing so the device node state is in sync
    # before the API returns.
    udevadm settle --timeout=10
    test ! -e "/dev/mapper/$volume"
}

prereq() {
    # Skip when kernel lacks dm-clone (CONFIG_DM_CLONE)
    modprobe dm_clone 2>/dev/null || true
    if [[ ! -d /sys/module/dm_clone ]]; then
        echo "no dm-clone" >/skipped
        exit 77
    fi
    echo "Found required kernel module: dm_clone"
}

prereq

# Use a common workdir
WORKDIR="$(mktemp -d)"

# Create test images for source, destination, and metadata
IMG_SRC="$WORKDIR/source.img"
IMG_DST="$WORKDIR/dest.img"
IMG_META="$WORKDIR/meta.img"

truncate -s 32M "$IMG_SRC"
truncate -s 32M "$IMG_DST"
truncate -s 8M "$IMG_META"

# Set up loop devices
LOOP_SRC="$(losetup --show --find "$IMG_SRC")"
LOOP_DST="$(losetup --show --find "$IMG_DST")"
LOOP_META="$(losetup --show --find "$IMG_META")"

udevadm settle --timeout=60

# Backup existing clonetab if any
[[ -e /etc/clonetab ]] && cp -fv /etc/clonetab /tmp/clonetab.bak

# Create test clonetab
cat >/etc/clonetab <<EOF
# name source dest metadata options
testclonesetup $LOOP_SRC $LOOP_DST $LOOP_META ""
EOF

# Run the generator explicitly for coverage
mkdir -p /tmp/clonesetup-generator.out
/usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

# Verify generator output
test -f /tmp/clonesetup-generator.out/systemd-clonesetup@testclonesetup.service
test -d /tmp/clonesetup-generator.out/clonesetup.target.requires
test -d /tmp/clonesetup-generator.out/dev-mapper-testclonesetup.device.requires
test -f /tmp/clonesetup-generator.out/dev-mapper-testclonesetup.device.d/40-device-timeout.conf

# Reload systemd to pick up generated units
systemctl daemon-reload
systemctl list-unit-files "systemd-clonesetup@*"

# Check clonesetup.target exists
systemctl show clonesetup.target

# Test clonesetup service
clonesetup_start_and_check testclonesetup

touch /testok

