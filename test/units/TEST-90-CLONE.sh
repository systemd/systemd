#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test dm-clone generator and systemd-clone

at_exit() {
    set +e

    rm -f /etc/clonetab
    [[ -e /tmp/clonetab.bak ]] && cp -fv /tmp/clonetab.bak /etc/clonetab
    [[ -n "${LOOP_SRC:-}" ]] && losetup -d "$LOOP_SRC"
    [[ -n "${LOOP_DST:-}" ]] && losetup -d "$LOOP_DST"
    [[ -n "${LOOP_META:-}" ]] && losetup -d "$LOOP_META"
    [[ -n "${WORKDIR:-}" ]] && rm -rf "$WORKDIR"
    dmsetup remove testclone 2>/dev/null || true

    systemctl daemon-reload
}

trap at_exit EXIT

clone_start_and_check() {
    local volume unit

    volume="${1:?}"
    unit="systemd-clone@$volume.service"

    # The unit existence check should always pass
    [[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
    systemctl list-unit-files "$unit"

    systemctl start "$unit"
    systemctl status "$unit"
    test -e "/dev/mapper/$volume"
    dmsetup status "$volume"

    systemctl stop "$unit"
    # Upstream libdevmapper (LVM2) uses dm_udev_wait() (and cookie APIs like
    # udevcreatecookie/udevreleasecookie): after a DM operation (create/remove),
    # it waits for udev to finish processing so the device node state is in sync
    # before the API returns. So "wait for udev" is the standard approach there.
    udevadm settle --timeout=10
    test ! -e "/dev/mapper/$volume"
}

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
testclone $LOOP_SRC $LOOP_DST $LOOP_META ""
EOF

# Run the generator explicitly for coverage
mkdir -p /tmp/clone-generator.out
/usr/lib/systemd/system-generators/systemd-clone-generator /tmp/clone-generator.out/ /tmp/clone-generator.out/ /tmp/clone-generator.out/

# Verify generator output
test -f /tmp/clone-generator.out/systemd-clone@testclone.service
test -d /tmp/clone-generator.out/clone.target.requires
test -d /tmp/clone-generator.out/dev-mapper-testclone.device.requires
test -f /tmp/clone-generator.out/dev-mapper-testclone.device.d/40-device-timeout.conf

# Reload systemd to pick up generated units
systemctl daemon-reload
systemctl list-unit-files "systemd-clone@*"

# Check clone.target exists
systemctl show clone.target

# Test clone service
clone_start_and_check testclone

touch /testok

