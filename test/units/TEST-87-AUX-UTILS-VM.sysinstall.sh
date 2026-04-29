#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-sysinstall >/dev/null; then
    echo "systemd-sysinstall not found, skipping."
    exit 0
fi

if ! command -v systemd-repart >/dev/null; then
    echo "systemd-repart not found, skipping."
    exit 0
fi

if ! command -v bootctl >/dev/null; then
    echo "bootctl not found, skipping."
    exit 0
fi

if ! command -v ukify >/dev/null; then
    echo "ukify not found, skipping."
    exit 0
fi

if [[ ! -d /usr/lib/systemd/boot/efi ]]; then
    echo "sd-boot is not installed, skipping."
    exit 0
fi

# We need a real environment to fiddle with loop devices.
(! systemd-detect-virt -cq)

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

WORKDIR="$(mktemp --directory /tmp/test-sysinstall.XXXXXXXXXX)"
LOOPDEV=""
MOUNTED=0

cleanup() {
    set +e
    if [[ "$MOUNTED" -eq 1 ]]; then
        umount -R "$WORKDIR/mnt"
        MOUNTED=0
    fi
    if [[ -n "$LOOPDEV" ]]; then
        systemd-dissect --detach "$LOOPDEV"
        LOOPDEV=""
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# 1) Build a small fake "OS source" tree. systemd-sysinstall picks this up via
#    the repart.sysinstall.d definitions: CopyFiles= seeds the new root
#    partition with these files.
SOURCE_ROOT="$WORKDIR/sourceroot"
mkdir -p "$SOURCE_ROOT/usr/lib" "$SOURCE_ROOT/etc"

cat >"$SOURCE_ROOT/usr/lib/os-release" <<'EOF'
ID=testos
NAME="Test OS"
PRETTY_NAME="Test OS for systemd-sysinstall"
VERSION_ID=1
EOF
ln -s ../usr/lib/os-release "$SOURCE_ROOT/etc/os-release"

# 2) Build a minimal UKI. bootctl link only requires a valid PE with .osrel and
#    the systemd-stub SBAT marker, so the .linux/.initrd contents do not need
#    to be a real kernel.
STUB="/usr/lib/systemd/boot/efi/linux$(bootctl --print-efi-architecture).efi.stub"
echo "fake-kernel" >"$WORKDIR/vmlinuz"
echo "fake-initrd" >"$WORKDIR/initrd"

ukify build \
    --stub "$STUB" \
    --linux "$WORKDIR/vmlinuz" \
    --initrd "$WORKDIR/initrd" \
    --os-release "@$SOURCE_ROOT/usr/lib/os-release" \
    --uname "1.2.3-testkernel" \
    --cmdline "quiet" \
    --output "$WORKDIR/testuki.efi"

# 3) Build a sysinstall partition definition: a single ESP plus a root
#    partition seeded from the fake source tree.
DEFS="$WORKDIR/sysinstall.d"
mkdir -p "$DEFS"

cat >"$DEFS/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=64M
SizeMaxBytes=64M
EOF

cat >"$DEFS/20-root.conf" <<EOF
[Partition]
Type=root
Format=ext4
SizeMinBytes=128M
CopyFiles=$SOURCE_ROOT:/
EOF

# 4) Allocate a sparse target file. systemd-sysinstall accepts a regular file
#    path here — systemd-repart and the in-process dissect logic transparently
#    handle the loop attach during install. We can't pre-attach the empty file
#    via systemd-dissect --attach since that requires a valid DDI.
truncate -s 512M "$WORKDIR/target.img"

# 5) Run the installer non-interactively against the target image. Also stash a
#    literal credential ('marker') so we can verify it ends up next to the UKI
#    and is referenced from the boot loader entry.
CRED_VALUE="systemd-sysinstall test credential payload"
systemd-sysinstall \
    --welcome=no \
    --chrome=no \
    --confirm=no \
    --summary=no \
    --erase=yes \
    --variables=no \
    --reboot=no \
    --mute-console=no \
    --copy-locale=no \
    --copy-keymap=no \
    --copy-timezone=no \
    --set-credential="marker:$CRED_VALUE" \
    --kernel="$WORKDIR/testuki.efi" \
    --definitions="$DEFS" \
    "$WORKDIR/target.img"

# 6) Attach the freshly installed image as a loopback device for inspection.
LOOPDEV="$(systemd-dissect --attach "$WORKDIR/target.img")"

# Verify the resulting on-disk layout. The disk must now carry a GPT with at
# least an ESP partition.
sfdisk_dump="$(sfdisk --dump "$LOOPDEV")"
assert_in "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" "$sfdisk_dump"

# 7) Mount the image read-only and verify the installed artifacts: an entry
#    file referencing the UKI on the ESP, the UKI itself, and the systemd-boot
#    binary.
MNT="$WORKDIR/mnt"
mkdir -p "$MNT"

systemd-dissect --mount --read-only "$LOOPDEV" "$MNT"
MOUNTED=1

ESP="$MNT/efi"
test -d "$ESP/loader/entries"

# Exactly one entry should have been linked, and it should reference the UKI
# we passed via --kernel=.
ENTRY=$(find "$ESP/loader/entries" -maxdepth 1 -name '*.conf' -type f | head -n1)
test -n "$ENTRY"
grep -E "^uki /[^/]+/testuki\.efi$" "$ENTRY" >/dev/null

# The UKI file referenced in the entry must exist on the ESP.
UKI_PATH=$(awk '/^uki / { print $2 }' "$ENTRY")
test -f "$ESP$UKI_PATH"

# bootctl install should have placed sd-boot on the ESP.
find "$ESP/EFI/systemd" -type f -iname 'systemd-boot*.efi' | grep . >/dev/null

# The credential we passed via --set-credential= must have been encrypted and
# placed next to the UKI, and must be referenced as 'extra' from the entry.
UKI_DIR="$(dirname "$ESP$UKI_PATH")"
TOKEN_DIR="$(basename "$UKI_DIR")"
test -s "$UKI_DIR/marker.cred"
grep -E "^extra /$TOKEN_DIR/marker\.cred$" "$ENTRY" >/dev/null

# Locale/keymap/timezone propagation is off, so those .cred files must NOT
# exist on the ESP.
test ! -e "$UKI_DIR/firstboot.locale.cred"
test ! -e "$UKI_DIR/firstboot.keymap.cred"
test ! -e "$UKI_DIR/firstboot.timezone.cred"

# 8) The seeded files from the fake source tree must end up in the new root.
test -f "$MNT/usr/lib/os-release"
grep '^ID=testos$' "$MNT/usr/lib/os-release" >/dev/null
