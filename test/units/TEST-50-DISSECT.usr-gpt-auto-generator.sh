#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-gpt-auto-generator"
WORK_DIR="$(mktemp --directory /var/tmp/test-gpt-auto-generator.XXXXXX)"
DEFINITIONS="$WORK_DIR/definitions"
IMAGE="$WORK_DIR/image.raw"
OUTPUT="$WORK_DIR/output"
ROOT="$WORK_DIR/root"
LOOP=""
DM_DEVICES=()

at_exit() {
    set +e

    for device in "${DM_DEVICES[@]}"; do
        dmsetup remove "$device"
    done

    if [[ -n "$LOOP" ]]; then
        losetup --detach "$LOOP"
        udevadm settle --timeout=60 || true
    fi

    rm -rf "$WORK_DIR"
}

trap at_exit EXIT

test -x "$GENERATOR_BIN"
mkdir -p "$DEFINITIONS" "$OUTPUT"/{normal,early,late} "$ROOT"

cat >"$DEFINITIONS/10-usr.conf" <<EOF
[Partition]
Type=usr
SizeMinBytes=10M
SizeMaxBytes=10M
EOF

cat >"$DEFINITIONS/20-home.conf" <<EOF
[Partition]
Type=home
SizeMinBytes=10M
SizeMaxBytes=10M
EOF

systemd-repart \
    --definitions="$DEFINITIONS" \
    --empty=create \
    --size=32M \
    --dry-run=no \
    --offline=yes \
    "$IMAGE"

LOOP="$(losetup --show --find --partscan "$IMAGE")"
udevadm wait --timeout=60 --settle "$LOOP"p1 "$LOOP"p2

# Put two device mapper layers on top of the /usr/ partition, so the test requires recursive lookup of the
# originating block device.
SECTORS="$(blockdev --getsz "$LOOP"p1)"
DM_INNER="test-gpt-auto-generator-${WORK_DIR##*.}-inner"
DM_OUTER="test-gpt-auto-generator-${WORK_DIR##*.}-outer"
dmsetup create "$DM_INNER" --table "0 $SECTORS linear ${LOOP}p1 0"
DM_DEVICES+=("$DM_INNER")
udevadm wait --timeout=60 --settle "/dev/mapper/$DM_INNER"
dmsetup create "$DM_OUTER" --table "0 $SECTORS linear /dev/mapper/$DM_INNER 0"
DM_DEVICES=("$DM_OUTER" "${DM_DEVICES[@]}")
udevadm wait --timeout=60 --settle "/dev/mapper/$DM_OUTER"
BACKING_DEVNUM="$(lsblk --noheadings --nodeps --raw --output MAJ:MIN "/dev/mapper/$DM_OUTER")"

# Recreate a root=tmpfs system whose /usr/ is backed by the stacked GPT partition and overlaid by
# systemd-sysext.
# Run the generator as PID 1 because generators deliberately do nothing in containers.
unshare --mount --pid --fork --mount-proc \
    bash -euxo pipefail -s -- "$ROOT" "$OUTPUT" "$WORK_DIR" "$BACKING_DEVNUM" "$GENERATOR_BIN" <<'EOF'
mount --make-rprivate /

mount --types tmpfs tmpfs "$1"
mkdir -p "$1"/{dev,proc,run/generator-output,sys,usr}
mount --bind /dev "$1/dev"
mount --bind /proc "$1/proc"
mount --bind /sys "$1/sys"
mount --bind "$2" "$1/run/generator-output"

mkdir -p "$3/usr-upper" "$3/usr-work"
mount --types overlay overlay \
    --options lowerdir=/usr,upperdir="$3/usr-upper",workdir="$3/usr-work" \
    "$1/usr"

for directory in bin lib lib64 sbin; do
    if [[ -e "/$directory" ]]; then
        mkdir -p "$1/$directory"
        mount --bind "/$directory" "$1/$directory"
    fi
done

mkdir -p "$1/usr/.systemd-sysext"
findmnt --noheadings --raw --output MAJ:MIN --target "$1/usr" >"$1/usr/.systemd-sysext/dev"
echo "$4" >"$1/usr/.systemd-sysext/backing"

export container=
export SYSTEMD_IN_INITRD=0
export SYSTEMD_PROC_CMDLINE="root=tmpfs systemd.gpt_auto=yes"
exec chroot "$1" "$5" \
    /run/generator-output/normal \
    /run/generator-output/early \
    /run/generator-output/late
EOF

test -f "$OUTPUT/late/home.mount"
WHAT="$(sed -n 's/^What=//p' "$OUTPUT/late/home.mount")"
test "$(readlink --canonicalize "$WHAT")" = "$(readlink --canonicalize "${LOOP}p2")"
