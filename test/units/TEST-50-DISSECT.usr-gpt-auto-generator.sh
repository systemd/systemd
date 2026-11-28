#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-gpt-auto-generator"
WORK_DIR="$(mktemp --directory /var/tmp/test-gpt-auto-generator.XXXXXX)"
DEFINITIONS="$WORK_DIR/definitions"
IMAGE="$WORK_DIR/image.raw"
OUTPUT="$WORK_DIR/output"
OUTPUT_SYMLINK="$WORK_DIR/output-symlink"
ROOT="$WORK_DIR/root"
LOOP=""

at_exit() {
    set +e

    if [[ -n "$LOOP" ]]; then
        losetup --detach "$LOOP"
    fi

    rm -rf "$WORK_DIR"
}

trap at_exit EXIT

test -x "$GENERATOR_BIN"
mkdir -p "$DEFINITIONS" "$OUTPUT"/{normal,early,late} "$OUTPUT_SYMLINK"/{normal,early,late} "$ROOT"

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
udevadm wait --timeout=60 --settle --initialized=no "$LOOP"p1 "$LOOP"p2

# Recreate a root=tmpfs system whose /usr/ is backed by a GPT partition and overlaid by systemd-sysext.
# Run the generator as PID 1 because generators deliberately do nothing in containers.
# Takes the output directory and whether to make /home a symlink to /var/home.
run_generator() {
    rm -rf "$WORK_DIR/usr-upper" "$WORK_DIR/usr-work"

    unshare --mount --pid --fork --mount-proc \
        bash -euxo pipefail -s -- "$ROOT" "$1" "$WORK_DIR" "$LOOP" "$GENERATOR_BIN" "$2" <<'EOF'
mount --make-rprivate /

mount --types tmpfs tmpfs "$1"
mkdir -p "$1"/{dev,proc,run/generator-output,sys,usr}
mount --bind /dev "$1/dev"
mount --bind /proc "$1/proc"
mount --bind /sys "$1/sys"
mount --bind "$2" "$1/run/generator-output"

if [[ "$6" == yes ]]; then
    mkdir -p "$1/var/home"
    ln -s var/home "$1/home"
fi

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
cat "/sys/class/block/${4##*/}p1/dev" >"$1/usr/.systemd-sysext/backing"

export container=
export SYSTEMD_IN_INITRD=0
export SYSTEMD_PROC_CMDLINE="root=tmpfs systemd.gpt_auto=yes"
exec chroot "$1" "$5" \
    /run/generator-output/normal \
    /run/generator-output/early \
    /run/generator-output/late
EOF
}

run_generator "$OUTPUT" no

test -f "$OUTPUT/late/home.mount"
test "$(sed -n 's/^Where=//p' "$OUTPUT/late/home.mount")" = "/home"
(! grep -F "# Canonicalized" "$OUTPUT/late/home.mount" >/dev/null)
WHAT="$(sed -n 's/^What=//p' "$OUTPUT/late/home.mount")"
test "$(readlink --canonicalize "$WHAT")" = "$(readlink --canonicalize "${LOOP}p2")"

# If /home is a symlink, the mount unit has to be generated for the path it points to.
run_generator "$OUTPUT_SYMLINK" yes

test ! -e "$OUTPUT_SYMLINK/late/home.mount"
test -f "$OUTPUT_SYMLINK/late/var-home.mount"
test "$(sed -n 's/^Where=//p' "$OUTPUT_SYMLINK/late/var-home.mount")" = "/var/home"
grep -Fx "# Canonicalized from /home" "$OUTPUT_SYMLINK/late/var-home.mount" >/dev/null
WHAT="$(sed -n 's/^What=//p' "$OUTPUT_SYMLINK/late/var-home.mount")"
test "$(readlink --canonicalize "$WHAT")" = "$(readlink --canonicalize "${LOOP}p2")"
