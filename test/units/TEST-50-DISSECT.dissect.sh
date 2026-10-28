#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235,SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

. /etc/os-release
if [[ "${ID_LIKE:-}" == alpine ]]; then
    # Alpine/Nura builds libdevmapper and so on without systemd support, and seems to not wait for
    # uevents for dm-X devices being processed by systemd-udevd. That causes a significant issue in
    # dissect-image.c especially when multiple dm-X devices are activated/deactivated in parallel.
    exit 0
fi

systemd-dissect --json=short "$MINIMAL_IMAGE.raw" | \
    grep -F '{"rw":"ro","designator":"root","partition_uuid":null,"partition_label":null,"fstype":"squashfs","architecture":null,"verity":"external"' >/dev/null
systemd-dissect --json=short "$MINIMAL_IMAGE.raw" | grep -F '"size":' >/dev/null
systemd-dissect "$MINIMAL_IMAGE.raw" | grep -F "MARKER=1" >/dev/null
# shellcheck disable=SC2153
systemd-dissect "$MINIMAL_IMAGE.raw" | grep -F -f <(sed 's/"//g' "$OS_RELEASE") >/dev/null

systemd-dissect --list "$MINIMAL_IMAGE.raw" | grep '^etc/os-release$' >/dev/null
systemd-dissect --mtree "$MINIMAL_IMAGE.raw" --mtree-hash yes | \
    grep -E "^.(/usr|)/bin/bash type=file mode=0755 uid=0 gid=0 size=[0-9]* sha256sum=[a-z0-9]*$" >/dev/null
systemd-dissect --mtree "$MINIMAL_IMAGE.raw" --mtree-hash no  | \
    grep -E "^.(/usr|)/bin/bash type=file mode=0755 uid=0 gid=0 size=[0-9]*$" >/dev/null

read -r SHA256SUM1 _ < <(systemd-dissect --copy-from "$MINIMAL_IMAGE.raw" etc/os-release | sha256sum)
test "$SHA256SUM1" != ""
read -r SHA256SUM2 _ < <(systemd-dissect --read-only --with "$MINIMAL_IMAGE.raw" sha256sum etc/os-release)
test "$SHA256SUM2" != ""
test "$SHA256SUM1" = "$SHA256SUM2"

if systemctl --version | grep -F -- "+LIBARCHIVE"  >/dev/null; then
    # Make sure tarballs are reproducible
    read -r SHA256SUM1 _ < <(systemd-dissect --make-archive "$MINIMAL_IMAGE.raw" | sha256sum)
    test "$SHA256SUM1" != ""
    read -r SHA256SUM2 _ < <(systemd-dissect --make-archive "$MINIMAL_IMAGE.raw" | sha256sum)
    test "$SHA256SUM2" != ""
    test "$SHA256SUM1" = "$SHA256SUM2"
    # Also check that a file we expect to be there is there
    systemd-dissect --make-archive "$MINIMAL_IMAGE.raw" | tar t | grep etc/os-release
fi

mv "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE.fooverity"
mv "$MINIMAL_IMAGE.roothash" "$MINIMAL_IMAGE.foohash"
systemd-dissect "$MINIMAL_IMAGE.raw" \
                --json=short \
                --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                --verity-data="$MINIMAL_IMAGE.fooverity" | \
                grep -F '{"rw":"ro","designator":"root","partition_uuid":null,"partition_label":null,"fstype":"squashfs","architecture":null,"verity":"external"' >/dev/null
systemd-dissect "$MINIMAL_IMAGE.raw" \
                --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                --verity-data="$MINIMAL_IMAGE.fooverity" | \
                grep -F "MARKER=1" >/dev/null
systemd-dissect "$MINIMAL_IMAGE.raw" \
                --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                --verity-data="$MINIMAL_IMAGE.fooverity" | \
                grep -F -f <(sed 's/"//g' "$OS_RELEASE") >/dev/null
mv "$MINIMAL_IMAGE.fooverity" "$MINIMAL_IMAGE.verity"
mv "$MINIMAL_IMAGE.foohash" "$MINIMAL_IMAGE.roothash"

mkdir -p "$IMAGE_DIR/mount" "$IMAGE_DIR/mount2"
# systemd-dissect --umount of one mount of a shared verity device leaves the loop devices under the verity device
# alone, since another mount still uses the verity device.
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount2"
test "$(findmnt -n -o MAJ:MIN "$IMAGE_DIR/mount2")" = "$(findmnt -n -o MAJ:MIN "$IMAGE_DIR/mount")"
systemd-dissect --umount "$IMAGE_DIR/mount2"
for loop in $(dmsetup deps -o blkdevname "$MINIMAL_IMAGE_ROOTHASH-verity" | grep -o 'loop[0-9]*'); do
    blockdev --getsize64 "/dev/$loop" >/dev/null
done
systemd-dissect --umount "$IMAGE_DIR/mount"
# The kernel removes the verity device some time after the last mount is gone. The next test mounts the image with
# a signature and checks that the kernel validated it. That check fails if the test reuses the device set up
# here without a signature.
timeout 60 bash -c 'while dmsetup info "$1" &>/dev/null; do sleep 0.1; done' bash "$MINIMAL_IMAGE_ROOTHASH-verity"
SYSTEMD_VERITY_SHARING=1 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/usr/lib/os-release"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/etc/os-release"
grep -q -F "MARKER=1" "$IMAGE_DIR/mount/usr/lib/os-release"
# Verity volume should be shared (opened only once)
SYSTEMD_VERITY_SHARING=1 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount2"
verity_count=$(find /dev/mapper/ -name "*verity*" | wc -l)
# In theory we should check that count is exactly one. In practice, libdevmapper
# randomly and unpredictably fails with an unhelpful EINVAL when a device is open
# (and even mounted and in use), so best-effort is the most we can do for now
if [[ "$verity_count" -lt 1 ]]; then
    echo "Verity device $MINIMAL_IMAGE.raw not found in /dev/mapper/"
    exit 1
fi
# Ensure the kernel is verifying the signature if the mkosi key is in the keyring
if [ "$VERITY_SIG_SUPPORTED" -eq 1 ]; then
    veritysetup status "$(cat "$MINIMAL_IMAGE.roothash")-verity" | grep "verified (with signature)" >/dev/null
fi
systemd-dissect --umount "$IMAGE_DIR/mount"
systemd-dissect --umount "$IMAGE_DIR/mount2"

# A shared verity device is reused even if its symlink in /dev/mapper/ doesn't exist, for example because udev
# hasn't processed the device yet. If the kernel can't validate the signature of the image, a device without a
# validated signature isn't reused for an image with a signature, so we ignore the signature.
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
udevadm wait --timeout=60 --settle "/dev/mapper/$MINIMAL_IMAGE_ROOTHASH-verity"
rm "/dev/mapper/$MINIMAL_IMAGE_ROOTHASH-verity"
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount2"
test "$(findmnt -n -o MAJ:MIN "$IMAGE_DIR/mount2")" = "$(findmnt -n -o MAJ:MIN "$IMAGE_DIR/mount")"
systemd-dissect --umount "$IMAGE_DIR/mount"
systemd-dissect --umount "$IMAGE_DIR/mount2"

# Verity devices also work if /dev isn't a devtmpfs and udev doesn't run, for example in a container.
# libdevmapper then creates /dev/mapper/control and the nodes in /dev/mapper/ itself. DM_DISABLE_UDEV=1
# makes libdevmapper behave as if udev doesn't run. The tmpfs on /dev only contains /dev/null, /dev/random,
# /dev/urandom and the nodes of the two loop devices.
data_loop="$(losetup --show -f -r "$MINIMAL_IMAGE.raw")"
hash_loop="$(losetup --show -f -r "$MINIMAL_IMAGE.verity")"
udevadm wait --timeout=60 --settle "$data_loop" "$hash_loop"
unshare --mount bash -euxc '
    data_devnum="$(stat -c "%t %T" "$1")"
    hash_devnum="$(stat -c "%t %T" "$2")"
    mount -t tmpfs tmpfs /dev
    mknod /dev/null c 1 3
    mknod /dev/random c 1 8
    mknod /dev/urandom c 1 9
    read -r major minor <<<"$data_devnum"
    mknod "$1" b "$((16#$major))" "$((16#$minor))"
    read -r major minor <<<"$hash_devnum"
    mknod "$2" b "$((16#$major))" "$((16#$minor))"
    DM_DISABLE_UDEV=1 SYSTEMD_VERITY_SHARING=1 \
        systemd-dissect --mtree "$1" --root-hash="$MINIMAL_IMAGE_ROOTHASH" --verity-data="$2" >/dev/null
' bash "$data_loop" "$hash_loop"
losetup -d "$data_loop" "$hash_loop"

# The hex encoding of a SHA-512 root hash doesn't fit in the name of a shared verity device, so the device
# isn't shared.
veritysetup format --hash=sha512 "$MINIMAL_IMAGE.raw" /tmp/test-50-sha512.verity \
                   --root-hash-file /tmp/test-50-sha512.roothash
SYSTEMD_VERITY_SHARING=1 systemd-dissect --mtree "$MINIMAL_IMAGE.raw" \
                                         --root-hash="$(</tmp/test-50-sha512.roothash)" \
                                         --verity-data=/tmp/test-50-sha512.verity 2>&1 >/dev/null | \
    grep -F "Root hash is too long for the name of a shared verity device" >/dev/null
rm /tmp/test-50-sha512.verity /tmp/test-50-sha512.roothash

# The tests below set up the shared verity device of $MINIMAL_IMAGE themselves. A device left over from an
# earlier test can still exist, for example until its deferred removal finished. We look it up with dmsetup,
# since some tests remove its symlink in /dev/mapper/.
wait_for_shared_verity_device_removal() {
    timeout 60 bash -c "while dmsetup info $MINIMAL_IMAGE_ROOTHASH-verity &>/dev/null; do sleep .1; done"
}

# libcryptsetup can leave the data device path unset when its /dev/dm-N node has no aliases. The activator
# must still request deferred removal of its verity device before exiting.
wait_for_shared_verity_device_removal
data_loop="$(losetup --show -f -r "$MINIMAL_IMAGE.raw")"
hash_loop="$(losetup --show -f -r "$MINIMAL_IMAGE.verity")"
udevadm wait --timeout=60 --settle "$data_loop" "$hash_loop"
dmsetup create --readonly test-50-data --table "0 $(blockdev --getsz "$data_loop") linear $data_loop 0"
data_node="$(readlink -f /dev/mapper/test-50-data)"
unshare --mount bash -euxc '
    data_devnum="$(stat -c "%t %T" "$1")"
    hash_devnum="$(stat -c "%t %T" "$2")"
    mount -t tmpfs tmpfs /dev
    mknod /dev/null c 1 3
    mknod /dev/random c 1 8
    mknod /dev/urandom c 1 9
    read -r major minor <<<"$data_devnum"
    mknod "$1" b "$((16#$major))" "$((16#$minor))"
    read -r major minor <<<"$hash_devnum"
    mknod "$2" b "$((16#$major))" "$((16#$minor))"
    DM_DISABLE_UDEV=1 SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
        systemd-dissect --mtree "$1" --root-hash="$MINIMAL_IMAGE_ROOTHASH" --verity-data="$2" >/dev/null
' bash "$data_node" "$hash_loop"
wait_for_shared_verity_device_removal
dmsetup remove test-50-data
losetup -d "$data_loop" "$hash_loop"

# libcryptsetup before 2.7.4 opens the data device of a verity device exclusively, even with
# CRYPT_ACTIVATE_SHARED. With such a version, setting up a verity device on a block device that another verity
# device already maps fails.
if systemd-analyze compare-versions "$(cryptsetup --version | cut -d' ' -f2)" ge 2.7.4; then
    VERITY_SHARED_DATA_DEVICE=1
else
    VERITY_SHARED_DATA_DEVICE=0
fi

# A shared verity device can be set up on a block device that another verity device already maps. If the shared
# device from an earlier test still exists, systemd-dissect reuses it instead of setting up a device on the
# block device.
if [[ "$VERITY_SHARED_DATA_DEVICE" -eq 1 ]]; then
    wait_for_shared_verity_device_removal
    loop="$(losetup --show -f -r "$MINIMAL_IMAGE.raw")"
    udevadm wait --timeout=60 --settle "$loop"
    veritysetup open "$loop" test-50-other "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE_ROOTHASH"
    SYSTEMD_VERITY_SHARING=1 systemd-dissect --mtree "$loop" \
                                             --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                             --verity-data="$MINIMAL_IMAGE.verity" >/dev/null
    veritysetup close test-50-other
    losetup -d "$loop"
fi

# Ensure the deferred close flag is set up correctly and we don't leak verity devices
# when sharing is disabled
# The devices are named 'loopXYZ-verity' when sharing is disabled
SYSTEMD_VERITY_SHARING=0 systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
d=""
for f in /dev/mapper/*; do
    if [[ "$(basename "$f")" =~ ^loop.*-verity ]] && veritysetup status "$(basename "$f")" | grep "$MINIMAL_IMAGE.raw" >/dev/null; then
        d="$f"
        break
    fi
done
test -n "$d"
dmsetup ls | grep "$(basename "$d")" >/dev/null
umount -R "$IMAGE_DIR/mount"
timeout 60 bash -c "while test -e $d; do sleep 0.1; done"
( ! dmsetup ls | grep "$(basename "$d")") >/dev/null

# A process that reuses a verity device leaves the device alone when it's done. Only the process that activated
# the device requests its removal. veritysetup didn't request deferred removal of the device, so the device must
# not have deferred removal set after systemd-dissect exits.
wait_for_shared_verity_device_removal
veritysetup open "$MINIMAL_IMAGE.raw" "$MINIMAL_IMAGE_ROOTHASH-verity" "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE_ROOTHASH"
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
    systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
test "$(findmnt -n -o MAJ:MIN "$IMAGE_DIR/mount")" = \
     "$(dmsetup info -c --noheadings -o major,minor "$MINIMAL_IMAGE_ROOTHASH-verity")"
systemd-dissect --umount "$IMAGE_DIR/mount"
dmsetup info "$MINIMAL_IMAGE_ROOTHASH-verity" >/var/tmp/test-50-info
(! grep -F "DEFERRED REMOVE" /var/tmp/test-50-info)
rm /var/tmp/test-50-info
veritysetup close "$MINIMAL_IMAGE_ROOTHASH-verity"

# A mount can use a unique device if a concurrent activator doesn't finish before its retries expire.
# We activate the shared device first so every concurrent mount can reuse it.
concurrent_dir="$(mktemp -d /var/tmp/test-50-concurrent.XXXXXXXXXX)"
mkdir "$concurrent_dir"/{0..7}
for _ in {1..3}; do
    wait_for_shared_verity_device_removal
    SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
        systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$concurrent_dir/0"
    devnum="$(findmnt -n -o MAJ:MIN "$concurrent_dir/0")"
    pids=()
    for i in {1..7}; do
        (
            timeout 60 bash -c 'until test -e "$1/start"; do sleep .01; done' bash "$concurrent_dir"
            SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
                systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$concurrent_dir/$i"
        ) &
        pids+=("$!")
    done
    touch "$concurrent_dir/start"
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    rm "$concurrent_dir/start"
    for i in {1..7}; do
        test "$(findmnt -n -o MAJ:MIN "$concurrent_dir/$i")" = "$devnum"
    done
    pids=()
    for i in {1..7}; do
        systemd-dissect --umount "$concurrent_dir/$i" &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    grep -F 'MARKER=1' "$concurrent_dir/0/usr/lib/os-release" >/dev/null
    test "$(findmnt -n -o MAJ:MIN "$concurrent_dir/0")" = "$devnum"
    systemd-dissect --umount "$concurrent_dir/0"
    wait_for_shared_verity_device_removal
done
rmdir "$concurrent_dir"/{0..7} "$concurrent_dir"

# A process that activates a verity device requests deferred removal of the device as soon as it opened it, so
# the device is removed even if the process gets killed. systemd-nspawn keeps the image until it exits and never
# relinquishes it. Without the request after the open, the device only gets deferred removal set when
# systemd-nspawn exits normally.
wait_for_shared_verity_device_removal
systemd-run --unit=test-50-nspawn.service \
            systemd-nspawn --pipe --register=no --keep-unit --image="$MINIMAL_IMAGE.raw" --read-only sleep infinity
timeout 60 bash -c "until dmsetup info $MINIMAL_IMAGE_ROOTHASH-verity 2>/dev/null | grep -F 'DEFERRED REMOVE' >/dev/null; do sleep .1; done"
systemctl kill --signal=SIGKILL test-50-nspawn.service
wait_for_shared_verity_device_removal
systemctl reset-failed test-50-nspawn.service

# A signature that can't be validated only prevents activation if the image policy allows "signed" but not
# "verity". Userspace validation only parses the signature if a certificate is installed. Without one, it
# reports a mismatch instead of failing on the garbage signature. The test image usually contains
# /usr/lib/verity.d/mkosi.crt, but we install a certificate in /run/verity.d/ to be sure.
mkdir -p /run/verity.d
cp /usr/share/mkosi.crt /run/verity.d/test-50-mkosi.crt
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test-50-unknown \
            -keyout /tmp/test-50-unknown.key -out /tmp/test-50-unknown.crt
openssl smime -sign -nocerts -noattr -binary \
              -in "$MINIMAL_IMAGE.roothash" \
              -inkey /tmp/test-50-unknown.key \
              -signer /tmp/test-50-unknown.crt \
              -outform der \
              -out /tmp/test-50-unknown.p7s
head -c 64 /dev/urandom >/tmp/test-50-garbage.p7s
# The kernel validated the signature of a shared device, so a mount without a signature reuses the device, even if
# the policy requires a signature.
if [ "$VERITY_SIG_SUPPORTED" -eq 1 ]; then
    mkdir -p /tmp/test-50-validated-mnt /tmp/test-50-reuse-mnt
    SYSTEMD_VERITY_SHARING=1 systemd-dissect --mount --image-policy=root=signed \
                                             "$MINIMAL_IMAGE.raw" /tmp/test-50-validated-mnt
    SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
        systemd-dissect --mount --image-policy=root=signed "$MINIMAL_IMAGE.raw" /tmp/test-50-reuse-mnt
    test "$(findmnt -n -o MAJ:MIN /tmp/test-50-reuse-mnt)" = "$(findmnt -n -o MAJ:MIN /tmp/test-50-validated-mnt)"
    systemd-dissect --umount /tmp/test-50-reuse-mnt
    systemd-dissect --umount /tmp/test-50-validated-mnt
    rmdir /tmp/test-50-validated-mnt /tmp/test-50-reuse-mnt
fi
for sig in /tmp/test-50-unknown.p7s /tmp/test-50-garbage.p7s; do
    SYSTEMD_VERITY_SHARING=0 systemd-dissect --mtree "$MINIMAL_IMAGE.raw" \
                                             --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                             --root-hash-sig="$sig" >/dev/null
    SYSTEMD_VERITY_SHARING=0 systemd-dissect --mtree "$MINIMAL_IMAGE.raw" \
                                             --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                             --root-hash-sig="$sig" \
                                             --image-policy=root=verity+signed >/dev/null
    # Every signature that no trusted key validates is reported the same way, whether the kernel has no key for
    # it or rejects it for another reason, for example because it is garbage.
    (! SYSTEMD_VERITY_SHARING=0 systemd-dissect --mtree "$MINIMAL_IMAGE.raw" \
                                                --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                                --root-hash-sig="$sig" \
                                                --image-policy=root=signed 2>&1 >/dev/null) |
        grep -F "Image lacks recognized signature." >/dev/null
done
# A service whose policy requires a signature fails if no trusted key validates its signature, instead of
# reusing a shared Verity device that was set up without a signature. Once a certificate for the signature is
# installed, the service works.
mkdir -p /tmp/test-50-unsigned-mnt
timeout 60 bash -c 'while dmsetup info "$1" &>/dev/null; do sleep 0.1; done' bash "$MINIMAL_IMAGE_ROOTHASH-verity"
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
    systemd-dissect --mount --image-policy=root=verity+signed "$MINIMAL_IMAGE.raw" /tmp/test-50-unsigned-mnt
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.raw" \
               -p RootHashSignature=/tmp/test-50-unknown.p7s \
               -p RootImagePolicy=root=signed+squashfs \
               true)
cp /tmp/test-50-unknown.crt /run/verity.d/test-50-unknown.crt
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootHashSignature=/tmp/test-50-unknown.p7s \
            -p RootImagePolicy=root=signed+squashfs \
            true
# If only userspace validates our signature, a device that we set up ourselves wouldn't have a validated
# signature either, so we reuse the shared device, even if the policy requires a signature.
mkdir -p /tmp/test-50-signed-mnt
for policy in root=verity+signed root=signed; do
    SYSTEMD_VERITY_SHARING=1 systemd-dissect --mount --image-policy="$policy" \
                                             --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                             --root-hash-sig=/tmp/test-50-unknown.p7s \
                                             "$MINIMAL_IMAGE.raw" /tmp/test-50-signed-mnt
    test "$(findmnt -n -o MAJ:MIN /tmp/test-50-signed-mnt)" = "$(findmnt -n -o MAJ:MIN /tmp/test-50-unsigned-mnt)"
    systemd-dissect --umount /tmp/test-50-signed-mnt
done
loop="$(losetup --find --show --read-only "$MINIMAL_IMAGE.raw")"
name="${loop##*/}"
if [ -e "/sys/class/block/$name/diskseq" ]; then
    name+="-$(cat "/sys/class/block/$name/diskseq")"
fi
name+="-verity"
veritysetup open "$loop" "$name" "$MINIMAL_IMAGE.verity" --root-hash-file "$MINIMAL_IMAGE.roothash"
mkdir -p /var/tmp/test-50-noshare-mnt
mount -o ro "/dev/mapper/$name" /var/tmp/test-50-noshare-mnt
SYSTEMD_VERITY_SHARING=0 systemd-dissect --mtree "$loop" \
                                      --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                      --verity-data="$MINIMAL_IMAGE.verity" \
                                      --image-policy=root=verity >/dev/null
for policy in root=verity+signed root=signed; do
    (! SYSTEMD_VERITY_SHARING=0 systemd-dissect --mtree "$loop" \
                                             --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                             --root-hash-sig=/tmp/test-50-unknown.p7s \
                                             --verity-data="$MINIMAL_IMAGE.verity" \
                                             --image-policy="$policy" >/dev/null)
done
dmsetup remove --deferred "$name"
umount /var/tmp/test-50-noshare-mnt
rmdir /var/tmp/test-50-noshare-mnt
losetup --detach "$loop"
# We only reuse a device without a validated signature if it uses our backing file. The owner of another copy of
# the image can modify that copy.
systemd-dissect --umount /tmp/test-50-unsigned-mnt
timeout 60 bash -c 'while dmsetup info "$1" &>/dev/null; do sleep 0.1; done' bash "$MINIMAL_IMAGE_ROOTHASH-verity"
cp "$MINIMAL_IMAGE.raw" /tmp/test-50-copy.raw
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
    systemd-dissect --mount --image-policy=root=verity+signed \
                    --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                    --verity-data="$MINIMAL_IMAGE.verity" \
                    /tmp/test-50-copy.raw /tmp/test-50-unsigned-mnt
SYSTEMD_VERITY_SHARING=1 systemd-dissect --mount --image-policy=root=signed \
                                         --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                         --root-hash-sig=/tmp/test-50-unknown.p7s \
                                         "$MINIMAL_IMAGE.raw" /tmp/test-50-signed-mnt
test "$(findmnt -n -o MAJ:MIN /tmp/test-50-signed-mnt)" != "$(findmnt -n -o MAJ:MIN /tmp/test-50-unsigned-mnt)"
systemd-dissect --umount /tmp/test-50-signed-mnt
systemd-dissect --umount /tmp/test-50-unsigned-mnt
rm /tmp/test-50-copy.raw
timeout 60 bash -c 'while dmsetup info "$1" &>/dev/null; do sleep 0.1; done' bash "$MINIMAL_IMAGE_ROOTHASH-verity"
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
    systemd-dissect --mount --image-policy=root=verity+signed "$MINIMAL_IMAGE.raw" /tmp/test-50-unsigned-mnt
rm /run/verity.d/test-50-unknown.crt
# If the kernel validates our signature, we set up our own device instead.
if [ "$VERITY_SIG_SUPPORTED" -eq 1 ]; then
    SYSTEMD_VERITY_SHARING=1 systemd-dissect --mount --image-policy=root=verity+signed \
                                             "$MINIMAL_IMAGE.raw" /tmp/test-50-signed-mnt
    test "$(findmnt -n -o MAJ:MIN /tmp/test-50-signed-mnt)" != "$(findmnt -n -o MAJ:MIN /tmp/test-50-unsigned-mnt)"
    systemd-dissect --umount /tmp/test-50-signed-mnt
fi
rmdir /tmp/test-50-signed-mnt
systemd-dissect --umount /tmp/test-50-unsigned-mnt
rmdir /tmp/test-50-unsigned-mnt
# A process that can't reuse an existing verity device leaves the device alone. Here, the process can't reuse
# the device because the device was activated without a signature, and the image policy requires a signature
# that neither the kernel nor userspace validates.
wait_for_shared_verity_device_removal
veritysetup open "$MINIMAL_IMAGE.raw" "$MINIMAL_IMAGE_ROOTHASH-verity" "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE_ROOTHASH"
(! SYSTEMD_VERITY_SHARING=1 systemd-dissect --mtree "$MINIMAL_IMAGE.raw" \
                                            --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                            --root-hash-sig=/tmp/test-50-unknown.p7s \
                                            --image-policy=root=signed >/dev/null)
veritysetup status "$MINIMAL_IMAGE_ROOTHASH-verity" >/dev/null
veritysetup close "$MINIMAL_IMAGE_ROOTHASH-verity"
# If we can't reuse a shared verity device, we activate a device with a unique name on the same data device
# instead. Here, we can't reuse the device because it has our name but uses a hash tree with a different salt,
# and hence a different root hash.
if [[ "$VERITY_SHARED_DATA_DEVICE" -eq 1 ]]; then
    veritysetup format --salt=0123456789abcdef "$MINIMAL_IMAGE.raw" /tmp/test-50-salt.verity \
                       --root-hash-file /tmp/test-50-salt.roothash
    loop="$(losetup --show -f -r "$MINIMAL_IMAGE.raw")"
    udevadm wait --timeout=60 --settle "$loop"
    veritysetup open "$loop" "$MINIMAL_IMAGE_ROOTHASH-verity" /tmp/test-50-salt.verity "$(</tmp/test-50-salt.roothash)"
    SYSTEMD_VERITY_SHARING=1 systemd-dissect --mtree "$loop" \
                                             --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                                             --verity-data="$MINIMAL_IMAGE.verity" >/dev/null
    veritysetup close "$MINIMAL_IMAGE_ROOTHASH-verity"
    losetup -d "$loop"
    rm /tmp/test-50-salt.verity /tmp/test-50-salt.roothash
fi
rm /run/verity.d/test-50-mkosi.crt /tmp/test-50-unknown.key /tmp/test-50-unknown.crt /tmp/test-50-unknown.p7s /tmp/test-50-garbage.p7s

# A blocked PCR measurement must not prevent deferred removal when the activating process dies.
run_with_blocked_pcrextend() {
    unshare --mount bash -euxc '
        mount -t tmpfs tmpfs /run/systemd
        socat UNIX-LISTEN:/run/systemd/io.systemd.PCRExtend,fork \
              SYSTEM:"touch /var/tmp/test-50-race/connected; while test ! -e /var/tmp/test-50-race/go; do sleep .1; done" &
        socat_pid=$!
        trap "kill $socat_pid" EXIT
        timeout 60 bash -c "until test -S /run/systemd/io.systemd.PCRExtend; do sleep .1; done"
        "$@"
    ' bash "$@"
}

if systemctl --version | grep -F -- "+TPM2" >/dev/null; then
    mkdir -p /var/tmp/test-50-race
    wait_for_shared_verity_device_removal
    run_with_blocked_pcrextend bash -euxc '
        echo "$$" >/var/tmp/test-50-race/pid
        exec env SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 systemd-dissect --mtree "$1" >/dev/null
    ' bash "$MINIMAL_IMAGE.raw" &
    pid=$!
    timeout 60 bash -c "until test -e /var/tmp/test-50-race/connected; do sleep .1; done"
    dmsetup info "$MINIMAL_IMAGE_ROOTHASH-verity" | grep -F 'DEFERRED REMOVE' >/dev/null
    (! veritysetup close "$MINIMAL_IMAGE_ROOTHASH-verity")
    SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
        systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
    test "$(findmnt -n -o MAJ:MIN "$IMAGE_DIR/mount")" = \
         "$(dmsetup info -c --noheadings -o major,minor "$MINIMAL_IMAGE_ROOTHASH-verity")"
    kill -KILL "$(</var/tmp/test-50-race/pid)"
    touch /var/tmp/test-50-race/go
    exit_status=0
    wait "$pid" || exit_status=$?
    test "$exit_status" -eq 137
    grep -F 'MARKER=1' "$IMAGE_DIR/mount/usr/lib/os-release" >/dev/null
    systemd-dissect --umount "$IMAGE_DIR/mount"
    wait_for_shared_verity_device_removal
    rm -r /var/tmp/test-50-race
fi

# Test BindLogSockets=
systemd-run --wait -p RootImage="$MINIMAL_IMAGE.raw" mountpoint /run/systemd/journal/socket
(! systemd-run --wait -p RootImage="$MINIMAL_IMAGE.raw" -p BindLogSockets=no ls /run/systemd/journal/socket)
(! systemd-run --wait -p RootImage="$MINIMAL_IMAGE.raw" -p MountAPIVFS=no ls /run/systemd/journal/socket)

# Test that the notify socket is bind mounted to /run/host/notify in sandboxed environments and
# $NOTIFY_SOCKET is set correctly.
systemd-run \
    --wait \
    -p RootImage="$MINIMAL_IMAGE.raw" \
    -p NotifyAccess=all \
    bash -xec \
    '
        [[ "$$NOTIFY_SOCKET" == "/run/host/notify" ]]
        test -S /run/host/notify
    '
if [[ "$(findmnt -n -o FSTYPE /)" == btrfs ]]; then
    [[ -d /test-dissect-btrfs-snapshot ]] && btrfs subvolume delete /test-dissect-btrfs-snapshot
    btrfs subvolume snapshot / /test-dissect-btrfs-snapshot

    # Same test with RootDirectory=, also try to send READY=1, as we can use systemd-notify.
    systemd-run \
        --wait \
        -p RootDirectory=/test-dissect-btrfs-snapshot \
        -p NotifyAccess=all \
        --service-type=notify \
        bash -xec \
        '
            systemd-notify --pid=auto --ready
            [[ "$$NOTIFY_SOCKET" == "/run/host/notify" ]]
            test -S /run/host/notify
        '

    btrfs subvolume delete /test-dissect-btrfs-snapshot
fi

systemd-run -P -p RootImage="$MINIMAL_IMAGE.raw" cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
mv "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE.fooverity"
mv "$MINIMAL_IMAGE.roothash" "$MINIMAL_IMAGE.foohash"
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootHash="$MINIMAL_IMAGE.foohash" \
            -p RootVerity="$MINIMAL_IMAGE.fooverity" \
            -p BindLogSockets=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
# Let's use the long option name just here as a test
systemd-run -P \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            --property RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            --property RootVerity="$MINIMAL_IMAGE.fooverity" \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
mv "$MINIMAL_IMAGE.fooverity" "$MINIMAL_IMAGE.verity"
mv "$MINIMAL_IMAGE.foohash" "$MINIMAL_IMAGE.roothash"

# Derive partition UUIDs from root hash, in UUID syntax
ROOT_UUID="$(systemd-id128 -u show "$(head -c 32 "$MINIMAL_IMAGE.roothash")" -u | tail -n 1 | cut -b 6-)"
VERITY_UUID="$(systemd-id128 -u show "$(tail -c 32 "$MINIMAL_IMAGE.roothash")" -u | tail -n 1 | cut -b 6-)"
USR_UUID="$ROOT_UUID"
USR_VERITY_UUID="$VERITY_UUID"

systemd-dissect --json=short \
                --root-hash "$MINIMAL_IMAGE_ROOTHASH" \
                "$MINIMAL_IMAGE.gpt" | \
                grep '{"rw":"ro","designator":"root","partition_uuid":"'"$ROOT_UUID"'","partition_label":"Root Partition","fstype":"squashfs","architecture":"'"$ARCHITECTURE"'","verity":"signed",' >/dev/null
systemd-dissect --json=short \
                --root-hash "$MINIMAL_IMAGE_ROOTHASH" \
                "$MINIMAL_IMAGE.gpt" | \
                grep '{"rw":"ro","designator":"root-verity","partition_uuid":"'"$VERITY_UUID"'","partition_label":"Verity Partition","fstype":"DM_verity_hash","architecture":"'"$ARCHITECTURE"'","verity":null,' >/dev/null
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    systemd-dissect --json=short \
                    --root-hash "$MINIMAL_IMAGE_ROOTHASH" \
                    "$MINIMAL_IMAGE.gpt" | \
                    grep -E '{"rw":"ro","designator":"root-verity-sig","partition_uuid":"'".*"'","partition_label":"Signature Partition","fstype":"verity_hash_signature","architecture":"'"$ARCHITECTURE"'","verity":null,' >/dev/null
fi
systemd-dissect --root-hash "$MINIMAL_IMAGE_ROOTHASH" "$MINIMAL_IMAGE.gpt" | grep -F "MARKER=1" >/dev/null
systemd-dissect --root-hash "$MINIMAL_IMAGE_ROOTHASH" "$MINIMAL_IMAGE.gpt" | grep -F -f <(sed 's/"//g' "$OS_RELEASE") >/dev/null
systemd-dissect --json=short \
                --usr-hash "$MINIMAL_IMAGE_ROOTHASH" \
                "$MINIMAL_IMAGE.usr.gpt" | \
                grep '{"rw":"ro","designator":"usr","partition_uuid":"'"$USR_UUID"'","partition_label":"Usr Partition","fstype":"squashfs","architecture":"'"$ARCHITECTURE"'","verity":"signed",' >/dev/null
systemd-dissect --json=short \
                --usr-hash "$MINIMAL_IMAGE_ROOTHASH" \
                "$MINIMAL_IMAGE.usr.gpt" | \
                grep '{"rw":"ro","designator":"usr-verity","partition_uuid":"'"$USR_VERITY_UUID"'","partition_label":"Usr Verity Partition","fstype":"DM_verity_hash","architecture":"'"$ARCHITECTURE"'","verity":null,' >/dev/null
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    systemd-dissect --json=short \
                    --usr-hash "$MINIMAL_IMAGE_ROOTHASH" \
                    "$MINIMAL_IMAGE.usr.gpt" | \
                    grep -E '{"rw":"ro","designator":"usr-verity-sig","partition_uuid":"'".*"'","partition_label":"Usr Signature Partition","fstype":"verity_hash_signature","architecture":"'"$ARCHITECTURE"'","verity":null,' >/dev/null
fi

# Test image policies
systemd-dissect --validate "$MINIMAL_IMAGE.gpt"
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy='*'
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy='~')
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy='-')
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=absent)
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=swap=unprotected+encrypted+verity)
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=unprotected
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=verity
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=verity:root-verity-sig=unused+absent
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=verity:swap=absent
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=verity:swap=absent+unprotected
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=verity:root-verity=unused+absent)
systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=signed
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=signed:root-verity-sig=unused+absent)
(! systemd-dissect --validate "$MINIMAL_IMAGE.gpt" --image-policy=root=signed:root-verity=unused+absent)

# Without a root hash, Verity can't be set up, so a policy that requires Verity must refuse the image instead
# of mounting the data partition directly.
SYSTEMD_DISSECT_VERITY_EMBEDDED=0 SYSTEMD_DISSECT_VERITY_GUESS=0 systemd-dissect --mtree "$MINIMAL_IMAGE.gpt" >/dev/null
(! SYSTEMD_DISSECT_VERITY_EMBEDDED=0 SYSTEMD_DISSECT_VERITY_GUESS=0 systemd-dissect --mtree "$MINIMAL_IMAGE.gpt" --image-policy=root=verity >/dev/null)
(! SYSTEMD_DISSECT_VERITY_EMBEDDED=0 SYSTEMD_DISSECT_VERITY_GUESS=0 systemd-dissect --mtree "$MINIMAL_IMAGE.gpt" --image-policy=root=signed >/dev/null)

systemd-dissect --validate "$MINIMAL_IMAGE.usr.gpt" --image-policy=usr=verity
systemd-dissect --validate "$MINIMAL_IMAGE.usr.gpt" --image-policy=usr=verity:usr-verity-sig=unused+absent
(! systemd-dissect --validate "$MINIMAL_IMAGE.usr.gpt" --image-policy=usr=verity:usr-verity=unused+absent)
systemd-dissect --validate "$MINIMAL_IMAGE.usr.gpt" --image-policy=usr=signed
(! systemd-dissect --validate "$MINIMAL_IMAGE.usr.gpt" --image-policy=usr=signed:usr-verity-sig=unused+absent)
(! systemd-dissect --validate "$MINIMAL_IMAGE.usr.gpt" --image-policy=usr=signed:usr-verity=unused+absent)

# A signature partition that can't be parsed is ignored, unless the image policy requires a signature.
cp "$MINIMAL_IMAGE.gpt" /tmp/test-50-badsig.gpt
loop="$(losetup --show -P -f /tmp/test-50-badsig.gpt)"
udevadm wait --timeout=60 --settle --initialized=no "${loop}p3"
printf 'garbage' | udevadm lock --timeout=60 --device="${loop}p3" dd of="${loop}p3" conv=notrunc
losetup -d "$loop"
udevadm settle --timeout=60
systemd-dissect --mtree /tmp/test-50-badsig.gpt >/dev/null
systemd-dissect --mtree /tmp/test-50-badsig.gpt --root-hash="$MINIMAL_IMAGE_ROOTHASH" >/dev/null
(! systemd-dissect --mtree /tmp/test-50-badsig.gpt --image-policy=root=signed >/dev/null)
(! systemd-dissect --mtree /tmp/test-50-badsig.gpt --root-hash="$MINIMAL_IMAGE_ROOTHASH" --image-policy=root=signed >/dev/null)
(! SYSTEMD_DISSECT_VERITY_GUESS=0 systemd-dissect --mtree /tmp/test-50-badsig.gpt --image-policy=root=signed >/dev/null)
# With a root hash, the signature partition is ignored and counts as absent. "verity+signed" allows that.
systemd-dissect --mtree /tmp/test-50-badsig.gpt --root-hash="$MINIMAL_IMAGE_ROOTHASH" --image-policy=root=verity+signed >/dev/null
# Set up a shared Verity device for the same root hash without a signature. A policy that requires a
# signature must not reuse it.
mkdir -p /tmp/test-50-badsig-mnt
SYSTEMD_VERITY_SHARING=1 SYSTEMD_DISSECT_VERITY_SIGNATURE=0 \
    systemd-dissect --mount --image-policy=root=verity+signed "$MINIMAL_IMAGE.raw" /tmp/test-50-badsig-mnt
(! SYSTEMD_VERITY_SHARING=1 systemd-dissect --mtree /tmp/test-50-badsig.gpt --image-policy=root=signed >/dev/null)
systemd-dissect --umount /tmp/test-50-badsig-mnt
rmdir /tmp/test-50-badsig-mnt
rm /tmp/test-50-badsig.gpt

# Test RootImagePolicy= unit file setting
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='*' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='~' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -F "MARKER=1") >/dev/null
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='-' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -F "MARKER=1") >/dev/null
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='root=absent' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -F "MARKER=1") >/dev/null
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='root=verity' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='root=signed' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='root=signed+lol:wut=wat+signed' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
# A policy pinning a single fstype on a GPT image should still use verity.
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootImagePolicy='root=verity+squashfs' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='root=encrypted' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -F "MARKER=1") >/dev/null

systemd-dissect --root-hash "$MINIMAL_IMAGE_ROOTHASH" --mount "$MINIMAL_IMAGE.gpt" "$IMAGE_DIR/mount"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/usr/lib/os-release"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/etc/os-release"
grep -q -F "MARKER=1" "$IMAGE_DIR/mount/usr/lib/os-release"
systemd-dissect --umount "$IMAGE_DIR/mount"

systemd-dissect --root-hash "$MINIMAL_IMAGE_ROOTHASH" --mount "$MINIMAL_IMAGE.gpt" --in-memory "$IMAGE_DIR/mount"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/usr/lib/os-release"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/etc/os-release"
grep -q -F "MARKER=1" "$IMAGE_DIR/mount/usr/lib/os-release"
systemd-dissect --umount "$IMAGE_DIR/mount"

# add explicit -p MountAPIVFS=yes once to test the parser
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootImageOptions="root:noatime,dev home:ro,dev ro,nosuid" \
            mount | grep -F "squashfs" | grep -F "nosuid" >/dev/null
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootImageOptions="root:ro,dev root:ro,noatime" \
            mount | grep -F "squashfs" | grep -F "noatime" >/dev/null

mkdir -p "$IMAGE_DIR/result"
cat >/run/systemd/system/testservice-50a.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "mount >/run/result/a"
BindPaths=$IMAGE_DIR/result:/run/result
TemporaryFileSystem=/run
RootImage=$MINIMAL_IMAGE.raw
RootImageOptions=root:relatime,dev home:ro,dev nosuid,dev
RootImageOptions=ro,noatime
EOF
systemctl start testservice-50a.service
grep -F "squashfs" "$IMAGE_DIR/result/a" | grep -F "noatime" >/dev/null
grep -F "squashfs" "$IMAGE_DIR/result/a" | grep -F -v "nosuid" >/dev/null

cat >/run/systemd/system/testservice-50b.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "mount >/run/result/b"
BindPaths=$IMAGE_DIR/result:/run/result
TemporaryFileSystem=/run
RootImage=$MINIMAL_IMAGE.gpt
RootImageOptions=nosuid,dev home:ro,dev nosuid,dev
RootImageOptions=home:ro,dev,%%foo root:ro,noatime,nosuid
# this is the default, but let's specify once to test the parser
MountAPIVFS=yes
EOF
systemctl start testservice-50b.service
grep -F "squashfs" "$IMAGE_DIR/result/b" | grep -F "noatime" >/dev/null

# Check that specifier escape is applied %%foo → %foo
busctl get-property org.freedesktop.systemd1 \
                    /org/freedesktop/systemd1/unit/testservice_2d50b_2eservice \
                    org.freedesktop.systemd1.Service RootImageOptions | grep -F "ro,dev,%foo"

# Now do some checks with MountImages, both by itself, with options and in combination with RootImage, and as single FS or GPT image
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img1/usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img2/usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2:nosuid,dev" \
            mount | grep -F "squashfs" | grep -F "nosuid" >/dev/null
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1:root:nosuid $MINIMAL_IMAGE.raw:/run/img2:home:suid" \
            mount | grep -F "squashfs" | grep -F "nosuid" >/dev/null
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.raw:/run/img2\:3" \
            cat /run/img2:3/usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.raw:/run/img2\:3:nosuid" \
            mount | grep -F "squashfs" | grep -F "nosuid" >/dev/null
systemd-run -P \
            -p TemporaryFileSystem=/run \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p TemporaryFileSystem=/run \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img1/usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p TemporaryFileSystem=/run \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img2/usr/lib/os-release | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.raw:/run/img2" \
            veritysetup status "${MINIMAL_IMAGE_ROOTHASH}-verity" | grep "${MINIMAL_IMAGE_ROOTHASH}" >/dev/null
cat >/run/systemd/system/testservice-50c.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run
RootImage=$MINIMAL_IMAGE.raw
MountImages=$MINIMAL_IMAGE.gpt:/run/img1:root:noatime:home:relatime
MountImages=$MINIMAL_IMAGE.raw:/run/img2\:3:nosuid
ExecStart=bash -c "cat /run/img1/usr/lib/os-release >/run/result/c"
ExecStart=bash -c "cat /run/img2:3/usr/lib/os-release >>/run/result/c"
ExecStart=bash -c "mount >>/run/result/c"
BindPaths=$IMAGE_DIR/result:/run/result
Type=oneshot
EOF
systemctl start testservice-50c.service
grep -q -F "MARKER=1" "$IMAGE_DIR/result/c"
grep -F "squashfs" "$IMAGE_DIR/result/c" | grep -F "noatime" >/dev/null
grep -F "squashfs" "$IMAGE_DIR/result/c" | grep -F -v "nosuid" >/dev/null

# Adding a new mounts at runtime works if the unit is in the active state,
# so use Type=notify to make sure there's no race condition in the test
cat >/run/systemd/system/testservice-50d.service <<EOF
[Service]
RuntimeMaxSec=300
Type=notify
RemainAfterExit=yes
MountAPIVFS=yes
PrivateTmp=yes
ExecStart=bash -c ' \\
    systemd-notify --ready; \\
    while [ ! -f /tmp/img/usr/lib/os-release ] || ! grep -q -F MARKER /tmp/img/usr/lib/os-release; do \\
        sleep 0.1; \\
    done; \\
    mount; \\
    mount | grep -F "on /tmp/img type squashfs" | grep -F "nosuid" >/dev/null; \\
'
EOF
systemctl start testservice-50d.service

# Mount twice to exercise mount-beneath (on kernel 6.5+, on older kernels it will just overmount)
mkdir -p /tmp/wrong/foo
mksquashfs /tmp/wrong/foo /tmp/wrong.raw -noappend
systemctl mount-image --mkdir testservice-50d.service /tmp/wrong.raw /tmp/img
test "$(systemctl show -P SubState testservice-50d.service)" = "running"
systemctl mount-image --mkdir testservice-50d.service "$MINIMAL_IMAGE.raw" /tmp/img root:nosuid
# shellcheck disable=SC2016
timeout 30s bash -xec 'while [[ $(systemctl show -P SubState testservice-50d.service) == running ]]; do sleep .2; done'
systemctl is-active testservice-50d.service

# ExtensionImages will set up an overlay
systemd-run -P \
            --property ExtensionImages=/tmp/app0.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script0.sh | grep -F "extension-release.app0" >/dev/null
systemd-run -P \
            --property ExtensionImages=/tmp/app0.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script0.sh | grep -F "extension-release.app0" >/dev/null
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script1.sh | grep -F "extension-release.app2" >/dev/null
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/other_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionImages=/tmp/app-nodistro.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionImages=/etc/service-scoped-test.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /etc/systemd/system/some_file | grep -F "MARKER_CONFEXT_123" >/dev/null
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/conf0.raw" \
            veritysetup status "$(cat /tmp/app0.roothash)-verity" | grep "$(cat /tmp/app0.roothash)" >/dev/null
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/conf0.raw" \
            veritysetup status "$(cat /tmp/conf0.roothash)-verity" | grep "$(cat /tmp/conf0.roothash)" >/dev/null

# Check that two identical verity images at different paths do not fail with -ELOOP from OverlayFS
mkdir -p /tmp/loop
cp /tmp/app0.raw /tmp/loop/app0.raw
veritysetup format /tmp/loop/app0.raw /tmp/loop/app0.verity --root-hash-file /tmp/loop/app0.roothash
cp /tmp/loop/app0.raw /tmp/loop/app0_copy.raw
cp /tmp/loop/app0.verity /tmp/loop/app0_copy.verity
cp /tmp/loop/app0.roothash /tmp/loop/app0_copy.roothash
systemd-run -P \
            --property ExtensionImages=/tmp/loop/app0.raw \
            --property ExtensionImages=/tmp/loop/app0_copy.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            "${BIND_LOG_SOCKETS[@]}" \
            cat /opt/script0.sh | grep -F "extension-release.app0" >/dev/null
rm -rf /tmp/loop/

# Check that using a symlink to NAME-VERSION.raw works as long as the symlink has the correct name NAME.raw
mkdir -p /tmp/symlink-test/
cp /tmp/app-nodistro.raw /tmp/symlink-test/app-nodistro-v1.raw
ln -fs /tmp/symlink-test/app-nodistro-v1.raw /tmp/symlink-test/app-nodistro.raw
systemd-run -P \
            --property ExtensionImages=/tmp/symlink-test/app-nodistro.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null

# Symlink check again but for confext
mkdir -p /etc/symlink-test/
cp /etc/service-scoped-test.raw /etc/symlink-test/service-scoped-test-v1.raw
ln -fs /etc/symlink-test/service-scoped-test-v1.raw /etc/symlink-test/service-scoped-test.raw
systemd-run -P \
            --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /etc/systemd/system/some_file | grep -F "MARKER_CONFEXT_123" >/dev/null
# And again mixing sysext and confext
systemd-run -P \
    --property ExtensionImages=/tmp/symlink-test/app-nodistro.raw \
    --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
    --property RootImage="$MINIMAL_IMAGE.raw" \
    cat /etc/systemd/system/some_file | grep -F "MARKER_CONFEXT_123" >/dev/null
systemd-run -P \
    --property ExtensionImages=/tmp/symlink-test/app-nodistro.raw \
    --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
    --property RootImage="$MINIMAL_IMAGE.raw" \
    cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null

cat >/run/systemd/system/testservice-50e.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run /var/lib
StateDirectory=app0
RootImage=$MINIMAL_IMAGE.raw
ExtensionImages=/tmp/app0.raw /tmp/app1.raw:nosuid
# Relevant only for sanitizer runs
UnsetEnvironment=LD_PRELOAD
ExecStart=bash -o pipefail -c '/opt/script0.sh | grep ID'
ExecStart=bash -o pipefail -c '/opt/script1.sh | grep ID'
Type=oneshot
RemainAfterExit=yes
EOF
systemctl start testservice-50e.service
systemctl is-active testservice-50e.service

# Check vpick support in ExtensionImages=
VBASE="vtest$RANDOM"
VDIR="/tmp/$VBASE.v"
EMPTY_VDIR="/tmp/$VBASE-empty.v"
NONEXISTENT_VDIR="/tmp/$VBASE-nonexistent.v"
mkdir "$VDIR" "$EMPTY_VDIR"

ln -s /tmp/app0.raw "$VDIR/${VBASE}_0.raw"
ln -s /tmp/app0.verity "$VDIR/${VBASE}_0.verity"
ln -s /tmp/app0.roothash "$VDIR/${VBASE}_0.roothash"
ln -s /tmp/app1.raw "$VDIR/${VBASE}_1.raw"

systemd-run -P -p ExtensionImages="$VDIR -$EMPTY_VDIR -$NONEXISTENT_VDIR" bash -o pipefail -c '/opt/script1.sh | grep ID'

# Check dissect shortcut for verity images
# No verity for the second img (previous test benefits from variations), remove it for the next one
rm -f "$VDIR/${VBASE}_1.raw"
cat >/run/systemd/system/testservice-50e-vpick.service <<EOF
[Service]
Type=notify
NotifyAccess=all
MountAPIVFS=yes
TemporaryFileSystem=/run /var/lib
StateDirectory=app-vpick
RootImage=$MINIMAL_IMAGE.raw
RootImagePolicy=root=squashfs
ExtensionImages=$VDIR:x-systemd.relax-extension-release-check -$EMPTY_VDIR -$NONEXISTENT_VDIR
ExtensionImagePolicy=root=squashfs
# Relevant only for sanitizer runs
UnsetEnvironment=LD_PRELOAD
ExecStartPre=bash -c '/opt/script0.sh | grep ID'
ExecStart=sh -c 'echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; sleep infinity'
EOF
systemctl start testservice-50e-vpick.service
systemctl is-active testservice-50e-vpick.service
# Ensure the device is preopened for reuse. Note that sd-dissect -M does not work on older
# kernels, <something> makes the devices disappear on Ubuntu 24.04/C9S, so set them
# up by hand. Don't fail if it's already set up.
veritysetup open "$MINIMAL_IMAGE.raw" "$(cat "$MINIMAL_IMAGE.roothash")-verity" "$MINIMAL_IMAGE.verity" --root-hash-file "$MINIMAL_IMAGE.roothash" ||:
veritysetup open "$VDIR/${VBASE}_0.raw" "$(cat "$VDIR/${VBASE}_0.roothash")-verity" "$VDIR/${VBASE}_0.verity" --root-hash-file "$VDIR/${VBASE}_0.roothash" ||:
mkdir -p /tmp/img /tmp/ext
mount -o ro "/dev/mapper/$(cat "$MINIMAL_IMAGE.roothash")-verity" /tmp/img
mount -o ro "/dev/mapper/$(cat "$VDIR/${VBASE}_0.roothash")-verity" /tmp/ext
journalctl --sync
since="$(date '+%H:%M:%S')"
systemctl restart testservice-50e-vpick.service
systemctl is-active testservice-50e-vpick.service
journalctl --sync
timeout -v 30 journalctl --since "$since" -n all --follow | grep -m 2 -F 'Reusing pre-existing verity-protected root image'
timeout -v 30 journalctl --since "$since" -n all --follow | grep -m 2 -F 'Reusing pre-existing verity-protected image'
systemctl stop testservice-50e-vpick.service
umount -R /tmp/img
umount -R /tmp/ext
veritysetup close "$(cat "$MINIMAL_IMAGE.roothash")-verity" ||:
veritysetup close "$(cat "$VDIR/${VBASE}_0.roothash")-verity" ||:

# RootImage= uses full image dissection when udev hasn't created the symlink in /dev/mapper/ yet.
wait_for_shared_verity_device_removal
veritysetup open "$MINIMAL_IMAGE.raw" "$MINIMAL_IMAGE_ROOTHASH-verity" "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE_ROOTHASH"
udevadm wait --timeout=60 --settle "/dev/mapper/$MINIMAL_IMAGE_ROOTHASH-verity"
rm "/dev/mapper/$MINIMAL_IMAGE_ROOTHASH-verity"
systemd-run --wait --unit=test-50-verity-shortcut.service \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootImagePolicy=root=squashfs \
            true
journalctl --sync
(! journalctl -u test-50-verity-shortcut.service | grep -F 'Reusing pre-existing verity-protected root image' >/dev/null)
# The mount namespace of the service can keep the device open for a moment after systemd-run returns. A close
# without --deferred fails in that case.
veritysetup close --deferred "$MINIMAL_IMAGE_ROOTHASH-verity"

# The kernel creates the device node before its table is active. All I/O on the device fails until then.
wait_for_shared_verity_device_removal
veritysetup open "$MINIMAL_IMAGE.raw" test-50-table "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE_ROOTHASH"
dmsetup create --readonly --notable "$MINIMAL_IMAGE_ROOTHASH-verity"
dmsetup table test-50-table | dmsetup load --readonly "$MINIMAL_IMAGE_ROOTHASH-verity"
systemd-run --wait -p RootImage="$MINIMAL_IMAGE.raw" -p RootImagePolicy=root=verity true
dmsetup remove "$MINIMAL_IMAGE_ROOTHASH-verity"
veritysetup close test-50-table

rm -rf "$VDIR" "$EMPTY_VDIR"

# ExtensionDirectories will set up an overlay
mkdir -p "$IMAGE_DIR/app0" "$IMAGE_DIR/app1" "$IMAGE_DIR/app-nodistro" "$IMAGE_DIR/service-scoped-test"
(! systemd-run -P \
               --property ExtensionDirectories="$IMAGE_DIR/nonexistent" \
               --property RootImage="$MINIMAL_IMAGE.raw" \
               cat /opt/script0.sh)
(! systemd-run -P \
               --property ExtensionDirectories="$IMAGE_DIR/app0" \
               --property RootImage="$MINIMAL_IMAGE.raw" \
               cat /opt/script0.sh)
systemd-dissect --mount /tmp/app0.raw "$IMAGE_DIR/app0"
systemd-dissect --mount /tmp/app1.raw "$IMAGE_DIR/app1"
systemd-dissect --mount /tmp/app-nodistro.raw "$IMAGE_DIR/app-nodistro"
systemd-dissect --mount /etc/service-scoped-test.raw "$IMAGE_DIR/service-scoped-test"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script0.sh | grep -F "extension-release.app0" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script0.sh | grep -F "extension-release.app0" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script1.sh | grep -F "extension-release.app2" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/other_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app-nodistro" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -F "MARKER=1" >/dev/null
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/service-scoped-test" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /etc/systemd/system/some_file | grep -F "MARKER_CONFEXT_123" >/dev/null
cat >/run/systemd/system/testservice-50f.service <<EOF
[Service]
MountAPIVFS=yes
TemporaryFileSystem=/run /var/lib
StateDirectory=app0
RootImage=$MINIMAL_IMAGE.raw
ExtensionDirectories=$IMAGE_DIR/app0 $IMAGE_DIR/app1
# Relevant only for sanitizer runs
UnsetEnvironment=LD_PRELOAD
ExecStart=bash -c '/opt/script0.sh | grep ID'
ExecStart=bash -c '/opt/script1.sh | grep ID'
Type=oneshot
RemainAfterExit=yes
EOF
systemctl start testservice-50f.service
systemctl is-active testservice-50f.service

# Check vpick support in ExtensionDirectories=
VBASE="vtest$RANDOM"
VDIR="/tmp/$VBASE.v"
EMPTY_VDIR="/tmp/$VBASE-empty.v"
NONEXISTENT_VDIR="/tmp/$VBASE-nonexistent.v"
mkdir "$VDIR" "$EMPTY_VDIR"

ln -s "$IMAGE_DIR/app0" "$VDIR/${VBASE}_0"
ln -s "$IMAGE_DIR/app1" "$VDIR/${VBASE}_1"

systemd-run -P --property ExtensionDirectories="$VDIR -$EMPTY_VDIR -$NONEXISTENT_VDIR" cat /opt/script1.sh | grep -F "extension-release.app2" >/dev/null

rm -rf "$VDIR" "$EMPTY_VDIR"

systemd-dissect --umount "$IMAGE_DIR/app0"
systemd-dissect --umount "$IMAGE_DIR/app1"

# Check reloading refreshes vpick extensions
VBASE="vtest$RANDOM"
VDIR="/tmp/${VBASE}.v"
mkdir "$VDIR"
rm -rf /tmp/markers/
mkdir /tmp/markers/
CDIR1="/tmp/${VBASE}_confext_a"
CDIR2="/tmp/${VBASE}_confext_b"
mkdir -p "$CDIR1/etc/extension-release.d/" "$CDIR2/etc/extension-release.d/"
echo "ID=_any" >"$CDIR1/etc/extension-release.d/extension-release.${VBASE}_confext_a"
touch "$CDIR1/etc/${VBASE}_confext_a.marker"
echo "ID=_any" >"$CDIR2/etc/extension-release.d/extension-release.${VBASE}_confext_b"
touch "$CDIR2/etc/${VBASE}_confext_b.marker"
cat >/run/systemd/system/testservice-50g.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
ExtensionDirectories=-${VDIR} ${CDIR1} ${CDIR2}
ExecStart=bash -o pipefail -x -c ' \\
    trap "{ \\
        systemd-notify --reloading; \\
        (ls /etc | grep marker || echo no-marker) >/tmp/markers/50g; \\
        systemd-notify --ready; \\
    }" SIGHUP; \\
    systemd-notify --ready; \\
    while true; do sleep 1; done; \\
'
EOF
mkdir -p "$VDIR/${VBASE}_1/etc/extension-release.d/"
echo "ID=_any" >"$VDIR/${VBASE}_1/etc/extension-release.d/extension-release.${VBASE}_1"
touch "$VDIR/${VBASE}_1/etc/${VBASE}_1.marker"
systemctl start testservice-50g.service
systemctl is-active testservice-50g.service
# First reload; at reload time, the marker file in /etc should be picked up.
systemctl reload testservice-50g.service
grep -q -F "${VBASE}_1.marker" /tmp/markers/50g
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50g
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50g
# Make a version 2 and reload again; this time we should see the v2 marker
mkdir -p "$VDIR/${VBASE}_2/etc/extension-release.d/"
echo "ID=_any" >"$VDIR/${VBASE}_2/etc/extension-release.d/extension-release.${VBASE}_2"
touch "$VDIR/${VBASE}_2/etc/${VBASE}_2.marker"
systemctl reload testservice-50g.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50g
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50g
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50g
# Do it for a couple more times (to make sure we're tearing down old overlays)
for _ in {1..5}; do systemctl reload testservice-50g.service; done
systemctl stop testservice-50g.service
rm -f /run/systemd/system/testservice-50g.service

# Repeat the same vpick notify-reload test with ExtensionImages= (keeping the
# same VBASE and reusing VDIR files for convenience, but using .raw extensions
# this time)
VDIR2="/tmp/${VBASE}.raw.v"
mkdir "$VDIR2"
CIMG1="/tmp/${VBASE}_confext_a.raw"
CIMG2="/tmp/${VBASE}_confext_b.raw"
mksquashfs "$CDIR1" "$CIMG1" -noappend
mksquashfs "$CDIR2" "$CIMG2" -noappend
cat >/run/systemd/system/testservice-50h.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
ExtensionImages=-$VDIR2 ${CIMG1} ${CIMG2}
ExecStart=bash -o pipefail -x -c ' \\
    trap "{ \\
        systemd-notify --reloading; \\
        (ls /etc | grep marker || echo no-marker) >/tmp/markers/50h; \\
        systemd-notify --ready; \\
    }" SIGHUP; \\
    systemd-notify --ready; \\
    while true; do sleep 1; done; \\
'
EOF
mksquashfs "$VDIR/${VBASE}_1" "$VDIR2/${VBASE}_1.raw" -noappend
systemctl start testservice-50h.service
systemctl is-active testservice-50h.service
# First reload should pick up the v1 marker
systemctl reload testservice-50h.service
grep -q -F "${VBASE}_1.marker" /tmp/markers/50h
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50h
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50h
# Second reload should pick up the v2 marker
mksquashfs "$VDIR/${VBASE}_2" "$VDIR2/${VBASE}_2.raw" -noappend
systemctl reload testservice-50h.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50h
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50h
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50h
# Test that removing all the vpick extensions don't cause any issues
rm -rf "${VDIR2:?}"/*
systemctl reload testservice-50h.service
systemctl is-active testservice-50h.service
(! grep -q -F "${VBASE}_2.marker" /tmp/markers/50h)
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50h
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50h
systemctl stop testservice-50h.service
rm -f /run/systemd/system/testservice-50h.service

# Test combining vpick reload/restart with RootDirectory= & RootImage=
cat >/run/systemd/system/testservice-50i.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
RootImage=$MINIMAL_IMAGE.raw
ExtensionDirectories=-${VDIR} ${CDIR1} ${CDIR2}
NotifyAccess=all
ExecStart=bash -x -o pipefail -c ' \
    trap '"'"' \
        now=\$\$(grep "^now" /proc/timer_list | cut -d" " -f3 | rev | cut -c 4- | rev); \
        stdbuf -o1K printf "RELOADING=1\\nMONOTONIC_USEC=\$\${now}\\n" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
        (ls /etc | grep marker) >/tmp/markers/50i; \
        (cat /usr/lib/os-release) >>/tmp/markers/50i; \
        echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
    '"'"' SIGHUP; \
    echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
    while true; do sleep 1; done; \
'
EOF
# Move away the v2 extension for now
mv "$VDIR/${VBASE}_2/" "$VDIR/.${VBASE}_2"
systemctl start testservice-50i.service
systemctl is-active testservice-50i.service
# Move the v2 extension back and reload
mv "$VDIR/.${VBASE}_2" "$VDIR/${VBASE}_2/"
systemctl reload testservice-50i.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50i
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50i
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50i
# Ensure that we are also still seeing files exclusive to the root image
grep -q -F "MARKER=1" /tmp/markers/50i
systemctl stop testservice-50i.service
rm -f /run/systemd/system/testservice-50i.service

unsquashfs -force -no-xattrs -d /tmp/vpickminimg "$MINIMAL_IMAGE.raw"
cat >/run/systemd/system/testservice-50j.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
RootDirectory=/tmp/vpickminimg
ExtensionDirectories=-${VDIR} ${CDIR1} ${CDIR2}
NotifyAccess=all
ExecStart=bash -x -o pipefail -c ' \
    trap '"'"' \
        now=\$\$(grep "^now" /proc/timer_list | cut -d" " -f3 | rev | cut -c 4- | rev); \
        stdbuf -o1K printf "RELOADING=1\\nMONOTONIC_USEC=\$\${now}\\n" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
        (ls /etc | grep marker) >/tmp/markers/50j; \
        (cat /usr/lib/os-release) >>/tmp/markers/50j; \
        echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
    '"'"' SIGHUP; \
    echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
    while true; do sleep 1; done; \
'
EOF
systemctl start testservice-50j.service
systemctl is-active testservice-50j.service
systemctl reload testservice-50j.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50j
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50j
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50j
grep -q -F "MARKER=1" /tmp/markers/50j
systemctl stop testservice-50j.service
rm -f /run/systemd/system/testservice-50j.service

cat >/run/systemd/system/testservice-50k.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
RootImage=$MINIMAL_IMAGE.raw
ExtensionImages=-$VDIR2 /tmp/app0.raw ${CIMG1} ${CIMG2}
PrivateUsers=yes
NotifyAccess=all
ExecStart=bash -x -o pipefail -c ' \
    trap '"'"' \
        now=\$\$(grep "^now" /proc/timer_list | cut -d" " -f3 | rev | cut -c 4- | rev); \
        stdbuf -o1K printf "RELOADING=1\\nMONOTONIC_USEC=\$\${now}\\n" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
        (ls /etc | grep marker) >/tmp/markers/50k; \
        (cat /usr/lib/os-release) >>/tmp/markers/50k; \
        echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
    '"'"' SIGHUP; \
    echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; \
    while true; do sleep 1; done; \
'
EOF
systemctl start testservice-50k.service
systemctl is-active testservice-50k.service
# Ensure the kernel is verifying the signature if the mkosi key is in the keyring
if [ "$VERITY_SIG_SUPPORTED" -eq 1 ]; then
    veritysetup status "$(cat "$MINIMAL_IMAGE.roothash")-verity" | grep "verified (with signature)" >/dev/null
fi
# First reload should pick up the v1 marker
mksquashfs "$VDIR/${VBASE}_1" "$VDIR2/${VBASE}_1.raw" -noappend
systemctl reload testservice-50k.service
grep -q -F "${VBASE}_1.marker" /tmp/markers/50k
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50k
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50k
# Second reload should pick up the v2 marker
mksquashfs "$VDIR/${VBASE}_2" "$VDIR2/${VBASE}_2.raw" -noappend
systemctl reload testservice-50k.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50k
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50k
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50k
# Test that removing all the vpick extensions don't cause any issues
rm -rf "${VDIR2:?}"/*
systemctl reload testservice-50k.service
systemctl is-active testservice-50k.service
grep -q -F "MARKER=1" /tmp/markers/50k
grep -q -F "${VBASE}_confext_a.marker" /tmp/markers/50k
grep -q -F "${VBASE}_confext_b.marker" /tmp/markers/50k
systemctl stop testservice-50k.service
rm -f /run/systemd/system/testservice-50k.service

systemctl daemon-reload
rm -rf "$VDIR" "$VDIR2" "$CDIR1" "$CDIR2" "$CIMG1" "$CIMG2" /tmp/vpickminimg /tmp/markers/

# Check dissect shortcut for verity images
cat >/run/systemd/system/testservice-50m.service <<EOF
[Service]
Type=notify
NotifyAccess=all
TemporaryFileSystem=/run /var/lib
StateDirectory=app0
RootImage=$MINIMAL_IMAGE.raw
RootImagePolicy=root=squashfs
ExtensionImages=/tmp/app0.raw /tmp/app1.raw
ExtensionImagePolicy=root=squashfs
MountImages=/tmp/app0.raw:/var/lib/app
MountImagePolicy=root=squashfs
# Relevant only for sanitizer runs
UnsetEnvironment=LD_PRELOAD
ExecStartPre=bash -o pipefail -c '/opt/script0.sh | grep ID'
ExecStartPre=bash -o pipefail -c '/opt/script1.sh | grep ID'
ExecStartPre=test -e "/dev/mapper/$(</tmp/app0.roothash)-verity"
ExecStart=sh -c 'echo "READY=1" | socat -t 5 - UNIX-SENDTO:\$\$NOTIFY_SOCKET; sleep infinity'
EOF
systemctl start testservice-50m.service
systemctl is-active testservice-50m.service
# Ensure the device is preopened for reuse. Note that sd-dissect -M does not work on older
# kernels, <something> makes the devices disappear on Ubuntu 24.04/C9S, so set them
# up by hand. Don't fail if it's already set up.
veritysetup open "$MINIMAL_IMAGE.raw" "$(cat "$MINIMAL_IMAGE.roothash")-verity" "$MINIMAL_IMAGE.verity" --root-hash-file "$MINIMAL_IMAGE.roothash" ||:
veritysetup open /tmp/app0.raw "$(cat /tmp/app0.roothash)-verity" /tmp/app0.verity --root-hash-file /tmp/app0.roothash ||:
mkdir -p /tmp/img /tmp/ext
mount -o ro "/dev/mapper/$(cat "$MINIMAL_IMAGE.roothash")-verity" /tmp/img
mount -o ro "/dev/mapper/$(cat /tmp/app0.roothash)-verity" /tmp/ext
journalctl --sync
since="$(date '+%H:%M:%S')"
systemctl restart testservice-50m.service
systemctl is-active testservice-50m.service
journalctl --sync
timeout -v 30 journalctl --since "$since" -n all --follow | grep -m 4 -F 'Reusing pre-existing verity-protected root image'
timeout -v 30 journalctl --since "$since" -n all --follow | grep -m 8 -F 'Reusing pre-existing verity-protected image'
systemctl stop testservice-50m.service
umount /tmp/img
umount /tmp/ext
veritysetup close "$(cat "$MINIMAL_IMAGE.roothash")-verity" ||:
veritysetup close "$(cat /tmp/app0.roothash)-verity" ||:
# The shortcut doesn't check whether the kernel validated a signature for an existing device. A unit whose image
# policy requires a signature doesn't take the shortcut, while a unit whose image policy allows "verity" does.
# veritysetup sets up the devices without a signature. The process of the unit logs the messages before it
# executes the command, and the unit exits right after. journald attributes the messages to the wrong unit if
# the process is gone when journald looks up its cgroup. So we don't filter the journal by unit. Each message
# starts with the name of the unit, and each line of the trace of this script starts with a "+". We match the
# messages from the start of the line, so the trace can't match.
for image in "$MINIMAL_IMAGE" /tmp/app0; do
    name="$(cat "$image.roothash")-verity"
    timeout 60 bash -c 'while dmsetup info "$1" &>/dev/null; do sleep 0.1; done' bash "$name"
    veritysetup open "$image.raw" "$name" "$image.verity" --root-hash-file "$image.roothash"
done
mount -o ro "/dev/mapper/$(cat "$MINIMAL_IMAGE.roothash")-verity" /tmp/img
mount -o ro "/dev/mapper/$(cat /tmp/app0.roothash)-verity" /tmp/ext
if [ "$VERITY_SIG_SUPPORTED" -eq 1 ]; then
    journalctl --sync
    cursor="$(journalctl -n 1 --show-cursor | sed -n 's/^-- cursor: //p')"
    test -n "$cursor"
    systemd-run --wait -P --unit=test-50-shortcut-signed.service \
                -p RootImage="$MINIMAL_IMAGE.raw" \
                -p RootImagePolicy=root=signed+squashfs \
                -p ExtensionImages=/tmp/app0.raw \
                -p ExtensionImagePolicy=root=signed+squashfs \
                -p TemporaryFileSystem=/var/lib \
                -p MountImages=/tmp/app0.raw:/var/lib/app \
                -p MountImagePolicy=root=signed+squashfs \
                cat /opt/script0.sh
    journalctl --sync
    journalctl --after-cursor="$cursor" -o cat >/tmp/test-50-shortcut.log
    test "$(grep -cxF 'test-50-shortcut-signed.service: Image policy requires a signature, skipping verity shortcut.' /tmp/test-50-shortcut.log)" -ge 3
    (! grep -E '^test-50-shortcut-signed.service: Reusing pre-existing verity-protected' /tmp/test-50-shortcut.log)
fi
journalctl --sync
cursor="$(journalctl -n 1 --show-cursor | sed -n 's/^-- cursor: //p')"
test -n "$cursor"
systemd-run --wait -P --unit=test-50-shortcut-verity.service \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootImagePolicy=root=verity+squashfs \
            -p ExtensionImages=/tmp/app0.raw \
            -p ExtensionImagePolicy=root=verity+squashfs \
            -p TemporaryFileSystem=/var/lib \
            -p MountImages=/tmp/app0.raw:/var/lib/app \
            -p MountImagePolicy=root=verity+squashfs \
            cat /opt/script0.sh
journalctl --sync
journalctl --after-cursor="$cursor" -o cat >/tmp/test-50-shortcut.log
grep -E '^test-50-shortcut-verity.service: Reusing pre-existing verity-protected root image ' /tmp/test-50-shortcut.log >/dev/null
test "$(grep -cE '^test-50-shortcut-verity.service: Reusing pre-existing verity-protected image ' /tmp/test-50-shortcut.log)" -ge 2
rm /tmp/test-50-shortcut.log
umount /tmp/img
umount /tmp/ext
# A unit that checks a device but can't reuse it requests deferred removal of the device, so the devices can be
# gone already.
veritysetup close "$(cat "$MINIMAL_IMAGE.roothash")-verity" ||:
veritysetup close "$(cat /tmp/app0.roothash)-verity" ||:

# Test that an extension consisting of an empty directory under /etc/extensions/ takes precedence
mkdir -p /var/lib/extensions/
ln -s /tmp/app-nodistro.raw /var/lib/extensions/app-nodistro.raw
systemd-sysext status
systemd-sysext list
systemd-sysext merge
grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
systemd-sysext unmerge
mkdir -p /etc/extensions/app-nodistro
systemd-sysext merge
test ! -e /usr/lib/systemd/system/some_file
systemd-sysext unmerge
rmdir /etc/extensions/app-nodistro

# Similar, but go via varlink
varlinkctl call --more /run/systemd/io.systemd.sysext io.systemd.sysext.List '{}'
(! grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file )
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Merge '{}'
grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Refresh '{}'
grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Unmerge '{}'
(! grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file )

# And again, but unprivileged, if we have pidfds and polkit support
# Also check that the required policy is installed, as packages might be out of date with the test
if systemd-analyze compare-versions "$(uname -r)" ge 6.5 && \
        systemd-analyze compare-versions "$(pkcheck --version | awk '{print $3}')" ge 124 && \
        test -f /usr/share/polkit-1/actions/io.systemd.sysext.policy; then
    mkdir -p /etc/polkit-1/rules.d
    cat >/etc/polkit-1/rules.d/sysext-unpriv.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "io.systemd.sysext.manage" &&
        subject.user == "testuser") {
        return polkit.Result.YES;
    }
});
EOF
    systemctl try-reload-or-restart polkit.service
    run0 -u testuser varlinkctl call --more /run/systemd/io.systemd.sysext io.systemd.sysext.List '{}'
    (! grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file )
    run0 -u testuser varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Merge '{"allowInteractiveAuthentication": true}'
    grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
    run0 -u testuser varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Refresh '{"allowInteractiveAuthentication": true}'
    grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file
    run0 -u testuser varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Unmerge '{"allowInteractiveAuthentication": true}'
    (! grep -q -F "MARKER=1" /usr/lib/systemd/system/some_file )
    rm -f /etc/polkit-1/rules.d/sysext-unpriv.rules
    systemctl try-reload-or-restart polkit.service
fi

# Check that extensions cannot contain os-release
mkdir -p /run/extensions/app-reject/usr/lib/{extension-release.d/,systemd/system}
echo "ID=_any" >/run/extensions/app-reject/usr/lib/extension-release.d/extension-release.app-reject
echo "ID=_any" >/run/extensions/app-reject/usr/lib/os-release
touch /run/extensions/app-reject/usr/lib/systemd/system/other_file
(! systemd-sysext merge)
test ! -e /usr/lib/systemd/system/some_file
test ! -e /usr/lib/systemd/system/other_file
systemd-sysext unmerge
rm -rf /run/extensions/app-reject
rm /var/lib/extensions/app-nodistro.raw

# Some super basic test that RootImage= works with .v/ dirs
VBASE="vtest$RANDOM"
VDIR="/tmp/$VBASE.v"
mkdir "$VDIR"

ln -s "$MINIMAL_IMAGE.raw" "$VDIR/${VBASE}_33.raw"
ln -s "$MINIMAL_IMAGE.raw" "$VDIR/${VBASE}_34.raw"
ln -s "$MINIMAL_IMAGE.raw" "$VDIR/${VBASE}_35.raw"

systemd-run -P -p RootImage="$VDIR" cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null

rm "$VDIR/${VBASE}_33.raw" "$VDIR/${VBASE}_34.raw" "$VDIR/${VBASE}_35.raw"
rmdir "$VDIR"

mkdir -p /run/machines /run/portables /run/extensions
touch /run/machines/a.raw /run/portables/b.raw /run/extensions/c.raw

systemd-dissect --discover --json=short >/tmp/discover.json
grep -q -F '{"name":"a","type":"raw","class":"machine","ro":false,"path":"/run/machines/a.raw"' /tmp/discover.json
grep -q -F '{"name":"b","type":"raw","class":"portable","ro":false,"path":"/run/portables/b.raw"' /tmp/discover.json
grep -q -F '{"name":"c","type":"raw","class":"sysext","ro":false,"path":"/run/extensions/c.raw"' /tmp/discover.json
rm /tmp/discover.json /run/machines/a.raw /run/portables/b.raw /run/extensions/c.raw

systemd-dissect --discover --system
systemd-dissect --discover --user
systemd-dissect --discover --system --user

LOOP="$(systemd-dissect --attach --loop-ref=waldo "$MINIMAL_IMAGE.raw")"

# Wait until the symlinks we want to test are established
udevadm trigger -w "$LOOP"

# Check if the /dev/loop/* symlinks really reference the right device
test /dev/disk/by-loop-ref/waldo -ef "$LOOP"

if [ "$(stat -c '%Hd:%Ld' "$MINIMAL_IMAGE.raw")" != '?d:?d' ] ; then
   # Old stat didn't know the %Hd and %Ld specifiers and turned them into ?d
   # instead. Let's simply skip the test on such old systems.
   test "$(stat -c '/dev/disk/by-loop-inode/%Hd:%Ld-%i' "$MINIMAL_IMAGE.raw")" -ef "$LOOP"
fi

# Detach by loopback device
systemd-dissect --detach "$LOOP"

# Test long reference name.
# Note, sizeof_field(struct loop_info64, lo_file_name) == 64,
# and --loop-ref accepts upto 63 characters, and udev creates symlink
# based on the name when it has upto _62_ characters.
name="$(for _ in {1..62}; do echo -n 'x'; done)"
LOOP="$(systemd-dissect --attach --loop-ref="$name" "$MINIMAL_IMAGE.raw")"
udevadm trigger -w "$LOOP"

# Check if the /dev/disk/by-loop-ref/$name symlink really references the right device
test "/dev/disk/by-loop-ref/$name" -ef "$LOOP"

# Detach by the /dev/disk/by-loop-ref symlink
systemd-dissect --detach "/dev/disk/by-loop-ref/$name"

name="$(for _ in {1..63}; do echo -n 'x'; done)"
LOOP="$(systemd-dissect --attach --loop-ref="$name" "$MINIMAL_IMAGE.raw")"
udevadm trigger -w "$LOOP"

# Check if the /dev/disk/by-loop-ref/$name symlink does not exist
test ! -e "/dev/disk/by-loop-ref/$name"

# Detach by backing inode
systemd-dissect --detach "$MINIMAL_IMAGE.raw"
(! systemd-dissect --detach "$MINIMAL_IMAGE.raw")

# --attach --relax also works on images that do not qualify as DDI, e.g. an entirely blank one
BLANK_IMAGE="$(mktemp /var/tmp/blankXXX.raw)"
truncate -s 16M "$BLANK_IMAGE"
(! systemd-dissect --attach "$BLANK_IMAGE")
LOOP="$(systemd-dissect --attach --relax "$BLANK_IMAGE")"
test -b "$LOOP"
systemd-dissect --detach "$LOOP"
rm -f "$BLANK_IMAGE"

# --relax makes no sense for the other verbs
(! systemd-dissect --relax "$MINIMAL_IMAGE.raw")

# check for confext functionality
mkdir -p /run/confexts/test/etc/extension-release.d
echo "ID=_any" >/run/confexts/test/etc/extension-release.d/extension-release.test
echo "ARCHITECTURE=_any" >>/run/confexts/test/etc/extension-release.d/extension-release.test
echo "MARKER_CONFEXT_123" >/run/confexts/test/etc/testfile
cat <<EOF >/run/confexts/test/etc/testscript
#!/usr/bin/env bash
echo "This should not happen"
EOF
chmod +x /run/confexts/test/etc/testscript
systemd-confext merge
grep -q -F "MARKER_CONFEXT_123" /etc/testfile
(! /etc/testscript)
systemd-confext status
systemd-confext status --json=pretty | jq -e 'any(.[]; .hierarchy == "/etc" and .extensions == ["test"] and .since != null)' >/dev/null
systemd-confext unmerge
systemd-confext status --json=pretty | jq -e 'any(.[]; .hierarchy == "/etc" and .extensions == [] and .since == null)' >/dev/null
rm -rf /run/confexts/

cleanup_sysupdate_notify_confext_mutable() {
    local mutable_marker="$1"
    local notify_socket_was_active="$2"

    if [[ "$notify_socket_was_active" == "yes" ]]; then
        systemctl restart systemd-sysupdate-notify-sysext.socket || :
    else
        systemctl stop systemd-sysupdate-notify-sysext.socket || :
    fi

    rm -f "$mutable_marker"
    rm -f "/var/lib/extensions.mutable/etc/${mutable_marker#/etc/}"
    systemd-confext unmerge || :
    rm -f /run/systemd/confext.conf.d/50-test-mutable.conf
    rm -rf /run/confexts/
    rmdir /var/lib/extensions.mutable/etc /var/lib/extensions.mutable 2>/dev/null || :
}

test_sysupdate_notify_confext_mutable() {
    local mutable_marker="/etc/test-confext-mutable-$RANDOM"
    local notify_socket_was_active=no

    if systemctl is-active --quiet systemd-sysupdate-notify-sysext.socket; then
        notify_socket_was_active=yes
    fi

    trap 'cleanup_sysupdate_notify_confext_mutable "$mutable_marker" "$notify_socket_was_active"' RETURN ERR

    # Check that the sysupdate notification refresh honors confext-specific configuration.
    mkdir -p /run/systemd/confext.conf.d
    cat >/run/systemd/confext.conf.d/50-test-mutable.conf <<EOF
[ConfExt]
Mutable=yes
EOF
    mkdir -p /run/confexts/test/etc/extension-release.d
    echo "ID=_any" >/run/confexts/test/etc/extension-release.d/extension-release.test
    echo "ARCHITECTURE=_any" >>/run/confexts/test/etc/extension-release.d/extension-release.test
    echo "MARKER_CONFEXT_123" >/run/confexts/test/etc/testfile
    systemd-confext merge
    echo "MARKER_CONFEXT_MUTABLE" >"$mutable_marker"
    systemctl start systemd-sysupdate-notify-sysext.socket
    varlinkctl call /run/systemd/sysupdate/notify/io.systemd.sysext io.systemd.SysUpdate.Notify.OnCompletedUpdate '{}'
    grep -F "MARKER_CONFEXT_MUTABLE" "$mutable_marker" >/dev/null
    trap - RETURN ERR
    cleanup_sysupdate_notify_confext_mutable "$mutable_marker" "$notify_socket_was_active"
}

test_sysupdate_notify_confext_mutable

cleanup_sysupdate_notify_confext_before_sysext() {
    local notify_socket_was_active="$1"

    if [[ "$notify_socket_was_active" == "yes" ]]; then
        systemctl restart systemd-sysupdate-notify-sysext.socket || :
    else
        systemctl stop systemd-sysupdate-notify-sysext.socket || :
    fi

    systemctl stop test-order-foo.service || :
    systemd-sysext unmerge || :
    systemd-confext unmerge || :
    rm -rf /run/extensions/test-order /run/confexts/test-order
    rm -f /run/test-order-marker
}

test_sysupdate_notify_confext_before_sysext() {
    local notify_socket_was_active=no

    if systemctl is-active --quiet systemd-sysupdate-notify-sysext.socket; then
        notify_socket_was_active=yes
    fi

    trap 'cleanup_sysupdate_notify_confext_before_sysext "$notify_socket_was_active"' RETURN ERR

    # Check that the sysupdate notification refresh merges confexts before sysexts, same order as for unit
    # startup at boot. The confext ships a drop-in for a whole prefix of units, meaning it can't know what
    # units to restart through EXTENSION_RESTART_UNITS= if it would be merged after the sysext that defines
    # the unit affected by the drop-in. Only if the confext is merged first the unit picks up the drop-in.
    # This is just one example the general scenario when a confext has to create state before a sysext's
    # service is started and the confext does not know what sysext's services would be affected.
    mkdir -p /run/confexts/test-order/etc/extension-release.d /run/confexts/test-order/etc/systemd/system/test-order-.service.d
    cat >/run/confexts/test-order/etc/extension-release.d/extension-release.test-order <<EOF
ID=_any
ARCHITECTURE=_any
EXTENSION_RELOAD_MANAGER=1
EOF
    cat >/run/confexts/test-order/etc/systemd/system/test-order-.service.d/10-marker.conf <<EOF
[Service]
Environment=MARKER=from-confext
EOF

    mkdir -p /run/extensions/test-order/usr/lib/extension-release.d /run/extensions/test-order/usr/lib/systemd/system
    cat >/run/extensions/test-order/usr/lib/extension-release.d/extension-release.test-order <<EOF
ID=_any
ARCHITECTURE=_any
EXTENSION_RELOAD_MANAGER=1
EXTENSION_RESTART_UNITS=test-order-foo.service
EOF
    cat >/run/extensions/test-order/usr/lib/systemd/system/test-order-foo.service <<'EOF'
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=sh -c 'echo "${MARKER:-unset}" >/run/test-order-marker'
EOF

    systemctl start systemd-sysupdate-notify-sysext.socket
    varlinkctl call /run/systemd/sysupdate/notify/io.systemd.sysext io.systemd.SysUpdate.Notify.OnCompletedUpdate '{}'

    test -f /etc/systemd/system/test-order-.service.d/10-marker.conf
    test -f /usr/lib/systemd/system/test-order-foo.service
    systemctl --quiet is-active test-order-foo.service
    grep -F "from-confext" /run/test-order-marker >/dev/null

    trap - RETURN ERR
    cleanup_sysupdate_notify_confext_before_sysext "$notify_socket_was_active"
}

test_sysupdate_notify_confext_before_sysext

unsquashfs -force -no-xattrs -d /tmp/img "$MINIMAL_IMAGE.raw"
systemd-run --unit=test-root-ephemeral \
    -p RootDirectory=/tmp/img \
    -p RootEphemeral=yes \
    -p Type=exec \
    bash -c "touch /abc && sleep infinity"
test -n "$(ls -A /var/lib/systemd/ephemeral-trees)"
systemctl stop test-root-ephemeral
# shellcheck disable=SC2016
timeout 10 bash -c 'until test -z "$(ls -A /var/lib/systemd/ephemeral-trees)"; do sleep .5; done'
test ! -f /tmp/img/abc

# Test RootDirectoryFileDescriptor=
systemd-run --wait --pipe --root-directory=/tmp/img -- grep -q 'MARKER=1' /usr/lib/os-release
# Make sure the same root file descriptor can be reused multiple times.
systemd-run --wait --pipe --same-root-dir -p ExecStartPre=true true

systemd-dissect --mtree /tmp/img >/dev/null
systemd-dissect --list /tmp/img >/dev/null

# Test --uapi16: exercise every inode type as well as hardlinks
MANIFEST_ROOT=$(mktemp -d /tmp/manifest-test.XXXXXX)

# Regular file (with content), empty regular file, directory + nested file
echo -n "hello world" >"$MANIFEST_ROOT/regular.txt"
: >"$MANIFEST_ROOT/empty.txt"
mkdir "$MANIFEST_ROOT/subdir"
echo -n "nested" >"$MANIFEST_ROOT/subdir/nested.txt"
# Symlink with a non-trivial relative target
ln -s regular.txt "$MANIFEST_ROOT/symlink"
# FIFO, char device (/dev/null = 1,3), block device (loop0 = 7,0)
mkfifo "$MANIFEST_ROOT/fifo"
mknod "$MANIFEST_ROOT/chardev" c 1 3
mknod "$MANIFEST_ROOT/blockdev" b 7 0
# Hardlinked pair of regular files (same inode, nlink=2)
echo -n "hardlinked content" >"$MANIFEST_ROOT/hardlink_a"
ln "$MANIFEST_ROOT/hardlink_a" "$MANIFEST_ROOT/hardlink_b"
# Unix socket — bind() it with python3 if available (process exits, file persists)
HAVE_SOCKET=0
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" "$MANIFEST_ROOT/socket"
    HAVE_SOCKET=1
fi
# Predictable permissions for mode assertions
chmod 0644 "$MANIFEST_ROOT/regular.txt" "$MANIFEST_ROOT/empty.txt" \
           "$MANIFEST_ROOT/subdir/nested.txt" "$MANIFEST_ROOT/hardlink_a"
chmod 0755 "$MANIFEST_ROOT/subdir"
chmod 0600 "$MANIFEST_ROOT/fifo"
chmod 0666 "$MANIFEST_ROOT/chardev" "$MANIFEST_ROOT/blockdev"

# Capture the JSON-seq stream and convert to JSON-Lines for jq filtering. Each
# record is already on its own line in compact form, so stripping the RS (0x1E)
# byte gives us a valid JSON-Lines stream.
systemd-dissect --uapi16 "$MANIFEST_ROOT" >"$MANIFEST_ROOT.seq"
tr -d '\036' <"$MANIFEST_ROOT.seq" >"$MANIFEST_ROOT.jsonl"
test -s "$MANIFEST_ROOT.jsonl"

# Helper: emit the entry whose "name" matches $1 (root entry has no name)
get_entry() { jq -c --arg n "$1" 'select(.name == $n)' <"$MANIFEST_ROOT.jsonl"; }

# Root entry is the first record, has mediaType and no name
head -n1 "$MANIFEST_ROOT.jsonl" | \
    jq -e '.mediaType == "application/vnd.uapi.16.manifest" and (has("name") | not)' >/dev/null

# Regular file: no "type" field, has size, sha256 matches sha256sum(1), mode is 0644
ENTRY=$(get_entry regular.txt)
test "$(jq 'has("type")' <<<"$ENTRY")" = "false"
test "$(jq -r '.size' <<<"$ENTRY")" = "11"
EXPECTED_SHA=$(sha256sum "$MANIFEST_ROOT/regular.txt" | awk '{print $1}')
test "$(jq -r '.sha256' <<<"$ENTRY")" = "$EXPECTED_SHA"
test "$(printf '%o' "$(jq -r '.mode' <<<"$ENTRY")")" = "644"
# A non-hardlinked entry must not have an inodeToken
test "$(jq 'has("inodeToken")' <<<"$ENTRY")" = "false"

# Empty file: size 0, sha256 of the empty input
ENTRY=$(get_entry empty.txt)
test "$(jq -r '.size' <<<"$ENTRY")" = "0"
test "$(jq -r '.sha256' <<<"$ENTRY")" = \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Directory
ENTRY=$(get_entry subdir)
test "$(jq -r '.type' <<<"$ENTRY")" = "dir"
test "$(printf '%o' "$(jq -r '.mode' <<<"$ENTRY")")" = "755"

# Nested file uses '/' as path separator
ENTRY=$(get_entry subdir/nested.txt)
test "$(jq -r '.size' <<<"$ENTRY")" = "6"
test "$(jq 'has("sha256")' <<<"$ENTRY")" = "true"

# Symlink: type=lnk, size = strlen(target), contents carries base64 of target,
# and there is no "mode" field for symlinks
ENTRY=$(get_entry symlink)
test "$(jq -r '.type' <<<"$ENTRY")" = "lnk"
test "$(jq -r '.size' <<<"$ENTRY")" = "11"
test "$(jq -r '.contents[0].literal' <<<"$ENTRY")" = "$(printf 'regular.txt' | base64 -w0)"
test "$(jq 'has("mode")' <<<"$ENTRY")" = "false"

# FIFO
ENTRY=$(get_entry fifo)
test "$(jq -r '.type' <<<"$ENTRY")" = "fifo"
test "$(printf '%o' "$(jq -r '.mode' <<<"$ENTRY")")" = "600"

# Char device with major/minor
ENTRY=$(get_entry chardev)
test "$(jq -r '.type' <<<"$ENTRY")" = "chr"
test "$(jq -r '.major' <<<"$ENTRY")" = "1"
test "$(jq -r '.minor' <<<"$ENTRY")" = "3"

# Block device with major/minor
ENTRY=$(get_entry blockdev)
test "$(jq -r '.type' <<<"$ENTRY")" = "blk"
test "$(jq -r '.major' <<<"$ENTRY")" = "7"
test "$(jq -r '.minor' <<<"$ENTRY")" = "0"

# Unix socket (only if we managed to create one)
if [[ "$HAVE_SOCKET" -eq 1 ]]; then
    ENTRY=$(get_entry socket)
    test "$(jq -r '.type' <<<"$ENTRY")" = "sock"
fi

# Hardlinks: both members carry an inodeToken > 0, with matching token and sha256
TOKEN_A=$(get_entry hardlink_a | jq -r '.inodeToken')
TOKEN_B=$(get_entry hardlink_b | jq -r '.inodeToken')
test "$TOKEN_A" != "null"
test "$TOKEN_A" != "0"
test "$TOKEN_A" = "$TOKEN_B"
EXPECTED_SHA=$(sha256sum "$MANIFEST_ROOT/hardlink_a" | awk '{print $1}')
test "$(get_entry hardlink_a | jq -r '.sha256')" = "$EXPECTED_SHA"
test "$(get_entry hardlink_b | jq -r '.sha256')" = "$EXPECTED_SHA"

# --uapi16 output must be stable for the same directory tree
systemd-dissect --uapi16 "$MANIFEST_ROOT" >"$MANIFEST_ROOT.seq2"
cmp "$MANIFEST_ROOT.seq" "$MANIFEST_ROOT.seq2"

# --uapi16 also works against a dissected image (uses the same code path)
systemd-dissect --uapi16 "$MINIMAL_IMAGE.raw" >/dev/null

rm -rf "$MANIFEST_ROOT" "$MANIFEST_ROOT.seq" "$MANIFEST_ROOT.seq2" "$MANIFEST_ROOT.jsonl"

read -r SHA256SUM1 _ < <(systemd-dissect --copy-from /tmp/img etc/os-release | sha256sum)
test "$SHA256SUM1" != ""

echo abc >abc
systemd-dissect --copy-to /tmp/img abc /abc
test -f /tmp/img/abc

# Test --copy-ownership= option
rm -rf /tmp/copychown-test
mkdir -p /tmp/copychown-test/srcdir
echo "test file" >/tmp/copychown-test/srcdir/testfile
chown 1234:5678 /tmp/copychown-test/srcdir/testfile
chown 1234:5678 /tmp/copychown-test/srcdir

# Test --copy-ownership=yes preserves ownership for regular files
systemd-dissect --copy-from /tmp/img etc/os-release /tmp/copychown-test/os-release-chown-yes --copy-ownership=yes
test "$(stat -c %u:%g /tmp/copychown-test/os-release-chown-yes)" = "0:0"

# Test --copy-ownership=no uses current user for regular files
systemd-dissect --copy-from /tmp/img etc/os-release /tmp/copychown-test/os-release-chown-no --copy-ownership=no
test "$(stat -c %u:%g /tmp/copychown-test/os-release-chown-no)" = "0:0"

# Test --copy-ownership=auto (default) does not preserve ownership for regular files
systemd-dissect --copy-from /tmp/img etc/os-release /tmp/copychown-test/os-release-chown-auto
test "$(stat -c %u:%g /tmp/copychown-test/os-release-chown-auto)" = "0:0"

# Test --copy-ownership=yes preserves ownership for directories
systemd-dissect --copy-to /tmp/img /tmp/copychown-test/srcdir /copychown-dir-yes --copy-ownership=yes
test "$(stat -c %u:%g /tmp/img/copychown-dir-yes)" = "1234:5678"
test "$(stat -c %u:%g /tmp/img/copychown-dir-yes/testfile)" = "1234:5678"
rm -rf /tmp/img/copychown-dir-yes

# Test --copy-ownership=no overrides ownership for directories
systemd-dissect --copy-to /tmp/img /tmp/copychown-test/srcdir /copychown-dir-no --copy-ownership=no
test "$(stat -c %u:%g /tmp/img/copychown-dir-no)" = "0:0"
test "$(stat -c %u:%g /tmp/img/copychown-dir-no/testfile)" = "0:0"
rm -rf /tmp/img/copychown-dir-no

# Test --copy-ownership=auto (default) preserves ownership for directories
systemd-dissect --copy-to /tmp/img /tmp/copychown-test/srcdir /copychown-dir-auto
test "$(stat -c %u:%g /tmp/img/copychown-dir-auto)" = "1234:5678"
test "$(stat -c %u:%g /tmp/img/copychown-dir-auto/testfile)" = "1234:5678"
rm -rf /tmp/img/copychown-dir-auto

rm -rf /tmp/copychown-test

# Test for dissect tool support with systemd-sysext
mkdir -p /run/extensions/ testkit/usr/lib/extension-release.d/
echo "ID=_any" >testkit/usr/lib/extension-release.d/extension-release.testkit
echo "ARCHITECTURE=_any" >>testkit/usr/lib/extension-release.d/extension-release.testkit
echo "MARKER_SYSEXT_123" >testkit/usr/lib/testfile
mksquashfs testkit/ testkit.raw -noappend
cp testkit.raw /run/extensions/
unsquashfs -force -l /run/extensions/testkit.raw
systemd-dissect --no-pager /run/extensions/testkit.raw | grep '✓ sysext for portable service' >/dev/null
systemd-dissect --no-pager /run/extensions/testkit.raw | grep '✓ sysext for system' >/dev/null
systemd-sysext merge
systemd-sysext status
grep -q -F "MARKER_SYSEXT_123" /usr/lib/testfile
systemd-sysext unmerge
rm -rf /run/extensions/ testkit/

# Test for dissect tool support with systemd-confext
mkdir -p /run/confexts/ testjob/etc/extension-release.d/
echo "ID=_any" >testjob/etc/extension-release.d/extension-release.testjob
echo "ARCHITECTURE=_any" >>testjob/etc/extension-release.d/extension-release.testjob
echo "MARKER_CONFEXT_123" >testjob/etc/testfile
mksquashfs testjob/ testjob.raw -noappend
cp testjob.raw /run/confexts/
unsquashfs -force -l /run/confexts/testjob.raw
systemd-dissect --no-pager /run/confexts/testjob.raw | grep '✓ confext for system' >/dev/null
systemd-dissect --no-pager /run/confexts/testjob.raw | grep '✓ confext for portable service' >/dev/null
systemd-confext merge
systemd-confext status
grep -q -F "MARKER_CONFEXT_123" /etc/testfile
systemd-confext unmerge
rm -rf /run/confexts/ testjob/

systemd-run -P -p RootImage="$MINIMAL_IMAGE.raw" cat /run/host/os-release | cmp "$OS_RELEASE"

# Test that systemd-sysext reloads the daemon.
mkdir -p /var/lib/extensions/
ln -s /tmp/app-reload.raw /var/lib/extensions/app-reload.raw
systemd-sysext merge --no-reload
# the service should not be running
(! systemctl --quiet is-active foo.service)
systemd-sysext unmerge --no-reload
systemd-sysext merge
journalctl --sync
# "journalctl -u foo.service" may not work as expected, especially entries for _TRANSPORT=stdout,
# for short-living services or when the service manager generates debugging logs.
# Instead, SYSLOG_IDENTIFIER= should be reliable for stdout. Let's use it.
timeout -v 30s bash -c "journalctl -b SYSLOG_IDENTIFIER=echo _TRANSPORT=stdout -o cat -n all --follow | grep -m 1 -q '^foo$'"
systemd-sysext unmerge --no-reload
# Grep on the Warning to find the warning helper mentioning the daemon reload.
systemctl status foo.service 2>&1 | grep -F "Warning" >/dev/null
systemd-sysext merge
systemd-sysext unmerge
systemctl status foo.service 2>&1 | grep -v -F "Warning" >/dev/null
rm /var/lib/extensions/app-reload.raw

# Test that GPT images with an ISO9660 El Torito boot catalog are dissected correctly. The blkid
# superblock filter must prevent the iso9660 superblock from being detected, so dissection proceeds via
# the GPT partition table rather than treating the whole image as a single iso9660 filesystem.
defs="$(mktemp --directory "$IMAGE_DIR/test-50-dissect-eltorito.defs.XXXXXXXXXX")"
imgs="$(mktemp --directory "$IMAGE_DIR/test-50-dissect-eltorito.imgs.XXXXXXXXXX")"

tee "$defs/00-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=100M
SizeMaxBytes=100M
EOF

tee "$defs/10-root.conf" <<EOF
[Partition]
Type=root
Format=ext4
SizeMinBytes=100M
SizeMaxBytes=100M
EOF

systemd-repart --pretty=yes \
               --definitions="$defs" \
               --empty=create \
               --size=auto \
               --dry-run=no \
               --offline=yes \
               --el-torito=yes \
               "$imgs/eltorito.img"

# Verify the image has both iso9660 superblock and GPT partition table
blkid -o value -s PTTYPE "$imgs/eltorito.img" | grep -x gpt
blkid -o value -s TYPE "$imgs/eltorito.img" | grep -x iso9660

# systemd-dissect must process the GPT partitions, not the whole-device iso9660 superblock
systemd-dissect --json=short "$imgs/eltorito.img" | grep -F '"designator":"root"' | grep -F '"fstype":"ext4"'
systemd-dissect --json=short "$imgs/eltorito.img" | grep -F '"designator":"esp"' | grep -F '"fstype":"vfat"'

rm -rf "$defs" "$imgs"

# Sneak in a couple of expected-to-fail invocations to cover
# https://github.com/systemd/systemd/issues/29610
(! systemd-run -P -p MountImages="/this/should/definitely/not/exist.img:/run/img2\:3:nosuid" false)
(! systemd-run -P -p ExtensionImages="/this/should/definitely/not/exist.img" false)
(! systemd-run -P -p RootImage="/this/should/definitely/not/exist.img" false)
(! systemd-run -P -p ExtensionDirectories="/foo/bar /foo/baz" false)

# Ensure a multi-device btrfs doesn't fail to mount due to loopdev
# https://github.com/systemd/systemd/issues/42520:
if [[ -f "${BTRFS_MEMBER1:-}" ]]; then
    img="" mnt="" loop=""

    # This block runs under 'set -e'; register cleanup up front so a failure in between can't leak the
    # attached loop device or the image and perturb later device enumeration / udevadm settle.
    # shellcheck disable=SC2317
    cleanup_btrfs_mountimages() {
        if [[ -n "$mnt" ]]; then
            umount -R "$mnt" || true
        fi
        if [[ -n "$loop" ]]; then
            # Drop the members from the kernel's global, boot-wide btrfs device cache before detaching;
            # otherwise the cached entries dangle at recycled loop minors and trip multi-device detection in
            # later tests reusing the same /dev/loopN.
            btrfs device scan --forget "${loop}p1" "${loop}p2" || true
            losetup -d "$loop" || true
            # Pair the detach with a settle, like every other losetup -d in this test, so teardown isn't
            # still in flight when control returns to the broader TEST-50 run.
            udevadm settle --timeout=60 || true
        fi
        rm -f "$img"
        # Only remove the mountpoint once it is confirmed unmounted, so a failed unmount above doesn't make
        # rm -rf recurse through the mountpoint into the still-mounted filesystem.
        if [[ -n "$mnt" ]] && ! mountpoint -q "$mnt"; then
            rm -rf "$mnt"
        fi
    }
    trap cleanup_btrfs_mountimages EXIT

    img="$(mktemp /var/tmp/test-50-mountimages-btrfs.img.XXXXXXXXXX)"
    mnt="$(mktemp -d "$IMAGE_DIR/test-50-mountimages-btrfs.mnt.XXXXXXXXXX")"
    truncate -s 600M "$img"
    echo -e 'label: gpt\nsize=280MiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=data1\ntype=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=data2' | sfdisk "$img"
    loop="$(losetup --show -P -f "$img")"
    udevadm wait --timeout=60 --settle --initialized=no "${loop}p1" "${loop}p2"
    udevadm lock --timeout=60 --device="$loop" dd if="$BTRFS_MEMBER1" of="${loop}p1" bs=4M
    udevadm lock --timeout=60 --device="$loop" dd if="$BTRFS_MEMBER2" of="${loop}p2" bs=4M
    udevadm settle --timeout=60
    btrfs device scan "${loop}p1" "${loop}p2"

    mount -t btrfs "${loop}p1" "$mnt"
    btrfs subvolume create "$mnt/@demo"
    echo "MARKER=1" >"$mnt/@demo/os-release"
    btrfs subvolume create "$mnt/@"
    btrfs subvolume set-default "$mnt/@"
    umount "$mnt"
    mount -t btrfs "${loop}p1" "$mnt"

    systemd-run -P \
                -p MountImages="${loop}p1:/run/img-btrfs:subvol=@demo" \
                cat /run/img-btrfs/os-release | grep -F "MARKER=1" >/dev/null
    # Double check that there's no loopdev
    src="$(systemd-run -P \
                    -p MountImages="${loop}p1:/run/img-btrfs:subvol=@demo" \
                    findmnt -n -o SOURCE /run/img-btrfs)"
    assert_eq "${src%%\[*}" "${loop}p1"

    trap - EXIT
    cleanup_btrfs_mountimages
fi
