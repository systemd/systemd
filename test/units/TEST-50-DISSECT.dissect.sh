#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235,SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-dissect --json=short "$MINIMAL_IMAGE.raw" | \
    grep -q -F '{"rw":"ro","designator":"root","partition_uuid":null,"partition_label":null,"fstype":"squashfs","architecture":null,"verity":"external"'
systemd-dissect "$MINIMAL_IMAGE.raw" | grep -q -F "MARKER=1"
# shellcheck disable=SC2153
systemd-dissect "$MINIMAL_IMAGE.raw" | grep -q -F -f <(sed 's/"//g' "$OS_RELEASE")

systemd-dissect --list "$MINIMAL_IMAGE.raw" | grep -q '^etc/os-release$'
systemd-dissect --mtree "$MINIMAL_IMAGE.raw" --mtree-hash yes | \
    grep -qE "^.(/usr|)/bin/cat type=file mode=0755 uid=0 gid=0 size=[0-9]* sha256sum=[a-z0-9]*$"
systemd-dissect --mtree "$MINIMAL_IMAGE.raw" --mtree-hash no  | \
    grep -qE "^.(/usr|)/bin/cat type=file mode=0755 uid=0 gid=0 size=[0-9]*$"

read -r SHA256SUM1 _ < <(systemd-dissect --copy-from "$MINIMAL_IMAGE.raw" etc/os-release | sha256sum)
test "$SHA256SUM1" != ""
read -r SHA256SUM2 _ < <(systemd-dissect --read-only --with "$MINIMAL_IMAGE.raw" sha256sum etc/os-release)
test "$SHA256SUM2" != ""
test "$SHA256SUM1" = "$SHA256SUM2"

if systemctl --version | grep -qF -- "+LIBARCHIVE" ; then
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
                grep -q -F '{"rw":"ro","designator":"root","partition_uuid":null,"partition_label":null,"fstype":"squashfs","architecture":null,"verity":"external"'
systemd-dissect "$MINIMAL_IMAGE.raw" \
                --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                --verity-data="$MINIMAL_IMAGE.fooverity" | \
                grep -q -F "MARKER=1"
systemd-dissect "$MINIMAL_IMAGE.raw" \
                --root-hash="$MINIMAL_IMAGE_ROOTHASH" \
                --verity-data="$MINIMAL_IMAGE.fooverity" | \
                grep -q -F -f <(sed 's/"//g' "$OS_RELEASE")
mv "$MINIMAL_IMAGE.fooverity" "$MINIMAL_IMAGE.verity"
mv "$MINIMAL_IMAGE.foohash" "$MINIMAL_IMAGE.roothash"

mkdir -p "$IMAGE_DIR/mount" "$IMAGE_DIR/mount2"
systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/usr/lib/os-release"
grep -q -F -f "$OS_RELEASE" "$IMAGE_DIR/mount/etc/os-release"
grep -q -F "MARKER=1" "$IMAGE_DIR/mount/usr/lib/os-release"
# Verity volume should be shared (opened only once)
systemd-dissect --mount "$MINIMAL_IMAGE.raw" "$IMAGE_DIR/mount2"
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
    veritysetup status "$(cat "$MINIMAL_IMAGE.roothash")-verity" | grep -q "verified (with signature)"
fi
systemd-dissect --umount "$IMAGE_DIR/mount"
systemd-dissect --umount "$IMAGE_DIR/mount2"

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

systemd-run -P -p RootImage="$MINIMAL_IMAGE.raw" cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv "$MINIMAL_IMAGE.verity" "$MINIMAL_IMAGE.fooverity"
mv "$MINIMAL_IMAGE.roothash" "$MINIMAL_IMAGE.foohash"
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootHash="$MINIMAL_IMAGE.foohash" \
            -p RootVerity="$MINIMAL_IMAGE.fooverity" \
            -p BindLogSockets=yes \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
# Let's use the long option name just here as a test
systemd-run -P \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            --property RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            --property RootVerity="$MINIMAL_IMAGE.fooverity" \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
mv "$MINIMAL_IMAGE.fooverity" "$MINIMAL_IMAGE.verity"
mv "$MINIMAL_IMAGE.foohash" "$MINIMAL_IMAGE.roothash"

# Derive partition UUIDs from root hash, in UUID syntax
ROOT_UUID="$(systemd-id128 -u show "$(head -c 32 "$MINIMAL_IMAGE.roothash")" -u | tail -n 1 | cut -b 6-)"
VERITY_UUID="$(systemd-id128 -u show "$(tail -c 32 "$MINIMAL_IMAGE.roothash")" -u | tail -n 1 | cut -b 6-)"

systemd-dissect --json=short \
                --root-hash "$MINIMAL_IMAGE_ROOTHASH" \
                "$MINIMAL_IMAGE.gpt" | \
                grep -q '{"rw":"ro","designator":"root","partition_uuid":"'"$ROOT_UUID"'","partition_label":"Root Partition","fstype":"squashfs","architecture":"'"$ARCHITECTURE"'","verity":"signed",'
systemd-dissect --json=short \
                --root-hash "$MINIMAL_IMAGE_ROOTHASH" \
                "$MINIMAL_IMAGE.gpt" | \
                grep -q '{"rw":"ro","designator":"root-verity","partition_uuid":"'"$VERITY_UUID"'","partition_label":"Verity Partition","fstype":"DM_verity_hash","architecture":"'"$ARCHITECTURE"'","verity":null,'
if [[ -n "${OPENSSL_CONFIG:-}" ]]; then
    systemd-dissect --json=short \
                    --root-hash "$MINIMAL_IMAGE_ROOTHASH" \
                    "$MINIMAL_IMAGE.gpt" | \
                    grep -qE '{"rw":"ro","designator":"root-verity-sig","partition_uuid":"'".*"'","partition_label":"Signature Partition","fstype":"verity_hash_signature","architecture":"'"$ARCHITECTURE"'","verity":null,'
fi
systemd-dissect --root-hash "$MINIMAL_IMAGE_ROOTHASH" "$MINIMAL_IMAGE.gpt" | grep -q -F "MARKER=1"
systemd-dissect --root-hash "$MINIMAL_IMAGE_ROOTHASH" "$MINIMAL_IMAGE.gpt" | grep -q -F -f <(sed 's/"//g' "$OS_RELEASE")

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

# Test RootImagePolicy= unit file setting
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='*' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='~' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -q -F "MARKER=1")
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='-' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -q -F "MARKER=1")
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='root=absent' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -q -F "MARKER=1")
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='root=verity' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='root=signed' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run --wait -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p RootImagePolicy='root=signed+lol:wut=wat+signed' \
            -p MountAPIVFS=yes \
            cat /usr/lib/os-release | grep -F "MARKER=1" >/dev/null
(! systemd-run --wait -P \
               -p RootImage="$MINIMAL_IMAGE.gpt" \
               -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
               -p RootImagePolicy='root=encrypted' \
               -p MountAPIVFS=yes \
               cat /usr/lib/os-release | grep -q -F "MARKER=1")

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
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p RootImageOptions="root:nosuid,dev home:ro,dev ro,noatime" \
            mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootImageOptions="root:ro,noatime root:ro,dev" \
            mount | grep -F "squashfs" | grep -q -F "noatime"

mkdir -p "$IMAGE_DIR/result"
cat >/run/systemd/system/testservice-50a.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "mount >/run/result/a"
BindPaths=$IMAGE_DIR/result:/run/result
TemporaryFileSystem=/run
RootImage=$MINIMAL_IMAGE.raw
RootImageOptions=root:ro,noatime home:ro,dev relatime,dev
RootImageOptions=nosuid,dev
EOF
systemctl start testservice-50a.service
grep -F "squashfs" "$IMAGE_DIR/result/a" | grep -q -F "noatime"
grep -F "squashfs" "$IMAGE_DIR/result/a" | grep -q -F -v "nosuid"

cat >/run/systemd/system/testservice-50b.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "mount >/run/result/b"
BindPaths=$IMAGE_DIR/result:/run/result
TemporaryFileSystem=/run
RootImage=$MINIMAL_IMAGE.gpt
RootImageOptions=root:ro,noatime,nosuid home:ro,dev nosuid,dev
RootImageOptions=home:ro,dev nosuid,dev,%%foo
# this is the default, but let's specify once to test the parser
MountAPIVFS=yes
EOF
systemctl start testservice-50b.service
grep -F "squashfs" "$IMAGE_DIR/result/b" | grep -q -F "noatime"

# Check that specifier escape is applied %%foo → %foo
busctl get-property org.freedesktop.systemd1 \
                    /org/freedesktop/systemd1/unit/testservice_2d50b_2eservice \
                    org.freedesktop.systemd1.Service RootImageOptions | grep -F "nosuid,dev,%foo"

# Now do some checks with MountImages, both by itself, with options and in combination with RootImage, and as single FS or GPT image
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img1/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img2/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2:nosuid,dev" \
            mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1:root:nosuid $MINIMAL_IMAGE.raw:/run/img2:home:suid" \
            mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.raw:/run/img2\:3" \
            cat /run/img2:3/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.raw:/run/img2\:3:nosuid" \
            mount | grep -F "squashfs" | grep -q -F "nosuid"
systemd-run -P \
            -p TemporaryFileSystem=/run \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p TemporaryFileSystem=/run \
            -p RootImage="$MINIMAL_IMAGE.raw" \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img1/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p TemporaryFileSystem=/run \
            -p RootImage="$MINIMAL_IMAGE.gpt" \
            -p RootHash="$MINIMAL_IMAGE_ROOTHASH" \
            -p MountImages="$MINIMAL_IMAGE.gpt:/run/img1 $MINIMAL_IMAGE.raw:/run/img2" \
            cat /run/img2/usr/lib/os-release | grep -q -F "MARKER=1"
systemd-run -P \
            -p MountImages="$MINIMAL_IMAGE.raw:/run/img2" \
            veritysetup status "${MINIMAL_IMAGE_ROOTHASH}-verity" | grep -q "${MINIMAL_IMAGE_ROOTHASH}"
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
grep -F "squashfs" "$IMAGE_DIR/result/c" | grep -q -F "noatime"
grep -F "squashfs" "$IMAGE_DIR/result/c" | grep -q -F -v "nosuid"

# Adding a new mounts at runtime works if the unit is in the active state,
# so use Type=notify to make sure there's no race condition in the test
cat >/run/systemd/system/testservice-50d.service <<EOF
[Service]
RuntimeMaxSec=300
Type=notify
RemainAfterExit=yes
MountAPIVFS=yes
PrivateTmp=yes
ExecStart=sh -c ' \\
    systemd-notify --ready; \\
    while [ ! -f /tmp/img/usr/lib/os-release ] || ! grep -q -F MARKER /tmp/img/usr/lib/os-release; do \\
        sleep 0.1; \\
    done; \\
    mount; \\
    mount | grep -F "on /tmp/img type squashfs" | grep -q -F "nosuid"; \\
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
            cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P \
            --property ExtensionImages=/tmp/app0.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script1.sh | grep -q -F "extension-release.app2"
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/app1.raw" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/other_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionImages=/tmp/app-nodistro.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionImages=/etc/service-scoped-test.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/conf0.raw" \
            veritysetup status "$(cat /tmp/app0.roothash)-verity" | grep -q "$(cat /tmp/app0.roothash)"
systemd-run -P \
            --property ExtensionImages="/tmp/app0.raw /tmp/conf0.raw" \
            veritysetup status "$(cat /tmp/conf0.roothash)-verity" | grep -q "$(cat /tmp/conf0.roothash)"

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
            cat /opt/script0.sh | grep -q -F "extension-release.app0"
rm -rf /tmp/loop/

# Check that using a symlink to NAME-VERSION.raw works as long as the symlink has the correct name NAME.raw
mkdir -p /tmp/symlink-test/
cp /tmp/app-nodistro.raw /tmp/symlink-test/app-nodistro-v1.raw
ln -fs /tmp/symlink-test/app-nodistro-v1.raw /tmp/symlink-test/app-nodistro.raw
systemd-run -P \
            --property ExtensionImages=/tmp/symlink-test/app-nodistro.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"

# Symlink check again but for confext
mkdir -p /etc/symlink-test/
cp /etc/service-scoped-test.raw /etc/symlink-test/service-scoped-test-v1.raw
ln -fs /etc/symlink-test/service-scoped-test-v1.raw /etc/symlink-test/service-scoped-test.raw
systemd-run -P \
            --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
# And again mixing sysext and confext
systemd-run -P \
    --property ExtensionImages=/tmp/symlink-test/app-nodistro.raw \
    --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
    --property RootImage="$MINIMAL_IMAGE.raw" \
    cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
systemd-run -P \
    --property ExtensionImages=/tmp/symlink-test/app-nodistro.raw \
    --property ExtensionImages=/etc/symlink-test/service-scoped-test.raw \
    --property RootImage="$MINIMAL_IMAGE.raw" \
    cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"

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
ln -s /tmp/app1.raw "$VDIR/${VBASE}_1.raw"

systemd-run -P -p ExtensionImages="$VDIR -$EMPTY_VDIR -$NONEXISTENT_VDIR" bash -o pipefail -c '/opt/script1.sh | grep ID'

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
            cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script0.sh | grep -q -F "extension-release.app0"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /opt/script1.sh | grep -q -F "extension-release.app2"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app0 $IMAGE_DIR/app1" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/other_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/app-nodistro" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /usr/lib/systemd/system/some_file | grep -q -F "MARKER=1"
systemd-run -P \
            --property ExtensionDirectories="$IMAGE_DIR/service-scoped-test" \
            --property RootImage="$MINIMAL_IMAGE.raw" \
            cat /etc/systemd/system/some_file | grep -q -F "MARKER_CONFEXT_123"
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

systemd-run -P --property ExtensionDirectories="$VDIR -$EMPTY_VDIR -$NONEXISTENT_VDIR" cat /opt/script1.sh | grep -q -F "extension-release.app2"

rm -rf "$VDIR" "$EMPTY_VDIR"

systemd-dissect --umount "$IMAGE_DIR/app0"
systemd-dissect --umount "$IMAGE_DIR/app1"

# Check reloading refreshes vpick extensions
VBASE="vtest$RANDOM"
VDIR="/tmp/${VBASE}.v"
mkdir "$VDIR"
rm -rf /tmp/markers/
mkdir /tmp/markers/
cat >/run/systemd/system/testservice-50g.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
ExtensionDirectories=-${VDIR}
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
# Make a version 2 and reload again; this time we should see the v2 marker
mkdir -p "$VDIR/${VBASE}_2/etc/extension-release.d/"
echo "ID=_any" >"$VDIR/${VBASE}_2/etc/extension-release.d/extension-release.${VBASE}_2"
touch "$VDIR/${VBASE}_2/etc/${VBASE}_2.marker"
systemctl reload testservice-50g.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50g
# Do it for a couple more times (to make sure we're tearing down old overlays)
for _ in {1..5}; do systemctl reload testservice-50g.service; done
systemctl stop testservice-50g.service
rm -f /run/systemd/system/testservice-50g.service

# Repeat the same vpick notify-reload test with ExtensionImages= (keeping the
# same VBASE and reusing VDIR files for convenience, but using .raw extensions
# this time)
VDIR2="/tmp/${VBASE}.raw.v"
mkdir "$VDIR2"
cat >/run/systemd/system/testservice-50h.service <<EOF
[Service]
Type=notify-reload
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateTmp=disconnected
BindPaths=/tmp/markers/
ExtensionImages=-$VDIR2
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
# Second reload should pick up the v2 marker
mksquashfs "$VDIR/${VBASE}_2" "$VDIR2/${VBASE}_2.raw" -noappend
systemctl reload testservice-50h.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50h
# Test that removing all the extensions don't cause any issues
rm -rf "${VDIR2:?}"/*
systemctl reload testservice-50h.service
systemctl is-active testservice-50h.service
grep -q -F "no-marker" /tmp/markers/50h
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
ExtensionDirectories=-${VDIR}
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
ExtensionDirectories=-${VDIR}
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
ExtensionImages=-$VDIR2 /tmp/app0.raw
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
    veritysetup status "$(cat "$MINIMAL_IMAGE.roothash")-verity" | grep -q "verified (with signature)"
fi
# First reload should pick up the v1 marker
mksquashfs "$VDIR/${VBASE}_1" "$VDIR2/${VBASE}_1.raw" -noappend
systemctl reload testservice-50k.service
grep -q -F "${VBASE}_1.marker" /tmp/markers/50k
# Second reload should pick up the v2 marker
mksquashfs "$VDIR/${VBASE}_2" "$VDIR2/${VBASE}_2.raw" -noappend
systemctl reload testservice-50k.service
grep -q -F "${VBASE}_2.marker" /tmp/markers/50k
# Test that removing all the extensions don't cause any issues
rm -rf "${VDIR2:?}"/*
systemctl reload testservice-50k.service
systemctl is-active testservice-50k.service
grep -q -F "MARKER=1" /tmp/markers/50k
systemctl stop testservice-50k.service
rm -f /run/systemd/system/testservice-50k.service

systemctl daemon-reload
rm -rf "$VDIR" "$VDIR2" /tmp/vpickminimg /tmp/markers/

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

systemd-run -P -p RootImage="$VDIR" cat /usr/lib/os-release | grep -q -F "MARKER=1"

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
systemd-confext unmerge
rm -rf /run/confexts/

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

systemd-dissect --mtree /tmp/img >/dev/null
systemd-dissect --list /tmp/img >/dev/null

read -r SHA256SUM1 _ < <(systemd-dissect --copy-from /tmp/img etc/os-release | sha256sum)
test "$SHA256SUM1" != ""

echo abc > abc
systemd-dissect --copy-to /tmp/img abc /abc
test -f /tmp/img/abc

# Test for dissect tool support with systemd-sysext
mkdir -p /run/extensions/ testkit/usr/lib/extension-release.d/
echo "ID=_any" >testkit/usr/lib/extension-release.d/extension-release.testkit
echo "ARCHITECTURE=_any" >>testkit/usr/lib/extension-release.d/extension-release.testkit
echo "MARKER_SYSEXT_123" >testkit/usr/lib/testfile
mksquashfs testkit/ testkit.raw -noappend
cp testkit.raw /run/extensions/
unsquashfs -force -l /run/extensions/testkit.raw
systemd-dissect --no-pager /run/extensions/testkit.raw | grep -q '✓ sysext for portable service'
systemd-dissect --no-pager /run/extensions/testkit.raw | grep -q '✓ sysext for system'
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
systemd-dissect --no-pager /run/confexts/testjob.raw | grep -q '✓ confext for system'
systemd-dissect --no-pager /run/confexts/testjob.raw | grep -q '✓ confext for portable service'
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
timeout -v 30s journalctl -b SYSLOG_IDENTIFIER=echo _TRANSPORT=stdout -o cat -n all --follow | grep -m 1 -q '^foo$'
systemd-sysext unmerge --no-reload
# Grep on the Warning to find the warning helper mentioning the daemon reload.
systemctl status foo.service 2>&1 | grep -q -F "Warning"
systemd-sysext merge
systemd-sysext unmerge
systemctl status foo.service 2>&1 | grep -v -q -F "Warning"
rm /var/lib/extensions/app-reload.raw

# Sneak in a couple of expected-to-fail invocations to cover
# https://github.com/systemd/systemd/issues/29610
(! systemd-run -P -p MountImages="/this/should/definitely/not/exist.img:/run/img2\:3:nosuid" false)
(! systemd-run -P -p ExtensionImages="/this/should/definitely/not/exist.img" false)
(! systemd-run -P -p RootImage="/this/should/definitely/not/exist.img" false)
(! systemd-run -P -p ExtensionDirectories="/foo/bar /foo/baz" false)
