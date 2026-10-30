#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-repart >/dev/null; then
    echo "no systemd-repart"
    exit 0
fi

if ! test -x /usr/lib/systemd/systemd-validatefs ; then
    echo "no systemd-validatefs"
    exit 0
fi

export SYSTEMD_LOG_LEVEL=debug
export PAGER=cat

at_exit() {
    set +e
    rm -rf /tmp/validatefs-test/
    umount -R /tmp/validatefs-test.mount
    rmdir /tmp/validatefs-test.mount
    umount /tmp/validatefs-test.fake
    rmdir /tmp/validatefs-test.fake
    umount /tmp/validatefs-test.tamper
    rmdir /tmp/validatefs-test.tamper
    rm -f /var/tmp/validatefs-test.raw /var/tmp/validatefs-test.pristine.raw /var/tmp/validatefs-test.bare.raw /tmp/validatefs-test.err
}

trap at_exit EXIT

mkdir /tmp/validatefs-test
cat >/tmp/validatefs-test/validatefs-root.conf <<EOF
[Partition]
Type=root
Label=kromm
Format=ext4
EOF

cat >/tmp/validatefs-test/validatefs-usr.conf <<EOF
[Partition]
Type=usr
Label=plisch
Format=ext4
Verity=data
VerityMatchKey=mupf
EOF

cat >/tmp/validatefs-test/validatefs-usr-verity.conf <<EOF
[Partition]
Type=usr-verity
Label=plisch-verity
Verity=hash
VerityMatchKey=mupf
EOF

cat >/tmp/validatefs-test/validatefs-home.conf <<EOF
[Partition]
Type=home
Label=rupft
Format=ext4
EOF

cat >/tmp/validatefs-test/validatefs-esp.conf <<EOF
[Partition]
Type=esp
Label=fumm
Format=vfat
EOF

cat >/tmp/validatefs-test/validatefs-generic.conf <<EOF
[Partition]
Label=qnurx
Type=linux-generic
MountPoint=/somewhere/else
Format=ext4
EOF

systemd-repart --dry-run=no --empty=create --size=410M --definitions=/tmp/validatefs-test /var/tmp/validatefs-test.raw

systemd-dissect --mount --mkdir /var/tmp/validatefs-test.raw /tmp/validatefs-test.mount

getfattr --dump /tmp/validatefs-test.mount/
getfattr --dump /tmp/validatefs-test.mount/ | grep user.validatefs.gpt_type_uuid= >/dev/null
getfattr --dump /tmp/validatefs-test.mount/ | grep user.validatefs.gpt_label=\"kromm\" >/dev/null
getfattr --dump /tmp/validatefs-test.mount/ | grep user.validatefs.mount_point=\"/\" >/dev/null
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/
(! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/ )

getfattr --dump /tmp/validatefs-test.mount/usr
getfattr --dump /tmp/validatefs-test.mount/usr | grep user.validatefs.gpt_type_uuid='".*\\000.*"' >/dev/null
getfattr --dump /tmp/validatefs-test.mount/usr | grep user.validatefs.gpt_label='"plisch\\000plisch-verity"' >/dev/null
getfattr --dump /tmp/validatefs-test.mount/usr | grep user.validatefs.mount_point=\"/usr\" >/dev/null
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/usr
(! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/usr )

getfattr --dump /tmp/validatefs-test.mount/home
getfattr --dump /tmp/validatefs-test.mount/home | grep user.validatefs.gpt_type_uuid= >/dev/null
getfattr --dump /tmp/validatefs-test.mount/home | grep user.validatefs.gpt_label=\"rupft\" >/dev/null
getfattr --dump /tmp/validatefs-test.mount/home | grep user.validatefs.mount_point=\"/home\" >/dev/null
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/home
(! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/home )

getfattr --dump /tmp/validatefs-test.mount/efi
(! getfattr --dump /tmp/validatefs-test.mount/efi | grep user.validatefs.gpt_type_uuid= >/dev/null )
(! getfattr --dump /tmp/validatefs-test.mount/efi | grep user.validatefs.gpt_label= >/dev/null )
(! getfattr --dump /tmp/validatefs-test.mount/efi | grep user.validatefs.mount_point= >/dev/null )
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/efi
/usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/efi

# the generic one we must mount by hand
mkdir -p /tmp/validatefs-test.mount/somewhere/else
udevadm wait --settle --timeout=30 /dev/disk/by-label/qnurx
mount /dev/disk/by-label/qnurx /tmp/validatefs-test.mount/somewhere/else
getfattr --dump /tmp/validatefs-test.mount/somewhere/else

/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/somewhere/else

# Set up a fake mount point with incorrect data to validate a failure
mkdir /tmp/validatefs-test.fake
mount --bind /tmp/validatefs-test.fake /tmp/validatefs-test.fake
/usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.fake

if setfattr -n "user.validatefs.mount_point" -v "/foo\000/bar\000/tmp/validatefs-test.fake\000/waldo" /tmp/validatefs-test.fake ; then
    # xattrs on tmpfs are only available starting with kernel 6.6, hence handle setfattr failures gracefully
    /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.fake
    setfattr -n "user.validatefs.mount_point" -v "/knurz/schnurz\000/foo/bar/mor\000/end" /tmp/validatefs-test.fake
    (! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.fake )
fi

umount /tmp/validatefs-test.fake
rmdir /tmp/validatefs-test.fake

# Now check that the image dissection logic enforces the very same constraints when mounting the image
umount /tmp/validatefs-test.mount/somewhere/else
systemd-dissect --umount --rmdir /tmp/validatefs-test.mount

cp --sparse=always /var/tmp/validatefs-test.raw /var/tmp/validatefs-test.pristine.raw

# Modifies an xattr on the root inode of the file system in the partition with the specified label
tamper() {
    local label="${1:?}" name="${2:?}" value="${3:?}" loop node

    cp --sparse=always /var/tmp/validatefs-test.pristine.raw /var/tmp/validatefs-test.raw

    loop="$(systemd-dissect --attach /var/tmp/validatefs-test.raw)"
    node="$(sfdisk --json "$loop" | jq -r --arg l "$label" '.partitiontable.partitions[] | select(.name == $l) | .node')"
    udevadm wait --settle --timeout=30 "$node"

    mkdir -p /tmp/validatefs-test.tamper
    mount "$node" /tmp/validatefs-test.tamper
    setfattr -n "$name" -v "$value" /tmp/validatefs-test.tamper
    getfattr --dump /tmp/validatefs-test.tamper
    umount /tmp/validatefs-test.tamper
    rmdir /tmp/validatefs-test.tamper

    systemd-dissect --detach "$loop"
}

# Changes the GPT partition label of the partition with the specified label
relabel() {
    local label="${1:?}" new="${2:?}" nr

    cp --sparse=always /var/tmp/validatefs-test.pristine.raw /var/tmp/validatefs-test.raw

    nr="$(sfdisk --json /var/tmp/validatefs-test.raw | jq -r --arg l "$label" '.partitiontable.partitions | map(.name) | index($l) + 1')"
    sfdisk --part-label /var/tmp/validatefs-test.raw "$nr" "$new"
}

# Checks that mounting the image fails due to validation (and that the refused file system is not left
# mounted at the specified path within the image), and then that it works with validation turned off
check_refused() {
    local image="${1:?}" path="${2:?}"

    (! systemd-dissect --mount --mkdir "$image" /tmp/validatefs-test.mount 2>/tmp/validatefs-test.err)
    cat /tmp/validatefs-test.err
    grep "File system validation constraints not met" /tmp/validatefs-test.err >/dev/null
    (! mountpoint -q "/tmp/validatefs-test.mount$path")
    # If a non-root partition is supposed to be refused, make sure the root partition got mounted, so that
    # we know it was really the partition in question that got refused
    [[ "$path" == / ]] || mountpoint -q /tmp/validatefs-test.mount
    # The dissection logic leaves partial mounts around on failure, clean them up
    umount -R /tmp/validatefs-test.mount || :

    SYSTEMD_DISSECT_VALIDATEFS=0 systemd-dissect --mount --mkdir "$image" /tmp/validatefs-test.mount
    systemd-dissect --umount --rmdir /tmp/validatefs-test.mount
}

# The untampered image must mount fine (this is where the constraints are validated in the positive case)
systemd-dissect --mount --mkdir /var/tmp/validatefs-test.raw /tmp/validatefs-test.mount
systemd-dissect --umount --rmdir /tmp/validatefs-test.mount

# Root file system claims to belong to /home
tamper kromm user.validatefs.mount_point "/home"
check_refused /var/tmp/validatefs-test.raw /

# /home file system claims to be in a partition with a different label
tamper rupft user.validatefs.gpt_label "wrong"
check_refused /var/tmp/validatefs-test.raw /home

# /home file system has an invalid type UUID constraint
tamper rupft user.validatefs.gpt_type_uuid "nouuid"
check_refused /var/tmp/validatefs-test.raw /home

# /home file system claims to be in a partition of type srv
tamper rupft user.validatefs.gpt_type_uuid "3b8f8425-20e0-4f3b-907f-1a25a76f98e8"
check_refused /var/tmp/validatefs-test.raw /home

# The (unprotected) GPT label of the /home partition is changed
relabel rupft wrong
check_refused /var/tmp/validatefs-test.raw /home

# The (unprotected) GPT label of the Verity hash partition of /usr is changed. Note that /usr is
# Verity protected, hence we cannot modify its xattrs, but the GPT partition label is not protected.
relabel plisch-verity plisch-wrong
check_refused /var/tmp/validatefs-test.raw /usr

# Restore the pristine image, which must mount fine again
cp --sparse=always /var/tmp/validatefs-test.pristine.raw /var/tmp/validatefs-test.raw
systemd-dissect --mount --mkdir /var/tmp/validatefs-test.raw /tmp/validatefs-test.mount
systemd-dissect --umount --rmdir /tmp/validatefs-test.mount

# Now extract the /home file system into a bare file system image, without partition table. This must be
# refused, since it would be mounted as root, not as /home.
read -r start size < <(sfdisk --json /var/tmp/validatefs-test.pristine.raw | jq -r '.partitiontable.partitions[] | select(.name == "rupft") | "\(.start) \(.size)"')
dd if=/var/tmp/validatefs-test.pristine.raw of=/var/tmp/validatefs-test.bare.raw bs=512 skip="$start" count="$size" conv=sparse
check_refused /var/tmp/validatefs-test.bare.raw /

# Even if declared to be a root file system it must be refused, since it carries GPT constraints, but
# there is no GPT partition table
mkdir /tmp/validatefs-test.tamper
mount /var/tmp/validatefs-test.bare.raw /tmp/validatefs-test.tamper
setfattr -n user.validatefs.mount_point -v "/" /tmp/validatefs-test.tamper
umount /tmp/validatefs-test.tamper
check_refused /var/tmp/validatefs-test.bare.raw /
grep "is supposed to be placed on a GPT partition, but partition table type is 'bare'" /tmp/validatefs-test.err >/dev/null

# Once the GPT constraints are dropped it may be mounted
mount /var/tmp/validatefs-test.bare.raw /tmp/validatefs-test.tamper
setfattr -x user.validatefs.gpt_label /tmp/validatefs-test.tamper
setfattr -x user.validatefs.gpt_type_uuid /tmp/validatefs-test.tamper
umount /tmp/validatefs-test.tamper
rmdir /tmp/validatefs-test.tamper
systemd-dissect --mount --mkdir /var/tmp/validatefs-test.bare.raw /tmp/validatefs-test.mount
systemd-dissect --umount --rmdir /tmp/validatefs-test.mount
