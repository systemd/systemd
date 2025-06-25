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
    rm -f /var/tmp/validatefs-test.raw
    systemd-dissect --umount --rmdir /tmp/validatefs-test.mount
    umount /tmp/validatefs-test.fake
    rmdir /tmp/validatefs-test.fake
}

trap at_exit EXIT

mkdir /tmp/validatefs-test
cat > /tmp/validatefs-test/validatefs-root.conf <<EOF
[Partition]
Type=root
Label=kromm
Format=ext4
EOF

cat > /tmp/validatefs-test/validatefs-usr.conf <<EOF
[Partition]
Type=usr
Label=plisch
Format=ext4
Verity=data
VerityMatchKey=mupf
EOF

cat > /tmp/validatefs-test/validatefs-usr-verity.conf <<EOF
[Partition]
Type=usr-verity
Label=plisch-verity
Verity=hash
VerityMatchKey=mupf
EOF

cat > /tmp/validatefs-test/validatefs-home.conf <<EOF
[Partition]
Type=home
Label=rupft
Format=ext4
EOF

cat > /tmp/validatefs-test/validatefs-esp.conf <<EOF
[Partition]
Type=esp
Label=fumm
Format=vfat
EOF

cat > /tmp/validatefs-test/validatefs-generic.conf <<EOF
[Partition]
Label=qnurx
Type=linux-generic
MountPoint=/somewhere/else
Format=ext4
EOF

systemd-repart --dry-run=no --empty=create --size=410M --definitions=/tmp/validatefs-test /var/tmp/validatefs-test.raw

systemd-dissect --mount --mkdir /var/tmp/validatefs-test.raw /tmp/validatefs-test.mount

getfattr --dump /tmp/validatefs-test.mount/
getfattr --dump /tmp/validatefs-test.mount/ | grep -q user.validatefs.gpt_type_uuid=
getfattr --dump /tmp/validatefs-test.mount/ | grep -q user.validatefs.gpt_label=\"kromm\"
getfattr --dump /tmp/validatefs-test.mount/ | grep -q user.validatefs.mount_point=\"/\"
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/
(! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/ )

getfattr --dump /tmp/validatefs-test.mount/usr
getfattr --dump /tmp/validatefs-test.mount/usr | grep -q user.validatefs.gpt_type_uuid='".*\\000.*"'
getfattr --dump /tmp/validatefs-test.mount/usr | grep -q user.validatefs.gpt_label='"plisch\\000plisch-verity"'
getfattr --dump /tmp/validatefs-test.mount/usr | grep -q user.validatefs.mount_point=\"/usr\"
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/usr
(! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/usr )

getfattr --dump /tmp/validatefs-test.mount/home
getfattr --dump /tmp/validatefs-test.mount/home | grep -q user.validatefs.gpt_type_uuid=
getfattr --dump /tmp/validatefs-test.mount/home | grep -q user.validatefs.gpt_label=\"rupft\"
getfattr --dump /tmp/validatefs-test.mount/home | grep -q user.validatefs.mount_point=\"/home\"
/usr/lib/systemd/systemd-validatefs --root=/tmp/validatefs-test.mount /tmp/validatefs-test.mount/home
(! /usr/lib/systemd/systemd-validatefs /tmp/validatefs-test.mount/home )

getfattr --dump /tmp/validatefs-test.mount/efi
(! getfattr --dump /tmp/validatefs-test.mount/efi | grep -q user.validatefs.gpt_type_uuid= )
(! getfattr --dump /tmp/validatefs-test.mount/efi | grep -q user.validatefs.gpt_label= )
(! getfattr --dump /tmp/validatefs-test.mount/efi | grep -q  user.validatefs.mount_point= )
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
