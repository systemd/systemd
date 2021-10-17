#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-repart &>/dev/null; then
    echo "no systemd-repart" >/skipped
    exit 0
fi

export SYSTEMD_LOG_LEVEL=debug
export PAGER=cat

rm -f /var/tmp/testsuite-58.img /var/tmp/testsuite-58.2.img /tmp/testsuite-58.dump
mkdir -p /tmp/testsuite-58-defs/

# First part: create a disk image and verify its in order

cat >/tmp/testsuite-58-defs/esp.conf <<EOF
[Partition]
Type=esp
SizeMinBytes=10M
Format=vfat
EOF

cat >/tmp/testsuite-58-defs/usr.conf <<EOF
[Partition]
Type=usr
SizeMinBytes=10M
Format=ext4
ReadOnly=yes
EOF

cat >/tmp/testsuite-58-defs/root.conf <<EOF
[Partition]
Type=root
SizeMinBytes=10M
Format=ext4
MakeDirectories=/usr /efi
EOF

systemd-repart --definitions=/tmp/testsuite-58-defs/ \
               --empty=create \
               --size=auto \
               --seed=750b6cd5c4ae4012a15e7be3c29e6a47 \
               /var/tmp/testsuite-58.img

sfdisk --dump /var/tmp/testsuite-58.img | tee /tmp/testsuite-58.dump

grep -qxF '/var/tmp/testsuite-58.img1 : start=        2048, size=       20480, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=39107B09-615D-48FB-BA37-C663885FCE67, name="esp"' /tmp/testsuite-58.dump
grep -qxF '/var/tmp/testsuite-58.img2 : start=       22528, size=       20480, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=60F33797-1D71-4DCB-AA6F-20564F036CD0, name="root-x86-64", attrs="GUID:59"' /tmp/testsuite-58.dump
grep -qxF '/var/tmp/testsuite-58.img3 : start=       43008, size=       20480, type=8484680C-9521-48C6-9C11-B0720656F69E, uuid=7E3369DD-D653-4513-ADF5-B993A9F20C16, name="usr-x86-64", attrs="GUID:60"' /tmp/testsuite-58.dump

# Second part, duplicate it with CopyBlocks=auto

cat >/tmp/testsuite-58-defs/esp.conf <<EOF
[Partition]
Type=esp
CopyBlocks=auto
EOF

cat >/tmp/testsuite-58-defs/usr.conf <<EOF
[Partition]
Type=usr
ReadOnly=yes
CopyBlocks=auto
EOF

cat >/tmp/testsuite-58-defs/root.conf <<EOF
[Partition]
Type=root
CopyBlocks=auto
EOF

systemd-repart --definitions=/tmp/testsuite-58-defs/ \
               --empty=create \
               --size=auto \
               --seed=750b6cd5c4ae4012a15e7be3c29e6a47 \
               --image=/var/tmp/testsuite-58.img \
               /var/tmp/testsuite-58.2.img

cmp /var/tmp/testsuite-58.img /var/tmp/testsuite-58.2.img

rm /var/tmp/testsuite-58.img /var/tmp/testsuite-58.2.img /tmp/testsuite-58.dump
rm -r /tmp/testsuite-58-defs/

echo OK >/testok

exit 0
